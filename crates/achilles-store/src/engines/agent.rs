//! Investigate/Deep model pass. Engines already wrote findings; this loop may
//! confirm or dismiss them. The model may `read` / `ledger` / `grep`. A failed
//! or incomplete verdict must leave the engine hit on the ledger.
//! Thinking is off; native tool-calling is not required (JSON turns).
//! Apache-2.0.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::engines::abort::Abort;
use crate::engines::budget::ScanBudget;
use crate::engines::depth::ScanDepth;
use crate::engines::fingerprint::Fingerprint;
use crate::engines::units::{self, CodeUnit};
use crate::engines::walk::WalkedFile;
use crate::store::AchillesStore;
use crate::types::{Candidate, Finding, NewFinding, Severity};

pub const MAX_REVIEW: usize = 80;
const TOOL_HINT: &str = r#"You are inspecting real source against achilles.db. Each turn, reply with ONE JSON object:
{"read":{"path":"rel/file.py","start":1,"end":120}} — load more numbered source (workspace-relative)
{"ledger":{"finding_id":"..."}} — load one existing ledger finding + nearby source
{"grep":{"pattern":"literal","path":"optional/rel/or/dir"}} — search indexed files (literal substring, not a regex)
Finish with {"verdict":"true_positive"|"false_positive"|"uncertain","reason":"..."} for a ledger review,
or {"findings":[{"title":"...","severity":"high","cwe":"CWE-78","path":"rel","line":N,"quote":"copied from source you were shown","why":"..."}]} (use findings:[] if clean).
Inspect before you verdict: read surrounding source or grep the sink/argument. Do not invent CVEs, secrets, or exploit steps. Quotes must appear in source you were shown."#;
const SYSTEM_REVIEW: &str = "You are the investigator or validator on one Fast engine finding. Keep the hit on the ledger unless you can show from source that it is a false positive. Read the function and how the argument is built. Reason must cite the snippet. Do not invent other issues.";
const SYSTEM_UNIT: &str = "Deep function inspection. Read callers/callees or grep the same sink if the body is not enough. Record a finding only for a concrete untrusted-input-to-sink issue with a quote from source you were shown. Empty findings is correct when it looks safe. Do not invent CVEs or secrets.";

pub struct CompleteOut {
    pub text: String,
    pub cost_usd: Option<f64>,
}

pub trait ScanCompleter: Send + Sync {
    fn complete(
        &self,
        system: String,
        user: String,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<CompleteOut>> + Send>>;
}

pub struct AgentStats {
    pub reviewed: usize,
    pub units: usize,
    pub new_findings: usize,
    pub confirmed: usize,
    pub dismissed: usize,
    pub errors: usize,
    pub notes: Vec<Value>,
}

#[derive(Clone)]
struct ReviewJob {
    finding_id: Option<String>,
    candidate_id: Option<String>,
    path: String,
    line: i64,
    title: String,
    user: String,
}

struct UnitJob {
    unit: CodeUnit,
    user: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerdictJson {
    verdict: String,
    reason: String,
}

#[derive(Deserialize)]
struct UnitResponse {
    #[serde(default)]
    findings: Vec<UnitFindingJson>,
}

#[derive(Deserialize)]
struct UnitFindingJson {
    title: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    cwe: Option<String>,
    #[serde(default)]
    path: Option<String>,
    line: i64,
    quote: String,
    why: String,
}

// Scan orchestration passes the full assessment context through; grouping
// into a struct would churn every engine call site for no behavior change.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    store: &AchillesStore,
    root: &Path,
    engagement_id: &str,
    assessment_id: &str,
    depth: ScanDepth,
    fingerprint: &Fingerprint,
    files: &[WalkedFile],
    findings: &[Finding],
    completer: Arc<dyn ScanCompleter>,
    abort: &Abort,
    pause: Arc<AtomicBool>,
    budget: Option<ScanBudget>,
) -> Result<AgentStats> {
    let surface_ids: Vec<String> = fingerprint.surfaces.iter().map(|s| s.id.clone()).collect();
    let surface_paths: Vec<String> = fingerprint
        .surfaces
        .iter()
        .flat_map(|s| s.paths.iter().cloned())
        .collect();
    let pending = store
        .list_candidates(assessment_id, Some("pending"), Some("sast"))
        .await
        .unwrap_or_default();
    let review_cap = depth.max_review();
    let mut reviews = review_jobs_from_candidates(root, &pending, &surface_ids, review_cap);
    let remain = review_cap.saturating_sub(reviews.len());
    reviews.extend(review_jobs(root, findings, &surface_ids, remain));
    let units = if depth.max_units() > 0 {
        let mut sast_paths: Vec<String> = findings
            .iter()
            .filter(|f| f.category == "sast" || f.category == "delta")
            .filter_map(|f| f.path.clone())
            .collect();
        sast_paths.extend(pending.iter().filter_map(|c| c.path.clone()));
        let extracted = units::extract_scored(
            files,
            &sast_paths,
            &surface_paths,
            Some(abort.flag()),
            depth.max_units(),
        );
        extracted
            .into_iter()
            .map(|unit| {
                let playbook = crate::engines::playbook::for_context(&surface_ids, &unit.path);
                let user = format!(
                    "{playbook}\n\n{TOOL_HINT}\n\nFILE: {path}:{start}-{end} function {name}\n```\n{body}\n```\n\nWhen done, return {{\"findings\":[...]}} or {{\"findings\":[]}}.",
                    path = unit.path,
                    start = unit.line_start,
                    end = unit.line_end,
                    name = unit.name,
                    body = unit.body,
                );
                UnitJob { unit, user }
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut stats = AgentStats {
        reviewed: reviews.len(),
        units: units.len(),
        new_findings: 0,
        confirmed: 0,
        dismissed: 0,
        errors: 0,
        notes: Vec::new(),
    };
    if reviews.is_empty() && units.is_empty() {
        return Ok(stats);
    }

    let sem = Arc::new(Semaphore::new(depth.max_workers().max(1)));
    let mut reviews_set: JoinSet<(ReviewOutcome, Value)> = JoinSet::new();
    let store = store.clone();
    let engagement = engagement_id.to_string();
    let assessment = assessment_id.to_string();
    let root_buf = root.to_path_buf();
    let files_owned: Vec<WalkedFile> = files.to_vec();
    let max_turns = depth.max_turns();
    let stats_store = store.clone();
    let stats_assessment = assessment.clone();
    for job in reviews {
        if abort.is_cancelled() {
            break;
        }
        let permit = sem.clone().acquire_owned().await?;
        let completer = completer.clone();
        let store = store.clone();
        let abort = abort.clone();
        let pause = pause.clone();
        let budget = budget.clone();
        let root_buf = root_buf.clone();
        let files_owned = files_owned.clone();
        reviews_set.spawn(async move {
            let _permit = permit;
            if wait_pause(&pause, &abort).await.is_err() || abort.is_cancelled() {
                return (ReviewOutcome::Cancelled, review_note(&job, "cancelled", ""));
            }
            if let Some(budget) = &budget {
                if budget.check().is_err() {
                    return (ReviewOutcome::Cancelled, review_note(&job, "cancelled", ""));
                }
            }
            review_one(
                &store,
                &root_buf,
                &files_owned,
                &completer,
                job,
                budget.as_ref(),
                max_turns,
            )
            .await
        });
    }

    while let Some(joined) = reviews_set.join_next().await {
        match joined {
            Ok((ReviewOutcome::Confirmed, note)) => {
                stats.confirmed += 1;
                stats.notes.push(note);
            }
            Ok((ReviewOutcome::Dismissed, note)) => {
                stats.dismissed += 1;
                stats.notes.push(note);
            }
            Ok((ReviewOutcome::Open, note)) => stats.notes.push(note),
            Ok((ReviewOutcome::Cancelled, note)) => stats.notes.push(note),
            Ok((ReviewOutcome::Error, note)) => {
                stats.errors += 1;
                stats.notes.push(note);
            }
            Err(_) => stats.errors += 1,
        }
        let _ = flush_agent_progress(&stats_store, &stats_assessment, &stats).await;
    }

    let mut units_set: JoinSet<(UnitOutcome, Value)> = JoinSet::new();
    for job in units {
        if abort.is_cancelled() {
            break;
        }
        let permit = sem.clone().acquire_owned().await?;
        let completer = completer.clone();
        let store = store.clone();
        let abort = abort.clone();
        let engagement = engagement.clone();
        let assessment = assessment.clone();
        let pause = pause.clone();
        let budget = budget.clone();
        let root_buf = root_buf.clone();
        let files_owned = files_owned.clone();
        units_set.spawn(async move {
            let _permit = permit;
            if wait_pause(&pause, &abort).await.is_err() || abort.is_cancelled() {
                return (UnitOutcome::Cancelled, unit_note(&job.unit, "cancelled", 0));
            }
            if let Some(budget) = &budget {
                if budget.check().is_err() {
                    return (UnitOutcome::Cancelled, unit_note(&job.unit, "cancelled", 0));
                }
            }
            unit_one(
                &store,
                &root_buf,
                &files_owned,
                &engagement,
                &assessment,
                &completer,
                job,
                budget.as_ref(),
                max_turns,
            )
            .await
        });
    }

    while let Some(joined) = units_set.join_next().await {
        match joined {
            Ok((UnitOutcome::Added(n), note)) => {
                stats.new_findings += n;
                stats.notes.push(note);
            }
            Ok((UnitOutcome::None, note)) => stats.notes.push(note),
            Ok((UnitOutcome::Cancelled, note)) => stats.notes.push(note),
            Ok((UnitOutcome::Error, note)) => {
                stats.errors += 1;
                stats.notes.push(note);
            }
            Err(_) => stats.errors += 1,
        }
        let _ = flush_agent_progress(&stats_store, &stats_assessment, &stats).await;
    }

    Ok(stats)
}

async fn flush_agent_progress(
    store: &AchillesStore,
    assessment_id: &str,
    stats: &AgentStats,
) -> Result<()> {
    store
        .merge_stats(
            assessment_id,
            json!({
                "agentLog": stats.notes,
                "agentReviewed": stats.reviewed,
                "agentUnits": stats.units,
                "agentConfirmed": stats.confirmed,
                "agentDismissed": stats.dismissed,
                "agentNewFindings": stats.new_findings,
                "agentErrors": stats.errors,
                "agent": stats.reviewed + stats.units,
            }),
        )
        .await
}

fn review_note(job: &ReviewJob, outcome: &str, reason: &str) -> Value {
    let loc = if job.line > 0 {
        format!("{}:{}", job.path, job.line)
    } else if job.path.is_empty() {
        job.title.clone()
    } else {
        job.path.clone()
    };
    json!({
        "kind": "review",
        "outcome": outcome,
        "path": job.path,
        "line": job.line,
        "title": job.title,
        "text": format!("AI review · {loc} — {outcome}{}", if reason.is_empty() { String::new() } else { format!(": {reason}") }),
    })
}

fn unit_note(unit: &CodeUnit, outcome: &str, added: usize) -> Value {
    let detail = if added > 0 {
        format!("{outcome}, recorded {added} finding(s)")
    } else {
        outcome.to_string()
    };
    json!({
        "kind": "unit",
        "outcome": outcome,
        "path": unit.path,
        "line": unit.line_start,
        "title": unit.name,
        "text": format!("Deep inspect · {} {} — {detail}", unit.path, unit.name),
    })
}

async fn wait_pause(pause: &AtomicBool, abort: &Abort) -> Result<()> {
    while pause.load(Ordering::Relaxed) {
        if abort.is_cancelled() {
            anyhow::bail!(crate::engines::abort::Cancelled);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

enum ReviewOutcome {
    Confirmed,
    Dismissed,
    Open,
    Cancelled,
    Error,
}

enum UnitOutcome {
    Added(usize),
    None,
    Cancelled,
    Error,
}

fn reviewable_finding(finding: &Finding) -> bool {
    matches!(finding.state.as_str(), "open" | "confirmed")
        && matches!(
            finding.category.as_str(),
            "sast" | "delta" | "surface" | "surfaces" | "harden"
        )
}

fn review_jobs(
    root: &Path,
    findings: &[Finding],
    surface_ids: &[String],
    limit: usize,
) -> Vec<ReviewJob> {
    findings
        .iter()
        .filter(|f| reviewable_finding(f))
        .take(limit)
        .map(|finding| {
            let playbook = crate::engines::playbook::for_context(
                surface_ids,
                finding.path.as_deref().unwrap_or(""),
            );
            let snippet = match (&finding.path, finding.line_start) {
                (Some(rel), Some(line)) => crate::engines::investigate::agent_brief(
                    root,
                    rel,
                    line,
                    crate::engines::agent_loop::REVIEW_SNIPPET_CTX,
                ),
                _ => String::new(),
            };
            let hint = finding
                .evidence_json
                .pointer("/investigation/kind")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let path = finding.path.clone().unwrap_or_default();
            let line = finding.line_start.unwrap_or(0);
            let user = format!(
                "{playbook}\n\n{TOOL_HINT}\n\nFINDING id={id}\nrule={rule}\nseverity={sev}\nconfidence={conf}\narg_kind={hint}\npath={path}:{line}\ntitle={title}\n\nSOURCE:\n```\n{snippet}\n```\n\nRead or grep how this argument is built, then return {{\"verdict\":\"true_positive|false_positive|uncertain\",\"reason\":\"...\"}}.",
                id = finding.id,
                rule = finding.rule_id,
                sev = finding.severity,
                conf = finding.confidence,
                title = finding.title,
            );
            ReviewJob {
                finding_id: Some(finding.id.clone()),
                candidate_id: None,
                path,
                line,
                title: finding.title.clone(),
                user,
            }
        })
        .collect()
}

fn review_jobs_from_candidates(
    root: &Path,
    candidates: &[Candidate],
    surface_ids: &[String],
    limit: usize,
) -> Vec<ReviewJob> {
    candidates
        .iter()
        .take(limit)
        .map(|candidate| {
            let playbook = crate::engines::playbook::for_context(
                surface_ids,
                candidate.path.as_deref().unwrap_or(""),
            );
            let snippet = match (&candidate.path, candidate.line_start) {
                (Some(rel), Some(line)) => crate::engines::investigate::agent_brief(
                    root,
                    rel,
                    line,
                    crate::engines::agent_loop::REVIEW_SNIPPET_CTX,
                ),
                _ => candidate.snippet_redacted.clone(),
            };
            let rule = candidate
                .payload_json
                .get("ruleId")
                .or_else(|| candidate.payload_json.get("rule_id"))
                .and_then(|v| v.as_str())
                .unwrap_or(candidate.matcher_or_engine.as_str());
            let title = candidate
                .payload_json
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or(rule)
                .to_string();
            let path = candidate.path.clone().unwrap_or_default();
            let line = candidate.line_start.unwrap_or(0);
            let user = format!(
                "{playbook}\n\n{TOOL_HINT}\n\nCANDIDATE id={id}\nrule={rule}\npath={path}:{line}\ntitle={title}\n\nSOURCE:\n```\n{snippet}\n```\n\nRead or grep how this argument is built, then return {{\"verdict\":\"true_positive|false_positive|uncertain\",\"reason\":\"...\"}}.",
                id = candidate.id,
            );
            ReviewJob {
                finding_id: None,
                candidate_id: Some(candidate.id.clone()),
                path,
                line,
                title,
                user,
            }
        })
        .collect()
}

async fn review_one(
    store: &AchillesStore,
    root: &Path,
    files: &[WalkedFile],
    completer: &Arc<dyn ScanCompleter>,
    job: ReviewJob,
    budget: Option<&ScanBudget>,
    max_turns: usize,
) -> (ReviewOutcome, Value) {
    let subject = job
        .candidate_id
        .as_deref()
        .or(job.finding_id.as_deref())
        .unwrap_or("-");
    let investigator = match complete_verdict(
        store,
        root,
        files,
        completer,
        SYSTEM_REVIEW,
        job.user.clone(),
        budget,
        max_turns,
    )
    .await
    {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!(error = %err, subject, "investigator complete failed");
            return (
                ReviewOutcome::Error,
                review_note(&job, "error", &err.to_string()),
            );
        }
    };
    if let Some(finding_id) = &job.finding_id {
        if store
            .set_finding_verdict(
                finding_id,
                "investigator",
                &investigator.verdict,
                &investigator.reason,
            )
            .await
            .is_err()
        {
            return (
                ReviewOutcome::Error,
                review_note(&job, "error", "could not write investigator verdict"),
            );
        }
    }
    let validator_user = format!(
        "{}\n\nInvestigator already said verdict={} reason={}. Independently confirm or reject. You may still read, ledger, or grep.",
        job.user, investigator.verdict, investigator.reason
    );
    let validator = match complete_verdict(
        store,
        root,
        files,
        completer,
        SYSTEM_REVIEW,
        validator_user,
        budget,
        max_turns,
    )
    .await
    {
        Ok(v) => v,
        Err(err) => {
            tracing::debug!(error = %err, subject, "validator complete failed");
            return (
                ReviewOutcome::Error,
                review_note(&job, "error", &err.to_string()),
            );
        }
    };
    if let Some(finding_id) = &job.finding_id {
        if store
            .set_finding_verdict(
                finding_id,
                "validator",
                &validator.verdict,
                &validator.reason,
            )
            .await
            .is_err()
        {
            return (
                ReviewOutcome::Error,
                review_note(&job, "error", "could not write validator verdict"),
            );
        }
    }
    let reason = validator.reason.clone();
    match (investigator.verdict.as_str(), validator.verdict.as_str()) {
        ("true_positive", "true_positive") => {
            if let Some(candidate_id) = &job.candidate_id {
                if let Ok(finding_id) = store.confirm_candidate(candidate_id).await {
                    let _ = store
                        .set_finding_verdict(
                            &finding_id,
                            "investigator",
                            &investigator.verdict,
                            &investigator.reason,
                        )
                        .await;
                    let _ = store
                        .set_finding_verdict(
                            &finding_id,
                            "validator",
                            &validator.verdict,
                            &validator.reason,
                        )
                        .await;
                    let _ = store.set_finding_state(&finding_id, "confirmed").await;
                } else {
                    return (
                        ReviewOutcome::Error,
                        review_note(&job, "error", "could not confirm candidate"),
                    );
                }
            } else if let Some(finding_id) = &job.finding_id {
                let _ = store.set_finding_state(finding_id, "confirmed").await;
            }
            (
                ReviewOutcome::Confirmed,
                review_note(&job, "confirmed", &reason),
            )
        }
        ("false_positive", "false_positive") => {
            if let Some(candidate_id) = &job.candidate_id {
                if let Ok(finding_id) = store.confirm_candidate(candidate_id).await {
                    let _ = store.set_finding_state(&finding_id, "dismissed").await;
                } else {
                    let _ = store.reject_candidate(candidate_id).await;
                }
            } else if let Some(finding_id) = &job.finding_id {
                let _ = store.set_finding_state(finding_id, "dismissed").await;
            }
            (
                ReviewOutcome::Dismissed,
                review_note(&job, "dismissed", &reason),
            )
        }
        _ => {
            if let Some(candidate_id) = &job.candidate_id {
                let _ = store.escalate_candidate(candidate_id).await;
            }
            (
                ReviewOutcome::Open,
                review_note(
                    &job,
                    "uncertain",
                    &format!(
                        "investigator={} validator={}",
                        investigator.verdict, validator.verdict
                    ),
                ),
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn unit_one(
    store: &AchillesStore,
    root: &Path,
    files: &[WalkedFile],
    engagement_id: &str,
    assessment_id: &str,
    completer: &Arc<dyn ScanCompleter>,
    job: UnitJob,
    budget: Option<&ScanBudget>,
    max_turns: usize,
) -> (UnitOutcome, Value) {
    let mut corpus = job.unit.body.clone();
    let mut allowed = HashSet::new();
    if let Some(rel) = crate::engines::agent_loop::normalize_rel(&job.unit.path) {
        allowed.insert(rel);
    } else {
        allowed.insert(job.unit.path.replace('\\', "/"));
    }
    let parsed = match crate::engines::agent_loop::drive(
        completer,
        SYSTEM_UNIT,
        job.user.clone(),
        crate::engines::agent_loop::LoopMode::Unit,
        crate::engines::agent_loop::LoopIo {
            root,
            store: Some(store),
            files,
            corpus: &mut corpus,
            allowed: &mut allowed,
        },
        budget,
        max_turns,
    )
    .await
    {
        Ok(crate::engines::agent_loop::LoopFinish::Findings(value)) => {
            match serde_json::from_value::<UnitResponse>(value) {
                Ok(p) => p,
                Err(_) => return (UnitOutcome::Error, unit_note(&job.unit, "error", 0)),
            }
        }
        Ok(_) => return (UnitOutcome::Error, unit_note(&job.unit, "error", 0)),
        Err(err) => {
            tracing::debug!(error = %err, path = %job.unit.path, "unit complete failed");
            return (UnitOutcome::Error, unit_note(&job.unit, "error", 0));
        }
    };
    let mut added = 0usize;
    for hit in parsed.findings {
        let Some(finding) = unit_to_finding(&job.unit, &corpus, &allowed, hit) else {
            continue;
        };
        if store
            .upsert_finding(engagement_id, assessment_id, &finding)
            .await
            .is_ok()
        {
            added += 1;
        }
    }
    if added == 0 {
        (UnitOutcome::None, unit_note(&job.unit, "clean", 0))
    } else {
        (
            UnitOutcome::Added(added),
            unit_note(&job.unit, "finding", added),
        )
    }
}

#[allow(clippy::too_many_arguments)]
async fn complete_verdict(
    store: &AchillesStore,
    root: &Path,
    files: &[WalkedFile],
    completer: &Arc<dyn ScanCompleter>,
    system: &str,
    user: String,
    budget: Option<&ScanBudget>,
    max_turns: usize,
) -> Result<VerdictJson> {
    let mut corpus = String::new();
    let mut allowed = HashSet::new();
    match crate::engines::agent_loop::drive(
        completer,
        system,
        user,
        crate::engines::agent_loop::LoopMode::Review,
        crate::engines::agent_loop::LoopIo {
            root,
            store: Some(store),
            files,
            corpus: &mut corpus,
            allowed: &mut allowed,
        },
        budget,
        max_turns,
    )
    .await?
    {
        crate::engines::agent_loop::LoopFinish::Verdict(v) => Ok(v),
        crate::engines::agent_loop::LoopFinish::Findings(_) => {
            anyhow::bail!("model returned findings instead of a verdict")
        }
    }
}

pub(crate) fn parse_verdict_value(value: &Value) -> Option<VerdictJson> {
    let parsed: VerdictJson = serde_json::from_value(value.clone()).ok()?;
    crate::engines::investigate::parse_verdict(&parsed.verdict)?;
    let reason = parsed.reason.trim();
    if reason.is_empty() {
        return None;
    }
    Some(VerdictJson {
        verdict: crate::engines::investigate::parse_verdict(&parsed.verdict)?.to_string(),
        reason: reason
            .chars()
            .take(crate::engines::investigate::MAX_VERDICT_REASON)
            .collect(),
    })
}

#[cfg(test)]
fn parse_verdict(text: &str) -> Option<VerdictJson> {
    parse_verdict_value(&extract_json(text)?)
}

fn unit_to_finding(
    unit: &CodeUnit,
    corpus: &str,
    allowed: &HashSet<String>,
    hit: UnitFindingJson,
) -> Option<NewFinding> {
    let quote = hit.quote.trim();
    if quote.len() < 6 || !corpus.contains(quote) {
        return None;
    }
    let path = hit
        .path
        .as_deref()
        .and_then(crate::engines::agent_loop::normalize_rel)
        .unwrap_or_else(|| unit.path.replace('\\', "/"));
    if !allowed.contains(&path) {
        return None;
    }
    let unit_path = unit.path.replace('\\', "/");
    if path == unit_path && (hit.line < unit.line_start || hit.line > unit.line_end) {
        return None;
    }
    if hit.line < 1 {
        return None;
    }
    let title = hit.title.trim();
    if title.is_empty() {
        return None;
    }
    let why = hit.why.trim();
    if why.is_empty() {
        return None;
    }
    let severity = parse_severity(hit.severity.as_deref().unwrap_or("medium"));
    let cwe = hit.cwe.as_deref().unwrap_or("").trim().to_ascii_uppercase();
    let cwe = if cwe.starts_with("CWE-") {
        vec![cwe]
    } else {
        vec![]
    };
    let mut hasher = Sha256::new();
    hasher.update(b"agent-unit");
    hasher.update(path.as_bytes());
    hasher.update(hit.line.to_string().as_bytes());
    hasher.update(title.as_bytes());
    let digest = hasher.finalize();
    Some(NewFinding {
        fingerprint: format!(
            "agent-unit:{}",
            digest
                .iter()
                .take(12)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        severity,
        confidence: "medium".into(),
        category: "sast".into(),
        rule_id: "agent-unit".into(),
        title: title.chars().take(80).collect(),
        description: format!("{why} `{path}:{}`.", hit.line),
        path: Some(path),
        line_start: Some(hit.line),
        line_end: Some(hit.line),
        cwe,
        cve: vec![],
        evidence: json!({
            "engine": "achilles-agent-v0",
            "source": "agent",
            "preview": quote.chars().take(80).collect::<String>(),
            "function": unit.name,
            "investigation": {
                "engine": "achilles-agent-v0",
                "needsAgent": false,
                "kind": "unit",
            }
        }),
    })
}

fn parse_severity(value: &str) -> Severity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

pub fn extract_json(text: &str) -> Option<Value> {
    let stripped = strip_fence(text);
    if let Ok(v) = serde_json::from_str::<Value>(stripped.trim()) {
        return Some(v);
    }
    let bytes = stripped.as_bytes();
    let start = stripped.find(['{', '['])?;
    let open = bytes[start];
    let close = if open == b'{' { b'}' } else { b']' };
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            x if x == open => depth += 1,
            x if x == close => {
                depth -= 1;
                if depth == 0 {
                    return stripped
                        .get(start..=i)
                        .and_then(|s| serde_json::from_str(s).ok());
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_fence(text: &str) -> &str {
    let t = text.trim();
    let t = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```JSON"))
        .unwrap_or(t);
    let t = t.strip_prefix("```").unwrap_or(t);
    t.trim().trim_end_matches("```").trim()
}

/// Test helper: each `complete` pops the next scripted reply.
pub struct ScriptedCompleter {
    replies: Mutex<VecDeque<String>>,
}

impl ScriptedCompleter {
    pub fn new(replies: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().map(Into::into).collect()),
        }
    }
}

impl ScanCompleter for ScriptedCompleter {
    fn complete(
        &self,
        _system: String,
        _user: String,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<CompleteOut>> + Send>> {
        let next = self
            .replies
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
            .unwrap_or_else(|| r#"{"findings":[]}"#.into());
        Box::pin(async move {
            Ok(CompleteOut {
                text: next,
                cost_usd: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_fenced_verdict() {
        let v = parse_verdict(
            "```json\n{\"verdict\":\"true_positive\",\"reason\":\"eval takes user_input\"}\n```",
        )
        .unwrap();
        assert_eq!(v.verdict, "true_positive");
    }

    #[test]
    fn rejects_quote_not_in_unit() {
        let unit = CodeUnit {
            path: "a.py".into(),
            name: "f".into(),
            line_start: 1,
            line_end: 4,
            body: "def f():\n    return 1\n".into(),
            score: 0,
        };
        let hit = UnitFindingJson {
            title: "RCE".into(),
            severity: Some("high".into()),
            cwe: Some("CWE-95".into()),
            path: None,
            line: 2,
            quote: "eval(user)".into(),
            why: "executes input".into(),
        };
        let allowed = HashSet::from(["a.py".into()]);
        assert!(unit_to_finding(&unit, &unit.body, &allowed, hit).is_none());
    }

    #[test]
    fn accepts_cited_quote() {
        let unit = CodeUnit {
            path: "a.py".into(),
            name: "f".into(),
            line_start: 1,
            line_end: 3,
            body: "def f(x):\n    eval(x)\n".into(),
            score: 0,
        };
        let hit = UnitFindingJson {
            title: "eval on argument".into(),
            severity: Some("high".into()),
            cwe: Some("CWE-95".into()),
            path: None,
            line: 2,
            quote: "eval(x)".into(),
            why: "argument is executed".into(),
        };
        let allowed = HashSet::from(["a.py".into()]);
        let finding = unit_to_finding(&unit, &unit.body, &allowed, hit).unwrap();
        assert_eq!(finding.rule_id, "agent-unit");
        assert_eq!(finding.evidence["source"], json!("agent"));
    }

    #[tokio::test]
    async fn review_loop_reads_then_verdicts() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("a.py"), "eval(user_input)\n").unwrap();
        let completer: Arc<dyn ScanCompleter> = Arc::new(ScriptedCompleter::new([
            r#"{"read":{"path":"a.py","start":1,"end":10}}"#,
            r#"{"verdict":"true_positive","reason":"eval takes user_input"}"#,
        ]));
        let files: Vec<WalkedFile> = Vec::new();
        let mut corpus = String::new();
        let mut allowed = HashSet::new();
        let finish = crate::engines::agent_loop::drive(
            &completer,
            SYSTEM_REVIEW,
            "review this finding".into(),
            crate::engines::agent_loop::LoopMode::Review,
            crate::engines::agent_loop::LoopIo {
                root: repo,
                store: None,
                files: &files,
                corpus: &mut corpus,
                allowed: &mut allowed,
            },
            None,
            8,
        )
        .await
        .unwrap();
        match finish {
            crate::engines::agent_loop::LoopFinish::Verdict(v) => {
                assert_eq!(v.verdict, "true_positive");
            }
            other => panic!("expected verdict, got {other:?}"),
        }
        assert!(corpus.contains("eval(user_input)"));
        assert!(allowed.contains("a.py"));
    }
}

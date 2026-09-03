//! Quick scan orchestration (secrets + SAST-lite + surfaces + SCA). Apache-2.0.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use serde_json::json;

use crate::engines::abort::{self, Abort};
use crate::engines::agent::ScanCompleter;
use crate::engines::budget::{self, ScanBudget};
use crate::engines::depth::ScanDepth;
use crate::engines::{
    boot, delta, fingerprint, graph, harden, history, investigate, literals, policy, sast, sbom,
    sca, scorecard, secrets, surfaces,
};
use crate::store::{canonicalize_working_dir, AchillesStore};
use crate::types::{
    Assessment, AssessmentStatus, CoverageSnapshot, Finding, NewFinding, WorkUnitDecision,
};

#[derive(Clone)]
struct ScanControl {
    abort: Abort,
    pause: Arc<AtomicBool>,
}

struct CancelOnDrop {
    abort: Abort,
    defused: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.defused {
            self.abort.cancel();
        }
    }
}

fn scan_controls() -> &'static Mutex<HashMap<String, ScanControl>> {
    static CONTROLS: OnceLock<Mutex<HashMap<String, ScanControl>>> = OnceLock::new();
    CONTROLS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_control(assessment_id: &str) -> ScanControl {
    let ctrl = ScanControl {
        abort: Abort::new(),
        pause: Arc::new(AtomicBool::new(false)),
    };
    if let Ok(mut map) = scan_controls().lock() {
        map.insert(assessment_id.to_string(), ctrl.clone());
    }
    ctrl
}

fn unregister_control(assessment_id: &str) {
    if let Ok(mut map) = scan_controls().lock() {
        map.remove(assessment_id);
    }
}

fn request_cancel_flag(assessment_id: &str) -> bool {
    let Ok(map) = scan_controls().lock() else {
        return false;
    };
    if let Some(ctrl) = map.get(assessment_id) {
        ctrl.abort.cancel();
        ctrl.pause.store(false, Ordering::SeqCst);
        true
    } else {
        false
    }
}

fn set_pause_flag(assessment_id: &str, paused: bool) -> bool {
    let Ok(map) = scan_controls().lock() else {
        return false;
    };
    if let Some(ctrl) = map.get(assessment_id) {
        ctrl.pause.store(paused, Ordering::SeqCst);
        true
    } else {
        false
    }
}

fn control_registered(assessment_id: &str) -> bool {
    scan_controls()
        .lock()
        .map(|map| map.contains_key(assessment_id))
        .unwrap_or(false)
}

async fn gate(
    store: &AchillesStore,
    assessment_id: &str,
    ctrl: &ScanControl,
    budget: &ScanBudget,
) -> Result<()> {
    budget.check()?;
    if ctrl.abort.is_cancelled() {
        anyhow::bail!(abort::Cancelled);
    }
    if !ctrl.pause.load(Ordering::Relaxed) {
        return Ok(());
    }
    while ctrl.pause.load(Ordering::Relaxed) {
        if ctrl.abort.is_cancelled() {
            anyhow::bail!(abort::Cancelled);
        }
        budget.check()?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if ctrl.abort.is_cancelled() {
        anyhow::bail!(abort::Cancelled);
    }
    budget.check()?;
    let _ = store
        .set_live_status(assessment_id, AssessmentStatus::Running)
        .await;
    Ok(())
}

async fn ingest_hits(
    store: &AchillesStore,
    engagement_id: &str,
    assessment_id: &str,
    engine: &str,
    hits: &[NewFinding],
    auto_confirm: bool,
    suppress: &policy::Suppressions,
) -> Result<usize> {
    let mut n = 0usize;
    for hit in hits {
        if suppress.matches(hit) {
            continue;
        }
        let candidate_id = store
            .upsert_candidate(engagement_id, assessment_id, engine, hit)
            .await?;
        if auto_confirm {
            store.confirm_candidate(&candidate_id).await?;
        }
        n += 1;
    }
    Ok(n)
}

async fn persist_findings(
    store: &AchillesStore,
    engagement_id: &str,
    assessment_id: &str,
    findings: &[NewFinding],
    suppress: &policy::Suppressions,
) -> Result<()> {
    for finding in findings {
        if suppress.matches(finding) {
            continue;
        }
        store
            .upsert_finding(engagement_id, assessment_id, finding)
            .await?;
    }
    Ok(())
}

async fn engine_unit<F, Fut, T>(
    store: &AchillesStore,
    assessment_id: &str,
    key: &str,
    digest: &str,
    run_id: &str,
    f: F,
) -> Result<Option<T>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    match store
        .begin_work_unit(assessment_id, "engine", key, digest, run_id)
        .await?
    {
        WorkUnitDecision::Skip => Ok(None),
        WorkUnitDecision::Run => match f().await {
            Ok(value) => {
                store
                    .finish_work_unit(assessment_id, "engine", key, "done")
                    .await?;
                Ok(Some(value))
            }
            Err(err) => {
                let status = if abort::is_cancel(&err) || budget::is_budget(&err) {
                    "pending"
                } else {
                    "error"
                };
                let _ = store
                    .finish_work_unit(assessment_id, "engine", key, status)
                    .await;
                Err(err)
            }
        },
    }
}

async fn stop_engine(ctx: &EngineCtx<'_>, engine: &str, summary: serde_json::Value) -> Result<()> {
    ctx.run(engine, "cancelled", summary, Some("cancelled"), None)
        .await?;
    ctx.store
        .set_phase(ctx.assessment_id, engine, "cancelled")
        .await?;
    anyhow::bail!(abort::Cancelled)
}

struct EngineCtx<'a> {
    store: &'a AchillesStore,
    assessment_id: &'a str,
    mode: &'a str,
    include_vendor: bool,
    scan_literals: bool,
    scan_delta: bool,
    depth: ScanDepth,
}

impl EngineCtx<'_> {
    fn argv(&self, engine: &str) -> String {
        fingerprint::sha256_hex(
            format!(
                "{engine}|{}|{}|{}|{}|{}",
                self.mode,
                self.include_vendor,
                self.scan_literals,
                self.scan_delta,
                self.depth.as_str()
            )
            .as_bytes(),
        )
    }

    fn digest(&self, engine: &str, tree_fp: &str) -> String {
        fingerprint::sha256_hex(format!("{}|{tree_fp}", self.argv(engine)).as_bytes())
    }

    async fn run(
        &self,
        engine: &str,
        status: &str,
        summary: serde_json::Value,
        error: Option<&str>,
        output_handle_id: Option<&str>,
    ) -> Result<()> {
        let argv = self.argv(engine);
        self.store
            .record_engine_run_with(
                self.assessment_id,
                engine,
                status,
                summary,
                error,
                Some(&argv),
                output_handle_id,
            )
            .await
    }
}

pub struct ScanRequest {
    pub working_dir: String,
    pub session_id: Option<String>,
    pub mode: String,
    pub trigger: String,
    pub parent_assessment_id: Option<String>,
    pub wait: bool,
    pub include_vendor: bool,
    /// Opt-in hardcoded-value scan (stability / config hygiene, not security).
    pub scan_literals: bool,
    /// Opt-in: compact staged/unstaged/untracked diffs and check introduced logic against the tree.
    pub scan_delta: bool,
    /// `fast` (default), `investigate`, or `deep`. Independent of `mode` (tree vs diff).
    pub depth: String,
    /// Optional Socket org token. Never persisted on the assessment.
    pub socket_api_token: Option<String>,
    pub socket_org: Option<String>,
    /// When set, Investigate/Deep run a stuffed-prompt model pass after engines.
    pub completer: Option<Arc<dyn ScanCompleter>>,
    /// Reopen a cancelled/partial assessment and skip work units whose digest still matches.
    pub resume_assessment_id: Option<String>,
    /// Wall-clock cap. Stop as `partial` so the same assessment can resume.
    pub max_duration_secs: Option<u64>,
    /// BYO spend cap in USD. Stop as `partial` when the completer reports cost.
    pub max_cost_usd: Option<f64>,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            working_dir: String::new(),
            session_id: None,
            mode: "quick".into(),
            trigger: "scan_cta".into(),
            parent_assessment_id: None,
            wait: false,
            include_vendor: false,
            scan_literals: false,
            scan_delta: false,
            depth: "fast".into(),
            socket_api_token: None,
            socket_org: None,
            completer: None,
            resume_assessment_id: None,
            max_duration_secs: None,
            max_cost_usd: None,
        }
    }
}

pub async fn start_quick_scan(
    store: AchillesStore,
    working_dir: &str,
    session_id: Option<&str>,
    mode: &str,
) -> Result<Assessment> {
    start_scan(
        store,
        ScanRequest {
            working_dir: working_dir.to_string(),
            session_id: session_id.map(str::to_string),
            mode: mode.to_string(),
            trigger: "scan_cta".into(),
            parent_assessment_id: None,
            wait: false,
            include_vendor: false,
            scan_literals: false,
            depth: "fast".into(),
            socket_api_token: None,
            socket_org: None,
            completer: None,
            ..Default::default()
        },
    )
    .await
}

pub async fn start_scan(store: AchillesStore, req: ScanRequest) -> Result<Assessment> {
    let working_dir = canonicalize_working_dir(&req.working_dir)?;
    let engagement = store.upsert_engagement(&working_dir).await?;
    let assessment = if let Some(resume_id) = req.resume_assessment_id.as_deref() {
        let existing = store
            .get_assessment(resume_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown assessment {resume_id}"))?;
        anyhow::ensure!(
            existing.engagement_id == engagement.id,
            "resume assessment is not for this workspace"
        );
        anyhow::ensure!(
            AchillesStore::is_resumable_status(existing.status)
                && existing.status != AssessmentStatus::Completed,
            "assessment {} is {} — start a new scan instead",
            resume_id,
            existing.status.as_str()
        );
        if control_registered(resume_id) {
            anyhow::bail!("assessment {resume_id} is still running");
        }
        store.reopen_assessment(resume_id).await?;
        store.reclaim_stale_units(resume_id).await?;
        store
            .get_assessment(resume_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("assessment vanished during resume"))?
    } else {
        store
            .create_assessment(
                &engagement,
                req.session_id.as_deref(),
                &req.mode,
                &req.trigger,
                req.parent_assessment_id.as_deref(),
            )
            .await?
    };
    let depth = ScanDepth::parse(&req.depth);
    store
        .merge_stats(
            &assessment.id,
            json!({
                "scanMode": req.mode,
                "includeVendor": req.include_vendor,
                "scanLiterals": req.scan_literals,
                "scanDelta": req.scan_delta,
                "scanDepth": depth.as_str(),
            }),
        )
        .await?;
    let assessment = store
        .get_assessment(&assessment.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assessment vanished after recording scan options"))?;
    store
        .set_scan_caps(&assessment.id, req.max_duration_secs, req.max_cost_usd)
        .await?;
    let budget = ScanBudget::new(req.max_duration_secs, req.max_cost_usd);
    let run_id = uuid::Uuid::new_v4().to_string();
    let store_bg = store.clone();
    let assessment_id = assessment.id.clone();
    let engagement_id = engagement.id.clone();
    let mode = req.mode.clone();
    let include_vendor = req.include_vendor;
    let scan_literals = req.scan_literals;
    let scan_delta = req.scan_delta;
    let socket_creds = crate::engines::socket::SocketCreds {
        token: req.socket_api_token.clone(),
        org: req.socket_org.clone(),
    };
    let completer = req.completer.clone();
    let parent_assessment_id = req.parent_assessment_id.clone();
    let ctrl = register_control(&assessment_id);
    let wait_abort = ctrl.abort.clone();
    let join = tokio::spawn(async move {
        let result = run_engines(
            &store_bg,
            &working_dir,
            &engagement_id,
            &assessment_id,
            &mode,
            include_vendor,
            scan_literals,
            scan_delta,
            depth,
            socket_creds,
            completer,
            parent_assessment_id,
            ctrl.clone(),
            budget,
            run_id,
        )
        .await;
        unregister_control(&assessment_id);
        if let Err(err) = result {
            let cancelled = ctrl.abort.is_cancelled() || abort::is_cancel(&err);
            if cancelled {
                let _ = store_bg
                    .finish_assessment(
                        &assessment_id,
                        AssessmentStatus::Cancelled,
                        json!({}),
                        Some("cancelled"),
                    )
                    .await;
            } else if budget::is_budget(&err) {
                let _ = store_bg
                    .finish_assessment(
                        &assessment_id,
                        AssessmentStatus::Partial,
                        json!({ "stopReason": err.to_string() }),
                        Some(&err.to_string()),
                    )
                    .await;
            } else {
                tracing::error!(error = %err, assessment_id, "achilles scan failed");
                let _ = store_bg
                    .finish_assessment(
                        &assessment_id,
                        AssessmentStatus::Failed,
                        json!({}),
                        Some(&err.to_string()),
                    )
                    .await;
            }
        }
    });
    if req.wait {
        let mut guard = CancelOnDrop {
            abort: wait_abort,
            defused: false,
        };
        let _ = join.await;
        guard.defused = true;
        return store
            .get_assessment(&assessment.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("assessment vanished after scan"));
    }
    Ok(assessment)
}

pub async fn cancel_scan(store: &AchillesStore, assessment_id: &str) -> Result<Assessment> {
    let assessment = store
        .get_assessment(assessment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown assessment {assessment_id}"))?;
    match assessment.status {
        AssessmentStatus::Completed
        | AssessmentStatus::Failed
        | AssessmentStatus::Cancelled
        | AssessmentStatus::Partial => return Ok(assessment),
        AssessmentStatus::Queued | AssessmentStatus::Running | AssessmentStatus::Paused => {}
    }
    let _ = request_cancel_flag(assessment_id);
    store
        .finish_assessment(
            assessment_id,
            AssessmentStatus::Cancelled,
            assessment.stats_json.clone(),
            Some("cancelled"),
        )
        .await?;
    store
        .get_assessment(assessment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assessment vanished after cancel"))
}

pub async fn pause_scan(
    store: &AchillesStore,
    assessment_id: &str,
    paused: bool,
) -> Result<Assessment> {
    let assessment = store
        .get_assessment(assessment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown assessment {assessment_id}"))?;
    match assessment.status {
        AssessmentStatus::Completed
        | AssessmentStatus::Failed
        | AssessmentStatus::Cancelled
        | AssessmentStatus::Partial => return Ok(assessment),
        AssessmentStatus::Queued | AssessmentStatus::Running | AssessmentStatus::Paused => {}
    }
    if !set_pause_flag(assessment_id, paused) {
        anyhow::bail!("scan is no longer running — start a new scan to continue");
    }
    store
        .set_live_status(
            assessment_id,
            if paused {
                AssessmentStatus::Paused
            } else {
                AssessmentStatus::Running
            },
        )
        .await?;
    store
        .get_assessment(assessment_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assessment vanished after pause"))
}

#[allow(clippy::too_many_arguments)]
async fn run_engines(
    store: &AchillesStore,
    working_dir: &str,
    engagement_id: &str,
    assessment_id: &str,
    mode: &str,
    include_vendor: bool,
    scan_literals: bool,
    scan_delta: bool,
    depth: ScanDepth,
    socket_creds: crate::engines::socket::SocketCreds,
    completer: Option<Arc<dyn ScanCompleter>>,
    parent_assessment_id: Option<String>,
    ctrl: ScanControl,
    budget: ScanBudget,
    run_id: String,
) -> Result<()> {
    let parent_open = if let Some(parent_id) = parent_assessment_id.as_deref() {
        open_fingerprints(&store.list_findings(Some(parent_id), None, None).await?)
    } else {
        HashSet::new()
    };
    let is_rescan = parent_assessment_id.is_some();
    let ctx = EngineCtx {
        store,
        assessment_id,
        mode,
        include_vendor,
        scan_literals,
        scan_delta,
        depth,
    };
    gate(store, assessment_id, &ctrl, &budget).await?;
    let root = Path::new(working_dir);
    let suppress = policy::load(root);
    let walk = depth.walk_opts(include_vendor);
    let path_filter = if crate::engines::scope::is_diff_mode(mode) {
        crate::engines::scope::changed_rel_paths(root)
    } else {
        None
    };
    // One tree walk. Engines filter this index in memory.
    let root_buf = PathBuf::from(working_dir);
    let root_walk = root_buf.clone();
    let cancel_walk = ctrl.abort.clone();
    let pause_walk = ctrl.pause.clone();
    let index = tokio::task::spawn_blocking(move || {
        crate::engines::walk::walk_files_with_cancel(
            &root_walk,
            walk,
            |_, _| true,
            Some(cancel_walk.flag()),
            Some(pause_walk.as_ref()),
        )
    })
    .await?;
    let index = Arc::new(index);
    let indexed_files: Vec<String> = index.iter().map(|file| file.rel.clone()).collect();
    let head = git_head(working_dir);
    let tree_fp = fingerprint::content_fingerprint(&index);
    let model_class = if completer.is_some() { "F" } else { "L" };
    store
        .set_scan_identity(assessment_id, head.as_deref(), &tree_fp, model_class)
        .await?;
    gate(store, assessment_id, &ctrl, &budget).await?;
    store
        .set_phase(assessment_id, "fingerprint", "running")
        .await?;
    let fp = fingerprint::fingerprint_files(&index);
    let startup = boot::map_startup(&index);
    if ctrl.abort.is_cancelled() {
        return stop_engine(
            &ctx,
            "fingerprint",
            json!({ "filesIndexed": indexed_files.len() }),
        )
        .await;
    }
    let surface_ids: Vec<String> = fp.surfaces.iter().map(|s| s.id.clone()).collect();
    let fp_payload = json!({
        "surfaces": fp.surfaces,
        "startupPaths": startup.clone(),
        "filesIndexed": indexed_files.len()
    });
    let fp_handle = store
        .write_handle(assessment_id, "fingerprint-json", &fp_payload)
        .await?;
    ctx.run(
        "fingerprint",
        "completed",
        fp_payload,
        None,
        Some(&fp_handle.handle_id),
    )
    .await?;
    store
        .merge_stats(
            assessment_id,
            json!({
                "detectedSurfaces": fp.surfaces,
                "startupPaths": startup.clone(),
                "filesIndexed": indexed_files.len(),
                "indexedFiles": indexed_files.clone(),
            }),
        )
        .await?;
    store
        .set_phase(assessment_id, "fingerprint", "done")
        .await?;

    gate(store, assessment_id, &ctrl, &budget).await?;
    let secrets_digest = ctx.digest("secrets", &tree_fp);
    let secret_count = match engine_unit(
        store,
        assessment_id,
        "secrets",
        &secrets_digest,
        &run_id,
        || async {
            store.set_phase(assessment_id, "secrets", "running").await?;
            let index_secrets = index.clone();
            let filter_secrets = path_filter.clone();
            let abort_secrets = ctrl.abort.clone();
            let secret_findings = tokio::task::spawn_blocking(move || {
                secrets::scan_secrets_on(
                    &index_secrets,
                    filter_secrets.as_ref(),
                    Some(abort_secrets.flag()),
                )
            })
            .await??;
            ingest_hits(
                store,
                engagement_id,
                assessment_id,
                "secrets",
                &secret_findings,
                true,
                &suppress,
            )
            .await?;
            let secret_count = secret_findings.len();
            if ctrl.abort.is_cancelled() {
                stop_engine(&ctx, "secrets", json!({ "findings": secret_count })).await?;
            }
            ctx.run(
                "secrets",
                "completed",
                json!({ "findings": secret_count }),
                None,
                None,
            )
            .await?;
            store.set_phase(assessment_id, "secrets", "done").await?;
            Ok(secret_count)
        },
    )
    .await?
    {
        Some(n) => n,
        None => store
            .list_candidates(assessment_id, None, Some("secrets"))
            .await?
            .len(),
    };

    let mut history_count = 0usize;
    if crate::engines::scope::is_diff_mode(mode) {
        ctx.run(
            "history",
            "skipped",
            json!({ "reason": "mode=diff" }),
            None,
            None,
        )
        .await?;
        store.set_phase(assessment_id, "history", "skipped").await?;
    } else {
        gate(store, assessment_id, &ctrl, &budget).await?;
        let history_digest = ctx.digest("history", &tree_fp);
        let live_rels: HashSet<String> = index.iter().map(|f| f.rel.clone()).collect();
        history_count = match engine_unit(
            store,
            assessment_id,
            "history",
            &history_digest,
            &run_id,
            || async {
                store.set_phase(assessment_id, "history", "running").await?;
                let abort_history = ctrl.abort.clone();
                let root_history = root_buf.clone();
                let history_findings = tokio::task::spawn_blocking(move || {
                    history::scan_history(&root_history, &live_rels, Some(abort_history.flag()))
                })
                .await??;
                ingest_hits(
                    store,
                    engagement_id,
                    assessment_id,
                    "history",
                    &history_findings,
                    true,
                    &suppress,
                )
                .await?;
                let history_count = history_findings.len();
                if ctrl.abort.is_cancelled() {
                    stop_engine(&ctx, "history", json!({ "findings": history_count })).await?;
                }
                ctx.run(
                    "history",
                    "completed",
                    json!({ "findings": history_count }),
                    None,
                    None,
                )
                .await?;
                store.set_phase(assessment_id, "history", "done").await?;
                Ok(history_count)
            },
        )
        .await?
        {
            Some(n) => n,
            None => store
                .list_candidates(assessment_id, None, Some("history"))
                .await?
                .len(),
        };
    }

    gate(store, assessment_id, &ctrl, &budget).await?;
    let sast_digest = ctx.digest("sast", &tree_fp);
    let sast_count = match engine_unit(
        store,
        assessment_id,
        "sast",
        &sast_digest,
        &run_id,
        || async {
            store.set_phase(assessment_id, "sast", "running").await?;
            let index_sast = index.clone();
            let filter_sast = path_filter.clone();
            let abort_sast = ctrl.abort.clone();
            let root_sast = root_buf.clone();
            let sast_findings = tokio::task::spawn_blocking(move || {
                let mut hits =
                    sast::scan_sast_on(&index_sast, filter_sast.as_ref(), Some(abort_sast.flag()))?;
                let inv = if depth.runs_investigate() && !abort_sast.is_cancelled() {
                    Some(investigate::apply(
                        &root_sast,
                        &mut hits,
                        depth,
                        Some(abort_sast.flag()),
                    ))
                } else {
                    None
                };
                anyhow::Ok((hits, inv))
            })
            .await??;
            let (sast_findings, inv) = sast_findings;
            if depth.runs_investigate() {
                if ctrl.abort.is_cancelled() {
                    store
                        .set_phase(assessment_id, "investigate", "cancelled")
                        .await?;
                } else if let Some(inv) = inv {
                    ctx.run(
                        "investigate",
                        "completed",
                        json!({
                            "reviewed": inv.reviewed,
                            "literal": inv.literal,
                            "dynamic": inv.dynamic,
                            "unknown": inv.unknown,
                            "depth": depth.as_str(),
                        }),
                        None,
                        None,
                    )
                    .await?;
                    store
                        .set_phase(assessment_id, "investigate", "done")
                        .await?;
                }
            } else {
                ctx.run(
                    "investigate",
                    "skipped",
                    json!({ "reason": "depth=fast", "depth": depth.as_str() }),
                    None,
                    None,
                )
                .await?;
                store
                    .set_phase(assessment_id, "investigate", "skipped")
                    .await?;
            }
            ingest_hits(
                store,
                engagement_id,
                assessment_id,
                "sast",
                &sast_findings,
                true,
                &suppress,
            )
            .await?;
            let sast_count = sast_findings.len();
            if ctrl.abort.is_cancelled() {
                stop_engine(&ctx, "sast", json!({ "findings": sast_count })).await?;
            }
            ctx.run(
                "sast",
                "completed",
                json!({ "findings": sast_count }),
                None,
                None,
            )
            .await?;
            store.set_phase(assessment_id, "sast", "done").await?;
            Ok(sast_count)
        },
    )
    .await?
    {
        Some(n) => n,
        None => store
            .list_candidates(assessment_id, None, Some("sast"))
            .await?
            .len(),
    };

    let mut literals_count = 0usize;
    if scan_literals {
        gate(store, assessment_id, &ctrl, &budget).await?;
        let lit_digest = ctx.digest("literals", &tree_fp);
        literals_count = match engine_unit(
            store,
            assessment_id,
            "literals",
            &lit_digest,
            &run_id,
            || async {
                store
                    .set_phase(assessment_id, "literals", "running")
                    .await?;
                let index_lit = index.clone();
                let filter_lit = path_filter.clone();
                let abort_lit = ctrl.abort.clone();
                let literal_findings = tokio::task::spawn_blocking(move || {
                    literals::scan_literals_on(
                        &index_lit,
                        filter_lit.as_ref(),
                        Some(abort_lit.flag()),
                    )
                })
                .await??;
                ingest_hits(
                    store,
                    engagement_id,
                    assessment_id,
                    "literals",
                    &literal_findings,
                    true,
                    &suppress,
                )
                .await?;
                let literals_count = literal_findings.len();
                if ctrl.abort.is_cancelled() {
                    stop_engine(&ctx, "literals", json!({ "findings": literals_count })).await?;
                }
                ctx.run(
                    "literals",
                    "completed",
                    json!({ "findings": literals_count, "security": false }),
                    None,
                    None,
                )
                .await?;
                store.set_phase(assessment_id, "literals", "done").await?;
                Ok(literals_count)
            },
        )
        .await?
        {
            Some(n) => n,
            None => store
                .list_candidates(assessment_id, None, Some("literals"))
                .await?
                .len(),
        };
    }

    let mut delta_count = 0usize;
    if scan_delta {
        gate(store, assessment_id, &ctrl, &budget).await?;
        let delta_digest = ctx.digest("delta", &tree_fp);
        delta_count = match engine_unit(
            store,
            assessment_id,
            "delta",
            &delta_digest,
            &run_id,
            || async {
                store.set_phase(assessment_id, "delta", "running").await?;
                let index_delta = index.clone();
                let abort_delta = ctrl.abort.clone();
                let root_delta = root_buf.clone();
                let include_vendor_delta = include_vendor;
                let outcome = tokio::task::spawn_blocking(move || {
                    delta::scan_delta_on(
                        &root_delta,
                        &index_delta,
                        include_vendor_delta,
                        Some(abort_delta.flag()),
                    )
                })
                .await??;
                ingest_hits(
                    store,
                    engagement_id,
                    assessment_id,
                    "delta",
                    &outcome.findings,
                    true,
                    &suppress,
                )
                .await?;
                let delta_count = outcome.findings.len();
                if ctrl.abort.is_cancelled() {
                    stop_engine(&ctx, "delta", json!({ "findings": delta_count })).await?;
                }
                let status = if outcome.skipped_reason.is_some() {
                    "skipped"
                } else {
                    "completed"
                };
                let compact_handle = store
                    .write_handle(assessment_id, "delta-json", &outcome.compact)
                    .await?;
                ctx.run(
                    "delta",
                    status,
                    json!({
                        "findings": delta_count,
                        "skippedReason": outcome.skipped_reason,
                        "filesChanged": outcome.compact.get("filesChanged"),
                        "units": outcome.compact.get("units").and_then(|v| v.as_array()).map(|a| a.len()),
                    }),
                    None,
                    Some(&compact_handle.handle_id),
                )
                .await?;
                store
                    .set_phase(
                        assessment_id,
                        "delta",
                        if status == "skipped" { "skipped" } else { "done" },
                    )
                    .await?;
                Ok(delta_count)
            },
        )
        .await?
        {
            Some(n) => n,
            None => store
                .list_candidates(assessment_id, None, Some("delta"))
                .await?
                .len(),
        };
    }

    gate(store, assessment_id, &ctrl, &budget).await?;
    let surfaces_digest = ctx.digest("surfaces", &tree_fp);
    let surface_count = match engine_unit(
        store,
        assessment_id,
        "surfaces",
        &surfaces_digest,
        &run_id,
        || async {
            store
                .set_phase(assessment_id, "surfaces", "running")
                .await?;
            let filter_surfaces = path_filter.clone();
            let abort_surfaces = ctrl.abort.clone();
            let root_surfaces = root_buf.clone();
            let fp_surfaces = fp.clone();
            let surface_findings = tokio::task::spawn_blocking(move || {
                surfaces::scan_surfaces_filtered(
                    &root_surfaces,
                    &fp_surfaces,
                    filter_surfaces.as_ref(),
                    Some(abort_surfaces.flag()),
                )
            })
            .await??;
            ingest_hits(
                store,
                engagement_id,
                assessment_id,
                "surfaces",
                &surface_findings,
                true,
                &suppress,
            )
            .await?;
            let surface_count = surface_findings.len();
            if ctrl.abort.is_cancelled() {
                stop_engine(&ctx, "surfaces", json!({ "findings": surface_count })).await?;
            }
            ctx.run(
                "surfaces",
                "completed",
                json!({
                    "findings": surface_count,
                    "scannedSurfaces": surface_ids,
                    "scanMode": mode,
                    "diffPathCount": path_filter.as_ref().map(|s| s.len()),
                }),
                None,
                None,
            )
            .await?;
            store.set_phase(assessment_id, "surfaces", "done").await?;
            Ok(surface_count)
        },
    )
    .await?
    {
        Some(n) => n,
        None => store
            .list_candidates(assessment_id, None, Some("surfaces"))
            .await?
            .len(),
    };

    gate(store, assessment_id, &ctrl, &budget).await?;
    let harden_digest = ctx.digest("harden", &tree_fp);
    let harden_count = match engine_unit(
        store,
        assessment_id,
        "harden",
        &harden_digest,
        &run_id,
        || async {
            store.set_phase(assessment_id, "harden", "running").await?;
            let index_harden = index.clone();
            let filter_harden = path_filter.clone();
            let abort_harden = ctrl.abort.clone();
            let harden_findings = tokio::task::spawn_blocking(move || {
                harden::scan_harden_on(
                    &index_harden,
                    filter_harden.as_ref(),
                    Some(abort_harden.flag()),
                )
            })
            .await??;
            ingest_hits(
                store,
                engagement_id,
                assessment_id,
                "harden",
                &harden_findings,
                true,
                &suppress,
            )
            .await?;
            let harden_count = harden_findings.len();
            if ctrl.abort.is_cancelled() {
                stop_engine(&ctx, "harden", json!({ "findings": harden_count })).await?;
            }
            ctx.run(
                "harden",
                "completed",
                json!({ "findings": harden_count }),
                None,
                None,
            )
            .await?;
            store.set_phase(assessment_id, "harden", "done").await?;
            Ok(harden_count)
        },
    )
    .await?
    {
        Some(n) => n,
        None => store
            .list_candidates(assessment_id, None, Some("harden"))
            .await?
            .len(),
    };

    gate(store, assessment_id, &ctrl, &budget).await?;
    store.set_phase(assessment_id, "sca", "running").await?;
    let mut sca_outcome =
        sca::scan_sca_abort_with_socket(root, &index, Some(&ctrl.abort), socket_creds).await;
    ingest_hits(
        store,
        engagement_id,
        assessment_id,
        "sca",
        &sca_outcome.findings,
        true,
        &suppress,
    )
    .await?;
    if sca_outcome.cancelled || ctrl.abort.is_cancelled() {
        return stop_engine(
            &ctx,
            "sca",
            json!({
                "findings": sca_outcome.findings.len(),
                "packagesConsidered": sca_outcome.packages_considered,
                "queried": sca_outcome.queried,
                "skippedReason": "cancelled",
                "socketPackages": sca_outcome.socket_packages,
                "socketSkipped": sca_outcome.socket_skipped,
            }),
        )
        .await;
    }
    store.set_phase(assessment_id, "sca", "done").await?;

    let packages = sca::collect_packages_from(index.as_ref());
    let sbom_payload = sbom::cyclonedx(&packages);
    let sbom_handle = store
        .write_handle(assessment_id, "sbom-json", &sbom_payload)
        .await?;
    let scorecard_hits = match scorecard::scan(root, store, Some(&ctrl.abort)).await {
        Ok(hits) => hits,
        Err(err) if abort::is_cancel(&err) => {
            return stop_engine(&ctx, "sca", json!({ "skippedReason": "cancelled" })).await;
        }
        Err(err) => {
            tracing::debug!(error = %err, "scorecard skipped");
            Vec::new()
        }
    };
    ingest_hits(
        store,
        engagement_id,
        assessment_id,
        "sca",
        &scorecard_hits,
        true,
        &suppress,
    )
    .await?;
    let scorecard_count = scorecard_hits.len();
    sca_outcome.findings.extend(scorecard_hits);

    gate(store, assessment_id, &ctrl, &budget).await?;
    store.set_phase(assessment_id, "intel", "running").await?;
    let mut intel_count = 0usize;
    if let Ok(intel) = crate::engines::intel::IntelClient::from_env() {
        match crate::engines::intel::apply_to_findings(
            &intel,
            store,
            &mut sca_outcome.findings,
            Some(&ctrl.abort),
        )
        .await
        {
            Ok(n) => intel_count = n,
            Err(err) if abort::is_cancel(&err) => {
                persist_findings(
                    store,
                    engagement_id,
                    assessment_id,
                    &sca_outcome.findings,
                    &suppress,
                )
                .await?;
                return stop_engine(&ctx, "intel", json!({})).await;
            }
            Err(err) => {
                tracing::debug!(error = %err, "intel enrich skipped");
            }
        }
    }
    if ctrl.abort.is_cancelled() {
        ingest_hits(
            store,
            engagement_id,
            assessment_id,
            "sca",
            &sca_outcome.findings,
            true,
            &suppress,
        )
        .await?;
        return stop_engine(&ctx, "intel", json!({})).await;
    }
    store
        .merge_stats(assessment_id, json!({ "intel": intel_count }))
        .await?;
    ctx.run(
        "intel",
        "completed",
        json!({ "findings": intel_count }),
        None,
        None,
    )
    .await?;
    store.set_phase(assessment_id, "intel", "done").await?;

    let sca_count = sca_outcome.findings.len();
    ingest_hits(
        store,
        engagement_id,
        assessment_id,
        "sca",
        &sca_outcome.findings,
        true,
        &suppress,
    )
    .await?;
    let sca_status = if sca_outcome.skipped_reason.is_some() && sca_outcome.queried == 0 {
        "skipped"
    } else {
        "completed"
    };
    ctx.run(
        "sca",
        sca_status,
        json!({
            "findings": sca_count,
            "packagesConsidered": sca_outcome.packages_considered,
            "queried": sca_outcome.queried,
            "skippedReason": sca_outcome.skipped_reason,
            "socketPackages": sca_outcome.socket_packages,
            "socketSkipped": sca_outcome.socket_skipped,
        }),
        None,
        None,
    )
    .await?;

    let mut sast_count = sast_count;
    if depth.runs_investigate() {
        gate(store, assessment_id, &ctrl, &budget).await?;
        store.set_phase(assessment_id, "agent", "running").await?;
        if let Some(completer) = completer {
            let current = store.list_findings(Some(assessment_id), None, None).await?;
            match crate::engines::agent::run(
                store,
                root,
                engagement_id,
                assessment_id,
                depth,
                &fp,
                &index,
                &current,
                completer,
                &ctrl.abort,
                ctrl.pause.clone(),
                Some(budget.clone()),
            )
            .await
            {
                Ok(agent_stats) => {
                    if ctrl.abort.is_cancelled() {
                        return stop_engine(
                            &ctx,
                            "agent",
                            json!({
                                "reviewed": agent_stats.reviewed,
                                "units": agent_stats.units,
                            }),
                        )
                        .await;
                    }
                    ctx.run(
                        "agent",
                        "completed",
                        json!({
                            "reviewed": agent_stats.reviewed,
                            "units": agent_stats.units,
                            "newFindings": agent_stats.new_findings,
                            "confirmed": agent_stats.confirmed,
                            "dismissed": agent_stats.dismissed,
                            "errors": agent_stats.errors,
                            "depth": depth.as_str(),
                        }),
                        None,
                        None,
                    )
                    .await?;
                    store
                        .merge_stats(
                            assessment_id,
                            json!({
                                "agent": agent_stats.reviewed + agent_stats.units,
                                "agentReviewed": agent_stats.reviewed,
                                "agentUnits": agent_stats.units,
                                "agentNewFindings": agent_stats.new_findings,
                                "agentConfirmed": agent_stats.confirmed,
                                "agentDismissed": agent_stats.dismissed,
                                "agentErrors": agent_stats.errors,
                                "agentLog": agent_stats.notes,
                            }),
                        )
                        .await?;
                    store.set_phase(assessment_id, "agent", "done").await?;
                    sast_count += agent_stats.new_findings;
                }
                Err(err) if abort::is_cancel(&err) => {
                    return stop_engine(&ctx, "agent", json!({})).await;
                }
                Err(err) => {
                    tracing::debug!(error = %err, "agent pass skipped");
                    ctx.run(
                        "agent",
                        "skipped",
                        json!({ "reason": err.to_string(), "depth": depth.as_str() }),
                        None,
                        None,
                    )
                    .await?;
                    store.set_phase(assessment_id, "agent", "skipped").await?;
                }
            }
        } else {
            ctx.run(
                "agent",
                "skipped",
                json!({ "reason": "no-model", "depth": depth.as_str() }),
                None,
                None,
            )
            .await?;
            store.set_phase(assessment_id, "agent", "skipped").await?;
        }
    }

    // Engine hits must stay on the ledger. Pending is a review queue, not a way
    // to hide Fast results when the model errors or never writes a verdict.
    store.confirm_pending_candidates(assessment_id).await?;

    let mut skip_absent: Vec<&str> = Vec::new();
    if !scan_literals {
        skip_absent.push("literals");
    }
    if !scan_delta {
        skip_absent.push("delta");
    }
    if crate::engines::scope::is_diff_mode(mode) {
        skip_absent.push("history");
    }
    if store
        .count_pending_candidates(assessment_id, "sast")
        .await?
        > 0
    {
        skip_absent.push("sast");
    }
    let closed_this_scan = store
        .close_absent_findings_except(engagement_id, assessment_id, &skip_absent)
        .await?;

    let findings = store.list_findings(Some(assessment_id), None, None).await?;
    let active: Vec<_> = findings
        .iter()
        .filter(|f| f.state == "open" || f.state == "confirmed")
        .cloned()
        .collect();
    let preview = ledger_preview(&active, 8);
    let child_open = open_fingerprints(&active);
    let (new_this_scan, gone_this_scan) = if is_rescan {
        let (new_count, gone_count) = diff_open_fingerprints(&parent_open, &child_open);
        (Some(new_count), Some(gone_count))
    } else {
        (None, None)
    };
    let graph_payload = graph::from_scan(&fp, &findings);
    let graph_handle = store
        .write_handle(assessment_id, "graph-json", &graph_payload)
        .await?;
    let handle = store
        .write_handle(
            assessment_id,
            "findings-json",
            &json!({
                "preview": preview,
                "findings": findings,
                "stats": {
                    "secrets": secret_count,
                    "history": history_count,
                    "sast": sast_count,
                    "literals": literals_count,
                    "delta": delta_count,
                    "surfaces": surface_count,
                    "harden": harden_count,
                    "sca": sca_count,
                    "intel": intel_count,
                    "scorecard": scorecard_count,
                    "open": active.len(),
                    "closedThisScan": closed_this_scan,
                    "newThisScan": new_this_scan,
                    "goneThisScan": gone_this_scan,
                    "detectedSurfaces": fp.surfaces,
                    "startupPaths": startup.clone(),
                    "scanMode": mode,
                    "includeVendor": include_vendor,
                    "scanLiterals": scan_literals,
                    "scanDelta": scan_delta,
                    "scanDepth": depth.as_str(),
                    "filesIndexed": indexed_files.len(),
                    "indexedFiles": indexed_files.clone(),
                    "diffPathCount": path_filter.as_ref().map(|s| s.len()),
                    "sbomHandleId": sbom_handle.handle_id,
                    "graph": graph_payload.clone(),
                }
            }),
        )
        .await?;

    let coverage_paths = match &path_filter {
        Some(changed) => {
            let mut paths: Vec<_> = changed.iter().cloned().collect();
            paths.sort();
            json!(paths)
        }
        None => json!(["**"]),
    };
    store
        .upsert_coverage_snapshot(
            assessment_id,
            indexed_files.len() as i64,
            coverage_paths,
            skipped_walk_globs(include_vendor),
        )
        .await?;

    gate(store, assessment_id, &ctrl, &budget).await?;
    store
        .finish_assessment(
            assessment_id,
            AssessmentStatus::Completed,
            json!({
                "secrets": secret_count,
                "history": history_count,
                "sast": sast_count,
                "literals": literals_count,
                "delta": delta_count,
                "surfaces": surface_count,
                "harden": harden_count,
                "sca": sca_count,
                "intel": intel_count,
                "scorecard": scorecard_count,
                "open": active.len(),
                "closedThisScan": closed_this_scan,
                "newThisScan": new_this_scan,
                "goneThisScan": gone_this_scan,
                "summaryHandleId": handle.handle_id,
                "graphHandleId": graph_handle.handle_id,
                "sbomHandleId": sbom_handle.handle_id,
                "graph": graph_payload,
                "gitHead": git_head(working_dir),
                "detectedSurfaces": fp.surfaces,
                "startupPaths": startup,
                "scanMode": mode,
                "includeVendor": include_vendor,
                "scanLiterals": scan_literals,
                "scanDelta": scan_delta,
                "scanDepth": depth.as_str(),
                "filesIndexed": indexed_files.len(),
                "indexedFiles": indexed_files,
                "diffPathCount": path_filter.as_ref().map(|s| s.len()),
            }),
            None,
        )
        .await?;
    let _ = store.backup_now().await;
    Ok(())
}

pub fn ledger_preview(findings: &[Finding], limit: usize) -> String {
    if findings.is_empty() {
        return "No open findings. Engines are authoritative — do not invent issues.".into();
    }
    let mut lines = vec![format!("{} finding(s):", findings.len())];
    for finding in findings.iter().take(limit) {
        let loc = match (&finding.path, finding.line_start) {
            (Some(path), Some(line)) => format!("{path}:{line}"),
            (Some(path), None) => path.clone(),
            _ => finding.rule_id.clone(),
        };
        lines.push(format!(
            "- id={} [{}] [{}] {} — {}",
            finding.id,
            finding.severity.to_uppercase(),
            finding.category,
            loc,
            finding.title
        ));
    }
    if findings.len() > limit {
        lines.push(format!(
            "- … {} more (call appsec_query if needed; do not tell the user this list is truncated)",
            findings.len() - limit
        ));
    }
    let queued = investigate_ids(findings);
    if !queued.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "SAST ids still needing a verdict (investigate/revalidate passes only, cap {}): {}",
            crate::engines::investigate::MAX_AGENT_QUEUE,
            queued.join(", ")
        ));
        lines.push(
            "Do not start that pass for ranking, counts, or \"what's worst\" questions. Answer from these findings first. Do not tell the user this is a preview."
                .into(),
        );
    }
    lines.join("\n")
}

/// Compact catalog of the latest scan on this chat session. Injected into the
/// model’s turn context so the user can ask about findings without pasting them.
pub async fn findings_context_for_session(
    store: &AchillesStore,
    session_id: &str,
) -> Result<Option<String>> {
    if session_id.trim().is_empty() {
        return Ok(None);
    }
    let Some(assessment) = store
        .list_assessments_for_session(session_id)
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let findings = store
        .list_findings(Some(&assessment.id), None, None)
        .await?;
    Ok(Some(findings_chat_context(&assessment, &findings)))
}

fn push_startup_context(lines: &mut Vec<String>, stats: &serde_json::Value) {
    let Some(paths) = stats.get("startupPaths").and_then(|v| v.as_array()) else {
        return;
    };
    if paths.is_empty() {
        return;
    }
    lines.push(
        "How this app starts (from manifests and usual entry files; not a runtime trace):".into(),
    );
    for item in paths.iter().take(16) {
        let Some(row) = item.as_object() else {
            continue;
        };
        let kind = row.get("kind").and_then(|v| v.as_str()).unwrap_or("start");
        let path = row.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let note = row.get("note").and_then(|v| v.as_str()).unwrap_or("");
        let command = row.get("command").and_then(|v| v.as_str());
        match command {
            Some(cmd) => lines.push(format!("- [{kind}] {path} → {cmd} ({note})")),
            None => lines.push(format!("- [{kind}] {path} ({note})")),
        }
    }
}

pub fn findings_chat_context(assessment: &Assessment, findings: &[Finding]) -> String {
    const LIMIT: usize = 40;
    let active: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.state == "open" || f.state == "confirmed")
        .collect();
    let mut lines = vec![
        "Current scan findings.".into(),
        format!(
            "assessment_id={} status={} open={}",
            assessment.id,
            assessment.status.as_str(),
            assessment.open_finding_count
        ),
        "These ids are enough to rank and summarize. Call appsec_query only if you need a fresher list. Call appsec_investigate only if they asked to inspect a specific finding, or if this turn is an investigate/revalidate pass. Never invent ids, CVEs, or secrets.".into(),
        "When talking to the user, spell out jargon: SAST = static analysis (insecure code patterns in source); SCA = software composition analysis (lockfile deps vs OSV CVEs/GHSAs including known malware advisories, pinning, local install-script and lookalike-name checks, npm/PyPI versions published less than 7 days ago, optional Socket extra alerts). Category `literals` is an optional hardcoded-value check — not security; say that plainly.".into(),
        "Say findings, never ledger, handle, or achilles.db. Do not mention that chat is a preview or that Findings has a fuller list.".into(),
        "Prefer they apply fixes in their usual editor or coding agent. Edit files here only if they clearly ask.".into(),
    ];
    push_startup_context(&mut lines, &assessment.stats_json);
    if active.is_empty() {
        lines.push("No open findings on this scan.".into());
        return lines.join("\n");
    }
    for finding in active.iter().take(LIMIT) {
        let loc = match (&finding.path, finding.line_start) {
            (Some(path), Some(line)) => format!("{path}:{line}"),
            (Some(path), None) => path.clone(),
            _ => finding.rule_id.clone(),
        };
        lines.push(format!(
            "- id={} [{}] {} — {} ({})",
            finding.id,
            finding.severity,
            category_plain(&finding.category),
            finding.title,
            loc
        ));
    }
    if active.len() > LIMIT {
        lines.push(format!(
            "- … {} more. Call appsec_query if needed; do not tell the user this list is truncated.",
            active.len() - LIMIT
        ));
    }
    lines.join("\n")
}

pub fn category_plain(category: &str) -> &'static str {
    match category.to_ascii_lowercase().as_str() {
        "sast" => "insecure code pattern (SAST)",
        "literals" => "hardcoded value (not a security finding — stability / config hygiene)",
        "delta" => "issue introduced by local git changes",
        "history" => "secret still in git history",
        "harden" => "insecure app/config default (cookies, CORS, CSP)",
        "sca" => "vulnerable dependency (SCA)",
        "secrets" => "leaked secret",
        "surface" | "surfaces" => "exposed deploy/CI surface",
        _ => "finding",
    }
}

pub fn investigate_ids(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|f| {
            (f.state == "open" || f.state == "confirmed")
                && crate::engines::investigate::finding_needs_agent(&f.evidence_json)
        })
        .take(crate::engines::investigate::MAX_AGENT_QUEUE)
        .map(|f| f.id.clone())
        .collect()
}

fn open_fingerprints(findings: &[Finding]) -> HashSet<String> {
    findings
        .iter()
        .filter(|finding| finding.state == "open" || finding.state == "confirmed")
        .map(|finding| finding.fingerprint.clone())
        .collect()
}

fn diff_open_fingerprints(parent: &HashSet<String>, child: &HashSet<String>) -> (u64, u64) {
    let new_count = child.difference(parent).count() as u64;
    let gone_count = parent.difference(child).count() as u64;
    (new_count, gone_count)
}

fn skipped_walk_globs(include_vendor: bool) -> serde_json::Value {
    let mut globs = vec!["**/.git/**".to_string()];
    if !include_vendor {
        globs.extend(
            [
                "**/node_modules/**",
                "**/vendor/**",
                "**/target/**",
                "**/dist/**",
                "**/build/**",
                "**/.next/**",
                "**/__pycache__/**",
                "**/.venv/**",
                "**/venv/**",
                "**/Pods/**",
                "**/.yarn/**",
                "**/coverage/**",
            ]
            .map(str::to_string),
        );
    }
    json!(globs)
}

fn git_head(working_dir: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["-C", working_dir, "rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn start_quick_scan_and_wait(
    store: Arc<AchillesStore>,
    working_dir: &str,
) -> Result<Assessment> {
    start_scan(
        (*store).clone(),
        ScanRequest {
            working_dir: working_dir.to_string(),
            session_id: None,
            mode: "quick".into(),
            trigger: "scan_cta".into(),
            parent_assessment_id: None,
            wait: true,
            include_vendor: false,
            scan_literals: false,
            depth: "fast".into(),
            socket_api_token: None,
            socket_org: None,
            completer: None,
            ..Default::default()
        },
    )
    .await
}

#[derive(Debug, Clone)]
pub struct LedgerQuery {
    pub assessment: Option<Assessment>,
    pub preview: String,
    pub summary_handle_id: Option<String>,
    pub findings: Vec<Finding>,
    pub investigate_ids: Vec<String>,
    pub coverage: Option<CoverageSnapshot>,
}

pub async fn query_ledger(
    store: &AchillesStore,
    working_dir: Option<&str>,
    assessment_id: Option<&str>,
    category: Option<&str>,
) -> Result<LedgerQuery> {
    let assessment = if let Some(id) = assessment_id {
        store.get_assessment(id).await?
    } else if let Some(dir) = working_dir {
        store.list_assessments(Some(dir)).await?.into_iter().next()
    } else {
        store.list_assessments(None).await?.into_iter().next()
    };
    let mut findings = if let Some(a) = &assessment {
        store.list_findings(Some(&a.id), None, None).await?
    } else if let Some(dir) = working_dir {
        store.list_findings(None, None, Some(dir)).await?
    } else {
        Vec::new()
    };
    if let Some(cat) = category.filter(|c| !c.is_empty()) {
        findings.retain(|f| f.category.eq_ignore_ascii_case(cat));
    }
    findings.retain(|f| f.state == "open" || f.state == "confirmed");
    let summary_handle_id = assessment.as_ref().and_then(|a| {
        a.stats_json
            .get("summaryHandleId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    let coverage = if let Some(a) = &assessment {
        store.get_coverage_snapshot(&a.id).await?
    } else {
        None
    };
    Ok(LedgerQuery {
        preview: ledger_preview(&findings, 8),
        summary_handle_id,
        investigate_ids: investigate_ids(&findings),
        findings,
        assessment,
        coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;
    use tempfile::tempdir;

    fn git_commit_all(repo: &Path, message: &str) {
        let repo_s = repo.to_str().unwrap();
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .args(["-C", repo_s])
                .args(args)
                .output()
                .expect("git");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        if !repo.join(".git").exists() {
            run(&["init"]);
            run(&["config", "user.email", "achilles@test"]);
            run(&["config", "user.name", "achilles"]);
        }
        run(&["add", "-A"]);
        run(&["commit", "-m", message, "--allow-empty"]);
    }

    static OSV_OVERRIDE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn quick_scan_records_secret_finding() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let mut file = std::fs::File::create(repo.join("leak.env")).unwrap();
        writeln!(file, "KEY=AKIAIOSFODNN7EXAMPLE").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_quick_scan_and_wait(store.clone(), repo.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(assessment.status, AssessmentStatus::Completed);
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        assert!(findings.iter().any(|f| f.category == "secrets"));
        let handle_id = assessment
            .stats_json
            .get("summaryHandleId")
            .and_then(|v| v.as_str())
            .expect("handle");
        let handle = store.get_handle(handle_id, true).await.unwrap().unwrap();
        assert!(handle.preview.contains("AWS"));
        let candidates = store
            .list_candidates(&assessment.id, None, Some("secrets"))
            .await
            .unwrap();
        assert!(candidates.iter().any(|c| c.status.as_str() == "confirmed"));
        let units = store.list_work_units(&assessment.id).await.unwrap();
        assert!(units
            .iter()
            .any(|u| u.key == "secrets" && u.status == "done"));
    }

    #[tokio::test]
    async fn duration_cap_stops_partial_and_resume_completes() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let mut file = std::fs::File::create(repo.join("leak.env")).unwrap();
        writeln!(file, "KEY=AKIAIOSFODNN7EXAMPLE").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let capped = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                wait: true,
                trigger: "test".into(),
                max_duration_secs: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(capped.status, AssessmentStatus::Partial);
        assert!(capped
            .error_message
            .as_deref()
            .unwrap_or("")
            .contains("max duration"));
        let resumed = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                wait: true,
                trigger: "test".into(),
                resume_assessment_id: Some(capped.id.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(resumed.id, capped.id);
        assert_eq!(resumed.status, AssessmentStatus::Completed);
        let findings = store
            .list_findings(Some(&resumed.id), None, None)
            .await
            .unwrap();
        assert!(findings.iter().any(|f| f.category == "secrets"));
    }

    #[tokio::test]
    async fn fingerprint_records_startup_paths() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            repo.join("package.json"),
            r#"{"name":"demo","scripts":{"start":"node server.js"}}"#,
        )
        .unwrap();
        std::fs::write(
            repo.join("Dockerfile"),
            "FROM node:20\nCMD node server.js\n",
        )
        .unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_quick_scan_and_wait(store, repo.to_str().unwrap())
            .await
            .unwrap();
        let paths = assessment
            .stats_json
            .get("startupPaths")
            .and_then(|v| v.as_array())
            .expect("startupPaths");
        let kinds: Vec<_> = paths
            .iter()
            .filter_map(|row| row.get("kind").and_then(|v| v.as_str()))
            .collect();
        assert!(kinds.contains(&"npm-script"), "{paths:?}");
        assert!(kinds.contains(&"docker-cmd"), "{paths:?}");
    }

    #[tokio::test]
    async fn literals_scan_is_opt_in_and_not_security() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            repo.join("app.py"),
            "API = \"https://api.prod.internal/v1\"\ntimeout = 5000\n",
        )
        .unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let off = start_quick_scan_and_wait(store.clone(), repo.to_str().unwrap())
            .await
            .unwrap();
        let off_findings = store
            .list_findings(Some(&off.id), None, None)
            .await
            .unwrap();
        assert!(!off_findings.iter().any(|f| f.category == "literals"));

        let on = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: Some(off.id.clone()),
                wait: true,
                include_vendor: false,
                scan_literals: true,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let on_findings = store.list_findings(Some(&on.id), None, None).await.unwrap();
        assert!(on_findings.iter().any(|f| f.category == "literals"));
        assert!(on_findings
            .iter()
            .filter(|f| f.category == "literals")
            .all(|f| f.cwe_json.as_array().is_some_and(|a| a.is_empty())));
        assert!(on_findings
            .iter()
            .any(|f| f.rule_id == "hardcoded-url" && f.severity == "info"));
        assert!(on_findings
            .iter()
            .any(|f| f.rule_id == "hardcoded-timeout" && f.severity == "low"));
        assert_eq!(
            on.stats_json.get("scanLiterals").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn delta_scan_is_opt_in_and_flags_introduced_logic() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .status()
                .expect("git");
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "Test"]);
        std::fs::write(
            repo.join("safe.py"),
            "import ast\n\ndef parse(raw):\n    return ast.literal_eval(raw)\n",
        )
        .unwrap();
        git(&["add", "safe.py"]);
        git(&["-c", "commit.gpgsign=false", "commit", "-m", "safe"]);
        std::fs::write(repo.join("new.py"), "def run(cmd):\n    eval(cmd)\n").unwrap();

        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let off = start_quick_scan_and_wait(store.clone(), repo.to_str().unwrap())
            .await
            .unwrap();
        let off_findings = store
            .list_findings(Some(&off.id), None, None)
            .await
            .unwrap();
        assert!(!off_findings.iter().any(|f| f.category == "delta"));

        let on = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: Some(off.id.clone()),
                wait: true,
                include_vendor: false,
                scan_literals: false,
                scan_delta: true,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let on_findings = store.list_findings(Some(&on.id), None, None).await.unwrap();
        assert!(
            on_findings
                .iter()
                .any(|f| f.category == "delta" && f.rule_id == "delta-py-eval"),
            "{:?}",
            on_findings
                .iter()
                .map(|f| (f.category.as_str(), f.rule_id.as_str()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            on.stats_json.get("scanDelta").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn diff_mode_only_scans_changed_secret_files() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .status()
                .expect("git");
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "Test"]);
        std::fs::write(repo.join("committed.env"), "KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        git(&["add", "committed.env"]);
        git(&["-c", "commit.gpgsign=false", "commit", "-m", "init"]);
        std::fs::write(repo.join("new.env"), "KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "diff".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(assessment.status, AssessmentStatus::Completed);
        assert_eq!(
            assessment
                .stats_json
                .get("scanMode")
                .and_then(|v| v.as_str()),
            Some("diff")
        );
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        let secret_paths: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "secrets")
            .filter_map(|f| f.path.clone())
            .collect();
        assert!(
            secret_paths.iter().any(|p| p.ends_with("new.env")),
            "{secret_paths:?}"
        );
        assert!(
            !secret_paths.iter().any(|p| p.ends_with("committed.env")),
            "{secret_paths:?}"
        );
    }

    #[tokio::test]
    async fn full_scan_flags_secret_only_in_git_history() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_commit_all(&repo, "empty");
        std::fs::write(repo.join("gone.env"), "KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        git_commit_all(&repo, "leak");
        std::fs::remove_file(repo.join("gone.env")).unwrap();
        git_commit_all(&repo, "delete");

        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_quick_scan_and_wait(store.clone(), repo.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(assessment.status, AssessmentStatus::Completed);
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "history" && f.rule_id.contains("aws-access-key")),
            "{:?}",
            findings
                .iter()
                .map(|f| (f.category.as_str(), f.rule_id.as_str(), f.path.clone()))
                .collect::<Vec<_>>()
        );
        assert!(assessment.stats_json.get("graphHandleId").is_some());
        assert!(assessment.stats_json.get("history").is_some());
        assert!(assessment.stats_json.get("harden").is_some());
    }

    #[tokio::test]
    async fn rescan_marks_removed_secret_verified_fixed() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("leak.env"), "KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let first = start_quick_scan_and_wait(store.clone(), repo.to_str().unwrap())
            .await
            .unwrap();
        std::fs::remove_file(repo.join("leak.env")).unwrap();
        let second = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: Some(first.id.clone()),
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let findings = store
            .list_findings(Some(&second.id), None, None)
            .await
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "secrets" && f.state == "verified_fixed"),
            "{findings:?}"
        );
        assert_eq!(
            second
                .stats_json
                .get("closedThisScan")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(second.new_finding_count, Some(0));
        assert_eq!(second.gone_finding_count, Some(1));
        assert!(first.new_finding_count.is_none());
        assert!(first.gone_finding_count.is_none());
    }

    #[tokio::test]
    async fn rescan_joins_parent_by_sha_and_fingerprint() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("readme.txt"), "one\n").unwrap();
        git_commit_all(&repo, "init");
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let first = start_quick_scan_and_wait(store.clone(), repo.to_str().unwrap())
            .await
            .unwrap();
        assert!(first.content_fingerprint.is_some(), "{first:?}");
        assert_eq!(first.model_class.as_deref(), Some("L"));
        assert_eq!(first.base_git_sha, first.head_git_sha);
        assert!(first.head_git_sha.is_some());
        let coverage = store
            .get_coverage_snapshot(&first.id)
            .await
            .unwrap()
            .unwrap();
        assert!(coverage.files_indexed >= 1);
        let pool = store.pool().await.unwrap();
        let fp_run = sqlx::query(
            "SELECT argv_fingerprint, output_handle_id FROM engine_runs WHERE assessment_id = ? AND engine = 'fingerprint'",
        )
        .bind(&first.id)
        .fetch_one(pool)
        .await
        .unwrap();
        let argv: Option<String> = fp_run.get("argv_fingerprint");
        let handle: Option<String> = fp_run.get("output_handle_id");
        assert!(argv.is_some());
        assert!(handle.is_some());

        std::fs::write(repo.join("readme.txt"), "two\n").unwrap();
        git_commit_all(&repo, "change");
        let second = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: Some(first.id.clone()),
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            second.parent_assessment_id.as_deref(),
            Some(first.id.as_str())
        );
        assert_eq!(second.base_git_sha, first.head_git_sha);
        assert_ne!(second.head_git_sha, first.head_git_sha);
        assert_ne!(second.content_fingerprint, first.content_fingerprint);

        std::fs::write(repo.join("readme.txt"), "three\n").unwrap();
        let third = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: Some(second.id.clone()),
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(third.base_git_sha, second.head_git_sha);
        assert_eq!(third.head_git_sha, second.head_git_sha);
        assert_ne!(third.content_fingerprint, second.content_fingerprint);
    }

    #[tokio::test]
    async fn investigate_depth_queues_sast_for_agent() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.py"), "eval(user_input)\n").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "investigate".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            assessment
                .stats_json
                .get("filesIndexed")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        let indexed = assessment
            .stats_json
            .get("indexedFiles")
            .and_then(|v| v.as_array())
            .expect("indexedFiles");
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0], "a.py");
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        let sast = findings
            .iter()
            .find(|f| f.category == "sast")
            .expect("sast finding");
        assert_eq!(
            sast.evidence_json["investigation"]["needsAgent"],
            serde_json::json!(true)
        );
        let query = query_ledger(&store, None, Some(&assessment.id), Some("sast"))
            .await
            .unwrap();
        assert!(query.investigate_ids.contains(&sast.id), "{query:?}");
        assert!(query.preview.contains(&format!("id={}", sast.id)));
        assert_eq!(
            assessment.phases_json.get("agent").and_then(|v| v.as_str()),
            Some("skipped")
        );
    }

    #[tokio::test]
    async fn investigate_with_completer_writes_verdicts() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.py"), "eval(user_input)\n").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let reply = r#"{"verdict":"true_positive","reason":"eval takes user_input"}"#;
        let completer = std::sync::Arc::new(crate::engines::agent::ScriptedCompleter::new([
            reply, reply,
        ]));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "investigate".into(),
                socket_api_token: None,
                socket_org: None,
                completer: Some(completer),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            assessment.phases_json.get("agent").and_then(|v| v.as_str()),
            Some("done")
        );
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        let sast = findings
            .iter()
            .find(|f| f.category == "sast")
            .expect("sast finding");
        assert_eq!(
            sast.evidence_json["investigation"]["passes"]["investigator"]["verdict"],
            serde_json::json!("true_positive")
        );
        assert_eq!(sast.state, "confirmed");
    }

    #[tokio::test]
    async fn investigate_keeps_sast_when_agent_does_not_verdict() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.py"), "eval(user_input)\n").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let completer = std::sync::Arc::new(crate::engines::agent::ScriptedCompleter::new([
            "not-a-verdict",
        ]));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "investigate".into(),
                socket_api_token: None,
                socket_org: None,
                completer: Some(completer),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        let sast = findings
            .iter()
            .find(|f| f.category == "sast")
            .expect("sast finding must remain on the ledger");
        assert!(
            sast.state == "open" || sast.state == "confirmed",
            "{}",
            sast.state
        );
        let pending = store
            .list_candidates(&assessment.id, Some("pending"), Some("sast"))
            .await
            .unwrap();
        assert!(pending.is_empty(), "{pending:?}");
    }

    #[tokio::test]
    async fn investigate_false_positive_dismisses_engine_hit() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("a.py"), "eval('1')\n").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let reply = r#"{"verdict":"false_positive","reason":"literal argument in source"}"#;
        let completer = std::sync::Arc::new(crate::engines::agent::ScriptedCompleter::new([
            reply, reply,
        ]));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "investigate".into(),
                socket_api_token: None,
                socket_org: None,
                completer: Some(completer),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let findings = store
            .list_findings_history(Some(&assessment.id), None, None)
            .await
            .unwrap();
        let sast = findings
            .iter()
            .find(|f| f.category == "sast")
            .expect("dismissed hit must still exist");
        assert_eq!(sast.state, "dismissed");
    }

    #[tokio::test]
    async fn deep_with_completer_records_cited_unit_finding() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            repo.join("auth.py"),
            "def login(user):\n    return user\n\ndef run(cmd):\n    os.system(cmd)\n",
        )
        .unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let verdict = r#"{"verdict":"uncertain","reason":"engine already flagged this"}"#;
        let empty = r#"{"findings":[]}"#;
        let hit = r#"{"findings":[{"title":"Command injection","severity":"high","cwe":"CWE-78","line":4,"quote":"os.system(cmd)","why":"command string is passed to the shell"}]}"#;
        let completer = std::sync::Arc::new(crate::engines::agent::ScriptedCompleter::new([
            verdict, verdict, empty, hit,
        ]));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: true,
                include_vendor: false,
                scan_literals: false,
                depth: "deep".into(),
                socket_api_token: None,
                socket_org: None,
                completer: Some(completer),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            assessment.phases_json.get("agent").and_then(|v| v.as_str()),
            Some("done")
        );
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "agent-unit"
                && f.title.contains("Command injection")
                && f.evidence_json["source"] == serde_json::json!("agent")),
            "{findings:?}"
        );
    }

    #[tokio::test]
    async fn cancel_marks_running_scan_cancelled() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        for i in 0..2_000 {
            std::fs::write(repo.join(format!("f{i}.txt")), "x\n").unwrap();
        }
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: false,
                include_vendor: false,
                scan_literals: false,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(assessment.status, AssessmentStatus::Running);
        let cancelled = cancel_scan(&store, &assessment.id).await.unwrap();
        assert_eq!(cancelled.status, AssessmentStatus::Cancelled);
        assert!(
            wait_unregistered(&assessment.id, 2_000).await,
            "scan worker was still running after stop"
        );
        let latest = store.get_assessment(&assessment.id).await.unwrap().unwrap();
        assert_eq!(latest.status, AssessmentStatus::Cancelled);
    }

    #[tokio::test]
    async fn cancel_aborts_in_flight_sca_http() {
        let _osv_lock = OSV_OVERRIDE_LOCK.lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let _hold = socket;
                    std::future::pending::<()>().await
                });
            }
        });
        crate::public_sources::override_osv_query_url(Some(format!("http://{addr}/v1/query")));
        struct ClearOsv;
        impl Drop for ClearOsv {
            fn drop(&mut self) {
                crate::public_sources::override_osv_query_url(None);
            }
        }
        let _clear = ClearOsv;

        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: false,
                include_vendor: false,
                scan_literals: false,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let started = std::time::Instant::now();
        for _ in 0..80 {
            let latest = store.get_assessment(&assessment.id).await.unwrap().unwrap();
            if latest.phases_json.get("sca").and_then(|v| v.as_str()) == Some("running") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let cancelled = cancel_scan(&store, &assessment.id).await.unwrap();
        assert_eq!(cancelled.status, AssessmentStatus::Cancelled);
        assert!(
            wait_unregistered(&assessment.id, 2_000).await,
            "SCA HTTP was not aborted after stop"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        let latest = store.get_assessment(&assessment.id).await.unwrap().unwrap();
        assert_eq!(latest.status, AssessmentStatus::Cancelled);
        crate::public_sources::override_osv_query_url(None);
    }

    async fn wait_unregistered(assessment_id: &str, timeout_ms: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if !control_registered(assessment_id) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        !control_registered(assessment_id)
    }

    #[tokio::test]
    async fn pause_and_resume_scan() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        for i in 0..2_000 {
            std::fs::write(repo.join(format!("f{i}.txt")), "x\n").unwrap();
        }
        let store = Arc::new(AchillesStore::new(tmp.path().to_path_buf()));
        let assessment = start_scan(
            (*store).clone(),
            ScanRequest {
                working_dir: repo.to_str().unwrap().into(),
                session_id: None,
                mode: "quick".into(),
                trigger: "test".into(),
                parent_assessment_id: None,
                wait: false,
                include_vendor: false,
                scan_literals: false,
                depth: "fast".into(),
                socket_api_token: None,
                socket_org: None,
                completer: None,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let paused = pause_scan(&store, &assessment.id, true).await.unwrap();
        assert_eq!(paused.status, AssessmentStatus::Paused);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let still = store.get_assessment(&assessment.id).await.unwrap().unwrap();
        assert_eq!(still.status, AssessmentStatus::Paused);
        let resumed = pause_scan(&store, &assessment.id, false).await.unwrap();
        assert_eq!(resumed.status, AssessmentStatus::Running);
        for _ in 0..80 {
            let latest = store.get_assessment(&assessment.id).await.unwrap().unwrap();
            if latest.status == AssessmentStatus::Completed {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let latest = store.get_assessment(&assessment.id).await.unwrap().unwrap();
        assert_eq!(latest.status, AssessmentStatus::Completed);
    }

    #[test]
    fn findings_chat_context_spells_out_sast_and_sca() {
        let assessment = Assessment {
            id: "a1".into(),
            engagement_id: "e1".into(),
            working_dir: "/repo".into(),
            session_id: Some("s1".into()),
            mode: "quick".into(),
            status: AssessmentStatus::Completed,
            started_at: "t0".into(),
            finished_at: Some("t1".into()),
            updated_at: "t1".into(),
            phases_json: serde_json::json!({}),
            stats_json: serde_json::json!({
                "startupPaths": [{
                    "kind": "npm-script",
                    "path": "package.json",
                    "command": "node server.js",
                    "note": "package.json scripts.start"
                }]
            }),
            error_message: None,
            trigger: "scan_cta".into(),
            parent_assessment_id: None,
            base_git_sha: None,
            head_git_sha: None,
            content_fingerprint: None,
            model_class: None,
            open_finding_count: 2,
            new_finding_count: None,
            gone_finding_count: None,
        };
        let findings = vec![
            Finding {
                id: "f-sast".into(),
                engagement_id: "e1".into(),
                assessment_id: "a1".into(),
                last_seen_assessment_id: "a1".into(),
                fingerprint: "fp1".into(),
                state: "open".into(),
                severity: "high".into(),
                confidence: "medium".into(),
                category: "sast".into(),
                rule_id: "py-eval".into(),
                title: "eval()".into(),
                description: "dynamic eval".into(),
                path: Some("app.py".into()),
                line_start: Some(12),
                line_end: Some(12),
                cwe_json: serde_json::json!([]),
                cve_json: serde_json::json!([]),
                evidence_json: serde_json::json!({}),
                first_seen_at: "t0".into(),
                last_seen_at: "t0".into(),
                status_reason: None,
            },
            Finding {
                id: "f-sca".into(),
                engagement_id: "e1".into(),
                assessment_id: "a1".into(),
                last_seen_assessment_id: "a1".into(),
                fingerprint: "fp2".into(),
                state: "open".into(),
                severity: "medium".into(),
                confidence: "high".into(),
                category: "sca".into(),
                rule_id: "osv".into(),
                title: "requests CVE".into(),
                description: "advisory".into(),
                path: Some("requirements.txt".into()),
                line_start: None,
                line_end: None,
                cwe_json: serde_json::json!([]),
                cve_json: serde_json::json!([]),
                evidence_json: serde_json::json!({}),
                first_seen_at: "t0".into(),
                last_seen_at: "t0".into(),
                status_reason: None,
            },
        ];
        let text = findings_chat_context(&assessment, &findings);
        assert!(text.contains("insecure code pattern (SAST)"));
        assert!(text.contains("vulnerable dependency (SCA)"));
        assert!(text.contains("OSV CVEs/GHSAs"));
        assert!(text.contains("f-sast"));
        assert!(text.contains("rank and summarize"));
        assert!(!text.contains("Loop is appsec_investigate"));
        assert!(text.contains("usual editor"));
        assert!(text.contains("never ledger"));
        assert!(text.contains("How this app starts"));
        assert!(text.contains("node server.js"));
        assert!(!text.contains("source of truth"));
        assert!(!text.contains("Findings view"));
    }

    fn preview_finding(id: &str, category: &str, needs_agent: bool) -> Finding {
        Finding {
            id: id.into(),
            engagement_id: "e1".into(),
            assessment_id: "a1".into(),
            last_seen_assessment_id: "a1".into(),
            fingerprint: id.into(),
            state: "open".into(),
            severity: "high".into(),
            confidence: "medium".into(),
            category: category.into(),
            rule_id: "py-eval".into(),
            title: "eval()".into(),
            description: "dynamic eval".into(),
            path: Some("app.py".into()),
            line_start: Some(12),
            line_end: Some(12),
            cwe_json: serde_json::json!([]),
            cve_json: serde_json::json!([]),
            evidence_json: if needs_agent {
                serde_json::json!({"investigation": {"needsAgent": true}})
            } else {
                serde_json::json!({})
            },
            first_seen_at: "t0".into(),
            last_seen_at: "t0".into(),
            status_reason: None,
        }
    }

    #[test]
    fn fingerprint_diff_counts_new_and_gone() {
        let parent = HashSet::from(["a".into(), "b".into()]);
        let child = HashSet::from(["b".into(), "c".into()]);
        assert_eq!(diff_open_fingerprints(&parent, &child), (1, 1));
    }

    #[test]
    fn ledger_preview_does_not_mandate_verdict_loop() {
        let preview = ledger_preview(&[preview_finding("f-sast", "sast", true)], 8);
        assert!(preview.contains("f-sast"));
        assert!(preview.contains("investigate/revalidate passes only"));
        assert!(preview.contains("what's worst"));
        assert!(!preview.contains("appsec_investigate → appsec_verdict"));
        assert!(!preview.contains("For each id:"));
        assert!(!preview.contains("Findings view"));
        assert!(!preview.contains("full set is on"));
    }
}

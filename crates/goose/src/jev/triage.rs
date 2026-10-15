//! Findings false-positive triage assistant (Feature C).
//!
//! Builds a structured state per finding (identity + code snippet + package /
//! advisory versions + scan versions + prior passes), asks Jev for a verdict
//! with corroborating signals, and applies the outcome through the existing
//! triage writes. Uncertain or erroring outcomes leave the finding open.

use super::client::JevClient;
use super::config;
use super::types::{Answer, Question, SystemOneResponse};
use achilles_store::brief::snippet_from_evidence;
use achilles_store::types::{Assessment, Finding};
use achilles_store::AchillesStore;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageDecision {
    DismissFalsePositive,
    ConfirmTruePositive,
    LeaveOpen,
}

/// Jev's verdict plus the corroborating signals, all from one fan-out call.
pub struct TriageAssessment {
    pub verdict: String,
    pub confidence: f64,
    pub fp_score: f64,
    pub version_affected: f64,
    pub sink_reachable: f64,
}

/// Structured state for one finding: identity, code snippet, package/advisory
/// versions, scan versions, and prior investigator/validator passes.
pub fn finding_state(finding: &Finding, assessment: Option<&Assessment>) -> Value {
    let location = match (&finding.path, finding.line_start, finding.line_end) {
        (Some(path), Some(start), Some(end)) => format!("{path}:{start}-{end}"),
        (Some(path), Some(start), None) => format!("{path}:{start}"),
        (Some(path), _, _) => path.clone(),
        (None, _, _) => String::new(),
    };
    json!({
        "finding": {
            "title": finding.title,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "category": finding.category,
            "location": location,
        },
        "code_snippet": snippet_from_evidence(finding).unwrap_or_default(),
        "package": {
            "name": finding.evidence_json.get("package"),
            "version": finding.evidence_json.get("version"),
            "ecosystem": finding.evidence_json.get("ecosystem"),
        },
        "advisory": {
            "cve": finding.cve_json,
            "cwe": finding.cwe_json,
        },
        "scan": assessment.map(|info| json!({
            "base_git_sha": info.base_git_sha,
            "head_git_sha": info.head_git_sha,
            "content_fingerprint": info.content_fingerprint,
            "first_seen_at": finding.first_seen_at,
            "last_seen_at": finding.last_seen_at,
        })).unwrap_or(Value::Null),
        "prior_passes": finding
            .evidence_json
            .get("investigation")
            .and_then(|investigation| investigation.get("passes"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// Ask Jev for a verdict plus corroborating signals in one parallel call.
pub async fn assess(client: &JevClient, state: Value) -> Result<TriageAssessment> {
    let questions = BTreeMap::from([
        (
            "verdict".to_string(),
            Question::choice(
                "Is this finding a true positive, a false positive, or uncertain",
                BTreeMap::from([
                    (
                        "true_positive".to_string(),
                        json!("The flagged issue is real and should be fixed."),
                    ),
                    (
                        "false_positive".to_string(),
                        json!("The flagged issue is not actually a problem."),
                    ),
                    (
                        "uncertain".to_string(),
                        json!("The evidence is insufficient to decide."),
                    ),
                ]),
            ),
        ),
        (
            "fp_likelihood".to_string(),
            Question::score(
                "How likely is this finding a false positive",
                vec![
                    json!("Likely a real issue."),
                    json!("Likely a false positive."),
                ],
            ),
        ),
        (
            "version_affected".to_string(),
            Question::noul(
                "Does the advisory's affected version range actually cover the locked package version",
            ),
        ),
        (
            "sink_reachable".to_string(),
            Question::noul(
                "Does the code context show the flagged sink reached with untrusted input",
            ),
        ),
    ]);

    let response = client.evaluate(state, questions).await?;
    let (verdict, confidence) = match response.answers.get("verdict") {
        Some(Answer::Choice(choice)) => (choice.choice.clone(), choice.confidence),
        _ => anyhow::bail!("Jev triage response has no choice answer for 'verdict'"),
    };
    let fp_score = match response.answers.get("fp_likelihood") {
        Some(Answer::Score(score)) => score.score,
        _ => anyhow::bail!("Jev triage response has no score answer for 'fp_likelihood'"),
    };
    Ok(TriageAssessment {
        verdict,
        confidence,
        fp_score,
        version_affected: noul_answer(&response, "version_affected")?,
        sink_reachable: noul_answer(&response, "sink_reachable")?,
    })
}

fn noul_answer(response: &SystemOneResponse, key: &str) -> Result<f64> {
    match response.answers.get(key) {
        Some(Answer::Noul(answer)) => Ok(answer.noul),
        _ => Err(anyhow::anyhow!(
            "Jev triage response has no noul answer for '{key}'"
        ))
        .context("Jev triage returned an unusable response"),
    }
}

/// Pure decision rule: high-confidence verdicts act, everything else stays open.
/// False-positive dismissal additionally requires a corroborating low signal.
pub fn decide(
    assessment: &TriageAssessment,
    thresholds: &config::TriageThresholds,
) -> TriageDecision {
    if assessment.confidence < thresholds.auto_at {
        return TriageDecision::LeaveOpen;
    }
    match assessment.verdict.as_str() {
        "false_positive" => {
            let corroborated = assessment.version_affected <= 1.0 - thresholds.auto_at
                || assessment.sink_reachable <= 1.0 - thresholds.auto_at;
            if corroborated {
                TriageDecision::DismissFalsePositive
            } else {
                TriageDecision::LeaveOpen
            }
        }
        "true_positive" => TriageDecision::ConfirmTruePositive,
        _ => TriageDecision::LeaveOpen,
    }
}

/// Triage one finding end to end: assess with Jev, record the verdict, and
/// apply the decision. Non-open findings and Jev errors yield `LeaveOpen`
/// without triage writes (errors) or Jev calls (non-open).
pub async fn triage_one(
    store: &AchillesStore,
    client: &JevClient,
    finding_id: &str,
    thresholds: &config::TriageThresholds,
) -> Result<TriageDecision> {
    let finding = store
        .get_finding(finding_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown finding {finding_id}"))?;
    if finding.state != "open" {
        return Ok(TriageDecision::LeaveOpen);
    }
    let assessment_info = store.get_assessment(&finding.assessment_id).await?;
    let state = finding_state(&finding, assessment_info.as_ref());
    let assessed = match assess(client, state).await {
        Ok(assessed) => assessed,
        Err(error) => {
            tracing::debug!("Jev triage call failed, leaving open: {error:#}");
            return Ok(TriageDecision::LeaveOpen);
        }
    };
    let decision = decide(&assessed, thresholds);
    let reason = format!(
        "jev: verdict={} confidence={:.2} version_affected={:.2} sink_reachable={:.2} fp_likelihood={:.2}",
        assessed.verdict,
        assessed.confidence,
        assessed.version_affected,
        assessed.sink_reachable,
        assessed.fp_score,
    );
    let signals = json!({
        "version_affected": assessed.version_affected,
        "sink_reachable": assessed.sink_reachable,
        "fp_score": assessed.fp_score,
        "confidence": assessed.confidence,
    });
    store
        .record_jev_verdict(finding_id, &assessed.verdict, &reason, signals)
        .await?;
    match decision {
        TriageDecision::DismissFalsePositive => {
            store
                .triage_finding_with_source(finding_id, "dismissed", Some("false_positive"), "jev")
                .await?;
        }
        TriageDecision::ConfirmTruePositive => {
            store
                .triage_finding_with_source(finding_id, "confirmed", None, "jev")
                .await?;
        }
        TriageDecision::LeaveOpen => {}
    }
    Ok(decision)
}

/// Outcome counts for a batch triage run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TriageSummary {
    pub processed: usize,
    pub dismissed: usize,
    pub confirmed: usize,
    pub left_open: usize,
}

/// Triage every open finding from one assessment, up to `limit`, sequentially.
/// Sequential keeps Jev rate usage predictable; callers scope the assessment.
pub async fn triage_assessment(
    store: &AchillesStore,
    client: &JevClient,
    assessment_id: &str,
    thresholds: &config::TriageThresholds,
    limit: usize,
) -> Result<TriageSummary> {
    let mut summary = TriageSummary::default();
    let findings = store.list_findings(Some(assessment_id), None, None).await?;
    for finding in findings
        .iter()
        .filter(|finding| finding.state == "open")
        .take(limit)
    {
        summary.processed += 1;
        match triage_one(store, client, &finding.id, thresholds).await? {
            TriageDecision::DismissFalsePositive => summary.dismissed += 1,
            TriageDecision::ConfirmTruePositive => summary.confirmed += 1,
            TriageDecision::LeaveOpen => summary.left_open += 1,
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::client::JevClient;
    use achilles_store::types::{Assessment, AssessmentStatus, Finding};
    use serde_json::{json, Value};
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sca_finding() -> Finding {
        Finding {
            id: "f-1".to_string(),
            engagement_id: "e-1".to_string(),
            assessment_id: "a-1".to_string(),
            last_seen_assessment_id: "a-1".to_string(),
            fingerprint: "sca|demo-pkg|demo".to_string(),
            state: "open".to_string(),
            severity: "high".to_string(),
            confidence: "medium".to_string(),
            category: "sca".to_string(),
            rule_id: "GHSA-demo".to_string(),
            title: "demo-pkg@1.0.0 has a demo advisory".to_string(),
            description: "test".to_string(),
            path: Some("Cargo.lock".to_string()),
            line_start: None,
            line_end: None,
            cwe_json: json!([]),
            cve_json: json!(["CVE-2026-0001"]),
            evidence_json: json!({
                "engine": "achilles-sca-osv-v0",
                "package": "demo-pkg",
                "version": "1.0.0",
                "ecosystem": "crates.io",
                "preview": "demo-pkg 1.0.0",
                "investigation": {
                    "passes": {
                        "investigator": {"verdict": "uncertain", "reason": "short", "at": "t"}
                    }
                }
            }),
            first_seen_at: "t0".to_string(),
            last_seen_at: "t1".to_string(),
            status_reason: None,
        }
    }

    fn assessment() -> Assessment {
        Assessment {
            id: "a-1".to_string(),
            engagement_id: "e-1".to_string(),
            working_dir: "/repo".to_string(),
            session_id: None,
            mode: "quick".to_string(),
            status: AssessmentStatus::Completed,
            started_at: "t0".to_string(),
            finished_at: Some("t1".to_string()),
            updated_at: "t1".to_string(),
            phases_json: json!({}),
            stats_json: json!({}),
            error_message: None,
            trigger: "scan_cta".to_string(),
            parent_assessment_id: None,
            base_git_sha: Some("abc".to_string()),
            head_git_sha: Some("def".to_string()),
            content_fingerprint: Some("fp".to_string()),
            model_class: None,
            open_finding_count: 1,
            new_finding_count: None,
            gone_finding_count: None,
        }
    }

    fn triage_answers(
        verdict: &str,
        confidence: f64,
        fp_score: f64,
        version_affected: f64,
        sink_reachable: f64,
    ) -> Value {
        json!({
            "model": "jev-1.13.0",
            "answers": {
                "verdict": {
                    "type": "choice",
                    "choice": verdict,
                    "confidence": confidence,
                    "probabilities": { verdict: confidence }
                },
                "fp_likelihood": {
                    "type": "score",
                    "score": fp_score,
                    "confidence": 0.8,
                    "legend": {"0": "likely real", "1": "likely false positive"},
                    "probabilities": {"0": 0.2, "1": 0.8}
                },
                "version_affected": {"type": "noul", "noul": version_affected},
                "sink_reachable": {"type": "noul", "noul": sink_reachable}
            },
            "usage": {"input_tokens": 10, "output_tokens": 2}
        })
    }

    fn test_client(server: &MockServer) -> JevClient {
        JevClient::new(
            format!("{}/v1/systemone", server.uri()),
            "test-key",
            "jev-latest",
            Duration::from_millis(5000),
        )
        .expect("client builds")
    }

    #[test]
    fn finding_state_includes_identity_snippet_and_versions() {
        let state = finding_state(&sca_finding(), Some(&assessment()));

        assert_eq!(
            state["finding"]["title"],
            json!("demo-pkg@1.0.0 has a demo advisory")
        );
        assert_eq!(state["finding"]["rule_id"], json!("GHSA-demo"));
        assert!(
            state["code_snippet"].as_str().unwrap().contains("demo-pkg"),
            "snippet missing: {state}"
        );
        assert_eq!(state["package"]["version"], json!("1.0.0"));
        assert_eq!(state["scan"]["head_git_sha"], json!("def"));
        assert_eq!(
            state["prior_passes"]["investigator"]["verdict"],
            json!("uncertain")
        );
    }

    #[tokio::test]
    async fn assess_parses_fan_out_answers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(triage_answers(
                "false_positive",
                0.9,
                0.85,
                0.05,
                0.1,
            )))
            .mount(&server)
            .await;

        let assessment = assess(&test_client(&server), json!({}))
            .await
            .expect("assess succeeds");
        assert_eq!(assessment.verdict, "false_positive");
        assert!((assessment.confidence - 0.9).abs() < f64::EPSILON);
        assert!((assessment.fp_score - 0.85).abs() < f64::EPSILON);
        assert!((assessment.version_affected - 0.05).abs() < f64::EPSILON);
        assert!((assessment.sink_reachable - 0.1).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn assess_errors_on_missing_verdict() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "model": "jev-1.13.0",
                "answers": {"unrelated": {"type": "noul", "noul": 1.0}},
                "usage": {"input_tokens": 1, "output_tokens": 0}
            })))
            .mount(&server)
            .await;

        let result = assess(&test_client(&server), json!({})).await;
        assert!(result.is_err(), "missing verdict must surface as Err");
    }

    fn fp_assessment(
        confidence: f64,
        version_affected: f64,
        sink_reachable: f64,
    ) -> TriageAssessment {
        TriageAssessment {
            verdict: "false_positive".to_string(),
            confidence,
            fp_score: 0.85,
            version_affected,
            sink_reachable,
        }
    }

    #[test]
    fn decide_dismisses_corroborated_high_confidence_fp() {
        let decision = decide(
            &fp_assessment(0.9, 0.05, 0.7),
            &config::TriageThresholds::default(),
        );
        assert!(matches!(decision, TriageDecision::DismissFalsePositive));
    }

    #[test]
    fn decide_leaves_uncorroborated_fp_open() {
        let decision = decide(
            &fp_assessment(0.9, 0.6, 0.7),
            &config::TriageThresholds::default(),
        );
        assert!(matches!(decision, TriageDecision::LeaveOpen));
    }

    #[test]
    fn decide_confirms_high_confidence_tp() {
        let assessment = TriageAssessment {
            verdict: "true_positive".to_string(),
            confidence: 0.85,
            fp_score: 0.1,
            version_affected: 0.9,
            sink_reachable: 0.9,
        };
        let decision = decide(&assessment, &config::TriageThresholds::default());
        assert!(matches!(decision, TriageDecision::ConfirmTruePositive));
    }

    #[test]
    fn decide_leaves_low_confidence_open() {
        let decision = decide(
            &fp_assessment(0.5, 0.05, 0.1),
            &config::TriageThresholds::default(),
        );
        assert!(matches!(decision, TriageDecision::LeaveOpen));
    }

    async fn stored_sca_finding() -> (
        tempfile::TempDir,
        achilles_store::AchillesStore,
        String,
        MockServer,
    ) {
        use achilles_store::types::{NewFinding, Severity};

        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let store = achilles_store::AchillesStore::new(dir.path().to_path_buf());
        let engagement = store
            .upsert_engagement(dir.path().to_str().unwrap())
            .await
            .unwrap();
        let assessment = store
            .create_assessment(&engagement, None, "quick", "scan_cta", None)
            .await
            .unwrap();
        store
            .upsert_finding(
                &engagement.id,
                &assessment.id,
                &NewFinding {
                    fingerprint: "sca|demo-pkg|demo".into(),
                    severity: Severity::High,
                    confidence: "medium".into(),
                    category: "sca".into(),
                    rule_id: "GHSA-demo".into(),
                    title: "demo-pkg@1.0.0 has a demo advisory".into(),
                    description: "test".into(),
                    path: Some("Cargo.lock".into()),
                    line_start: None,
                    line_end: None,
                    cwe: vec![],
                    cve: vec!["CVE-2026-0001".into()],
                    evidence: json!({
                        "engine": "achilles-sca-osv-v0",
                        "package": "demo-pkg",
                        "version": "1.0.0",
                        "ecosystem": "crates.io",
                        "preview": "demo-pkg 1.0.0",
                    }),
                },
            )
            .await
            .unwrap();
        let listed = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        let id = listed[0].id.clone();
        (dir, store, id, server)
    }

    #[tokio::test]
    async fn triage_one_dismisses_corroborated_fp_with_jev_source() {
        let (_dir, store, id, server) = stored_sca_finding().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(triage_answers(
                "false_positive",
                0.9,
                0.85,
                0.05,
                0.7,
            )))
            .mount(&server)
            .await;

        let decision = triage_one(
            &store,
            &test_client(&server),
            &id,
            &config::TriageThresholds::default(),
        )
        .await
        .expect("triage_one succeeds");
        assert!(matches!(decision, TriageDecision::DismissFalsePositive));

        let finding = store.get_finding(&id).await.unwrap().unwrap();
        assert_eq!(finding.state, "dismissed");
        assert_eq!(finding.status_reason.as_deref(), Some("false_positive"));
        assert_eq!(finding.evidence_json["triage"]["source"], json!("jev"));
        assert_eq!(
            finding.evidence_json["jev_assessment"]["verdict"],
            json!("false_positive")
        );
    }

    #[tokio::test]
    async fn triage_one_skips_non_open_findings_without_calling_jev() {
        let (_dir, store, id, server) = stored_sca_finding().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(triage_answers(
                "false_positive",
                0.9,
                0.85,
                0.05,
                0.1,
            )))
            .mount(&server)
            .await;
        store.triage_finding(&id, "confirmed", None).await.unwrap();

        let decision = triage_one(
            &store,
            &test_client(&server),
            &id,
            &config::TriageThresholds::default(),
        )
        .await
        .expect("triage_one succeeds");
        assert!(matches!(decision, TriageDecision::LeaveOpen));

        let received = server.received_requests().await.expect("requests tracked");
        assert!(received.is_empty(), "confirmed findings cost no Jev call");
    }

    #[tokio::test]
    async fn triage_one_leaves_open_on_jev_error() {
        let (_dir, store, id, server) = stored_sca_finding().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let decision = triage_one(
            &store,
            &test_client(&server),
            &id,
            &config::TriageThresholds::default(),
        )
        .await
        .expect("triage_one succeeds");
        assert!(matches!(decision, TriageDecision::LeaveOpen));

        let finding = store.get_finding(&id).await.unwrap().unwrap();
        assert_eq!(finding.state, "open");
    }

    async fn stored_assessment_with_findings(
        fingerprints: &[&str],
    ) -> (tempfile::TempDir, achilles_store::AchillesStore, String) {
        use achilles_store::types::{NewFinding, Severity};

        let dir = tempfile::tempdir().unwrap();
        let store = achilles_store::AchillesStore::new(dir.path().to_path_buf());
        let engagement = store
            .upsert_engagement(dir.path().to_str().unwrap())
            .await
            .unwrap();
        let assessment = store
            .create_assessment(&engagement, None, "quick", "scan_cta", None)
            .await
            .unwrap();
        for fingerprint in fingerprints {
            store
                .upsert_finding(
                    &engagement.id,
                    &assessment.id,
                    &NewFinding {
                        fingerprint: (*fingerprint).into(),
                        severity: Severity::Medium,
                        confidence: "medium".into(),
                        category: "sca".into(),
                        rule_id: "GHSA-demo".into(),
                        title: format!("finding {fingerprint}"),
                        description: "test".into(),
                        path: Some("Cargo.lock".into()),
                        line_start: None,
                        line_end: None,
                        cwe: vec![],
                        cve: vec![],
                        evidence: json!({
                            "engine": "achilles-sca-osv-v0",
                            "package": "demo-pkg",
                            "version": "1.0.0",
                            "ecosystem": "crates.io",
                            "preview": "demo-pkg 1.0.0",
                        }),
                    },
                )
                .await
                .unwrap();
        }
        (dir, store, assessment.id)
    }

    #[tokio::test]
    async fn triage_assessment_dismisses_all_open_findings() {
        let (_dir, store, assessment_id) =
            stored_assessment_with_findings(&["sca|a", "sca|b"]).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(triage_answers(
                "false_positive",
                0.9,
                0.85,
                0.05,
                0.7,
            )))
            .mount(&server)
            .await;

        let summary = triage_assessment(
            &store,
            &test_client(&server),
            &assessment_id,
            &config::TriageThresholds::default(),
            10,
        )
        .await
        .expect("batch triage succeeds");

        assert_eq!(summary.processed, 2);
        assert_eq!(summary.dismissed, 2);
        assert_eq!(summary.confirmed, 0);
        assert_eq!(summary.left_open, 0);
        let remaining = store
            .list_findings(Some(&assessment_id), None, None)
            .await
            .unwrap();
        assert!(
            remaining.iter().all(|f| f.state == "dismissed"),
            "all open findings dismissed: {remaining:?}"
        );
    }

    #[tokio::test]
    async fn triage_assessment_respects_limit() {
        let (_dir, store, assessment_id) =
            stored_assessment_with_findings(&["sca|a", "sca|b", "sca|c"]).await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(triage_answers(
                "false_positive",
                0.9,
                0.85,
                0.05,
                0.7,
            )))
            .mount(&server)
            .await;

        let summary = triage_assessment(
            &store,
            &test_client(&server),
            &assessment_id,
            &config::TriageThresholds::default(),
            2,
        )
        .await
        .expect("batch triage succeeds");

        assert_eq!(summary.processed, 2);
        assert_eq!(summary.dismissed, 2);
        let received = server.received_requests().await.expect("requests tracked");
        assert_eq!(received.len(), 2, "limit caps Jev calls");
    }
}

//! Quick scan orchestration (secrets + SCA). Proprietary — `LICENSE-ACHILLES`.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use serde_json::json;

use crate::engines::{sca, secrets};
use crate::store::{canonicalize_working_dir, AchillesStore};
use crate::types::{Assessment, AssessmentStatus, Finding};

pub struct ScanRequest {
    pub working_dir: String,
    pub session_id: Option<String>,
    pub mode: String,
    pub trigger: String,
    pub parent_assessment_id: Option<String>,
    pub wait: bool,
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
        },
    )
    .await
}

pub async fn start_scan(store: AchillesStore, req: ScanRequest) -> Result<Assessment> {
    let working_dir = canonicalize_working_dir(&req.working_dir)?;
    let engagement = store.upsert_engagement(&working_dir).await?;
    let assessment = store
        .create_assessment(
            &engagement,
            req.session_id.as_deref(),
            &req.mode,
            &req.trigger,
            req.parent_assessment_id.as_deref(),
        )
        .await?;
    let store_bg = store.clone();
    let assessment_id = assessment.id.clone();
    let engagement_id = engagement.id.clone();
    let join = tokio::spawn(async move {
        if let Err(err) = run_engines(&store_bg, &working_dir, &engagement_id, &assessment_id).await
        {
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
    });
    if req.wait {
        let _ = join.await;
        return store
            .get_assessment(&assessment.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("assessment vanished after scan"));
    }
    Ok(assessment)
}

async fn run_engines(
    store: &AchillesStore,
    working_dir: &str,
    engagement_id: &str,
    assessment_id: &str,
) -> Result<()> {
    let root = Path::new(working_dir);
    store
        .set_phase(assessment_id, "fingerprint", "done")
        .await?;

    store.set_phase(assessment_id, "secrets", "running").await?;
    let secret_findings = secrets::scan_secrets(root)?;
    let secret_count = secret_findings.len();
    for finding in &secret_findings {
        store
            .upsert_finding(engagement_id, assessment_id, finding)
            .await?;
    }
    store
        .record_engine_run(
            assessment_id,
            "secrets",
            "completed",
            json!({ "findings": secret_count }),
            None,
        )
        .await?;
    store.set_phase(assessment_id, "secrets", "done").await?;

    store.set_phase(assessment_id, "sca", "running").await?;
    let sca_outcome = sca::scan_sca(root).await;
    let sca_count = sca_outcome.findings.len();
    for finding in &sca_outcome.findings {
        store
            .upsert_finding(engagement_id, assessment_id, finding)
            .await?;
    }
    let sca_status = if sca_outcome.skipped_reason.is_some() && sca_outcome.queried == 0 {
        "skipped"
    } else {
        "completed"
    };
    store
        .record_engine_run(
            assessment_id,
            "sca",
            sca_status,
            json!({
                "findings": sca_count,
                "packagesConsidered": sca_outcome.packages_considered,
                "queried": sca_outcome.queried,
                "skippedReason": sca_outcome.skipped_reason,
            }),
            None,
        )
        .await?;
    store.set_phase(assessment_id, "sca", "done").await?;

    let findings = store
        .list_findings(Some(assessment_id), None, None)
        .await?;
    let preview = ledger_preview(&findings, 8);
    let handle = store
        .write_handle(
            assessment_id,
            "findings-json",
            &json!({
                "preview": preview,
                "findings": findings,
                "stats": {
                    "secrets": secret_count,
                    "sca": sca_count,
                    "open": findings.len()
                }
            }),
        )
        .await?;

    store
        .finish_assessment(
            assessment_id,
            AssessmentStatus::Completed,
            json!({
                "secrets": secret_count,
                "sca": sca_count,
                "open": findings.len(),
                "summaryHandleId": handle.handle_id
            }),
            None,
        )
        .await?;
    Ok(())
}

pub fn ledger_preview(findings: &[Finding], limit: usize) -> String {
    if findings.is_empty() {
        return "No open findings. Engines are authoritative — do not invent issues.".into();
    }
    let mut lines = vec![format!(
        "{} finding(s). Show at most {limit} here; full set is on the handle / Findings view.",
        findings.len()
    )];
    for finding in findings.iter().take(limit) {
        let loc = match (&finding.path, finding.line_start) {
            (Some(path), Some(line)) => format!("{path}:{line}"),
            (Some(path), None) => path.clone(),
            _ => finding.rule_id.clone(),
        };
        lines.push(format!(
            "- [{}] [{}] {} — {}",
            finding.severity.to_uppercase(),
            finding.category,
            loc,
            finding.title
        ));
    }
    if findings.len() > limit {
        lines.push(format!("- … {} more", findings.len() - limit));
    }
    lines.join("\n")
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
    let summary_handle_id = assessment.as_ref().and_then(|a| {
        a.stats_json
            .get("summaryHandleId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    Ok(LedgerQuery {
        preview: ledger_preview(&findings, 8),
        summary_handle_id,
        findings,
        assessment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

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
    }
}

//! OpenSSF Scorecard for the origin GitHub repo. Public API; Rancero can replace the URL.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;

use crate::engines::abort::{self, Abort};
use crate::public_sources::{self, HTTP_USER_AGENT, ID_SCORECARD};
use crate::store::AchillesStore;
use crate::types::{NewFinding, Severity};

pub async fn scan(
    root: &Path,
    store: &AchillesStore,
    abort: Option<&Abort>,
) -> Result<Vec<NewFinding>> {
    let Some(project) = github_origin(root) else {
        return Ok(Vec::new());
    };
    if abort.is_some_and(Abort::is_cancelled) {
        anyhow::bail!(abort::Cancelled);
    }
    let key = format!("scorecard:{project}");
    let payload = if let Some(cached) = store.intel_cache_get(&key, 24 * 3600).await? {
        cached
    } else {
        let url = format!(
            "{}/github.com/{project}",
            public_sources::scorecard_projects_url().trim_end_matches('/')
        );
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(HTTP_USER_AGENT)
            .build()?;
        let resp = abort::http(abort, http.get(url).send()).await?;
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }
        let value: serde_json::Value = abort::http(abort, resp.json()).await?;
        let _ = store.intel_cache_put(&key, ID_SCORECARD, &value).await;
        value
    };
    let score = payload
        .get("score")
        .and_then(|v| v.as_f64())
        .unwrap_or(-1.0);
    if score < 0.0 || score >= 5.0 {
        return Ok(Vec::new());
    }
    Ok(vec![NewFinding {
        fingerprint: format!("scorecard:{project}"),
        severity: if score < 3.0 {
            Severity::High
        } else {
            Severity::Medium
        },
        confidence: "medium".into(),
        category: "sca".into(),
        rule_id: "openssf-scorecard-low".into(),
        title: format!("OpenSSF Scorecard {score:.1} for {project}"),
        description: format!(
            "Public OpenSSF Scorecard for github.com/{project} is {score:.1} (below 5). Review checks; this is not a CVE."
        ),
        path: None,
        line_start: None,
        line_end: None,
        cwe: vec![],
        cve: vec![],
        evidence: json!({
            "engine": "achilles-scorecard-v0",
            "project": project,
            "score": score,
            "source": ID_SCORECARD,
        }),
    }])
}

fn github_origin(root: &Path) -> Option<String> {
    let out = Command::new("git")
        .args([
            "--git-dir",
            &root.join(".git").to_string_lossy(),
            "--work-tree",
            &root.to_string_lossy(),
            "remote",
            "get-url",
            "origin",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_github_slug(&String::from_utf8_lossy(&out.stdout))
}

fn parse_github_slug(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = url
        .strip_prefix("git@github.com:")
        .or_else(|| url.strip_prefix("https://github.com/"))
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))?;
    let rest = rest.trim_end_matches(".git").trim_end_matches('/');
    let mut parts = rest.split('/');
    let org = parts.next()?;
    let repo = parts.next()?;
    if org.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{org}/{repo}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_and_ssh() {
        assert_eq!(
            parse_github_slug("https://github.com/kineticquant/achilles-harness.git"),
            Some("kineticquant/achilles-harness".into())
        );
        assert_eq!(
            parse_github_slug("git@github.com:foo/bar.git"),
            Some("foo/bar".into())
        );
    }
}

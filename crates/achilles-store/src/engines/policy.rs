//! Workspace suppressions (`.achilles/suppressions.json`). Not a model decision.

use std::path::Path;

use serde::Deserialize;

use crate::types::NewFinding;

#[derive(Debug, Default, Clone)]
pub struct Suppressions {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    until: Option<String>,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    suppressions: Vec<Rule>,
}

pub fn load(root: &Path) -> Suppressions {
    let path = root.join(".achilles").join("suppressions.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Suppressions::default();
    };
    let Ok(file) = serde_json::from_str::<File>(&text) else {
        return Suppressions::default();
    };
    let today = chrono::Utc::now().date_naive().to_string();
    let rules = file
        .suppressions
        .into_iter()
        .filter(|r| {
            r.until
                .as_ref()
                .map(|u| u.as_str() >= today.as_str())
                .unwrap_or(true)
        })
        .collect();
    Suppressions { rules }
}

impl Suppressions {
    pub fn matches(&self, hit: &NewFinding) -> bool {
        self.rules.iter().any(|rule| {
            let rule_ok = rule
                .rule_id
                .as_deref()
                .map(|id| id == hit.rule_id)
                .unwrap_or(true);
            let path_ok = match (rule.path.as_deref(), hit.path.as_deref()) {
                (None, _) => true,
                (Some(want), Some(got)) => got == want || got.ends_with(want),
                (Some(_), None) => false,
            };
            rule_ok && path_ok && rule.reason.as_deref().is_some_and(|r| !r.trim().is_empty())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    #[test]
    fn expires_and_matches_rule() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".achilles")).unwrap();
        std::fs::write(
            dir.path().join(".achilles/suppressions.json"),
            r#"{"suppressions":[{"ruleId":"cors-star","path":"server.js","reason":"intentional public API","until":"2099-01-01"}]}"#,
        )
        .unwrap();
        let s = load(dir.path());
        let hit = NewFinding {
            fingerprint: "x".into(),
            severity: Severity::Medium,
            confidence: "medium".into(),
            category: "harden".into(),
            rule_id: "cors-star".into(),
            title: "cors".into(),
            description: "cors".into(),
            path: Some("server.js".into()),
            line_start: Some(1),
            line_end: Some(1),
            cwe: vec![],
            cve: vec![],
            evidence: serde_json::json!({}),
        };
        assert!(s.matches(&hit));
    }
}

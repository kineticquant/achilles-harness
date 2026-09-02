//! Pasteable finding brief for a coding editor / harness. Apache-2.0.

use crate::scan::category_plain;
use crate::types::Finding;

pub const ACHILLES_SITE: &str = "https://achilles.sh";
pub const ACHILLES_REPO: &str = "https://github.com/kineticquant/achilles-harness";

pub const EDITOR_BRIEF_LEAD: &str = "You are fixing a finding from Achilles (https://achilles.sh). Achilles is a local AppSec harness: a native desktop agent that scans your own workspace for leaked secrets, insecure code patterns (SAST), vulnerable dependencies (SCA), and exposed deploy/CI surfaces, then records those findings for triage. It is not an IDE. Product: https://achilles.sh — source: https://github.com/kineticquant/achilles-harness";

fn loc(finding: &Finding) -> String {
    match (&finding.path, finding.line_start, finding.line_end) {
        (Some(path), Some(start), Some(end)) if end != start => {
            format!("{path}:{start}-{end}")
        }
        (Some(path), Some(start), _) => format!("{path}:{start}"),
        (Some(path), None, _) => path.clone(),
        _ => finding.rule_id.clone(),
    }
}

fn json_list(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Array(items) if !items.is_empty() => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(|v| {
                    v.as_str()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .or_else(|| {
                            if v.is_null() || v.as_str().is_some() {
                                None
                            } else {
                                Some(v.to_string())
                            }
                        })
                })
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(", "))
            }
        }
        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

fn optional_line(label: &str, value: Option<String>) -> String {
    match value {
        Some(v) if !v.is_empty() => format!("{label}: {v}\n"),
        _ => String::new(),
    }
}

fn evidence_context(finding: &Finding) -> String {
    let ev = finding.evidence_json.as_object();
    let Some(map) = ev else {
        return String::new();
    };
    let mut lines = Vec::new();
    for key in [
        "engine",
        "kind",
        "package",
        "name",
        "ecosystem",
        "version",
        "advisory",
        "cve",
        "surface",
    ] {
        let Some(value) = map.get(key) else {
            continue;
        };
        let rendered = value
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if value.is_null() || value.is_object() || value.is_array() {
                    None
                } else {
                    Some(value.to_string())
                }
            });
        if let Some(rendered) = rendered {
            lines.push(format!("{key}: {rendered}"));
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("\nExtra context:\n{}\n", lines.join("\n"))
    }
}

pub fn editor_brief(finding: &Finding, snippet: &str) -> String {
    let loc = loc(finding);
    let snippet = snippet.trim();
    let source = if snippet.is_empty() {
        "(no source snippet on this finding)".to_string()
    } else {
        format!("```\n{snippet}\n```")
    };
    let cwe = optional_line("CWE", json_list(&finding.cwe_json));
    let cve = optional_line("CVE", json_list(&finding.cve_json));
    let extra = evidence_context(finding);
    format!(
        "{EDITOR_BRIEF_LEAD}\n\n\
## Finding\n\
Achilles finding id: {}\n\
State: {}\n\
File: {loc}\n\
Severity: {}\n\
Confidence: {}\n\
Kind: {}\n\
Rule: {}\n\
Title: {}\n\
{cwe}{cve}{extra}\n\
What Achilles found:\n{}\n\n\
Source (may be redacted by Achilles; do not print secret values):\n{source}\n\n\
## Rules for the coding agent\n\
- Fix only this finding (the id above). Do not invent other findings, CVEs, or exploits.\n\
- Do not print secrets. If this is a leaked credential, rotate it at the provider and remove it from the file (and from git history if it was committed).\n\
- After a real patch, tell the user they can Rescan in Achilles Findings, or mark this finding fixed there.\n\
\n\
## Achilles MCP (optional)\n\
If Achilles MCP is connected in this editor, or the user asks you to use it, you may close or inspect this finding yourself. Tools (never invent finding ids):\n\
- `appsec_investigate` with `finding_id={}` — extra nearby source for this finding only.\n\
- `appsec_query` — current findings list / ranking. Do not invent ids.\n\
- After the fix is actually in the tree: `appsec_triage` with `finding_id={}` and `state=verified_fixed`.\n\
- If this is a false positive and the user agrees: `appsec_triage` with `finding_id={}` and `state=dismissed`.\n\
- Do not call `appsec_scan` unless they ask. If MCP is not connected, apply the patch here and tell them to Rescan or mark the finding in Achilles Findings.\n",
        finding.id,
        finding.state,
        finding.severity,
        finding.confidence,
        category_plain(&finding.category),
        finding.rule_id,
        finding.title.trim(),
        finding.description.trim(),
        finding.id,
        finding.id,
        finding.id,
    )
}

pub fn snippet_from_evidence(finding: &Finding) -> Option<String> {
    finding
        .evidence_json
        .pointer("/investigation/snippet")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            finding
                .evidence_json
                .get("preview")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Finding;

    fn finding() -> Finding {
        Finding {
            id: "f-1".into(),
            engagement_id: "e".into(),
            assessment_id: "a".into(),
            last_seen_assessment_id: "a".into(),
            fingerprint: "fp".into(),
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
            cwe_json: serde_json::json!(["CWE-95"]),
            cve_json: serde_json::json!([]),
            evidence_json: serde_json::json!({"preview": "eval(user)", "engine": "achilles-sast-v0"}),
            first_seen_at: "t0".into(),
            last_seen_at: "t0".into(),
            status_reason: None,
        }
    }

    #[test]
    fn brief_introduces_achilles_and_the_finding() {
        let text = editor_brief(&finding(), "eval(user)");
        assert!(text.starts_with(EDITOR_BRIEF_LEAD));
        assert!(text.contains(ACHILLES_SITE));
        assert!(text.contains(ACHILLES_REPO));
        assert!(!text.contains("Paste this into your coding editor"));
        assert!(text.contains("app.py:12"));
        assert!(text.contains("f-1"));
        assert!(text.contains("Rule: py-eval"));
        assert!(text.contains("Confidence: medium"));
        assert!(text.contains("CWE: CWE-95"));
        assert!(text.contains("engine: achilles-sast-v0"));
        assert!(text.contains("eval(user)"));
        assert!(text.contains("appsec_triage"));
        assert!(text.contains("state=verified_fixed"));
        assert!(text.contains("state=dismissed"));
        assert!(text.contains("Rescan"));
    }
}

//! App-config hardening smells in source (cookies, CORS, CSP). Not a runtime probe.

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::engines::walk::WalkedFile;
use crate::types::{NewFinding, Severity};

const MAX_HITS: usize = 80;

struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    regex: Regex,
    why: &'static str,
    cwe: &'static str,
}

pub fn scan_harden_on(
    files: &[WalkedFile],
    only_rel: Option<&HashSet<String>>,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<Vec<NewFinding>> {
    let rules = rules()?;
    let mut findings = Vec::new();
    for file in files {
        if crate::engines::abort::flagged(cancel) || findings.len() >= MAX_HITS {
            break;
        }
        if let Some(only) = only_rel {
            if !only.contains(&file.rel) {
                continue;
            }
        }
        if !is_source(&file.rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file.abs) else {
            continue;
        };
        for (idx, line) in text.lines().enumerate() {
            if findings.len() >= MAX_HITS {
                break;
            }
            let line_no = idx + 1;
            for rule in &rules {
                if rule.regex.is_match(line) {
                    findings.push(hit(rule, &file.rel, line_no, line));
                    break;
                }
            }
        }
    }
    Ok(findings)
}

fn is_source(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".jsx")
        || lower.ends_with(".mjs")
        || lower.ends_with(".cjs")
        || lower.ends_with(".py")
        || lower.ends_with(".go")
        || lower.ends_with(".rb")
        || lower.ends_with(".php")
        || lower.ends_with(".java")
        || lower.ends_with(".cs")
        || lower.ends_with(".rs")
}

fn rules() -> anyhow::Result<Vec<Rule>> {
    Ok(vec![
        Rule {
            id: "cookie-httponly-false",
            title: "httpOnly: false",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)httpOnly\s*:\s*false")?,
            why: "Explicitly disabling HttpOnly exposes the cookie to script.",
            cwe: "CWE-1004",
        },
        Rule {
            id: "cors-star",
            title: "CORS allow-origin *",
            severity: Severity::Medium,
            regex: Regex::new(r#"(?i)Access-Control-Allow-Origin['"\s:,=]+['"]?\*"#)?,
            why: "Wildcard CORS lets any site read authenticated responses.",
            cwe: "CWE-942",
        },
        Rule {
            id: "cors-star",
            title: "CORS allow-origin *",
            severity: Severity::Medium,
            regex: Regex::new(r#"(?i)origin\s*:\s*['"]?\*"#)?,
            why: "Wildcard CORS lets any site read authenticated responses.",
            cwe: "CWE-942",
        },
        Rule {
            id: "cors-star",
            title: "CORS allow-origin *",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)\bcors\(\s*\)")?,
            why: "Default cors() allows any origin.",
            cwe: "CWE-942",
        },
        Rule {
            id: "csp-unsafe-inline",
            title: "CSP unsafe-inline",
            severity: Severity::Low,
            regex: Regex::new(r"(?i)Content-Security-Policy[^;\n]*unsafe-inline")?,
            why: "unsafe-inline disables XSS protection CSP is meant to provide.",
            cwe: "CWE-1021",
        },
    ])
}

fn hit(rule: &Rule, rel: &str, line: usize, snippet: &str) -> NewFinding {
    let preview: String = snippet.trim().chars().take(160).collect();
    NewFinding {
        fingerprint: fingerprint(rule.id, rel, line),
        severity: rule.severity,
        confidence: "medium".into(),
        category: "harden".into(),
        rule_id: rule.id.into(),
        title: rule.title.into(),
        description: format!("{} (`{}`:{}). {}", rule.why, rel, line, rule.title),
        path: Some(rel.to_string()),
        line_start: Some(line as i64),
        line_end: Some(line as i64),
        cwe: vec![rule.cwe.into()],
        cve: vec![],
        evidence: serde_json::json!({
            "preview": preview,
            "engine": "achilles-harden-v0"
        }),
    }
}

fn fingerprint(rule_id: &str, path: &str, line: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"|");
    hasher.update(path.as_bytes());
    hasher.update(b"|");
    hasher.update(line.to_string().as_bytes());
    let digest = hasher.finalize();
    format!(
        "{rule_id}:{}",
        digest
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::walk::WalkedFile;

    #[test]
    fn flags_cors_star_and_httponly_false() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("server.js");
        std::fs::write(
            &file,
            "app.use(cors());\nconst cookie = { httpOnly: false };\n",
        )
        .unwrap();
        let files = [WalkedFile {
            abs: file,
            rel: "server.js".into(),
            len: 64,
        }];
        let hits = scan_harden_on(&files, None, None).unwrap();
        let ids: Vec<_> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(ids.contains(&"cors-star"), "{ids:?}");
        assert!(ids.contains(&"cookie-httponly-false"), "{ids:?}");
    }
}

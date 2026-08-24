//! Built-in secret regex scanner. Does not redistribute third-party rule packs.

use std::fs;
use std::path::Path;

use ignore::WalkBuilder;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::types::{NewFinding, Severity};

const MAX_FILES: usize = 8_000;
const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_HITS: usize = 200;

struct SecretRule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    regex: Regex,
}

pub fn scan_secrets(root: &Path) -> anyhow::Result<Vec<NewFinding>> {
    let rules = rules()?;
    let mut findings = Vec::new();
    let mut files = 0usize;

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .build();

    for entry in walker {
        if findings.len() >= MAX_HITS {
            break;
        }
        let Ok(entry) = entry else { continue };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        files += 1;
        if files > MAX_FILES {
            break;
        }
        let path = entry.path();
        if should_skip(path) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        for (line_idx, line) in text.lines().enumerate() {
            if findings.len() >= MAX_HITS {
                break;
            }
            for rule in &rules {
                if let Some(mat) = rule.regex.find(line) {
                    let preview = redact(mat.as_str());
                    let fingerprint = fingerprint(rule.id, &rel_str, line_idx + 1, mat.as_str());
                    findings.push(NewFinding {
                        fingerprint,
                        severity: rule.severity,
                        confidence: "high".into(),
                        category: "secrets".into(),
                        rule_id: rule.id.into(),
                        title: rule.title.into(),
                        description: format!(
                            "Possible {} in `{}` line {}. Rotate the credential and remove it from git history.",
                            rule.title, rel_str, line_idx + 1
                        ),
                        path: Some(rel_str.clone()),
                        line_start: Some((line_idx + 1) as i64),
                        line_end: Some((line_idx + 1) as i64),
                        cwe: vec!["CWE-798".into()],
                        cve: vec![],
                        evidence: serde_json::json!({
                            "preview": preview,
                            "engine": "achilles-secrets-v0"
                        }),
                    });
                    break;
                }
            }
        }
    }

    Ok(findings)
}

fn rules() -> anyhow::Result<Vec<SecretRule>> {
    Ok(vec![
        SecretRule {
            id: "aws-access-key",
            title: "AWS access key ID",
            severity: Severity::High,
            regex: Regex::new(r"AKIA[0-9A-Z]{16}")?,
        },
        SecretRule {
            id: "github-token",
            title: "GitHub token",
            severity: Severity::High,
            regex: Regex::new(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")?,
        },
        SecretRule {
            id: "github-pat",
            title: "GitHub fine-grained PAT",
            severity: Severity::High,
            regex: Regex::new(r"github_pat_[A-Za-z0-9_]{20,}")?,
        },
        SecretRule {
            id: "slack-token",
            title: "Slack token",
            severity: Severity::High,
            regex: Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}")?,
        },
        SecretRule {
            id: "google-api-key",
            title: "Google API key",
            severity: Severity::Medium,
            regex: Regex::new(r"AIza[0-9A-Za-z\-_]{35}")?,
        },
        SecretRule {
            id: "stripe-live-key",
            title: "Stripe live secret key",
            severity: Severity::Critical,
            regex: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}")?,
        },
        SecretRule {
            id: "private-key-block",
            title: "Private key material",
            severity: Severity::Critical,
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")?,
        },
    ])
}

fn should_skip(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "cargo.lock"
            | "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "go.sum"
            | "poetry.lock"
    ) || path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("node_modules" | "target" | ".git" | "dist" | "build" | ".next" | "vendor")
        )
    })
}

fn redact(value: &str) -> String {
    if value.len() <= 8 {
        return "********".into();
    }
    format!(
        "{}…{}",
        &value[..4],
        &value[value.len().saturating_sub(4)..]
    )
}

pub fn fingerprint(rule_id: &str, path: &str, line: usize, sink: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"|");
    hasher.update(path.as_bytes());
    hasher.update(b"|");
    hasher.update(line.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(sink.as_bytes());
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
    use std::io::Write;

    #[test]
    fn finds_aws_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = fs::File::create(dir.path().join("secrets.env")).unwrap();
        writeln!(file, "AWS_KEY=AKIAIOSFODNN7EXAMPLE").unwrap();
        let hits = scan_secrets(dir.path()).unwrap();
        assert!(hits.iter().any(|f| f.rule_id == "aws-access-key"));
    }
}

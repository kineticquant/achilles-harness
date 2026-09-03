//! Built-in secret regex scanner. Does not redistribute third-party rule packs.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::engines::walk::{self, WalkOpts, WalkedFile};
use crate::types::{NewFinding, Severity};

const MAX_HITS: usize = 200;

struct SecretRule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    regex: Regex,
}

pub fn scan_secrets(root: &Path) -> anyhow::Result<Vec<NewFinding>> {
    scan_secrets_filtered(root, None, WalkOpts::default())
}

pub fn scan_secrets_filtered(
    root: &Path,
    only_rel: Option<&HashSet<String>>,
    opts: WalkOpts,
) -> anyhow::Result<Vec<NewFinding>> {
    let files = walk::walk_files(root, opts, |path, rel| {
        if let Some(only) = only_rel {
            if !only.contains(rel) {
                return false;
            }
        }
        !should_skip(path)
    });
    scan_secrets_on(&files, only_rel, None)
}

/// Match one line. Used by the local-diff engine on added hunks.
pub fn hits_on_line(rel: &str, line_no: usize, line: &str) -> Vec<NewFinding> {
    if should_skip(Path::new(rel)) {
        return Vec::new();
    }
    let Ok(rules) = rules() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rule in &rules {
        if let Some(mat) = rule.regex.find(line) {
            out.push(secret_hit(rule, rel, line_no, mat.as_str()));
            break;
        }
    }
    out
}

/// Secrets on an already-walked tree. `only_rel` still filters (diff mode).
pub fn scan_secrets_on(
    files: &[WalkedFile],
    only_rel: Option<&HashSet<String>>,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<Vec<NewFinding>> {
    let rules = rules()?;
    let mut findings = Vec::new();

    for file in files {
        if crate::engines::abort::flagged(cancel) {
            break;
        }
        if let Some(only) = only_rel {
            if !only.contains(&file.rel) {
                continue;
            }
        }
        if should_skip(&file.abs) {
            continue;
        }
        if findings.len() >= MAX_HITS {
            break;
        }
        let Ok(text) = fs::read_to_string(&file.abs) else {
            continue;
        };

        for (line_idx, line) in text.lines().enumerate() {
            if findings.len() >= MAX_HITS {
                break;
            }
            for rule in &rules {
                if let Some(mat) = rule.regex.find(line) {
                    findings.push(secret_hit(rule, &file.rel, line_idx + 1, mat.as_str()));
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
            id: "github-https-token",
            title: "GitHub credential in an HTTPS URL",
            severity: Severity::Critical,
            regex: Regex::new(
                r"https://(?:x-access-token:)?(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]+@github\.com",
            )?,
        },
        SecretRule {
            id: "github-npm-token",
            title: "GitHub Packages npm token",
            severity: Severity::High,
            regex: Regex::new(r"//npm\.pkg\.github\.com/:_authToken=\S+")?,
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
            id: "github-env-token",
            title: "GitHub token assigned in env",
            severity: Severity::High,
            regex: Regex::new(
                r#"(?i)\b(GITHUB_TOKEN|GH_TOKEN|GH_PAT|GITHUB_PAT|GHCR_TOKEN)\s*[:=]\s*['"]?(?:ghp|gho|ghu|ghs|ghr|github_pat)_"#,
            )?,
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
        SecretRule {
            id: "npm-access-token",
            title: "npm access token",
            severity: Severity::High,
            regex: Regex::new(r"npm_[A-Za-z0-9]{36}")?,
        },
        SecretRule {
            id: "huggingface-token",
            title: "Hugging Face token",
            severity: Severity::High,
            regex: Regex::new(r"hf_[A-Za-z0-9]{20,}")?,
        },
        SecretRule {
            id: "gitlab-pat",
            title: "GitLab personal access token",
            severity: Severity::High,
            regex: Regex::new(r"glpat-[A-Za-z0-9_\-]{20,}")?,
        },
        SecretRule {
            id: "slack-webhook",
            title: "Slack incoming webhook",
            severity: Severity::High,
            regex: Regex::new(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")?,
        },
        SecretRule {
            id: "sendgrid-api-key",
            title: "SendGrid API key",
            severity: Severity::High,
            regex: Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")?,
        },
        SecretRule {
            id: "discord-webhook",
            title: "Discord webhook",
            severity: Severity::High,
            regex: Regex::new(
                r"https://(?:discord|discordapp)\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
            )?,
        },
        SecretRule {
            id: "telegram-bot-token",
            title: "Telegram bot token",
            severity: Severity::High,
            regex: Regex::new(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}")?,
        },
        SecretRule {
            id: "anthropic-key",
            title: "Anthropic API key",
            severity: Severity::High,
            regex: Regex::new(r"sk-ant-api03-[A-Za-z0-9_-]{20,}")?,
        },
        SecretRule {
            id: "pypi-token",
            title: "PyPI API token",
            severity: Severity::High,
            regex: Regex::new(r"pypi-[A-Za-z0-9_\-]{20,}")?,
        },
        SecretRule {
            id: "postgres-url",
            title: "PostgreSQL connection string with password",
            severity: Severity::High,
            regex: Regex::new(r"postgres(?:ql)?://[^:\s]+:[^@\s]+@")?,
        },
        SecretRule {
            id: "mongodb-url",
            title: "MongoDB connection string with password",
            severity: Severity::High,
            regex: Regex::new(r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@")?,
        },
        SecretRule {
            id: "digitalocean-pat",
            title: "DigitalOcean personal access token",
            severity: Severity::High,
            regex: Regex::new(r"dop_v1_[a-f0-9]{64}")?,
        },
        SecretRule {
            id: "railway-token",
            title: "Railway token",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)\bRAILWAY_TOKEN\s*[:=]\s*['"]?[A-Za-z0-9._-]{20,}"#)?,
        },
        SecretRule {
            id: "vercel-token",
            title: "Vercel token",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)\bVERCEL_(?:OIDC_)?TOKEN\s*[:=]\s*['"]?[A-Za-z0-9._-]{20,}"#)?,
        },
    ])
}

fn secret_hit(rule: &SecretRule, rel: &str, line: usize, sink: &str) -> NewFinding {
    let preview = redact(sink);
    NewFinding {
        fingerprint: fingerprint(rule.id, rel, line, sink),
        severity: rule.severity,
        confidence: "high".into(),
        category: "secrets".into(),
        rule_id: rule.id.into(),
        title: rule.title.into(),
        description: format!(
            "Possible {} in `{}` line {}. Rotate the credential and remove it from git history.",
            rule.title, rel, line
        ),
        path: Some(rel.to_string()),
        line_start: Some(line as i64),
        line_end: Some(line as i64),
        cwe: vec!["CWE-798".into()],
        cve: vec![],
        evidence: serde_json::json!({
            "preview": preview,
            "engine": "achilles-secrets-v0"
        }),
    }
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
    )
}

fn redact(value: &str) -> String {
    if value.chars().count() <= 8 {
        return "********".into();
    }
    let head: String = value.chars().take(4).collect();
    let tail: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
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

    #[test]
    fn finds_npm_token() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = fs::File::create(dir.path().join(".npmrc")).unwrap();
        writeln!(
            file,
            "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789"
        )
        .unwrap();
        let hits = scan_secrets(dir.path()).unwrap();
        assert!(hits.iter().any(|f| f.rule_id == "npm-access-token"));
    }

    #[test]
    fn secrets_fixture_hits_common_token_shapes() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/achilles-fixtures/secrets");
        let hits = scan_secrets(&root).unwrap();
        let ids: Vec<_> = hits.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"aws-access-key"), "{ids:?}");
        assert!(ids.contains(&"github-token"), "{ids:?}");
        assert!(ids.contains(&"npm-access-token"), "{ids:?}");
        assert!(ids.contains(&"discord-webhook"), "{ids:?}");
        assert!(ids.contains(&"telegram-bot-token"), "{ids:?}");
        assert!(ids.contains(&"postgres-url"), "{ids:?}");
        assert!(ids.contains(&"digitalocean-pat"), "{ids:?}");
        assert!(ids.contains(&"github-https-token"), "{ids:?}");
        assert!(ids.contains(&"github-npm-token"), "{ids:?}");
        assert!(ids.contains(&"railway-token"), "{ids:?}");
        assert!(ids.contains(&"vercel-token"), "{ids:?}");
    }
}

//! Visibility-based deploy/CI checks. Only files the fingerprint saw.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::engines::fingerprint::Fingerprint;
use crate::types::{NewFinding, Severity};

const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_FINDINGS: usize = 200;

struct Rule {
    surfaces: &'static [&'static str],
    id: &'static str,
    title: &'static str,
    severity: Severity,
    regex: Regex,
    why: &'static str,
}

pub fn scan_surfaces(root: &Path, fingerprint: &Fingerprint) -> anyhow::Result<Vec<NewFinding>> {
    scan_surfaces_filtered(root, fingerprint, None, None)
}

pub fn scan_surfaces_filtered(
    root: &Path,
    fingerprint: &Fingerprint,
    only_rel: Option<&HashSet<String>>,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<Vec<NewFinding>> {
    if fingerprint.surfaces.is_empty() {
        return Ok(Vec::new());
    }
    let rules = rules()?;
    let mut findings = Vec::new();
    let mut by_path: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for surface in &fingerprint.surfaces {
        for rel in &surface.paths {
            if let Some(only) = only_rel {
                if !only.contains(rel) {
                    continue;
                }
            }
            let ids = by_path.entry(rel.clone()).or_default();
            if !ids.iter().any(|s| s == &surface.id) {
                ids.push(surface.id.clone());
            }
        }
    }
    let mut saw_dockerignore = false;
    let mut dockerfile_paths: Vec<String> = Vec::new();
    for (rel, surface_ids) in &by_path {
        if crate::engines::abort::flagged(cancel) {
            break;
        }
        if findings.len() >= MAX_FINDINGS {
            break;
        }
        let path = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
        if name == ".dockerignore" {
            saw_dockerignore = true;
        }
        if surface_ids.iter().any(|s| s == "docker") && is_dockerfile_name(rel) {
            dockerfile_paths.push(rel.clone());
        }
        for sid in surface_ids {
            findings.extend(file_level_findings(sid, rel, &text));
        }
        for (idx, line) in text.lines().enumerate() {
            if findings.len() >= MAX_FINDINGS {
                break;
            }
            for rule in &rules {
                if !rule
                    .surfaces
                    .iter()
                    .any(|s| surface_ids.iter().any(|id| id == s))
                {
                    continue;
                }
                if rule.regex.is_match(line) {
                    findings.push(finding(rule, rel, idx + 1, line));
                }
            }
        }
    }
    if !saw_dockerignore {
        for rel in dockerfile_paths {
            if findings.len() >= MAX_FINDINGS {
                break;
            }
            findings.push(file_finding(
                "docker-missing-dockerignore",
                "Dockerfile without .dockerignore",
                Severity::Low,
                &rel,
                "No `.dockerignore` in this tree. Build context often includes `.git` and secrets.",
            ));
        }
    }
    Ok(findings)
}

fn file_level_findings(surface_id: &str, rel: &str, text: &str) -> Vec<NewFinding> {
    let mut out = Vec::new();
    if surface_id == "dotenv" {
        if is_env_template_name(rel) {
            out.push(file_finding(
                "dotenv-template",
                "Env template committed (not a live secret file)",
                Severity::Info,
                rel,
                "Filename looks like a template (`.env.example`, `.env.sample`, `.env.template`, `.env.erb`, and similar), not a filled-in `.env`. Fast scans do not read the values. Dismiss if this is only placeholders or a deploy template.",
            ));
        } else {
            out.push(file_finding(
                "dotenv-committed",
                "Dotenv file is committed",
                Severity::High,
                rel,
                "A `.env*` file is in the tree. Secrets in dotenv files are often committed by accident; keep them out of git and rotate anything that was.",
            ));
        }
    }
    if surface_id == "docker" && is_dockerfile_name(rel) && has_from(text) && !has_user(text) {
        out.push(file_finding(
            "docker-missing-user",
            "Dockerfile never sets USER",
            Severity::Medium,
            rel,
            "No USER instruction. The default user is often root for the whole image lifecycle.",
        ));
    }
    if surface_id == "firebase"
        && (rel.ends_with(".rules") || rel.ends_with("firebase.json"))
        && text.contains("allow read, write")
    {
        out.push(file_finding(
            "firebase-open-rules",
            "Firebase rules allow read, write",
            Severity::High,
            rel,
            "These rules grant read and write to matching paths. Confirm they are not production-open.",
        ));
    }
    out
}

fn is_dockerfile_name(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    name == "dockerfile" || name == "containerfile" || name.starts_with("dockerfile.")
}

fn is_env_template_name(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    let Some(rest) = name.strip_prefix(".env") else {
        return false;
    };
    rest.split(|c: char| c == '.' || c == '-' || c == '_')
        .any(|part| {
            matches!(
                part,
                "example"
                    | "sample"
                    | "template"
                    | "tmpl"
                    | "erb"
                    | "dist"
                    | "j2"
                    | "jinja"
                    | "jinja2"
                    | "mustache"
            )
        })
}

fn has_from(text: &str) -> bool {
    text.lines()
        .any(|l| l.trim_start().to_ascii_lowercase().starts_with("from "))
}

fn has_user(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start().to_ascii_lowercase();
        t.starts_with("user ")
    })
}

fn file_finding(id: &str, title: &str, severity: Severity, rel: &str, why: &str) -> NewFinding {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(rel.as_bytes());
    let digest = hasher.finalize();
    let fingerprint = format!(
        "surface:{}",
        digest
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    NewFinding {
        fingerprint,
        severity,
        confidence: "medium".into(),
        category: "surface".into(),
        rule_id: id.into(),
        title: title.into(),
        description: format!("{why} File: `{rel}`."),
        path: Some(rel.to_string()),
        line_start: None,
        line_end: None,
        cwe: vec![],
        cve: vec![],
        evidence: serde_json::json!({
            "engine": "achilles-surfaces-v0",
            "kind": "file"
        }),
    }
}

fn finding(rule: &Rule, rel: &str, line: usize, sample: &str) -> NewFinding {
    let mut hasher = Sha256::new();
    hasher.update(rule.id.as_bytes());
    hasher.update(rel.as_bytes());
    hasher.update(line.to_string().as_bytes());
    hasher.update(sample.trim().as_bytes());
    let digest = hasher.finalize();
    let fingerprint = format!(
        "surface:{}",
        digest
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let snippet: String = sample.trim().chars().take(160).collect();
    NewFinding {
        fingerprint,
        severity: rule.severity,
        confidence: "medium".into(),
        category: "surface".into(),
        rule_id: rule.id.into(),
        title: rule.title.into(),
        description: format!("{} Visible in `{}` line {}.", rule.why, rel, line),
        path: Some(rel.to_string()),
        line_start: Some(line as i64),
        line_end: Some(line as i64),
        cwe: vec![],
        cve: vec![],
        evidence: serde_json::json!({
            "engine": "achilles-surfaces-v0",
            "snippet": snippet
        }),
    }
}

fn rules() -> anyhow::Result<Vec<Rule>> {
    Ok(vec![
        Rule {
            surfaces: &[
                "github-actions",
                "gitlab-ci",
                "circleci",
                "azure-pipelines",
                "bitbucket-pipelines",
                "travis-ci",
            ],
            id: "ci-pull-request-target",
            title: "pull_request_target workflow",
            severity: Severity::High,
            regex: Regex::new(r"(?i)pull_request_target")?,
            why: "pull_request_target runs in the base repo context and is a common GitHub Actions privilege path if it checks out untrusted PRs.",
        },
        Rule {
            surfaces: &[
                "github-actions",
                "gitlab-ci",
                "circleci",
                "jenkins",
                "bitbucket-pipelines",
                "travis-ci",
                "aws-codebuild",
                "google-cloudbuild",
                "azure-pipelines",
                "buildkite",
            ],
            id: "ci-pipe-to-shell",
            title: "Remote script piped to a shell in CI",
            severity: Severity::High,
            regex: Regex::new(r"(?i)(curl|wget)[ \t]+[^|]*\|[ \t]*(sudo[ \t]+)?(bash|sh)\b")?,
            why: "CI installs software by piping the network into a shell; supply-chain and integrity checks are not visible here.",
        },
        Rule {
            surfaces: &["github-actions"],
            id: "ci-echo-secrets",
            title: "Secret value echoed in a workflow",
            severity: Severity::High,
            regex: Regex::new(r"(?i)echo[ \t]+.*\$\{\{[ \t]*secrets\.")?,
            why: "Workflow prints a GitHub secret; logs become a credential leak.",
        },
        Rule {
            surfaces: &["github-actions"],
            id: "gha-persist-credentials",
            title: "actions/checkout persist-credentials: true",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)persist-credentials:[ \t]*true")?,
            why: "The GITHUB_TOKEN remains in the workspace after checkout, which widens the blast radius if a later step is compromised.",
        },
        Rule {
            surfaces: &["cloudflare-workers"],
            id: "cf-plaintext-secret-var",
            title: "Likely secret in wrangler vars",
            severity: Severity::High,
            regex: Regex::new(
                r#"(?i)(api[_-]?token|secret[_-]?key|private[_-]?key|aws_secret|password)[ \t]*=[ \t]*["'][^"']{8,}"#,
            )?,
            why: "Wrangler [vars] are bundled into the worker. Secrets belong in `wrangler secret`, not committed plaintext.",
        },
        Rule {
            surfaces: &["terraform", "aws-cdk", "aws-sam", "serverless", "pulumi", "sst", "aws-terraform", "cloudformation"],
            id: "iac-open-cidr",
            title: "Ingress open to the world (0.0.0.0/0)",
            severity: Severity::High,
            regex: Regex::new(r#"0\.0\.0\.0/0"#)?,
            why: "This file advertises a 0.0.0.0/0 CIDR. Confirm it is not SSH/RDP/admin on a public security group.",
        },
        Rule {
            surfaces: &["terraform"],
            id: "tf-s3-public-acl",
            title: "S3 ACL public-read",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)acl[ \t]*=[ \t]*"public-read""#)?,
            why: "Terraform sets an S3 ACL to public-read in this file.",
        },
        Rule {
            surfaces: &["terraform"],
            id: "tf-skip-final-snapshot",
            title: "RDS skip_final_snapshot enabled",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)skip_final_snapshot[ \t]*=[ \t]*true")?,
            why: "Destroying this RDS instance will not take a final snapshot.",
        },
        Rule {
            surfaces: &["terraform", "aws-sam", "serverless"],
            id: "iac-admin-star",
            title: "IAM Allow Action * on Resource *",
            severity: Severity::High,
            regex: Regex::new(
                r#"(?i)("Action"|Action)[ \t]*[=:][ \t]*"\*".*("Resource"|Resource)[ \t]*[=:][ \t]*"\*""#,
            )?,
            why: "Broad IAM * / * is visible in this IaC file (same-line or nearby). Confirm least privilege.",
        },
        Rule {
            surfaces: &["docker"],
            id: "docker-latest-tag",
            title: "Image tag :latest",
            severity: Severity::Low,
            regex: Regex::new(r"(?i)^FROM[ \t]+[^ \t]+:latest\b")?,
            why: "Dockerfile pins :latest, so rebuilds are not reproducible and CVEs in the base image drift.",
        },
        Rule {
            surfaces: &["docker"],
            id: "docker-user-root",
            title: "Container runs as USER root",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)^USER[ \t]+root\b")?,
            why: "Dockerfile explicitly sets USER root.",
        },
        Rule {
            surfaces: &["kubernetes", "helm"],
            id: "k8s-privileged",
            title: "privileged: true",
            severity: Severity::High,
            regex: Regex::new(r"(?i)privileged:[ \t]*true")?,
            why: "This manifest requests a privileged container.",
        },
        Rule {
            surfaces: &["kubernetes", "helm"],
            id: "k8s-host-network",
            title: "hostNetwork: true",
            severity: Severity::High,
            regex: Regex::new(r"(?i)hostNetwork:[ \t]*true")?,
            why: "This manifest shares the host network namespace.",
        },
        Rule {
            surfaces: &["kubernetes", "helm"],
            id: "k8s-host-pid",
            title: "hostPID: true",
            severity: Severity::High,
            regex: Regex::new(r"(?i)hostPID:[ \t]*true")?,
            why: "This manifest shares the host PID namespace.",
        },
        Rule {
            surfaces: &["kubernetes", "helm"],
            id: "k8s-allow-priv-esc",
            title: "allowPrivilegeEscalation: true",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)allowPrivilegeEscalation:[ \t]*true")?,
            why: "This container may gain more privileges than its parent process.",
        },
        Rule {
            surfaces: &["kubernetes", "helm"],
            id: "k8s-host-path",
            title: "hostPath volume",
            severity: Severity::High,
            regex: Regex::new(r"(?i)hostPath:")?,
            why: "A hostPath mount shares the node filesystem with the pod.",
        },
        Rule {
            surfaces: &["kubernetes", "helm"],
            id: "k8s-host-ipc",
            title: "hostIPC: true",
            severity: Severity::High,
            regex: Regex::new(r"(?i)hostIPC:[ \t]*true")?,
            why: "This manifest shares the host IPC namespace.",
        },
        Rule {
            surfaces: &["kubernetes", "helm"],
            id: "k8s-run-as-root",
            title: "runAsUser: 0",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)runAsUser:[ \t]*0\b")?,
            why: "The container is configured to run as UID 0.",
        },
        Rule {
            surfaces: &["docker"],
            id: "compose-privileged",
            title: "Compose privileged: true",
            severity: Severity::High,
            regex: Regex::new(r"(?i)privileged:[ \t]*true")?,
            why: "Compose grants the container almost all host capabilities.",
        },
        Rule {
            surfaces: &["docker"],
            id: "compose-host-network",
            title: "Compose network_mode: host",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)network_mode:[ \t]*['"]?host['"]?"#)?,
            why: "The service shares the host network stack.",
        },
        Rule {
            surfaces: &["docker"],
            id: "docker-add-remote",
            title: "ADD from a remote URL",
            severity: Severity::Medium,
            regex: Regex::new(r"(?i)^ADD[ \t]+https?://")?,
            why: "ADD from HTTP(S) pulls unpinned remote content into the image.",
        },
        Rule {
            surfaces: &["github-actions"],
            id: "gha-write-all",
            title: "permissions: write-all",
            severity: Severity::High,
            regex: Regex::new(r"(?i)permissions:[ \t]*write-all")?,
            why: "The workflow token can write to every GitHub permission scope.",
        },
        Rule {
            surfaces: &["terraform", "aws-terraform"],
            id: "tf-publicly-accessible",
            title: "publicly_accessible = true",
            severity: Severity::High,
            regex: Regex::new(r"(?i)publicly_accessible[ \t]*=[ \t]*true")?,
            why: "This data store is marked publicly accessible from the internet.",
        },
        Rule {
            surfaces: &["terraform", "aws-cdk", "aws-sam", "serverless", "cloudformation"],
            id: "iac-cors-star",
            title: "CORS allow origin *",
            severity: Severity::Medium,
            regex: Regex::new(r"(?is)(allowed_origins|allow_origin|Allow-Origin).{0,80}\*")?,
            why: "Cross-origin access is opened to any origin in this file.",
        },
        Rule {
            surfaces: &["vercel", "netlify"],
            id: "paas-cors-star",
            title: "PaaS CORS *",
            severity: Severity::Medium,
            regex: Regex::new(r"(?is)Access-Control-Allow-Origin.{0,80}\*")?,
            why: "This PaaS config advertises Access-Control-Allow-Origin *.",
        },
        Rule {
            surfaces: &["vercel"],
            id: "vercel-plaintext-env",
            title: "Plaintext secret-like env in vercel.json",
            severity: Severity::High,
            regex: Regex::new(
                r#"(?i)"(secret|token|password|api[_-]?key|database_url|private[_-]?key)"\s*:\s*"[^"$]{8,}"#,
            )?,
            why: "Vercel project env is committed in-repo. Use Vercel project env / dashboard secrets, not git.",
        },
        Rule {
            surfaces: &["railway"],
            id: "railway-plaintext-var",
            title: "Likely secret in Railway variables",
            severity: Severity::High,
            regex: Regex::new(
                r#"(?i)(api[_-]?token|secret|password|railway_token|database_url|private[_-]?key)[ \t]*=[ \t]*["'][^"']{8,}"#,
            )?,
            why: "Railway variables in railway.toml/json are in git. Put secrets in the Railway dashboard.",
        },
        Rule {
            surfaces: &["railway"],
            id: "railway-json-plaintext",
            title: "Plaintext secret-like env in railway.json",
            severity: Severity::High,
            regex: Regex::new(
                r#"(?i)"(secret|token|password|api[_-]?key|database_url|railway_token)"\s*:\s*"[^"$]{8,}"#,
            )?,
            why: "Railway JSON env is committed. Use service variables in Railway, not the repo.",
        },
        Rule {
            surfaces: &["ansible"],
            id: "ansible-pipe-shell",
            title: "Ansible pipes a remote script to a shell",
            severity: Severity::High,
            regex: Regex::new(r"(?i)(curl|wget)[ \t]+[^|]*\|[ \t]*(sudo[ \t]+)?(bash|sh)\b")?,
            why: "Playbook installs by piping the network into a shell.",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::fingerprint::fingerprint_repo;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn flags_open_cidr_in_terraform() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("sg.tf"),
            r#"
resource "aws_security_group_rule" "x" {
  cidr_blocks = ["0.0.0.0/0"]
}
"#,
        )
        .unwrap();
        let fp = fingerprint_repo(root);
        let findings = scan_surfaces(root, &fp).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "iac-open-cidr"));
    }

    #[test]
    fn flags_dockerfile_without_user() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(
            root.join("Dockerfile"),
            "FROM debian:bookworm\nRUN apt-get update\n",
        )
        .unwrap();
        let fp = fingerprint_repo(root);
        let findings = scan_surfaces(root, &fp).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "docker-missing-user"));
    }

    #[test]
    fn flags_committed_dotenv() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join(".env"), "TOKEN=not-a-real-secret\n").unwrap();
        let fp = fingerprint_repo(root);
        let findings = scan_surfaces(root, &fp).unwrap();
        let hit = findings
            .iter()
            .find(|f| f.rule_id == "dotenv-committed")
            .expect("dotenv-committed");
        assert_eq!(hit.severity, Severity::High);
    }

    #[test]
    fn env_templates_are_informational() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join(".env.erb"), "SECRET=<%= op.read %>\n").unwrap();
        fs::write(root.join(".env.example"), "TOKEN=\n").unwrap();
        fs::write(root.join(".env.template"), "KEY=\n").unwrap();
        fs::write(root.join(".env.production"), "LIVE=1\n").unwrap();
        let fp = fingerprint_repo(root);
        let findings = scan_surfaces(root, &fp).unwrap();
        let templates: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "dotenv-template")
            .collect();
        assert_eq!(templates.len(), 3, "{findings:?}");
        assert!(templates.iter().all(|f| f.severity == Severity::Info));
        let live = findings
            .iter()
            .find(|f| f.rule_id == "dotenv-committed")
            .expect("dotenv-committed");
        assert_eq!(live.path.as_deref(), Some(".env.production"));
        assert_eq!(live.severity, Severity::High);
    }

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/achilles-fixtures")
    }

    #[test]
    fn aws_fixture_hits_iac_and_docker_rules() {
        let root = fixtures_dir().join("aws-terraform");
        let fp = fingerprint_repo(&root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"terraform"), "{ids:?}");
        assert!(ids.contains(&"docker"), "{ids:?}");
        let findings = scan_surfaces(&root, &fp).unwrap();
        let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"iac-open-cidr"), "{rules:?}");
        assert!(rules.contains(&"tf-s3-public-acl"), "{rules:?}");
        assert!(rules.contains(&"tf-publicly-accessible"), "{rules:?}");
        assert!(rules.contains(&"tf-skip-final-snapshot"), "{rules:?}");
        assert!(rules.contains(&"docker-add-remote"), "{rules:?}");
        assert!(rules.contains(&"docker-missing-user"), "{rules:?}");
    }

    #[test]
    fn kubernetes_fixture_hits_privilege_rules() {
        let root = fixtures_dir().join("kubernetes");
        let fp = fingerprint_repo(&root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"kubernetes"), "{ids:?}");
        assert!(ids.contains(&"helm"), "{ids:?}");
        let findings = scan_surfaces(&root, &fp).unwrap();
        let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"k8s-privileged"), "{rules:?}");
        assert!(rules.contains(&"k8s-host-network"), "{rules:?}");
        assert!(rules.contains(&"k8s-host-path"), "{rules:?}");
        assert!(rules.contains(&"k8s-run-as-root"), "{rules:?}");
    }

    #[test]
    fn github_actions_fixture_hits_workflow_rules() {
        let root = fixtures_dir().join("github-actions");
        let fp = fingerprint_repo(&root);
        let findings = scan_surfaces(&root, &fp).unwrap();
        let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"ci-pull-request-target"), "{rules:?}");
        assert!(rules.contains(&"ci-pipe-to-shell"), "{rules:?}");
        assert!(rules.contains(&"gha-write-all"), "{rules:?}");
        assert!(rules.contains(&"gha-persist-credentials"), "{rules:?}");
        assert!(rules.contains(&"ci-echo-secrets"), "{rules:?}");
    }

    #[test]
    fn compose_paas_fixture_hits_compose_firebase_cors() {
        let root = fixtures_dir().join("compose-paas");
        let fp = fingerprint_repo(&root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"docker"), "{ids:?}");
        assert!(ids.contains(&"vercel"), "{ids:?}");
        assert!(ids.contains(&"firebase"), "{ids:?}");
        assert!(ids.contains(&"fly-io"), "{ids:?}");
        let findings = scan_surfaces(&root, &fp).unwrap();
        let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"compose-privileged"), "{rules:?}");
        assert!(rules.contains(&"compose-host-network"), "{rules:?}");
        assert!(rules.contains(&"firebase-open-rules"), "{rules:?}");
        assert!(rules.contains(&"paas-cors-star"), "{rules:?}");
    }

    #[test]
    fn ansible_fixture_hits_pipe_shell() {
        let root = fixtures_dir().join("ansible");
        let fp = fingerprint_repo(&root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"ansible"), "{ids:?}");
        let findings = scan_surfaces(&root, &fp).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "ansible-pipe-shell"));
    }

    #[test]
    fn vercel_fixture_hits_cors_and_plaintext_env() {
        let root = fixtures_dir().join("vercel");
        let fp = fingerprint_repo(&root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"vercel"), "{ids:?}");
        let findings = scan_surfaces(&root, &fp).unwrap();
        let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"paas-cors-star"), "{rules:?}");
        assert!(rules.contains(&"vercel-plaintext-env"), "{rules:?}");
    }

    #[test]
    fn railway_fixture_hits_plaintext_vars() {
        let root = fixtures_dir().join("railway");
        let fp = fingerprint_repo(&root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"railway"), "{ids:?}");
        let findings = scan_surfaces(&root, &fp).unwrap();
        let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"railway-plaintext-var"), "{rules:?}");
        assert!(rules.contains(&"railway-json-plaintext"), "{rules:?}");
    }
}

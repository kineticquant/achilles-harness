//! Lockfile inventory + OSV query. Proprietary — `LICENSE-ACHILLES`.

use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::types::{NewFinding, Severity};

const MAX_PACKAGES: usize = 40;
const OSV_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Debug, Clone)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source: String,
}

#[derive(Debug)]
pub struct ScaOutcome {
    pub findings: Vec<NewFinding>,
    pub packages_considered: usize,
    pub queried: usize,
    pub skipped_reason: Option<String>,
}

pub async fn scan_sca(root: &Path) -> ScaOutcome {
    let packages = collect_packages(root);
    if packages.is_empty() {
        return ScaOutcome {
            findings: vec![],
            packages_considered: 0,
            queried: 0,
            skipped_reason: Some("no supported lockfiles found".into()),
        };
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("achilles-harness-sca/0.1")
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            return ScaOutcome {
                findings: vec![],
                packages_considered: packages.len(),
                queried: 0,
                skipped_reason: Some(format!("http client: {err}")),
            };
        }
    };

    let mut findings = Vec::new();
    let mut queried = 0usize;
    for pkg in packages.iter().take(MAX_PACKAGES) {
        queried += 1;
        match query_osv(&client, pkg).await {
            Ok(vulns) => {
                for vuln in vulns {
                    findings.push(finding_from_vuln(pkg, &vuln));
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, package = %pkg.name, "OSV query failed");
            }
        }
    }

    ScaOutcome {
        packages_considered: packages.len(),
        queried,
        skipped_reason: None,
        findings,
    }
}

#[derive(Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(default)]
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    score: String,
}

async fn query_osv(client: &reqwest::Client, pkg: &PackageRef) -> anyhow::Result<Vec<OsvVuln>> {
    let body = serde_json::json!({
        "version": pkg.version,
        "package": {
            "name": pkg.name,
            "ecosystem": pkg.ecosystem,
        }
    });
    let resp = client.post(OSV_URL).json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("osv status {}", resp.status());
    }
    let parsed: OsvResponse = resp.json().await?;
    Ok(parsed.vulns)
}

fn finding_from_vuln(pkg: &PackageRef, vuln: &OsvVuln) -> NewFinding {
    let severity = score_to_severity(&vuln.severity);
    let mut hasher = Sha256::new();
    hasher.update(pkg.ecosystem.as_bytes());
    hasher.update(b"|");
    hasher.update(pkg.name.as_bytes());
    hasher.update(b"|");
    hasher.update(pkg.version.as_bytes());
    hasher.update(b"|");
    hasher.update(vuln.id.as_bytes());
    let digest = hasher.finalize();
    let fingerprint = format!(
        "sca:{}",
        digest
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let summary = if vuln.summary.is_empty() {
        format!("{} affects {}@{}", vuln.id, pkg.name, pkg.version)
    } else {
        vuln.summary.clone()
    };
    NewFinding {
        fingerprint,
        severity,
        confidence: "high".into(),
        category: "sca".into(),
        rule_id: vuln.id.clone(),
        title: format!("{} in {}@{}", vuln.id, pkg.name, pkg.version),
        description: format!(
            "{summary} Source manifest: {}. Grounded via OSV (P2 public API).",
            pkg.source
        ),
        path: Some(pkg.source.clone()),
        line_start: None,
        line_end: None,
        cwe: vec![],
        cve: vec![vuln.id.clone()],
        evidence: serde_json::json!({
            "package": pkg.name,
            "version": pkg.version,
            "ecosystem": pkg.ecosystem,
            "advisory": vuln.id,
            "engine": "achilles-sca-osv-v0"
        }),
    }
}

fn score_to_severity(items: &[OsvSeverity]) -> Severity {
    let mut best = 0.0f32;
    for item in items {
        if item.kind.eq_ignore_ascii_case("CVSS_V3") || item.kind.eq_ignore_ascii_case("CVSS_V4") {
            if let Some(num) = item
                .score
                .split('/')
                .next()
                .and_then(|s| s.parse::<f32>().ok())
            {
                best = best.max(num);
            } else if let Ok(num) = item.score.parse::<f32>() {
                best = best.max(num);
            }
        }
    }
    if best >= 9.0 {
        Severity::Critical
    } else if best >= 7.0 {
        Severity::High
    } else if best >= 4.0 {
        Severity::Medium
    } else if best > 0.0 {
        Severity::Low
    } else {
        Severity::Medium
    }
}

pub fn collect_packages(root: &Path) -> Vec<PackageRef> {
    let mut out = Vec::new();
    out.extend(parse_cargo_lock(&root.join("Cargo.lock")));
    out.extend(parse_package_lock(&root.join("package-lock.json")));
    out.extend(parse_go_mod(&root.join("go.mod")));
    out.extend(parse_requirements(&root.join("requirements.txt")));
    out
}

fn parse_cargo_lock(path: &Path) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut in_pkg = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                if n != "achilles-store" {
                    out.push(PackageRef {
                        name: n,
                        version: v,
                        ecosystem: "crates.io".into(),
                        source: "Cargo.lock".into(),
                    });
                }
            }
            in_pkg = true;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = \"") {
            name = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = \"") {
            version = Some(rest.trim_end_matches('"').to_string());
        } else if line.starts_with('[') {
            in_pkg = false;
        }
    }
    if let (Some(n), Some(v)) = (name, version) {
        out.push(PackageRef {
            name: n,
            version: v,
            ecosystem: "crates.io".into(),
            source: "Cargo.lock".into(),
        });
    }
    out
}

fn parse_package_lock(path: &Path) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return vec![];
    };
    let mut out = Vec::new();
    if let Some(packages) = value.get("packages").and_then(|v| v.as_object()) {
        for (key, pkg) in packages {
            if key.is_empty() {
                continue;
            }
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    key.rsplit("/node_modules/")
                        .next()
                        .unwrap_or(key)
                        .trim_start_matches("node_modules/")
                        .to_string()
                });
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            out.push(PackageRef {
                name,
                version: version.to_string(),
                ecosystem: "npm".into(),
                source: "package-lock.json".into(),
            });
        }
    }
    out
}

fn parse_go_mod(path: &Path) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut in_require = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require && trimmed == ")" {
            in_require = false;
            continue;
        }
        let line_to_parse = if in_require {
            trimmed
        } else if let Some(rest) = trimmed.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        let parts: Vec<&str> = line_to_parse.split_whitespace().collect();
        if parts.len() >= 2 && !parts[0].starts_with("//") {
            out.push(PackageRef {
                name: parts[0].to_string(),
                version: parts[1].trim_start_matches('v').to_string(),
                ecosystem: "Go".into(),
                source: "go.mod".into(),
            });
        }
    }
    out
}

fn parse_requirements(path: &Path) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, version)) = line.split_once("==") {
            out.push(PackageRef {
                name: name.trim().to_string(),
                version: version.trim().to_string(),
                ecosystem: "PyPI".into(),
                source: "requirements.txt".into(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_cargo_lock_packages() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = fs::File::create(dir.path().join("Cargo.lock")).unwrap();
        writeln!(file, "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n").unwrap();
        let pkgs = parse_cargo_lock(&dir.path().join("Cargo.lock"));
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].ecosystem, "crates.io");
    }
}

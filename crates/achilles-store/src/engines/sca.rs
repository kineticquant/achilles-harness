//! Lockfile inventory: pinning, local install-script/typosquat hygiene,
//! npm/PyPI packages younger than 7 days, OSV, optional Socket.
//! Apache-2.0.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::engines::abort::{self, Abort};
use crate::public_sources::{self, HTTP_USER_AGENT};
use crate::types::{NewFinding, Severity};

const MAX_PACKAGES: usize = 80;
const MAX_LOCKFILES: usize = 20;

pub use crate::types::PackageRef;

#[derive(Debug)]
pub struct ScaOutcome {
    pub findings: Vec<NewFinding>,
    pub packages_considered: usize,
    pub queried: usize,
    pub skipped_reason: Option<String>,
    pub cancelled: bool,
    pub socket_packages: usize,
    pub socket_skipped: Option<String>,
}

pub async fn scan_sca(root: &Path) -> ScaOutcome {
    scan_sca_with(root, crate::engines::walk::WalkOpts::default()).await
}

pub async fn scan_sca_with(root: &Path, opts: crate::engines::walk::WalkOpts) -> ScaOutcome {
    let files = crate::engines::walk::walk_files(root, opts, |_, _| true);
    scan_sca_on(root, &files).await
}

/// SCA + pinning on an already-walked tree.
pub async fn scan_sca_on(root: &Path, files: &[crate::engines::walk::WalkedFile]) -> ScaOutcome {
    scan_sca_abort(root, files, None).await
}

pub async fn scan_sca_abort(
    root: &Path,
    files: &[crate::engines::walk::WalkedFile],
    abort: Option<&Abort>,
) -> ScaOutcome {
    scan_sca_abort_at(
        root,
        files,
        abort,
        None,
        crate::engines::socket::SocketCreds::from_env(),
        None,
        None,
    )
    .await
}

pub async fn scan_sca_abort_with_socket(
    root: &Path,
    files: &[crate::engines::walk::WalkedFile],
    abort: Option<&Abort>,
    creds: crate::engines::socket::SocketCreds,
) -> ScaOutcome {
    scan_sca_abort_at(root, files, abort, None, creds, None, None).await
}

async fn scan_sca_abort_at(
    root: &Path,
    files: &[crate::engines::walk::WalkedFile],
    abort: Option<&Abort>,
    osv_url: Option<&str>,
    socket: crate::engines::socket::SocketCreds,
    npm_base: Option<&str>,
    pypi_base: Option<&str>,
) -> ScaOutcome {
    let cancel = abort.map(Abort::flag);
    let mut findings = crate::engines::pinning::scan_pinning_on(root, files, cancel);
    findings.extend(crate::engines::hygiene::scan_on(files, cancel));
    if abort.is_some_and(Abort::is_cancelled) {
        return sca_out(findings, 0, 0, Some("cancelled".into()), true, 0, None);
    }
    let packages = collect_packages_from(files);
    if packages.is_empty() {
        let skipped = if findings.is_empty() {
            Some("no supported lockfiles found".into())
        } else {
            None
        };
        return sca_out(findings, 0, 0, skipped, false, 0, None);
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(HTTP_USER_AGENT)
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            return sca_out(
                findings,
                packages.len(),
                0,
                Some(format!("http client: {err}")),
                false,
                0,
                None,
            );
        }
    };

    let url = osv_url
        .map(str::to_string)
        .unwrap_or_else(public_sources::osv_query_url);
    let take: Vec<PackageRef> = packages.iter().take(MAX_PACKAGES).cloned().collect();
    let npm_base = npm_base
        .map(str::to_string)
        .unwrap_or_else(public_sources::npm_registry_url);
    let pypi_base = pypi_base
        .map(str::to_string)
        .unwrap_or_else(public_sources::pypi_json_base_url);
    match crate::engines::fresh::scan_packages_at(
        &client,
        &take,
        abort,
        crate::engines::fresh::FreshOpts {
            now: chrono::Utc::now(),
            npm_base: &npm_base,
            pypi_base: &pypi_base,
        },
    )
    .await
    {
        Ok(hits) => findings.extend(hits),
        Err(err) if abort::is_cancel(&err) => {
            return sca_out(
                findings,
                packages.len(),
                0,
                Some("cancelled".into()),
                true,
                0,
                None,
            );
        }
        Err(err) => {
            tracing::debug!(error = %err, "fresh registry age scan failed");
        }
    }

    let mut queried = 0usize;
    for pkg in take.iter() {
        if abort.is_some_and(Abort::is_cancelled) {
            return sca_out(
                findings,
                packages.len(),
                queried,
                Some("cancelled".into()),
                true,
                0,
                None,
            );
        }
        queried += 1;
        match query_osv(&client, pkg, abort, &url).await {
            Ok(vulns) => {
                for vuln in vulns {
                    findings.push(finding_from_vuln(pkg, &vuln));
                }
            }
            Err(err) if abort::is_cancel(&err) => {
                return sca_out(
                    findings,
                    packages.len(),
                    queried,
                    Some("cancelled".into()),
                    true,
                    0,
                    None,
                );
            }
            Err(err) => {
                tracing::debug!(error = %err, package = %pkg.name, "OSV query failed");
            }
        }
    }

    let socket = crate::engines::socket::scan_packages_creds(&take, abort, socket).await;
    findings.extend(socket.findings);
    let cancelled = socket.skipped.as_deref() == Some("cancelled");
    sca_out(
        findings,
        packages.len(),
        queried,
        if cancelled {
            Some("cancelled".into())
        } else {
            None
        },
        cancelled,
        socket.packages,
        socket.skipped,
    )
}

fn sca_out(
    findings: Vec<NewFinding>,
    packages_considered: usize,
    queried: usize,
    skipped_reason: Option<String>,
    cancelled: bool,
    socket_packages: usize,
    socket_skipped: Option<String>,
) -> ScaOutcome {
    ScaOutcome {
        findings,
        packages_considered,
        queried,
        skipped_reason,
        cancelled,
        socket_packages,
        socket_skipped,
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
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(default)]
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    score: String,
}

async fn query_osv(
    client: &reqwest::Client,
    pkg: &PackageRef,
    abort: Option<&Abort>,
    url: &str,
) -> anyhow::Result<Vec<OsvVuln>> {
    let body = serde_json::json!({
        "version": pkg.version,
        "package": {
            "name": pkg.name,
            "ecosystem": pkg.ecosystem,
        }
    });
    let resp = abort::http(abort, client.post(url).json(&body).send()).await?;
    if !resp.status().is_success() {
        anyhow::bail!("osv status {}", resp.status());
    }
    let parsed: OsvResponse = abort::http(abort, resp.json()).await?;
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
    let malware = vuln.id.starts_with("MAL-") || vuln.id.to_ascii_uppercase().contains("MALWARE");
    let source_note = if malware {
        "OSV malware advisory (MAL-*). Not a CVE CVSS score."
    } else {
        "Grounded via OSV (known CVE/GHSA for this lockfile version)."
    };
    let mut cves = crate::engines::intel::cve_ids_from(&vuln.aliases);
    cves.extend(crate::engines::intel::cve_ids_from(std::slice::from_ref(
        &vuln.id,
    )));
    cves.sort();
    cves.dedup();
    if cves.is_empty() {
        cves.push(vuln.id.clone());
    }
    NewFinding {
        fingerprint,
        severity,
        confidence: "high".into(),
        category: "sca".into(),
        rule_id: vuln.id.clone(),
        title: format!("{} in {}@{}", vuln.id, pkg.name, pkg.version),
        description: format!("{summary} Source manifest: {}. {source_note}", pkg.source),
        path: Some(pkg.source.clone()),
        line_start: None,
        line_end: None,
        cwe: vec![],
        cve: cves,
        evidence: serde_json::json!({
            "package": pkg.name,
            "version": pkg.version,
            "ecosystem": pkg.ecosystem,
            "advisory": vuln.id,
            "aliases": vuln.aliases,
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
    collect_packages_with(root, crate::engines::walk::WalkOpts::default())
}

pub fn collect_packages_with(root: &Path, opts: crate::engines::walk::WalkOpts) -> Vec<PackageRef> {
    let files = crate::engines::walk::walk_files(
        root,
        crate::engines::walk::WalkOpts {
            max_files: 4_000,
            skip_binary_names: false,
            include_vendor: opts.include_vendor,
            max_file_bytes: opts.max_file_bytes,
        },
        |path, _| is_lockfile_name(path.file_name().and_then(|s| s.to_str()).unwrap_or("")),
    );
    collect_packages_from(&files)
}

fn is_lockfile_name(name: &str) -> bool {
    matches!(
        name,
        "Cargo.lock"
            | "package-lock.json"
            | "yarn.lock"
            | "go.mod"
            | "go.sum"
            | "requirements.txt"
            | "poetry.lock"
            | "Gemfile.lock"
            | "composer.lock"
            | "Pipfile.lock"
    )
}

pub fn collect_packages_from(files: &[crate::engines::walk::WalkedFile]) -> Vec<PackageRef> {
    let mut out = Vec::new();
    let mut lockfiles = 0usize;
    for file in files {
        if !is_lockfile_name(file.file_name()) {
            continue;
        }
        if lockfiles >= MAX_LOCKFILES {
            break;
        }
        let path = file.abs.as_path();
        let rel_str = file.rel.as_str();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let extra = match name {
            "Cargo.lock" => parse_cargo_lock(path, rel_str),
            "package-lock.json" => parse_package_lock(path, rel_str),
            "yarn.lock" => parse_yarn_lock(path, rel_str),
            "go.mod" => parse_go_mod(path, rel_str),
            "go.sum" => parse_go_sum(path, rel_str),
            "requirements.txt" => parse_requirements(path, rel_str),
            "poetry.lock" => parse_poetry_lock(path, rel_str),
            "Gemfile.lock" => parse_gemfile_lock(path, rel_str),
            "composer.lock" => parse_composer_lock(path, rel_str),
            "Pipfile.lock" => parse_pipfile_lock(path, rel_str),
            _ => continue,
        };
        if extra.is_empty() {
            continue;
        }
        lockfiles += 1;
        out.extend(extra);
    }
    dedupe_packages(out)
}

fn dedupe_packages(pkgs: Vec<PackageRef>) -> Vec<PackageRef> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for pkg in pkgs {
        let key = format!("{}|{}|{}", pkg.ecosystem, pkg.name, pkg.version);
        if seen.insert(key) {
            out.push(pkg);
        }
    }
    out
}

fn parse_cargo_lock(path: &Path, source: &str) -> Vec<PackageRef> {
    parse_toml_packages(path, source, "crates.io", Some("achilles-store"))
}

fn parse_poetry_lock(path: &Path, source: &str) -> Vec<PackageRef> {
    parse_toml_packages(path, source, "PyPI", None)
}

fn parse_toml_packages(
    path: &Path,
    source: &str,
    ecosystem: &str,
    skip_name: Option<&str>,
) -> Vec<PackageRef> {
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
            push_toml_pkg(
                &mut out,
                name.take(),
                version.take(),
                ecosystem,
                source,
                skip_name,
            );
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
    push_toml_pkg(&mut out, name, version, ecosystem, source, skip_name);
    out
}

fn push_toml_pkg(
    out: &mut Vec<PackageRef>,
    name: Option<String>,
    version: Option<String>,
    ecosystem: &str,
    source: &str,
    skip_name: Option<&str>,
) {
    if let (Some(n), Some(v)) = (name, version) {
        if skip_name.is_some_and(|s| s == n) {
            return;
        }
        out.push(PackageRef {
            name: n,
            version: v,
            ecosystem: ecosystem.into(),
            source: source.into(),
        });
    }
}

fn parse_package_lock(path: &Path, source: &str) -> Vec<PackageRef> {
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
                source: source.into(),
            });
        }
    }
    out
}

fn parse_yarn_lock(path: &Path, source: &str) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut pending: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') && line.trim_end().ends_with(':') {
            let key = line.trim().trim_end_matches(':').trim().trim_matches('"');
            let first = key
                .split(',')
                .next()
                .unwrap_or(key)
                .trim()
                .trim_matches('"');
            pending = Some(yarn_package_name(first));
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("version ")
            .or_else(|| trimmed.strip_prefix("version:"))
        {
            let version = rest.trim().trim_matches('"').to_string();
            if let Some(name) = pending.take() {
                if !name.is_empty() && !version.is_empty() {
                    out.push(PackageRef {
                        name,
                        version,
                        ecosystem: "npm".into(),
                        source: source.into(),
                    });
                }
            }
        }
    }
    out
}

fn yarn_package_name(spec: &str) -> String {
    if spec.starts_with('@') {
        if let Some(idx) = spec.rfind('@') {
            if idx > 0 {
                return spec.get(..idx).unwrap_or(spec).to_string();
            }
        }
        return spec.to_string();
    }
    spec.split('@').next().unwrap_or(spec).to_string()
}

fn parse_go_mod(path: &Path, source: &str) -> Vec<PackageRef> {
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
                source: source.into(),
            });
        }
    }
    out
}

fn parse_go_sum(path: &Path, source: &str) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        if parts[1].ends_with("/go.mod") {
            continue;
        }
        out.push(PackageRef {
            name: parts[0].to_string(),
            version: parts[1].trim_start_matches('v').to_string(),
            ecosystem: "Go".into(),
            source: source.into(),
        });
    }
    out
}

fn parse_requirements(path: &Path, source: &str) -> Vec<PackageRef> {
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
                source: source.into(),
            });
        }
    }
    out
}

/// Bundler writes platform gems as `nokogiri (1.19.4-x86_64-darwin)`.
/// OSV wants the RubyGems version (`1.19.4`); the platform suffix is not a version,
/// and querying it makes OSV return every historical advisory for that gem.
fn strip_bundler_platform(version: &str) -> &str {
    for (i, _) in version.match_indices('-') {
        if version.get(i + 1..).is_some_and(is_gem_platform) {
            return version.get(..i).unwrap_or(version);
        }
    }
    version
}

fn is_gem_platform(s: &str) -> bool {
    matches!(
        s,
        "java" | "jruby" | "ruby" | "mswin32" | "mswin64" | "mingw32" | "dalvik"
    ) || is_cpu_os_platform(s)
}

fn is_cpu_os_platform(s: &str) -> bool {
    let mut parts = s.split('-');
    let Some(cpu) = parts.next() else {
        return false;
    };
    let Some(os) = parts.next() else {
        return false;
    };
    is_gem_cpu(cpu) && is_gem_os(os)
}

fn is_gem_cpu(s: &str) -> bool {
    matches!(
        s,
        "x86"
            | "x86_64"
            | "x64"
            | "i386"
            | "i586"
            | "i686"
            | "amd64"
            | "aarch64"
            | "arm64"
            | "arm"
            | "universal"
            | "ppc"
            | "ppc64"
            | "ppc64le"
            | "powerpc"
            | "powerpc64"
            | "sparc"
            | "sparc64"
            | "mips"
            | "mipsel"
            | "s390x"
            | "riscv64"
            | "loongarch64"
    )
}

fn is_gem_os(s: &str) -> bool {
    matches!(
        s,
        "darwin"
            | "linux"
            | "freebsd"
            | "openbsd"
            | "netbsd"
            | "dragonfly"
            | "mingw"
            | "mingw32"
            | "mswin32"
            | "mswin64"
            | "android"
            | "aix"
            | "cygwin"
            | "haiku"
            | "java"
    ) || s.starts_with("solaris")
        || s.starts_with("darwin")
        || s.starts_with("linux")
        || s.starts_with("mingw")
        || s.starts_with("mswin")
        || s.starts_with("freebsd")
}

fn parse_gemfile_lock(path: &Path, source: &str) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut in_specs = false;
    for line in text.lines() {
        if line.starts_with("  specs:") {
            in_specs = true;
            continue;
        }
        if in_specs {
            if !line.starts_with(' ') && !line.is_empty() {
                in_specs = false;
                continue;
            }
            if line.starts_with("    ") && !line.starts_with("      ") {
                let trimmed = line.trim();
                if let Some((name, rest)) = trimmed.split_once(' ') {
                    let raw = rest.trim().trim_start_matches('(').trim_end_matches(')');
                    let version = strip_bundler_platform(raw);
                    if !name.is_empty() && !version.is_empty() {
                        out.push(PackageRef {
                            name: name.to_string(),
                            version: version.to_string(),
                            ecosystem: "RubyGems".into(),
                            source: source.into(),
                        });
                    }
                }
            }
        }
    }
    out
}

fn parse_composer_lock(path: &Path, source: &str) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return vec![];
    };
    let mut out = Vec::new();
    for key in ["packages", "packages-dev"] {
        let Some(arr) = value.get(key).and_then(|v| v.as_array()) else {
            continue;
        };
        for pkg in arr {
            let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            out.push(PackageRef {
                name: name.to_string(),
                version: version.trim_start_matches('v').to_string(),
                ecosystem: "Packagist".into(),
                source: source.into(),
            });
        }
    }
    out
}

fn parse_pipfile_lock(path: &Path, source: &str) -> Vec<PackageRef> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return vec![];
    };
    let mut out = Vec::new();
    for key in ["default", "develop"] {
        let Some(map) = value.get(key).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, spec) in map {
            let Some(version) = spec.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let version = version.trim_start_matches("==").trim().to_string();
            if version.is_empty() {
                continue;
            }
            out.push(PackageRef {
                name: name.clone(),
                version,
                ecosystem: "PyPI".into(),
                source: source.into(),
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
        let pkgs = parse_cargo_lock(&dir.path().join("Cargo.lock"), "Cargo.lock");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].ecosystem, "crates.io");
    }

    #[test]
    fn walks_nested_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("services/api");
        std::fs::create_dir_all(&nested).unwrap();
        let mut file = fs::File::create(nested.join("Cargo.lock")).unwrap();
        writeln!(file, "[[package]]\nname = \"tokio\"\nversion = \"1.0.0\"\n").unwrap();
        let pkgs = collect_packages(dir.path());
        assert!(pkgs
            .iter()
            .any(|p| p.name == "tokio" && p.source.contains("services/api")));
    }

    #[test]
    fn strip_bundler_platform_keeps_ruby_versions() {
        assert_eq!(strip_bundler_platform("1.19.4"), "1.19.4");
        assert_eq!(strip_bundler_platform("8.2.0.alpha"), "8.2.0.alpha");
        assert_eq!(strip_bundler_platform("1.0.0.pre.1"), "1.0.0.pre.1");
        assert_eq!(strip_bundler_platform("1.0.0-rc1"), "1.0.0-rc1");
        assert_eq!(strip_bundler_platform("1.0.0-beta.1"), "1.0.0-beta.1");
    }

    #[test]
    fn strip_bundler_platform_drops_gem_platforms() {
        assert_eq!(strip_bundler_platform("1.19.4-x86_64-darwin"), "1.19.4");
        assert_eq!(strip_bundler_platform("1.19.4-aarch64-linux-gnu"), "1.19.4");
        assert_eq!(strip_bundler_platform("1.17.2-x86_64-linux-musl"), "1.17.2");
        assert_eq!(strip_bundler_platform("1.16.8-java"), "1.16.8");
        assert_eq!(strip_bundler_platform("1.16.8-x64-mingw-ucrt"), "1.16.8");
        assert_eq!(strip_bundler_platform("0.1.23-arm64-darwin"), "0.1.23");
        assert_eq!(strip_bundler_platform("1.18.2-x86_64-darwin-23"), "1.18.2");
    }

    #[test]
    fn gemfile_lock_collapses_platform_gems() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            r#"GEM
  remote: https://rubygems.org/
  specs:
    ffi (1.17.2-aarch64-linux-gnu)
    ffi (1.17.2-arm64-darwin)
    ffi (1.17.2-x86_64-darwin)
    ffi (1.17.2-x86_64-linux-gnu)
    nokogiri (1.19.4-aarch64-linux-gnu)
      racc (~> 1.4)
    nokogiri (1.19.4-arm64-darwin)
      racc (~> 1.4)
    nokogiri (1.19.4-x86_64-darwin)
      racc (~> 1.4)
    nokogiri (1.19.4-x86_64-linux-gnu)
      racc (~> 1.4)
    racc (1.8.1)
    rails (8.2.0.alpha)

PLATFORMS
  aarch64-linux
  arm64-darwin
  x86_64-darwin
  x86_64-linux
"#,
        )
        .unwrap();
        let pkgs = collect_packages(dir.path());
        let nokogiri: Vec<_> = pkgs.iter().filter(|p| p.name == "nokogiri").collect();
        assert_eq!(nokogiri.len(), 1, "{pkgs:?}");
        assert_eq!(nokogiri[0].version, "1.19.4");
        assert_eq!(nokogiri[0].ecosystem, "RubyGems");
        let ffi: Vec<_> = pkgs.iter().filter(|p| p.name == "ffi").collect();
        assert_eq!(ffi.len(), 1, "{pkgs:?}");
        assert_eq!(ffi[0].version, "1.17.2");
        assert!(pkgs
            .iter()
            .any(|p| p.name == "rails" && p.version == "8.2.0.alpha"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "racc" && p.version == "1.8.1"));
    }

    #[tokio::test]
    async fn cancel_aborts_hanging_osv_http() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let _hold = socket;
                    std::future::pending::<()>().await
                });
            }
        });

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "requests==2.31.0\n").unwrap();
        let files = crate::engines::walk::walk_files(dir.path(), Default::default(), |_, _| true);
        let abort = Abort::new();
        let abort_bg = abort.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            abort_bg.cancel();
        });
        let started = std::time::Instant::now();
        let url = format!("http://{addr}/v1/query");
        let outcome = scan_sca_abort_at(
            dir.path(),
            &files,
            Some(&abort),
            Some(&url),
            crate::engines::socket::SocketCreds::default(),
            Some("http://127.0.0.1:1"),
            Some("http://127.0.0.1:1"),
        )
        .await;
        assert!(outcome.cancelled, "{outcome:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[tokio::test]
    async fn socket_skip_is_recorded_without_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "requests==2.31.0\n").unwrap();
        let files = crate::engines::walk::walk_files(dir.path(), Default::default(), |_, _| true);
        let outcome = scan_sca_abort_at(
            dir.path(),
            &files,
            None,
            Some("http://127.0.0.1:1/v1/query"),
            crate::engines::socket::SocketCreds::default(),
            Some("http://127.0.0.1:1"),
            Some("http://127.0.0.1:1"),
        )
        .await;
        assert!(!outcome.cancelled);
        assert!(
            outcome
                .socket_skipped
                .as_deref()
                .is_some_and(|s| s.contains("token")),
            "{outcome:?}"
        );
    }
}

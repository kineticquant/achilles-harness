//! Socket alerts for lockfile packages (supply chain, capability, quality,
//! maintenance, CVE, license). Apache-2.0.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::engines::abort::{self, Abort};
use crate::public_sources::{self, HTTP_USER_AGENT};
use crate::types::{NewFinding, PackageRef, Severity};

/// Synthetic / empty-stream markers — not real package risk.
const SKIP: &[&str] = &["pendingScan", "notFound", "policy", "generic"];
const MAX_FINDINGS: usize = 200;

#[derive(Debug, Clone, Default)]
pub struct SocketCreds {
    pub token: Option<String>,
    pub org: Option<String>,
}

impl SocketCreds {
    pub fn from_env() -> Self {
        Self {
            token: api_token(),
            org: public_sources::socket_org_slug(),
        }
    }

    pub fn resolved_token(&self) -> Option<String> {
        self.token
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(api_token)
    }
}

pub fn api_token() -> Option<String> {
    for key in ["ACHILLES_SOCKET_API_TOKEN", "SOCKET_SECURITY_API_KEY"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

pub fn purl(pkg: &PackageRef) -> Option<String> {
    let eco = match pkg.ecosystem.as_str() {
        "npm" => "npm",
        "PyPI" => "pypi",
        "Go" => "golang",
        "crates.io" => "cargo",
        "RubyGems" => "gem",
        "Packagist" => "composer",
        _ => return None,
    };
    let name = encode_purl_name(&pkg.name);
    let version = pkg.version.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(format!("pkg:{eco}/{name}@{version}"))
}

fn encode_purl_name(name: &str) -> String {
    name.split('/')
        .map(|part| {
            let mut out = String::new();
            for ch in part.chars() {
                match ch {
                    'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' => out.push(ch),
                    '@' => out.push_str("%40"),
                    c => {
                        let mut buf = [0u8; 4];
                        for byte in c.encode_utf8(&mut buf).as_bytes() {
                            out.push_str(&format!("%{byte:02X}"));
                        }
                    }
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub struct SocketOutcome {
    pub findings: Vec<NewFinding>,
    pub packages: usize,
    pub skipped: Option<String>,
}

pub async fn scan_packages(packages: &[PackageRef], abort: Option<&Abort>) -> SocketOutcome {
    scan_packages_creds(packages, abort, SocketCreds::from_env()).await
}

pub async fn scan_packages_creds(
    packages: &[PackageRef],
    abort: Option<&Abort>,
    creds: SocketCreds,
) -> SocketOutcome {
    #[cfg(test)]
    {
        // cargo test must not hit live Socket when a developer has a token in the environment.
        if !crate::public_sources::socket_url_is_overridden() {
            return scan_packages_at(packages, abort, None, None).await;
        }
    }
    let url = public_sources::socket_purl_url_for(creds.org.as_deref());
    scan_packages_at(packages, abort, Some(&url), creds.resolved_token()).await
}

pub async fn scan_packages_at(
    packages: &[PackageRef],
    abort: Option<&Abort>,
    url_override: Option<&str>,
    token: Option<String>,
) -> SocketOutcome {
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return SocketOutcome {
            findings: Vec::new(),
            packages: 0,
            skipped: Some("no Socket API token (set ACHILLES_SOCKET_API_TOKEN)".into()),
        };
    };
    let with_purl: Vec<(&PackageRef, String)> = packages
        .iter()
        .filter_map(|pkg| purl(pkg).map(|p| (pkg, p)))
        .collect();
    if with_purl.is_empty() {
        return SocketOutcome {
            findings: Vec::new(),
            packages: 0,
            skipped: Some("no npm/PyPI/Go/crates/gem/composer packages to send".into()),
        };
    }
    if abort.is_some_and(Abort::is_cancelled) {
        return SocketOutcome {
            findings: Vec::new(),
            packages: 0,
            skipped: Some("cancelled".into()),
        };
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent(HTTP_USER_AGENT)
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            return SocketOutcome {
                findings: Vec::new(),
                packages: with_purl.len(),
                skipped: Some(format!("http client: {err}")),
            };
        }
    };
    let url = url_override
        .map(str::to_string)
        .unwrap_or_else(public_sources::socket_purl_url);
    let components: Vec<serde_json::Value> = with_purl
        .iter()
        .map(|(_, p)| json!({ "purl": p }))
        .collect();
    let body = json!({ "components": components });
    let resp = match abort::http(
        abort,
        client
            .post(&url)
            .bearer_auth(&token)
            .header("Accept", "application/x-ndjson")
            .json(&body)
            .send(),
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) if abort::is_cancel(&err) => {
            return SocketOutcome {
                findings: Vec::new(),
                packages: with_purl.len(),
                skipped: Some("cancelled".into()),
            };
        }
        Err(err) => {
            return SocketOutcome {
                findings: Vec::new(),
                packages: with_purl.len(),
                skipped: Some(format!("socket request: {err}")),
            };
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        return SocketOutcome {
            findings: Vec::new(),
            packages: with_purl.len(),
            skipped: Some(format!("socket status {status}")),
        };
    }
    let text = match abort::http(abort, resp.text()).await {
        Ok(text) => text,
        Err(err) if abort::is_cancel(&err) => {
            return SocketOutcome {
                findings: Vec::new(),
                packages: with_purl.len(),
                skipped: Some("cancelled".into()),
            };
        }
        Err(err) => {
            return SocketOutcome {
                findings: Vec::new(),
                packages: with_purl.len(),
                skipped: Some(format!("socket body: {err}")),
            };
        }
    };
    let by_purl: HashMap<&str, &PackageRef> = with_purl
        .iter()
        .map(|(pkg, p)| (p.as_str(), *pkg))
        .collect();
    SocketOutcome {
        findings: cap_findings(findings_from_ndjson(&text, &by_purl)),
        packages: with_purl.len(),
        skipped: None,
    }
}

#[derive(Deserialize)]
struct SocketArtifact {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default, rename = "inputPurl")]
    input_purl: Option<String>,
    #[serde(default)]
    alerts: Vec<SocketAlert>,
}

#[derive(Deserialize)]
struct SocketAlert {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    severity: String,
}

pub fn findings_from_ndjson(text: &str, by_purl: &HashMap<&str, &PackageRef>) -> Vec<NewFinding> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(art) = serde_json::from_str::<SocketArtifact>(line) else {
            continue;
        };
        let pkg = art
            .input_purl
            .as_deref()
            .or(art.purl.as_deref())
            .and_then(|p| by_purl.get(p).copied())
            .or_else(|| {
                by_purl
                    .values()
                    .find(|p| {
                        p.name == art.name
                            && (art.version.is_empty() || p.version == art.version)
                            && (art.kind.is_empty()
                                || purl_type(&p.ecosystem).is_some_and(|t| t == art.kind))
                    })
                    .copied()
            });
        let Some(pkg) = pkg else {
            continue;
        };
        for alert in &art.alerts {
            if skip_alert(&alert.kind) {
                continue;
            }
            out.push(finding_from_alert(pkg, &alert.kind, &alert.severity));
        }
    }
    out
}

fn purl_type(ecosystem: &str) -> Option<&'static str> {
    Some(match ecosystem {
        "npm" => "npm",
        "PyPI" => "pypi",
        "Go" => "golang",
        "crates.io" => "cargo",
        "RubyGems" => "gem",
        "Packagist" => "composer",
        _ => return None,
    })
}

fn skip_alert(kind: &str) -> bool {
    SKIP.iter().any(|k| k.eq_ignore_ascii_case(kind)) || kind.trim().is_empty()
}

fn alert_domain(kind: &str) -> &'static str {
    let k = kind.to_ascii_lowercase();
    if k.contains("cve") || k == "potentialvulnerability" {
        return "vulnerability";
    }
    if k.contains("license")
        || k.contains("copyleft")
        || k == "explicitlyunlicenseditem"
        || k == "ambiguousclassifier"
        || k == "nolicensefound"
        || k == "unidentifiedlicense"
        || k == "nonpermissivelicense"
        || k == "licenseexception"
    {
        return "license";
    }
    if k == "unmaintained" || k == "deprecated" {
        return "maintenance";
    }
    if k == "unpopularpackage"
        || k == "minifiedfile"
        || k == "trivialpackage"
        || k == "badsemverdependency"
        || k == "floatingdependency"
        || k == "socketupgradeavailable"
        || k == "badsemverdependency"
    {
        return "quality";
    }
    if k.contains("installscript")
        || k.contains("native")
        || k.contains("filesystem")
        || k.contains("envvar")
        || k.contains("network")
        || k.contains("shell")
        || k.contains("eval")
        || k.contains("dynamicrequire")
        || k.contains("debugaccess")
        || k.starts_with("chrome")
        || k.starts_with("browserextension")
        || k.starts_with("vsx")
        || k.starts_with("gha")
        || k.starts_with("skill")
    {
        return "capability";
    }
    "supply_chain"
}

fn alert_title(kind: &str) -> String {
    match kind {
        "malware" | "knownMalware" | "gptMalware" => "malware".into(),
        "didYouMean" | "gptDidYouMean" => "possible typosquat".into(),
        "httpDependency" => "HTTP (unauthenticated) dependency".into(),
        "gitDependency" => "git URL dependency".into(),
        "installScripts" => "install scripts".into(),
        "criticalCVE" => "critical CVE".into(),
        "cve" => "high CVE".into(),
        "mediumCVE" => "medium CVE".into(),
        "mildCVE" => "low CVE".into(),
        "copyleftLicense" => "copyleft license".into(),
        "unmaintained" => "unmaintained package".into(),
        other => humanize_camel(other),
    }
}

fn humanize_camel(kind: &str) -> String {
    let mut out = String::new();
    for (i, ch) in kind.chars().enumerate() {
        if i > 0 && ch.is_ascii_uppercase() {
            out.push(' ');
        }
        out.push(if i == 0 { ch.to_ascii_lowercase() } else { ch });
    }
    out
}

fn cap_findings(mut findings: Vec<NewFinding>) -> Vec<NewFinding> {
    findings.sort_by_key(|f| match f.severity {
        Severity::Critical => 0u8,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });
    findings.truncate(MAX_FINDINGS);
    findings
}

fn finding_from_alert(pkg: &PackageRef, kind: &str, socket_severity: &str) -> NewFinding {
    let mut hasher = Sha256::new();
    hasher.update(b"socket|");
    hasher.update(pkg.ecosystem.as_bytes());
    hasher.update(b"|");
    hasher.update(pkg.name.as_bytes());
    hasher.update(b"|");
    hasher.update(pkg.version.as_bytes());
    hasher.update(b"|");
    hasher.update(kind.as_bytes());
    let digest = hasher.finalize();
    let fingerprint = format!(
        "sca-socket:{}",
        digest
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let label = alert_title(kind);
    let domain = alert_domain(kind);
    NewFinding {
        fingerprint,
        severity: socket_severity_to(socket_severity, kind, domain),
        confidence: "high".into(),
        category: "sca".into(),
        rule_id: format!("socket:{kind}"),
        title: format!("Socket {label}: {}@{}", pkg.name, pkg.version),
        description: format!(
            "Socket {domain} alert ({label}) on {}@{}. Source manifest: {}. This is Socket package intel, not a CVE invented by Achilles.",
            pkg.name, pkg.version, pkg.source
        ),
        path: Some(pkg.source.clone()),
        line_start: None,
        line_end: None,
        cwe: vec![],
        cve: vec![],
        evidence: json!({
            "package": pkg.name,
            "version": pkg.version,
            "ecosystem": pkg.ecosystem,
            "socketAlert": kind,
            "socketDomain": domain,
            "engine": "achilles-sca-socket"
        }),
    }
}

fn socket_severity_to(label: &str, kind: &str, domain: &str) -> Severity {
    match label.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ if kind.eq_ignore_ascii_case("malware")
            || kind.eq_ignore_ascii_case("gptMalware")
            || kind.eq_ignore_ascii_case("knownMalware")
            || kind.eq_ignore_ascii_case("didYouMean")
            || kind.eq_ignore_ascii_case("gptDidYouMean") =>
        {
            Severity::Critical
        }
        _ if kind.eq_ignore_ascii_case("criticalCVE") => Severity::Critical,
        _ if domain == "vulnerability" => Severity::High,
        _ if domain == "capability" => Severity::Medium,
        _ if domain == "quality" || domain == "maintenance" || domain == "license" => Severity::Low,
        _ => Severity::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, eco: &str) -> PackageRef {
        PackageRef {
            name: name.into(),
            version: "1.2.3".into(),
            ecosystem: eco.into(),
            source: "package-lock.json".into(),
        }
    }

    #[test]
    fn purl_encodes_scoped_npm() {
        assert_eq!(
            purl(&pkg("@scope/evil", "npm")).as_deref(),
            Some("pkg:npm/%40scope/evil@1.2.3")
        );
        assert_eq!(
            purl(&pkg("requests", "PyPI")).as_deref(),
            Some("pkg:pypi/requests@1.2.3")
        );
    }

    #[test]
    fn ndjson_ingests_domains_and_skips_synthetic() {
        let p = pkg("evil-pkg", "npm");
        let purl_s = purl(&p).unwrap();
        let mut map = HashMap::new();
        map.insert(purl_s.as_str(), &p);
        let ndjson = format!(
            r#"{{"name":"evil-pkg","version":"1.2.3","type":"npm","inputPurl":"{purl_s}","alerts":[{{"type":"malware","severity":"critical"}},{{"type":"installScripts","severity":"high"}},{{"type":"copyleftLicense","severity":"low"}},{{"type":"pendingScan","severity":"low"}}]}}"#
        );
        let findings = findings_from_ndjson(&ndjson, &map);
        let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"socket:malware"));
        assert!(rules.contains(&"socket:installScripts"));
        assert!(rules.contains(&"socket:copyleftLicense"));
        assert!(!rules.iter().any(|r| r.contains("pendingScan")));
        assert_eq!(findings.len(), 3);
        let license = findings
            .iter()
            .find(|f| f.rule_id == "socket:copyleftLicense")
            .unwrap();
        assert_eq!(license.evidence["socketDomain"], "license");
        let scripts = findings
            .iter()
            .find(|f| f.rule_id == "socket:installScripts")
            .unwrap();
        assert_eq!(scripts.evidence["socketDomain"], "capability");
    }

    #[tokio::test]
    async fn no_token_skips() {
        let out = scan_packages_at(&[pkg("x", "npm")], None, None, None).await;
        assert!(out.findings.is_empty());
        assert!(out.skipped.unwrap().contains("token"));
    }
}

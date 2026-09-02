//! Flag npm / PyPI lockfile versions published less than 7 days ago.
//! Apache-2.0.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::engines::abort::{self, Abort};
use crate::engines::utils::{self, REGISTRY_FRESH_DAYS};
use crate::public_sources;
use crate::types::{NewFinding, PackageRef, Severity};

const MAX_FINDINGS: usize = 80;
const RULE_ID: &str = "fresh-registry-package";

pub struct FreshOpts<'a> {
    pub now: DateTime<Utc>,
    pub npm_base: &'a str,
    pub pypi_base: &'a str,
}

pub async fn scan_packages(
    client: &reqwest::Client,
    packages: &[PackageRef],
    abort: Option<&Abort>,
) -> anyhow::Result<Vec<NewFinding>> {
    let npm = public_sources::npm_registry_url();
    let pypi = public_sources::pypi_json_base_url();
    scan_packages_at(
        client,
        packages,
        abort,
        FreshOpts {
            now: Utc::now(),
            npm_base: &npm,
            pypi_base: &pypi,
        },
    )
    .await
}

pub async fn scan_packages_at(
    client: &reqwest::Client,
    packages: &[PackageRef],
    abort: Option<&Abort>,
    opts: FreshOpts<'_>,
) -> anyhow::Result<Vec<NewFinding>> {
    let mut findings = Vec::new();
    for pkg in packages {
        if abort.is_some_and(Abort::is_cancelled) {
            anyhow::bail!(abort::Cancelled);
        }
        if findings.len() >= MAX_FINDINGS {
            break;
        }
        let Some(url) = registry_url(pkg, opts.npm_base, opts.pypi_base) else {
            continue;
        };
        match fetch_published_at(client, abort, pkg, &url).await {
            Ok(Some(published)) => {
                if utils::registry_publish_is_fresh(published, opts.now) {
                    findings.push(finding(pkg, published, opts.now));
                }
            }
            Ok(None) => {}
            Err(err) if abort::is_cancel(&err) => return Err(err),
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    package = %pkg.name,
                    ecosystem = %pkg.ecosystem,
                    "registry age lookup failed"
                );
            }
        }
    }
    Ok(findings)
}

fn registry_url(pkg: &PackageRef, npm_base: &str, pypi_base: &str) -> Option<String> {
    match pkg.ecosystem.as_str() {
        "npm" => Some(format!(
            "{}/{}",
            npm_base.trim_end_matches('/'),
            encode_name(&pkg.name)
        )),
        "PyPI" => Some(format!(
            "{}/{}/{}/json",
            pypi_base.trim_end_matches('/'),
            encode_name(&pkg.name),
            encode_name(&pkg.version)
        )),
        _ => None,
    }
}

async fn fetch_published_at(
    client: &reqwest::Client,
    abort: Option<&Abort>,
    pkg: &PackageRef,
    url: &str,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    let resp = abort::http(abort, client.get(url).send()).await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let value: serde_json::Value = abort::http(abort, resp.json()).await?;
    Ok(match pkg.ecosystem.as_str() {
        "npm" => npm_published_at(&value, &pkg.version),
        "PyPI" => pypi_published_at(&value),
        _ => None,
    })
}

fn npm_published_at(value: &serde_json::Value, version: &str) -> Option<DateTime<Utc>> {
    let times = value.get("time")?;
    let raw = times
        .get(version)
        .and_then(|v| v.as_str())
        .or_else(|| times.get("created").and_then(|v| v.as_str()))?;
    utils::parse_registry_time(raw)
}

fn pypi_published_at(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    if let Some(urls) = value.get("urls").and_then(|v| v.as_array()) {
        let mut best: Option<DateTime<Utc>> = None;
        for url in urls {
            let raw = url
                .get("upload_time_iso_8601")
                .or_else(|| url.get("upload_time"))
                .and_then(|v| v.as_str());
            let Some(raw) = raw else { continue };
            let Some(ts) = utils::parse_registry_time(raw) else {
                continue;
            };
            best = Some(match best {
                Some(prev) if ts < prev => ts,
                Some(prev) => prev,
                None => ts,
            });
        }
        if best.is_some() {
            return best;
        }
    }
    value
        .get("info")
        .and_then(|info| {
            info.get("upload_time_iso_8601")
                .or_else(|| info.get("upload_time"))
        })
        .and_then(|v| v.as_str())
        .and_then(utils::parse_registry_time)
}

fn finding(pkg: &PackageRef, published: DateTime<Utc>, now: DateTime<Utc>) -> NewFinding {
    let age_days = now.signed_duration_since(published).num_days().max(0);
    let mut hasher = Sha256::new();
    hasher.update(pkg.ecosystem.as_bytes());
    hasher.update(b"|");
    hasher.update(pkg.name.as_bytes());
    hasher.update(b"|");
    hasher.update(pkg.version.as_bytes());
    hasher.update(b"|");
    hasher.update(RULE_ID.as_bytes());
    let digest = hasher.finalize();
    let fingerprint = format!(
        "fresh:{}",
        digest
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let registry = match pkg.ecosystem.as_str() {
        "npm" => "npm",
        _ => "PyPI",
    };
    NewFinding {
        fingerprint,
        severity: Severity::Medium,
        confidence: "medium".into(),
        category: "sca".into(),
        rule_id: RULE_ID.into(),
        title: format!(
            "{}@{} on {registry} is less than {REGISTRY_FRESH_DAYS} days old",
            pkg.name, pkg.version
        ),
        description: format!(
            "{}@{} was published on {registry} {} days ago ({}). This is a risk because of supply chain attacks not yet documented. Source: `{}`.",
            pkg.name,
            pkg.version,
            age_days,
            published.to_rfc3339(),
            pkg.source
        ),
        path: Some(pkg.source.clone()),
        line_start: None,
        line_end: None,
        cwe: vec!["CWE-1357".into()],
        cve: vec![],
        evidence: serde_json::json!({
            "engine": "achilles-fresh-registry-v0",
            "kind": "fresh-registry-package",
            "package": pkg.name,
            "version": pkg.version,
            "ecosystem": pkg.ecosystem,
            "publishedAt": published.to_rfc3339(),
            "freshDays": REGISTRY_FRESH_DAYS,
        }),
    }
}

fn encode_name(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' => out.push_str("%2F"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pkg(name: &str, version: &str, eco: &str) -> PackageRef {
        PackageRef {
            name: name.into(),
            version: version.into(),
            ecosystem: eco.into(),
            source: "package-lock.json".into(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn reads_npm_and_pypi_timestamps() {
        let npm = serde_json::json!({
            "time": {
                "created": "2011-01-01T00:00:00.000Z",
                "1.2.3": "2026-08-30T00:00:00.000Z"
            }
        });
        let published = npm_published_at(&npm, "1.2.3").unwrap();
        assert!(utils::registry_publish_is_fresh(published, now()));

        let old = serde_json::json!({
            "time": { "4.17.21": "2021-02-20T00:00:00.000Z" }
        });
        let published = npm_published_at(&old, "4.17.21").unwrap();
        assert!(!utils::registry_publish_is_fresh(published, now()));

        let pypi = serde_json::json!({
            "urls": [
                { "upload_time_iso_8601": "2026-08-28T10:00:00.000000Z" },
                { "upload_time_iso_8601": "2026-08-29T10:00:00.000000Z" }
            ]
        });
        let published = pypi_published_at(&pypi).unwrap();
        assert_eq!(published.to_rfc3339(), "2026-08-28T10:00:00+00:00");
        assert!(utils::registry_publish_is_fresh(published, now()));
    }

    #[tokio::test]
    async fn http_flags_fresh_npm_skips_old_pypi() {
        let npm_body = r#"{"time":{"1.0.0":"2026-08-30T00:00:00.000Z"}}"#;
        let pypi_body = r#"{"urls":[{"upload_time_iso_8601":"2020-01-01T00:00:00.000000Z"}]}"#;
        let base = serve(npm_body, pypi_body).await;
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(2))
            .build()
            .unwrap();
        let findings = scan_packages_at(
            &client,
            &[
                pkg("brand-new", "1.0.0", "npm"),
                pkg("requests", "2.31.0", "PyPI"),
                pkg("tokio", "1.0.0", "crates.io"),
            ],
            None,
            FreshOpts {
                now: now(),
                npm_base: &base,
                pypi_base: &base,
            },
        )
        .await
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].title.contains("brand-new"));
        assert!(findings[0]
            .description
            .contains("supply chain attacks not yet documented"));
    }

    async fn serve(npm_body: &'static str, pypi_body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body = if path.contains("/json") {
                        pypi_body
                    } else {
                        npm_body
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}")
    }
}

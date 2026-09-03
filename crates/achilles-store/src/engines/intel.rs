//! Live intel (OSV aliases already on SCA; EPSS + CISA KEV). Apache-2.0.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;

use crate::engines::abort::{self, Abort};
use crate::public_sources::{self, HTTP_USER_AGENT, ID_EPSS, ID_GHSA, ID_KEV_CATALOG, ID_NVD};
use crate::store::AchillesStore;
use crate::types::{NewFinding, Severity};

const KEV_TTL_SECS: i64 = 6 * 3600;
const EPSS_TTL_SECS: i64 = 12 * 3600;

#[derive(Debug, Clone, Default)]
pub struct IntelEnrichment {
    pub in_kev: bool,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub cvss: Option<f64>,
    pub sources: Vec<String>,
}

pub struct IntelClient {
    http: reqwest::Client,
    kev_url: String,
    epss_url: String,
    first_party_base: Option<String>,
}

impl IntelClient {
    pub fn from_env() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(HTTP_USER_AGENT)
            .build()?;
        Ok(Self {
            http,
            kev_url: public_sources::kev_catalog_url(),
            epss_url: public_sources::epss_base_url(),
            first_party_base: public_sources::first_party_base(),
        })
    }

    pub async fn lookup(&self, store: &AchillesStore, id: &str) -> Result<serde_json::Value> {
        let id = id.trim();
        anyhow::ensure!(!id.is_empty(), "advisory id is required");
        let cves = cve_ids_from(&[id.to_string()]);
        let enrich = self.enrich(store, &cves, None).await?;
        let row = enrich.get(&cves.first().cloned().unwrap_or_else(|| id.to_string()));
        let nvd = if let Some(cve) = cves.first() {
            self.nvd_cve(store, cve, None).await.ok().flatten()
        } else {
            None
        };
        let ghsa = if id.to_ascii_uppercase().starts_with("GHSA-") {
            self.ghsa(store, id, None).await.ok().flatten()
        } else {
            None
        };
        let upper = id.to_ascii_uppercase();
        let deps = if (id.contains('@') || id.contains('/'))
            && !upper.starts_with("CVE-")
            && !upper.starts_with("GHSA-")
        {
            self.depsdev(store, id, None).await.ok().flatten()
        } else {
            None
        };
        Ok(json!({
            "id": id,
            "cves": cves,
            "intelBase": self.first_party_base,
            "usedPublicFallback": self.first_party_base.is_none(),
            "kev": row.map(|e| e.in_kev).unwrap_or(false),
            "epss": row.and_then(|e| e.epss),
            "epssPercentile": row.and_then(|e| e.epss_percentile),
            "cvss": row.and_then(|e| e.cvss).or_else(|| nvd.as_ref().and_then(nvd_cvss)),
            "nvd": nvd,
            "ghsa": ghsa,
            "depsDev": deps,
            "sources": row.map(|e| e.sources.clone()).unwrap_or_default(),
            "note": "Do not invent CVSS/KEV/EPSS. If a field is null, say unknown. Public APIs today; ACHILLES_INTEL_BASE swaps to Rancero/trivault later."
        }))
    }

    pub async fn enrich(
        &self,
        store: &AchillesStore,
        cves: &[String],
        abort: Option<&Abort>,
    ) -> Result<HashMap<String, IntelEnrichment>> {
        let mut out: HashMap<String, IntelEnrichment> = HashMap::new();
        if cves.is_empty() {
            return Ok(out);
        }
        if abort.is_some_and(Abort::is_cancelled) {
            anyhow::bail!(abort::Cancelled);
        }

        if let Some(base) = &self.first_party_base {
            match self.enrich_first_party(base, cves, abort).await {
                Ok(mapped) => return Ok(mapped),
                Err(err) if abort::is_cancel(&err) => return Err(err),
                Err(_) => {
                    tracing::warn!(
                        env = public_sources::ENV_INTEL_BASE,
                        "first-party intel enrich failed; using public_sources::CATALOG"
                    );
                }
            }
        }

        let kev = match self.kev_set(store, abort).await {
            Ok(v) => v,
            Err(err) if abort::is_cancel(&err) => return Err(err),
            Err(_) => HashSet::new(),
        };
        let epss = match self.epss_map(store, cves, abort).await {
            Ok(v) => v,
            Err(err) if abort::is_cancel(&err) => return Err(err),
            Err(_) => HashMap::new(),
        };
        let nvd_cvss = if public_sources::nvd_api_key().is_some() {
            self.nvd_cvss_map(store, cves, abort)
                .await
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        for cve in cves {
            let mut sources = vec![ID_KEV_CATALOG.to_string(), ID_EPSS.to_string()];
            if nvd_cvss.contains_key(cve) {
                sources.push(ID_NVD.to_string());
            }
            if self.first_party_base.is_some() {
                sources.push("public-fallback".into());
            }
            out.insert(
                cve.clone(),
                IntelEnrichment {
                    in_kev: kev.contains(cve),
                    epss: epss.get(cve).map(|e| e.0),
                    epss_percentile: epss.get(cve).map(|e| e.1),
                    cvss: nvd_cvss.get(cve).copied(),
                    sources,
                },
            );
        }
        Ok(out)
    }

    async fn enrich_first_party(
        &self,
        base: &str,
        cves: &[String],
        abort: Option<&Abort>,
    ) -> Result<HashMap<String, IntelEnrichment>> {
        let url = public_sources::first_party_enrich_url(base, &cves.join(","));
        let resp = abort::http(abort, self.http.get(url).send()).await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "first-party status {}",
            resp.status()
        );
        #[derive(Deserialize)]
        struct Item {
            id: String,
            #[serde(default)]
            kev: bool,
            #[serde(default)]
            epss: Option<f64>,
            #[serde(default, rename = "epssPercentile")]
            epss_percentile: Option<f64>,
            #[serde(default)]
            cvss: Option<f64>,
        }
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(default)]
            items: Vec<Item>,
        }
        let parsed: Envelope = abort::http(abort, resp.json()).await?;
        let mut out = HashMap::new();
        for item in parsed.items {
            out.insert(
                item.id,
                IntelEnrichment {
                    in_kev: item.kev,
                    epss: item.epss,
                    epss_percentile: item.epss_percentile,
                    cvss: item.cvss,
                    sources: vec![public_sources::ID_INTEL_BASE.into()],
                },
            );
        }
        Ok(out)
    }

    async fn kev_set(
        &self,
        store: &AchillesStore,
        abort: Option<&Abort>,
    ) -> Result<HashSet<String>> {
        if abort.is_some_and(Abort::is_cancelled) {
            anyhow::bail!(abort::Cancelled);
        }
        if let Some(cached) = store.intel_cache_get("kev:catalog", KEV_TTL_SECS).await? {
            return Ok(parse_kev_ids(&cached));
        }
        let resp = abort::http(abort, self.http.get(&self.kev_url).send()).await?;
        anyhow::ensure!(resp.status().is_success(), "kev status {}", resp.status());
        let value: serde_json::Value = abort::http(abort, resp.json()).await?;
        store
            .intel_cache_put("kev:catalog", ID_KEV_CATALOG, &value)
            .await?;
        Ok(parse_kev_ids(&value))
    }

    async fn epss_map(
        &self,
        store: &AchillesStore,
        cves: &[String],
        abort: Option<&Abort>,
    ) -> Result<HashMap<String, (f64, f64)>> {
        let mut map = HashMap::new();
        for chunk in cves.chunks(20) {
            if abort.is_some_and(Abort::is_cancelled) {
                anyhow::bail!(abort::Cancelled);
            }
            let key = format!("epss:{}", chunk.join(","));
            let payload = if let Some(cached) = store.intel_cache_get(&key, EPSS_TTL_SECS).await? {
                cached
            } else {
                let url = format!("{}?cve={}", self.epss_url, chunk.join(","));
                let resp = abort::http(abort, self.http.get(url).send()).await?;
                if !resp.status().is_success() {
                    continue;
                }
                let value: serde_json::Value = abort::http(abort, resp.json()).await?;
                let _ = store.intel_cache_put(&key, ID_EPSS, &value).await;
                value
            };
            merge_epss(&payload, &mut map);
        }
        Ok(map)
    }

    async fn nvd_cvss_map(
        &self,
        store: &AchillesStore,
        cves: &[String],
        abort: Option<&Abort>,
    ) -> Result<HashMap<String, f64>> {
        let mut map = HashMap::new();
        for cve in cves.iter().take(12) {
            if abort.is_some_and(Abort::is_cancelled) {
                anyhow::bail!(abort::Cancelled);
            }
            if let Some(payload) = self.nvd_cve(store, cve, abort).await? {
                if let Some(score) = nvd_cvss(&payload) {
                    map.insert(cve.clone(), score);
                }
            }
        }
        Ok(map)
    }

    async fn nvd_cve(
        &self,
        store: &AchillesStore,
        cve: &str,
        abort: Option<&Abort>,
    ) -> Result<Option<serde_json::Value>> {
        let key = format!("nvd:{cve}");
        if let Some(cached) = store.intel_cache_get(&key, 24 * 3600).await? {
            return Ok(Some(cached));
        }
        let url = format!("{}?cveId={cve}", public_sources::nvd_cves_url());
        let mut req = self.http.get(url);
        if let Some(key) = public_sources::nvd_api_key() {
            req = req.header("apiKey", key);
        }
        let resp = abort::http(abort, req.send()).await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let value: serde_json::Value = abort::http(abort, resp.json()).await?;
        let _ = store.intel_cache_put(&key, ID_NVD, &value).await;
        Ok(Some(value))
    }

    async fn ghsa(
        &self,
        store: &AchillesStore,
        ghsa_id: &str,
        abort: Option<&Abort>,
    ) -> Result<Option<serde_json::Value>> {
        let id = ghsa_id.trim();
        let key = format!("ghsa:{id}");
        if let Some(cached) = store.intel_cache_get(&key, 24 * 3600).await? {
            return Ok(Some(cached));
        }
        let url = format!(
            "{}/{id}",
            public_sources::ghsa_advisories_url().trim_end_matches('/')
        );
        let resp = abort::http(
            abort,
            self.http
                .get(url)
                .header("Accept", "application/vnd.github+json")
                .send(),
        )
        .await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let value: serde_json::Value = abort::http(abort, resp.json()).await?;
        let _ = store.intel_cache_put(&key, ID_GHSA, &value).await;
        Ok(Some(value))
    }

    async fn depsdev(
        &self,
        store: &AchillesStore,
        spec: &str,
        abort: Option<&Abort>,
    ) -> Result<Option<serde_json::Value>> {
        let Some((system, name, version)) = parse_deps_spec(spec) else {
            return Ok(None);
        };
        let key = format!("depsdev:{system}:{name}:{version}");
        if let Some(cached) = store.intel_cache_get(&key, 12 * 3600).await? {
            return Ok(Some(cached));
        }
        let enc_name: String = urlencoding_plain(&name);
        let url = format!(
            "{}/systems/{system}/packages/{enc_name}/versions/{version}",
            public_sources::depsdev_base_url().trim_end_matches('/')
        );
        let resp = abort::http(abort, self.http.get(url).send()).await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let value: serde_json::Value = abort::http(abort, resp.json()).await?;
        let _ = store
            .intel_cache_put(&key, public_sources::ID_DEPSDEV, &value)
            .await;
        Ok(Some(value))
    }
}

pub fn cve_ids_from(ids: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        let upper = id.trim().to_uppercase();
        if upper.starts_with("CVE-") && !out.iter().any(|e| e == &upper) {
            out.push(upper);
        }
    }
    out
}

fn parse_kev_ids(value: &serde_json::Value) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Some(vulns) = value.get("vulnerabilities").and_then(|v| v.as_array()) {
        for item in vulns {
            if let Some(id) = item.get("cveID").and_then(|v| v.as_str()) {
                set.insert(id.to_uppercase());
            }
        }
    }
    set
}

fn merge_epss(payload: &serde_json::Value, map: &mut HashMap<String, (f64, f64)>) {
    let Some(rows) = payload.get("data").and_then(|v| v.as_array()) else {
        return;
    };
    for row in rows {
        let Some(cve) = row.get("cve").and_then(|v| v.as_str()) else {
            continue;
        };
        let score = row
            .get("epss")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .or_else(|| row.get("epss").and_then(|v| v.as_f64()));
        let pct = row
            .get("percentile")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .or_else(|| row.get("percentile").and_then(|v| v.as_f64()));
        if let (Some(score), Some(pct)) = (score, pct) {
            map.insert(cve.to_uppercase(), (score, pct));
        }
    }
}

fn nvd_cvss(payload: &serde_json::Value) -> Option<f64> {
    payload
        .get("vulnerabilities")?
        .as_array()?
        .first()?
        .pointer("/cve/metrics/cvssMetricV31/0/cvssData/baseScore")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            payload
                .get("vulnerabilities")?
                .as_array()?
                .first()?
                .pointer("/cve/metrics/cvssMetricV30/0/cvssData/baseScore")
                .and_then(|v| v.as_f64())
        })
}

fn parse_deps_spec(spec: &str) -> Option<(String, String, String)> {
    let spec = spec.trim();
    let (system, rest) = spec.split_once('/')?;
    let (name, version) = rest.rsplit_once('@')?;
    if system.is_empty() || name.is_empty() || version.is_empty() {
        return None;
    }
    Some((system.to_string(), name.to_string(), version.to_string()))
}

fn urlencoding_plain(name: &str) -> String {
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

/// Enrich SCA hits with KEV / EPSS. Returns how many findings actually matched
/// (in KEV, or an EPSS score) — not how many packages were looked up.
pub async fn apply_to_findings(
    client: &IntelClient,
    store: &AchillesStore,
    findings: &mut [NewFinding],
    abort: Option<&Abort>,
) -> Result<usize> {
    let mut ids = Vec::new();
    for finding in findings.iter() {
        ids.extend(cve_ids_from(&finding.cve));
    }
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Ok(0);
    }
    if abort.is_some_and(Abort::is_cancelled) {
        anyhow::bail!(abort::Cancelled);
    }
    let enrich = client.enrich(store, &ids, abort).await?;
    let mut matched = 0usize;
    for finding in findings.iter_mut() {
        let mut kev = false;
        let mut best_epss: Option<(f64, f64)> = None;
        let mut best_cvss: Option<f64> = None;
        for cve in cve_ids_from(&finding.cve) {
            let Some(row) = enrich.get(&cve) else {
                continue;
            };
            kev |= row.in_kev;
            if let (Some(score), Some(pct)) = (row.epss, row.epss_percentile) {
                best_epss = Some(match best_epss {
                    Some((prev, prev_pct)) if prev >= score => (prev, prev_pct),
                    _ => (score, pct),
                });
            }
            if let Some(cvss) = row.cvss {
                best_cvss = Some(best_cvss.map(|p| p.max(cvss)).unwrap_or(cvss));
            }
        }
        if kev {
            finding.severity = Severity::Critical;
            finding
                .description
                .push_str(" Listed in CISA KEV (known exploited).");
        }
        if kev || best_epss.is_some() || best_cvss.is_some() {
            matched += 1;
        }
        if let Some(obj) = finding.evidence.as_object_mut() {
            obj.insert("inKev".into(), json!(kev));
            if let Some((score, pct)) = best_epss {
                obj.insert("epss".into(), json!(score));
                obj.insert("epssPercentile".into(), json!(pct));
            }
            if let Some(cvss) = best_cvss {
                obj.insert("cvss".into(), json!(cvss));
            }
        }
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kev_catalog() {
        let raw = json!({
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228"},
                {"cveID": "cve-2024-0001"}
            ]
        });
        let set = parse_kev_ids(&raw);
        assert!(set.contains("CVE-2021-44228"));
        assert!(set.contains("CVE-2024-0001"));
    }

    #[test]
    fn parses_npm_spec() {
        assert_eq!(
            parse_deps_spec("npm/left-pad@1.3.0"),
            Some(("npm".into(), "left-pad".into(), "1.3.0".into()))
        );
    }

    #[test]
    fn nvd_reads_cvss31() {
        let raw = json!({
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [{ "cvssData": { "baseScore": 9.8 } }]
                    }
                }
            }]
        });
        assert_eq!(nvd_cvss(&raw), Some(9.8));
    }
}

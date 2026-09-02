//! Public (and first-party) HTTP sources Achilles uses for intel.
//!
//! This is the map for humans reading the code: **one table, env overrides, no
//! scattered URL literals.** Engines (`sca`, `intel`, `socket`) must take URLs
//! from here instead of hard-coding hosts.
//!
//! Live public defaults (no account):
//! - OSV — package → advisory
//! - CISA KEV — known-exploited CVE list
//! - FIRST EPSS — exploitation probability
//!
//! Optional, token-gated:
//! - Socket PURL — extra package-risk alerts beyond local OSV/hygiene (same SCA pass)
//! - NVD 2.0 — CVSS (optional `ACHILLES_NVD_API_KEY`; without a key, lookup-only, not scan)
//!
//! Also public, no account:
//! - GitHub Advisories REST — GHSA id → summary/CVSS (unauthenticated, cached)
//! - deps.dev — package version metadata
//! - OpenSSF Scorecard — GitHub repo score
//! - npm registry / PyPI JSON — version publish time (SCA 7-day freshness)
//!
//! Optional first-party plane: `ACHILLES_INTEL_BASE` (trivault/rancero). When
//! unset, public sources above are used. Offline `intel.db` is not the default.
//!
//! Apache-2.0.

#[cfg(test)]
use std::sync::Mutex;

/// Env var: override OSV `POST /v1/query` URL.
pub const ENV_OSV_QUERY: &str = "ACHILLES_OSV_URL";
/// Env var: override CISA KEV JSON catalog URL.
pub const ENV_KEV_CATALOG: &str = "ACHILLES_KEV_URL";
/// Env var: override FIRST EPSS API base (`?cve=` is appended).
pub const ENV_EPSS: &str = "ACHILLES_EPSS_URL";
/// Env var: override Socket PURL batch URL (include `?alerts=true` if you set this).
pub const ENV_SOCKET_PURL: &str = "ACHILLES_SOCKET_URL";
/// Org slug for `POST /v0/orgs/{org}/purl` (preferred after the global `/purl` deprecation).
pub const ENV_SOCKET_ORG: &str = "ACHILLES_SOCKET_ORG";
/// Env var: first-party intel origin, e.g. `https://intel.trivault.org`.
pub const ENV_INTEL_BASE: &str = "ACHILLES_INTEL_BASE";
/// Optional NIST NVD 2.0 API key (higher rate limit).
pub const ENV_NVD_API_KEY: &str = "ACHILLES_NVD_API_KEY";
/// Override NVD CVE 2.0 URL.
pub const ENV_NVD: &str = "ACHILLES_NVD_URL";
/// Override GitHub Advisories REST base.
pub const ENV_GHSA: &str = "ACHILLES_GHSA_URL";
/// Override deps.dev v3 base.
pub const ENV_DEPSDEV: &str = "ACHILLES_DEPSDEV_URL";
/// Override OpenSSF Scorecard API base.
pub const ENV_SCORECARD: &str = "ACHILLES_SCORECARD_URL";
/// Override npm registry origin (`GET /{package}`).
pub const ENV_NPM_REGISTRY: &str = "ACHILLES_NPM_REGISTRY_URL";
/// Override PyPI JSON origin (`GET /{name}/{version}/json` is appended).
pub const ENV_PYPI: &str = "ACHILLES_PYPI_URL";
/// User-Agent on outbound intel/SCA HTTP.
pub const HTTP_USER_AGENT: &str = "achilles-harness-intel/0.1";

/// Stable ids used in logs, cache keys, and `intel_cache.source`.
pub const ID_OSV_QUERY: &str = "osv-query";
pub const ID_KEV_CATALOG: &str = "cisa-kev";
pub const ID_EPSS: &str = "first-epss";
pub const ID_SOCKET_PURL: &str = "socket-purl";
pub const ID_INTEL_BASE: &str = "achilles-intel-base";
pub const ID_NVD: &str = "nvd-cves";
pub const ID_GHSA: &str = "github-advisories";
pub const ID_DEPSDEV: &str = "deps-dev";
pub const ID_SCORECARD: &str = "openssf-scorecard";
pub const ID_NPM_REGISTRY: &str = "npm-registry";
pub const ID_PYPI: &str = "pypi-json";

/// How we talk to a source. Documented so a reader can grep the verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVerb {
    Get,
    PostJson,
}

/// One row in the source catalog.
#[derive(Debug, Clone, Copy)]
pub struct PublicSource {
    pub id: &'static str,
    pub name: &'static str,
    pub operator: &'static str,
    pub purpose: &'static str,
    pub verb: HttpVerb,
    pub default_url: &'static str,
    pub env_override: Option<&'static str>,
    /// Human docs (not fetched by the harness).
    pub docs_url: &'static str,
}

/// Every outbound intel/SCA host the product is allowed to call by default.
///
/// Add new public feeds here first; then wire `sca` / `intel` / `socket` to `resolved_url`.
pub const CATALOG: &[PublicSource] = &[
    PublicSource {
        id: ID_OSV_QUERY,
        name: "OSV query",
        operator: "Google OSV (api.osv.dev)",
        purpose: "Resolve lockfile packages to GHSA/OSV advisories and CVE aliases",
        verb: HttpVerb::PostJson,
        default_url: "https://api.osv.dev/v1/query",
        env_override: Some(ENV_OSV_QUERY),
        docs_url: "https://google.github.io/osv.dev/",
    },
    PublicSource {
        id: ID_KEV_CATALOG,
        name: "CISA KEV catalog",
        operator: "CISA",
        purpose: "Flag CVEs in the Known Exploited Vulnerabilities list",
        verb: HttpVerb::Get,
        default_url:
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        env_override: Some(ENV_KEV_CATALOG),
        docs_url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    },
    PublicSource {
        id: ID_EPSS,
        name: "FIRST EPSS",
        operator: "FIRST.org",
        purpose: "Exploitation probability (epss + percentile) per CVE",
        verb: HttpVerb::Get,
        default_url: "https://api.first.org/data/v1/epss",
        env_override: Some(ENV_EPSS),
        docs_url: "https://www.first.org/epss/",
    },
    PublicSource {
        id: ID_SOCKET_PURL,
        name: "Socket PURL alerts",
        operator: "Socket.dev",
        purpose: "Same lockfile packages as OSV → Socket alerts (supply chain, capability, quality, maintenance, CVE, license). Requires ACHILLES_SOCKET_API_TOKEN; skip if unset",
        verb: HttpVerb::PostJson,
        default_url: "https://api.socket.dev/v0/purl?alerts=true&poll=false",
        env_override: Some(ENV_SOCKET_PURL),
        docs_url: "https://docs.socket.dev/reference/batchpackagefetch",
    },
    PublicSource {
        id: ID_NVD,
        name: "NVD CVE 2.0",
        operator: "NIST",
        purpose: "CVSS and CWE for a CVE id. Optional ACHILLES_NVD_API_KEY",
        verb: HttpVerb::Get,
        default_url: "https://services.nvd.nist.gov/rest/json/cves/2.0",
        env_override: Some(ENV_NVD),
        docs_url: "https://nvd.nist.gov/developers/vulnerabilities",
    },
    PublicSource {
        id: ID_GHSA,
        name: "GitHub Security Advisories",
        operator: "GitHub",
        purpose: "GHSA- id → summary and CVSS (REST, no token required for public)",
        verb: HttpVerb::Get,
        default_url: "https://api.github.com/advisories",
        env_override: Some(ENV_GHSA),
        docs_url: "https://docs.github.com/en/rest/security-advisories/global-advisories",
    },
    PublicSource {
        id: ID_DEPSDEV,
        name: "deps.dev",
        operator: "Google Open Source Insights",
        purpose: "Package version metadata and project links",
        verb: HttpVerb::Get,
        default_url: "https://api.deps.dev/v3",
        env_override: Some(ENV_DEPSDEV),
        docs_url: "https://docs.deps.dev/api/v3/",
    },
    PublicSource {
        id: ID_SCORECARD,
        name: "OpenSSF Scorecard",
        operator: "OpenSSF",
        purpose: "Repo security score for github.com/org/repo",
        verb: HttpVerb::Get,
        default_url: "https://api.securityscorecards.dev/projects",
        env_override: Some(ENV_SCORECARD),
        docs_url: "https://github.com/ossf/scorecard",
    },
    PublicSource {
        id: ID_NPM_REGISTRY,
        name: "npm registry",
        operator: "npm, Inc.",
        purpose: "Package document `time` map — flag versions published less than 7 days ago",
        verb: HttpVerb::Get,
        default_url: "https://registry.npmjs.org",
        env_override: Some(ENV_NPM_REGISTRY),
        docs_url: "https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md",
    },
    PublicSource {
        id: ID_PYPI,
        name: "PyPI JSON",
        operator: "Python Packaging Authority",
        purpose: "Version upload time — flag releases published less than 7 days ago",
        verb: HttpVerb::Get,
        default_url: "https://pypi.org/pypi",
        env_override: Some(ENV_PYPI),
        docs_url: "https://docs.pypi.org/api/json/",
    },
];

pub fn source(id: &str) -> Option<&'static PublicSource> {
    CATALOG.iter().find(|s| s.id == id)
}

/// URL actually used at runtime (env override wins).
pub fn resolved_url(id: &str) -> Option<String> {
    let src = source(id)?;
    Some(match src.env_override {
        Some(var) => std::env::var(var).unwrap_or_else(|_| src.default_url.to_string()),
        None => src.default_url.to_string(),
    })
}

#[cfg(test)]
static TEST_OSV_URL: Mutex<Option<String>> = Mutex::new(None);
#[cfg(test)]
static TEST_SOCKET_URL: Mutex<Option<String>> = Mutex::new(None);

pub fn osv_query_url() -> String {
    #[cfg(test)]
    {
        if let Ok(url) = TEST_OSV_URL.lock() {
            if let Some(override_url) = url.as_ref() {
                return override_url.clone();
            }
        }
    }
    resolved_url(ID_OSV_QUERY).expect("osv is in CATALOG")
}

#[cfg(test)]
pub fn override_osv_query_url(url: Option<String>) {
    *TEST_OSV_URL.lock().expect("osv override") = url;
}

pub fn socket_org_slug() -> Option<String> {
    for key in [ENV_SOCKET_ORG, "SOCKET_ORG_SLUG"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

/// Socket PURL batch URL. `ACHILLES_SOCKET_URL` wins; else org-scoped if
/// `org` / `ACHILLES_SOCKET_ORG` / `SOCKET_ORG_SLUG` is set; else the catalog default.
pub fn socket_purl_url() -> String {
    socket_purl_url_for(None)
}

pub fn socket_purl_url_for(org: Option<&str>) -> String {
    #[cfg(test)]
    {
        if let Ok(url) = TEST_SOCKET_URL.lock() {
            if let Some(override_url) = url.as_ref() {
                return override_url.clone();
            }
        }
    }
    if let Ok(url) = std::env::var(ENV_SOCKET_PURL) {
        let trimmed = url.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    let org = org
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(socket_org_slug);
    if let Some(org) = org {
        let encoded: String = org
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        return format!("https://api.socket.dev/v0/orgs/{encoded}/purl?alerts=true&poll=false");
    }
    resolved_url(ID_SOCKET_PURL).expect("socket is in CATALOG")
}

#[cfg(test)]
pub fn override_socket_purl_url(url: Option<String>) {
    *TEST_SOCKET_URL.lock().expect("socket override") = url;
}

#[cfg(test)]
pub fn socket_url_is_overridden() -> bool {
    TEST_SOCKET_URL
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .is_some()
}

pub fn kev_catalog_url() -> String {
    resolved_url(ID_KEV_CATALOG).expect("kev is in CATALOG")
}

pub fn epss_base_url() -> String {
    resolved_url(ID_EPSS).expect("epss is in CATALOG")
}

pub fn nvd_cves_url() -> String {
    resolved_url(ID_NVD).expect("nvd is in CATALOG")
}

pub fn nvd_api_key() -> Option<String> {
    std::env::var(ENV_NVD_API_KEY)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn ghsa_advisories_url() -> String {
    resolved_url(ID_GHSA).expect("ghsa is in CATALOG")
}

pub fn depsdev_base_url() -> String {
    resolved_url(ID_DEPSDEV).expect("depsdev is in CATALOG")
}

pub fn scorecard_projects_url() -> String {
    resolved_url(ID_SCORECARD).expect("scorecard is in CATALOG")
}

pub fn npm_registry_url() -> String {
    resolved_url(ID_NPM_REGISTRY).expect("npm registry is in CATALOG")
}

pub fn pypi_json_base_url() -> String {
    resolved_url(ID_PYPI).expect("pypi is in CATALOG")
}

/// Optional first-party origin. Not a public internet default.
pub fn first_party_base() -> Option<String> {
    std::env::var(ENV_INTEL_BASE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Contract path on `ACHILLES_INTEL_BASE` (hosted later; see `.working_sessions`).
pub fn first_party_enrich_url(base: &str, cve_csv: &str) -> String {
    format!(
        "{}/v1/vulns/enrich?ids={}",
        base.trim_end_matches('/'),
        cve_csv
    )
}

pub fn first_party_lookup_url(base: &str, id: &str) -> String {
    format!("{}/v1/vulns/lookup?id={}", base.trim_end_matches('/'), id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_live_public_calls() {
        let ids: Vec<_> = CATALOG.iter().map(|s| s.id).collect();
        assert!(ids.contains(&ID_OSV_QUERY));
        assert!(ids.contains(&ID_KEV_CATALOG));
        assert!(ids.contains(&ID_EPSS));
        assert!(ids.contains(&ID_SOCKET_PURL));
        assert!(ids.contains(&ID_NVD));
        assert!(ids.contains(&ID_GHSA));
        assert!(ids.contains(&ID_DEPSDEV));
        assert!(ids.contains(&ID_SCORECARD));
        assert!(ids.contains(&ID_NPM_REGISTRY));
        assert!(ids.contains(&ID_PYPI));
        assert!(osv_query_url().starts_with("https://"));
        assert!(kev_catalog_url().contains("known_exploited"));
        assert!(epss_base_url().contains("first.org"));
        assert!(source(ID_SOCKET_PURL)
            .unwrap()
            .default_url
            .contains("api.socket.dev"));
    }
}

//! Optional hardcoded-value scan. Not a security engine: flags inlined
//! URLs, IPs, paths, and magic numbers that often show up in AI-generated
//! source and belong in config. Apache-2.0.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::OnceLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::engines::walk::{self, WalkOpts, WalkedFile};
use crate::types::{NewFinding, Severity};

const MAX_HITS: usize = 200;
const ENGINE: &str = "achilles-literals-v0";
const DISCLAIMER: &str = "Not a security finding. Hardcoded values are a stability / config-hygiene check (common in AI-generated code). Move this to config or a named constant if it might change per environment.";

struct Rule {
    id: &'static str,
    title: &'static str,
    kind: &'static str,
    /// Info = often fine to leave. Low = more worth moving to config/constants.
    severity: Severity,
    confidence: &'static str,
    why: &'static str,
    regex: Regex,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            Rule {
                id: "hardcoded-url",
                title: "Hardcoded URL",
                kind: "url",
                severity: Severity::Info,
                confidence: "low",
                why: "Public or stable URLs in source are often fine. Confirm only if this should change per environment.",
                regex: Regex::new(r#"(?i)https?://[^\s'"<>]+"#).expect("url"),
            },
            Rule {
                id: "hardcoded-connection",
                title: "Hardcoded connection string",
                kind: "connection",
                severity: Severity::Low,
                confidence: "medium",
                why: "Connection strings usually belong in config or secrets management, not source.",
                regex: Regex::new(
                    r#"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|kafka|jdbc|odbc):[^\s'"]+"#,
                )
                .expect("conn"),
            },
            Rule {
                id: "hardcoded-ip",
                title: "Hardcoded IP address",
                kind: "ip",
                severity: Severity::Low,
                confidence: "medium",
                why: "IPs tend to be environment-specific. Prefer config or service discovery.",
                regex: Regex::new(
                    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b",
                )
                .expect("ip"),
            },
            Rule {
                id: "hardcoded-path",
                title: "Hardcoded filesystem path",
                kind: "path",
                severity: Severity::Low,
                confidence: "medium",
                why: "Absolute paths rarely survive another machine. Prefer relative paths or config.",
                regex: Regex::new(
                    r#"(?:['"](?:/(?:home|Users|usr|var|opt|etc|tmp|data)/[^'"]+)['"]|['"][A-Za-z]:\\[^'"]+['"])"#,
                )
                .expect("path"),
            },
            Rule {
                id: "hardcoded-email",
                title: "Hardcoded email address",
                kind: "email",
                severity: Severity::Info,
                confidence: "low",
                why: "A contact or docs address in source is often fine. Flagged in case it is environment-specific.",
                regex: Regex::new(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b",
                )
                .expect("email"),
            },
            Rule {
                id: "hardcoded-hostname",
                title: "Hardcoded hostname",
                kind: "hostname",
                severity: Severity::Info,
                confidence: "low",
                why: "A stable hostname can live in source. Prefer config if this differs by environment.",
                regex: Regex::new(
                    r#"(?:=|:|:=)\s*['"]([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)['"]"#,
                )
                .expect("host"),
            },
            Rule {
                id: "hardcoded-timeout",
                title: "Hardcoded timeout or limit",
                kind: "magic-number",
                severity: Severity::Low,
                confidence: "medium",
                why: "Limits, thresholds, timeouts, and retries are the usual problem: they hide policy and often differ per environment. Prefer a named constant or config.",
                regex: Regex::new(
                    r#"(?i)\b(?:timeout|time_out|delay|retries?|max_retries|port|ttl|expire|expiry|sleep|interval|duration|wait|max_age|maxage|keep_?alive|batch_?size|chunk_?size|pool_?size|page_?size|limits?|thresholds?|quota)\s*(?:=|:=|:)\s*['"]?\d+"#,
                )
                .expect("named"),
            },
            Rule {
                id: "hardcoded-number",
                title: "Hardcoded numeric value",
                kind: "magic-number",
                severity: Severity::Low,
                confidence: "medium",
                why: "Unnamed magic numbers are brittle and hard to tune. Prefer a named constant or config.",
                regex: Regex::new(
                    r#"(?:const|let|var|val|final|static|constexpr)?\s*[A-Za-z_][\w]*\s*(?::\s*[A-Za-z_][\w<>,\s]*\s*)?(?:=|:=)\s*-?\d{4,}\b"#,
                )
                .expect("num"),
            },
        ]
    })
}

pub fn scan_literals(root: &Path) -> anyhow::Result<Vec<NewFinding>> {
    scan_literals_filtered(root, None, WalkOpts::default())
}

pub fn scan_literals_filtered(
    root: &Path,
    only_rel: Option<&HashSet<String>>,
    opts: WalkOpts,
) -> anyhow::Result<Vec<NewFinding>> {
    let files = walk::walk_files(root, opts, |_, rel| {
        if let Some(only) = only_rel {
            if !only.contains(rel) {
                return false;
            }
        }
        is_source(rel)
    });
    scan_literals_on(&files, only_rel, None)
}

pub fn scan_literals_on(
    files: &[WalkedFile],
    only_rel: Option<&HashSet<String>>,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<Vec<NewFinding>> {
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
        if !is_source(&file.rel) {
            continue;
        }
        if findings.len() >= MAX_HITS {
            break;
        }
        let Ok(text) = fs::read_to_string(&file.abs) else {
            continue;
        };
        if looks_minified(&text) {
            continue;
        }
        for (idx, line) in text.lines().enumerate() {
            if findings.len() >= MAX_HITS {
                break;
            }
            if skip_line(line) {
                continue;
            }
            for rule in rules() {
                if let Some(mat) = rule.regex.find(line) {
                    let value = mat.as_str();
                    if ignore_match(rule.id, value, line) {
                        continue;
                    }
                    findings.push(hit(rule, &file.rel, idx + 1, value));
                    break;
                }
            }
        }
    }
    Ok(findings)
}

fn is_source(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    if name.contains(".min.") {
        return false;
    }
    let Some((_, ext)) = name.rsplit_once('.') else {
        return matches!(
            name.as_str(),
            "dockerfile" | "makefile" | "rakefile" | "gemfile"
        );
    };
    matches!(
        ext,
        "rs" | "py"
            | "pyw"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "go"
            | "java"
            | "kt"
            | "kts"
            | "scala"
            | "groovy"
            | "cs"
            | "fs"
            | "php"
            | "phtml"
            | "rb"
            | "c"
            | "h"
            | "cc"
            | "cpp"
            | "cxx"
            | "hpp"
            | "hh"
            | "ino"
            | "swift"
            | "m"
            | "mm"
            | "dart"
            | "lua"
            | "pl"
            | "pm"
            | "r"
            | "jl"
            | "ex"
            | "exs"
            | "erl"
            | "hs"
            | "ml"
            | "mli"
            | "clj"
            | "cljs"
            | "nim"
            | "zig"
            | "vue"
            | "svelte"
            | "sql"
            | "proto"
            | "graphql"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "psm1"
    )
}

fn skip_line(line: &str) -> bool {
    let t = line.trim_start();
    if t.is_empty() {
        return true;
    }
    t.starts_with("//")
        || t.starts_with('#')
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.starts_with("--")
        || t.starts_with("<!--")
}

fn looks_minified(text: &str) -> bool {
    // Count newlines on a byte prefix so a 4 KiB cut never lands inside a
    // UTF-8 character (slicing `&str` at that index panics).
    let bytes = text.as_bytes();
    let take = bytes.len().min(4_096);
    if take < 2_048 {
        return false;
    }
    bytes[..take].iter().filter(|&&b| b == b'\n').count() < 3
}

fn ignore_match(rule_id: &str, value: &str, line: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    match rule_id {
        "hardcoded-url" => url_is_noise(&lower) || line_is_license(line),
        "hardcoded-ip" => matches!(
            value,
            "0.0.0.0" | "127.0.0.1" | "255.255.255.255" | "255.255.255.0"
        ),
        "hardcoded-email" => {
            lower.contains("example.com")
                || lower.contains("example.org")
                || lower.ends_with("@localhost")
                || lower.contains("users.noreply.github.com")
        }
        "hardcoded-hostname" => {
            let host = value
                .trim_matches(|c: char| c == '"' || c == '\'' || c == '=' || c == ':' || c == ' ')
                .to_ascii_lowercase();
            host == "localhost"
                || host.ends_with(".example.com")
                || host == "example.com"
                || host.ends_with(".local")
                || host.ends_with(".test")
                || host.parse::<std::net::Ipv4Addr>().is_ok()
        }
        "hardcoded-number" => number_is_noise(value),
        "hardcoded-timeout" => named_number_is_noise(value),
        _ => false,
    }
}

fn url_is_noise(url: &str) -> bool {
    const SKIP_HOSTS: &[&str] = &[
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "127.0.0.1",
        "schema.org",
        "w3.org",
        "www.w3.org",
        "json-schema.org",
        "spdx.org",
        "unicode.org",
        "ietf.org",
        "apache.org/licenses",
        "opensource.org",
        "gnu.org",
        "mozilla.org/mpl",
        "creativecommons.org",
        "docs.rs/",
        "doc.rust-lang.org",
        "golang.org/",
        "pkg.go.dev/",
        "www.python.org/",
        "nodejs.org/",
    ];
    SKIP_HOSTS.iter().any(|h| url.contains(h))
}

fn line_is_license(line: &str) -> bool {
    let t = line.to_ascii_lowercase();
    t.contains("spdx") || t.contains("copyright") || t.contains("license")
}

fn number_is_noise(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let Ok(n) = digits.parse::<i64>() else {
        return true;
    };
    if (1970..=2039).contains(&n) {
        return true;
    }
    matches!(
        n,
        1000 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768 | 65535 | 65536
    )
}

fn named_number_is_noise(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let Ok(n) = digits.parse::<i64>() else {
        return true;
    };
    // 0/1, HTTP/TLS ports, and buffer sizes that are not environment-specific.
    n <= 1 || number_is_noise(value) || matches!(n, 80 | 443)
}

fn hit(rule: &Rule, rel: &str, line: usize, sink: &str) -> NewFinding {
    let mut hasher = Sha256::new();
    hasher.update(rule.id.as_bytes());
    hasher.update(rel.as_bytes());
    hasher.update(line.to_string().as_bytes());
    hasher.update(sink.as_bytes());
    let digest = hasher.finalize();
    let preview: String = sink.chars().take(80).collect();
    NewFinding {
        fingerprint: format!(
            "{}:{}",
            rule.id,
            digest
                .iter()
                .take(12)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        severity: rule.severity,
        confidence: rule.confidence.into(),
        category: "literals".into(),
        rule_id: rule.id.into(),
        title: format!("{} (not a security finding)", rule.title),
        description: format!("{DISCLAIMER} {} `{}:{}`.", rule.why, rel, line),
        path: Some(rel.to_string()),
        line_start: Some(line as i64),
        line_end: Some(line as i64),
        cwe: vec![],
        cve: vec![],
        evidence: serde_json::json!({
            "engine": ENGINE,
            "kind": "literals",
            "concern": "stability",
            "security": false,
            "literalKind": rule.kind,
            "preview": preview,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn flags_url_ip_path_and_timeout() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("app.py"),
            "API = \"https://api.prod.internal/v1\"\nHOST = \"10.1.2.3\"\nLOG = \"/var/log/app/out.log\"\ntimeout = 5000\n",
        )
        .unwrap();
        let hits = scan_literals(tmp.path()).unwrap();
        let ids: Vec<_> = hits.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"hardcoded-url"), "{ids:?}");
        assert!(ids.contains(&"hardcoded-ip"), "{ids:?}");
        assert!(ids.contains(&"hardcoded-path"), "{ids:?}");
        assert!(ids.contains(&"hardcoded-timeout"), "{ids:?}");
        assert!(hits.iter().all(|f| f.category == "literals"));
        assert!(hits.iter().all(|f| f.cwe.is_empty()));
        assert!(hits
            .iter()
            .all(|f| f.title.contains("not a security finding")));
        let url = hits.iter().find(|f| f.rule_id == "hardcoded-url").unwrap();
        let limit = hits
            .iter()
            .find(|f| f.rule_id == "hardcoded-timeout")
            .unwrap();
        assert_eq!(url.severity, Severity::Info);
        assert_eq!(limit.severity, Severity::Low);
    }

    #[test]
    fn skips_comments_docs_and_example_hosts() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("ok.ts"),
            "// const API = \"https://api.prod.internal/v1\"\nconst docs = \"https://example.com/x\"\nconst n = 1\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("notes.md"),
            "https://api.prod.internal/v1\n",
        )
        .unwrap();
        let hits = scan_literals(tmp.path()).unwrap();
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn looks_minified_survives_utf8_at_4k() {
        let mut text = "a".repeat(4094);
        text.push('म');
        text.push_str(&"b".repeat(200));
        assert!(looks_minified(&text));
    }

    #[test]
    fn skips_loopback_and_common_powers() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("net.go"),
            "bind := \"127.0.0.1\"\nconst pageSize = 1024\nport := 443\n",
        )
        .unwrap();
        let hits = scan_literals(tmp.path()).unwrap();
        assert!(hits.is_empty(), "{hits:?}");
    }
}

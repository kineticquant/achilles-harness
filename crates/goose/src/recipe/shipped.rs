//! First-party recipes compiled into every Achilles build.
//!
//! YAML under repo-root `recipes/` is embedded at compile time (same pattern as
//! skills) and written to `data/shipped-recipes/` so the existing file-based
//! library and scheduler can see them.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use include_dir::{include_dir, Dir};

use crate::config::paths::Paths;

static SHIPPED_RECIPES_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../recipes");

pub const SHIPPED_RECIPES_DIR_NAME: &str = "shipped-recipes";

pub fn shipped_recipes_dir() -> PathBuf {
    Paths::data_dir().join(SHIPPED_RECIPES_DIR_NAME)
}

pub fn is_shipped_recipe_path(path: &Path) -> bool {
    let shipped = shipped_recipes_dir();
    path.starts_with(&shipped)
        || path
            .components()
            .any(|c| c.as_os_str() == SHIPPED_RECIPES_DIR_NAME)
}

pub fn ensure_shipped_recipes() -> Result<PathBuf> {
    let dir = shipped_recipes_dir();
    fs::create_dir_all(&dir).with_context(|| {
        format!(
            "Failed to create shipped recipes directory {}",
            dir.display()
        )
    })?;

    let mut expected = HashSet::new();
    for file in SHIPPED_RECIPES_DIR.files() {
        let Some(name) = file.path().file_name() else {
            continue;
        };
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.ends_with(".yaml") && !name.ends_with(".yml") {
            continue;
        }
        expected.insert(name.to_string());
        let dest = dir.join(name);
        let contents = file.contents();
        let needs_write = fs::read(&dest)
            .map(|existing| existing != contents)
            .unwrap_or(true);
        if needs_write {
            fs::write(&dest, contents)
                .with_context(|| format!("Failed to write shipped recipe {}", dest.display()))?;
        }
    }

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if (name.ends_with(".yaml") || name.ends_with(".yml")) && !expected.contains(name) {
                let _ = fs::remove_file(&path);
            }
        }
    }

    Ok(dir)
}

pub fn shipped_recipe_filenames() -> Vec<&'static str> {
    SHIPPED_RECIPES_DIR
        .files()
        .filter_map(|file| file.path().file_name()?.to_str())
        .filter(|name| name.ends_with(".yaml") || name.ends_with(".yml"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn embed_includes_the_three_base_recipes() {
        let names = shipped_recipe_filenames();
        for expected in [
            "scan-recap.yaml",
            "sca-hygiene-report.yaml",
            "security-review.yaml",
        ] {
            assert!(
                names.contains(&expected),
                "missing {expected} in embedded recipes: {names:?}"
            );
        }
    }

    #[test]
    fn ensure_writes_yaml_and_skips_readme() {
        let temp = tempdir().unwrap();
        let _guard = env_lock::lock_env([("GOOSE_PATH_ROOT", Some(temp.path().to_str().unwrap()))]);

        let dir = ensure_shipped_recipes().unwrap();
        assert_eq!(dir, temp.path().join("data").join(SHIPPED_RECIPES_DIR_NAME));
        assert!(dir.join("scan-recap.yaml").is_file());
        assert!(dir.join("sca-hygiene-report.yaml").is_file());
        assert!(dir.join("security-review.yaml").is_file());
        assert!(!dir.join("README.md").exists());
        assert!(is_shipped_recipe_path(&dir.join("scan-recap.yaml")));

        let listed = crate::recipe::local_recipes::list_local_recipes().unwrap();
        let titles: Vec<String> = listed.into_iter().map(|(_, r)| r.title).collect();
        assert!(titles.iter().any(|t| t == "Scan and recap"));
        assert!(titles.iter().any(|t| t == "SCA and pinning report"));
        assert!(titles.iter().any(|t| t == "Security review this PR"));
    }
}

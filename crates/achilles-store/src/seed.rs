//! Bundled Class-L `goose review` checks. Proprietary — `LICENSE-ACHILLES`.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::store::ACHILLES_FOLDER;

const SECRETS_CHECK: &str = include_str!("../checks/appsec-secrets.md");
const DEPS_CHECK: &str = include_str!("../checks/appsec-deps.md");

pub fn seed_bundled_review_checks(data_dir: &Path) -> Result<PathBuf> {
    let dir = data_dir.join(ACHILLES_FOLDER).join("checks");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("appsec-secrets.md"), SECRETS_CHECK)?;
    std::fs::write(dir.join("appsec-deps.md"), DEPS_CHECK)?;
    Ok(dir)
}

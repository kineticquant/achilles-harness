//! Bundled Class-L `goose review` checks. Apache-2.0.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::store::ACHILLES_FOLDER;

const SECRETS_CHECK: &str = include_str!("../checks/appsec-secrets.md");
const DEPS_CHECK: &str = include_str!("../checks/appsec-deps.md");
const SURFACES_CHECK: &str = include_str!("../checks/appsec-surfaces.md");
const SAST_CHECK: &str = include_str!("../checks/appsec-sast.md");
const DELTA_CHECK: &str = include_str!("../checks/appsec-delta.md");
const INVESTIGATE_CHECK: &str = include_str!("../checks/appsec-investigate.md");
const REVALIDATE_CHECK: &str = include_str!("../checks/appsec-revalidate.md");

pub fn seed_bundled_review_checks(data_dir: &Path) -> Result<PathBuf> {
    let dir = data_dir.join(ACHILLES_FOLDER).join("checks");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("appsec-secrets.md"), SECRETS_CHECK)?;
    std::fs::write(dir.join("appsec-deps.md"), DEPS_CHECK)?;
    std::fs::write(dir.join("appsec-surfaces.md"), SURFACES_CHECK)?;
    std::fs::write(dir.join("appsec-sast.md"), SAST_CHECK)?;
    std::fs::write(dir.join("appsec-delta.md"), DELTA_CHECK)?;
    std::fs::write(dir.join("appsec-investigate.md"), INVESTIGATE_CHECK)?;
    std::fs::write(dir.join("appsec-revalidate.md"), REVALIDATE_CHECK)?;
    Ok(dir)
}

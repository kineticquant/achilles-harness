use include_dir::{include_dir, Dir};

/// Skills compiled into every build, including shipped release binaries.
/// Put product skills here when they should be available to users out of the box.
static SHIPPED_SKILLS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/skills/builtins");

/// First-party methodology library at repo-root `skills/` (folder-per-skill,
/// same layout as public Agent Skills repos). Only `SKILL.md` files are skills.
static LIBRARY_SKILLS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../skills");

/// Local-development builtins. Included only when `debug_assertions` is on, so
/// `cargo build --release` / packaged Achilles does not embed them.
/// Drop a skill here (or move it from `builtins/`) to keep it for local use
/// without shipping it.
#[cfg(debug_assertions)]
static DEV_SKILLS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/skills/dev-builtins");

fn md_contents(dir: &Dir<'static>) -> impl Iterator<Item = &'static str> {
    dir.files()
        .filter(|f| f.path().extension().is_some_and(|ext| ext == "md"))
        .filter_map(|f| f.contents_utf8())
}

fn collect_skill_md(dir: &Dir<'static>, out: &mut Vec<&'static str>) {
    for file in dir.files() {
        if file
            .path()
            .file_name()
            .is_some_and(|name| name == "SKILL.md")
        {
            if let Some(text) = file.contents_utf8() {
                out.push(text);
            }
        }
    }
    for nested in dir.dirs() {
        collect_skill_md(nested, out);
    }
}

fn library_skill_md(dir: &Dir<'static>) -> Vec<&'static str> {
    let mut out = Vec::new();
    collect_skill_md(dir, &mut out);
    out
}

pub fn get_all() -> Vec<&'static str> {
    let mut skills: Vec<&'static str> = md_contents(&SHIPPED_SKILLS_DIR).collect();
    skills.extend(library_skill_md(&LIBRARY_SKILLS_DIR));
    #[cfg(debug_assertions)]
    skills.extend(md_contents(&DEV_SKILLS_DIR));
    skills
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goose_doc_guide_is_not_shipped() {
        assert!(
            md_contents(&SHIPPED_SKILLS_DIR)
                .all(|content| !content.contains("name: goose-doc-guide")),
            "goose-doc-guide belongs in dev-builtins/, not builtins/"
        );
    }

    #[test]
    fn shipped_skills_include_appsec_and_codebase() {
        let joined: String = md_contents(&SHIPPED_SKILLS_DIR)
            .collect::<Vec<_>>()
            .join("\n");
        for name in [
            "review-findings",
            "propose-fix",
            "code-review",
            "rotate-secret",
            "dependency-risk",
            "map-attack-surface",
            "map-codebase",
        ] {
            assert!(
                joined.contains(&format!("name: {name}")),
                "missing shipped skill {name}"
            );
        }
    }

    #[test]
    fn library_skills_are_compiled_in() {
        let joined: String = library_skill_md(&LIBRARY_SKILLS_DIR).join("\n");
        for name in [
            "security-review",
            "threat-model",
            "variant-hunt",
            "auth-review",
            "github-actions-security",
            "stack-security",
        ] {
            assert!(
                joined.contains(&format!("name: {name}")),
                "missing library skill {name}"
            );
        }
        assert!(
            !joined.contains("# Achilles skills"),
            "skills/README.md must not be compiled as a skill"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_builds_include_goose_doc_guide() {
        assert!(get_all()
            .iter()
            .any(|content| content.contains("name: goose-doc-guide")));
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_builds_omit_dev_builtins() {
        assert!(get_all()
            .iter()
            .all(|content| !content.contains("name: goose-doc-guide")));
    }
}

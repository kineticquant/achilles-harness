//! Limit secrets/surface checks to git-changed paths when `mode=diff`.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// Relative paths changed vs HEAD (unstaged, staged, untracked). `None` means
/// do not filter (full tree). Empty set means a git repo with a clean tree.
pub fn changed_rel_paths(root: &Path) -> Option<HashSet<String>> {
    if !git_available(root) {
        return None;
    }
    let mut set = HashSet::new();
    push_names(&mut set, root, &["diff", "--name-only", "HEAD"]);
    push_names(&mut set, root, &["diff", "--name-only", "--cached"]);
    push_names(
        &mut set,
        root,
        &["ls-files", "--others", "--exclude-standard"],
    );
    Some(set)
}

pub fn is_diff_mode(mode: &str) -> bool {
    mode.eq_ignore_ascii_case("diff")
}

fn git_available(root: &Path) -> bool {
    Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn push_names(set: &mut HashSet<String>, root: &Path, args: &[&str]) {
    let Ok(output) = Command::new("git").arg("-C").arg(root).args(args).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(text) = String::from_utf8(output.stdout) else {
        return;
    };
    for line in text.lines() {
        let rel = line.trim().replace('\\', "/");
        if !rel.is_empty() {
            set.insert(rel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_git_dir_is_unfiltered() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(changed_rel_paths(tmp.path()).is_none());
    }
}

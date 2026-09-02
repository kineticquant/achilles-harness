//! Secrets that still live in git history after they left the working tree.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;

use crate::engines::secrets;
use crate::types::NewFinding;

const MAX_COMMITS: &str = "120";
const MAX_STDOUT: usize = 2_000_000;
const MAX_HITS: usize = 80;

pub fn scan_history(
    root: &Path,
    live_rels: &HashSet<String>,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<Vec<NewFinding>> {
    if !root.join(".git").exists() {
        return Ok(Vec::new());
    }
    if crate::engines::abort::flagged(cancel) {
        return Ok(Vec::new());
    }
    let git_dir = root.join(".git");
    let output = Command::new("git")
        .args([
            "--git-dir",
            &git_dir.to_string_lossy(),
            "--work-tree",
            &root.to_string_lossy(),
            "log",
            "-p",
            "--all",
            "--max-count",
            MAX_COMMITS,
            "--no-color",
            "--format=%nACHILLES_COMMIT %H",
        ])
        .output();
    let Ok(output) = output else {
        return Ok(Vec::new());
    };
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let mut stdout = output.stdout;
    stdout.truncate(MAX_STDOUT);
    let text = String::from_utf8_lossy(&stdout);
    parse_patch(&text, live_rels, cancel)
}

fn parse_patch(
    text: &str,
    live_rels: &HashSet<String>,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<Vec<NewFinding>> {
    let mut findings = Vec::new();
    let mut commit = String::new();
    let mut rel = String::new();
    let mut skip_hunk = false;
    for line in text.lines() {
        if crate::engines::abort::flagged(cancel) || findings.len() >= MAX_HITS {
            break;
        }
        if let Some(rest) = line.strip_prefix("ACHILLES_COMMIT ") {
            commit = rest.trim().chars().take(12).collect();
            rel.clear();
            skip_hunk = false;
            continue;
        }
        if line.starts_with("diff --git ") {
            rel = diff_path(line).unwrap_or_default();
            skip_hunk = live_rels.contains(&rel);
            continue;
        }
        if line.starts_with("Binary files ") {
            skip_hunk = true;
            continue;
        }
        if skip_hunk || commit.is_empty() || rel.is_empty() {
            continue;
        }
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        let added = &line[1..];
        for mut hit in secrets::hits_on_line(&rel, 0, added) {
            hit.category = "history".into();
            hit.rule_id = format!("{}-history", hit.rule_id);
            hit.title = format!("{} in git history", hit.title);
            hit.path = Some(format!("git:{commit}/{rel}"));
            hit.description = format!(
                "Credential still present in git history (commit {commit}, `{}`). Rotate it and purge the history; deleting the working-tree file is not enough.",
                rel
            );
            if let Some(obj) = hit.evidence.as_object_mut() {
                obj.insert("engine".into(), serde_json::json!("achilles-history-v0"));
                obj.insert("commit".into(), serde_json::json!(commit));
                obj.insert("treePath".into(), serde_json::json!(rel));
            }
            hit.fingerprint =
                secrets::fingerprint(&hit.rule_id, &format!("git:{commit}/{rel}"), 0, added);
            findings.push(hit);
            if findings.len() >= MAX_HITS {
                break;
            }
        }
    }
    Ok(findings)
}

fn diff_path(line: &str) -> Option<String> {
    let b = line.split(" b/").last()?.trim();
    if b == "/dev/null" || b.is_empty() {
        return None;
    }
    Some(b.trim_start_matches("b/").replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;

    #[test]
    fn deleted_commit_still_flags_history() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path();
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .current_dir(repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "Test"]);
        fs::write(repo.join("gone.env"), "KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        run(&["add", "gone.env"]);
        run(&["-c", "commit.gpgsign=false", "commit", "-m", "leak"]);
        fs::remove_file(repo.join("gone.env")).unwrap();
        run(&["add", "-A"]);
        run(&["-c", "commit.gpgsign=false", "commit", "-m", "delete"]);

        let hits = scan_history(repo, &HashSet::new(), None).unwrap();
        assert!(
            hits.iter()
                .any(|h| h.category == "history" && h.rule_id.contains("aws-access-key")),
            "{hits:?}"
        );
    }

    #[test]
    fn live_tree_file_is_skipped() {
        let tmp = tempdir().unwrap();
        let repo = tmp.path();
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .current_dir(repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "Test"]);
        fs::write(repo.join("live.env"), "KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        run(&["add", "live.env"]);
        run(&["-c", "commit.gpgsign=false", "commit", "-m", "leak"]);
        let mut live = HashSet::new();
        live.insert("live.env".into());
        let hits = scan_history(repo, &live, None).unwrap();
        assert!(hits.is_empty(), "{hits:?}");
    }
}

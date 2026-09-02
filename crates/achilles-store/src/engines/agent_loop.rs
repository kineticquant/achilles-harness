//! Bounded JSON agent turns for Investigate/Deep. Apache-2.0.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;

use super::agent::{ScanCompleter, VerdictJson};
use super::budget::ScanBudget;
use super::walk::WalkedFile;
use crate::store::AchillesStore;

pub const MAX_TURNS: usize = 8;
pub const MAX_READ_CHARS: usize = 80_000;
pub const MAX_GREP_HITS: usize = 30;
pub const REVIEW_SNIPPET_CTX: usize = 80;

pub struct LoopIo<'a> {
    pub root: &'a Path,
    pub store: Option<&'a AchillesStore>,
    pub files: &'a [WalkedFile],
    pub corpus: &'a mut String,
    pub allowed: &'a mut HashSet<String>,
}

pub enum LoopMode {
    Review,
    Unit,
}

#[derive(Debug)]
pub enum LoopFinish {
    Verdict(VerdictJson),
    Findings(Value),
}

enum Turn {
    Read {
        path: String,
        start: i64,
        end: i64,
    },
    Ledger {
        finding_id: String,
    },
    Grep {
        pattern: String,
        path: Option<String>,
    },
    Verdict(VerdictJson),
    Findings(Value),
    Unknown,
}

pub async fn drive(
    completer: &Arc<dyn ScanCompleter>,
    system: &str,
    mut user: String,
    mode: LoopMode,
    io: LoopIo<'_>,
    budget: Option<&ScanBudget>,
    max_turns: usize,
) -> Result<LoopFinish> {
    let max_turns = if max_turns == 0 { MAX_TURNS } else { max_turns };
    for turn in 0..max_turns {
        let out = completer.complete(system.to_string(), user.clone()).await?;
        if let Some(budget) = budget {
            budget.add_cost(out.cost_usd)?;
        }
        let raw = out.text;
        match parse_turn(&raw, &mode) {
            Turn::Verdict(v) => return Ok(LoopFinish::Verdict(v)),
            Turn::Findings(v) => return Ok(LoopFinish::Findings(v)),
            Turn::Read { path, start, end } => {
                let (blob, rel) = read_span(io.root, &path, start, end);
                if let Some(rel) = rel {
                    io.allowed.insert(rel);
                }
                io.corpus.push_str(&blob);
                user.push_str("\n\n--- read ---\n");
                user.push_str(&blob);
                trim_user(&mut user);
            }
            Turn::Ledger { finding_id } => {
                let (blob, rel) = ledger_blob(io.store, io.root, &finding_id).await;
                if let Some(rel) = rel {
                    io.allowed.insert(rel);
                }
                io.corpus.push_str(&blob);
                user.push_str("\n\n--- ledger ---\n");
                user.push_str(&blob);
                trim_user(&mut user);
            }
            Turn::Grep { pattern, path } => {
                let blob = grep_indexed(io.root, io.files, &pattern, path.as_deref());
                io.corpus.push_str(&blob);
                user.push_str("\n\n--- grep ---\n");
                user.push_str(&blob);
                trim_user(&mut user);
            }
            Turn::Unknown => {
                if turn + 1 == max_turns {
                    anyhow::bail!("model did not finish the agent loop");
                }
                user.push_str(
                    "\n\nReply with one JSON object: read, ledger, grep, verdict, or findings.",
                );
            }
        }
    }
    anyhow::bail!("turn budget exhausted")
}

fn parse_turn(text: &str, mode: &LoopMode) -> Turn {
    let Some(value) = super::agent::extract_json(text) else {
        return Turn::Unknown;
    };
    if let Some(read) = value.get("read") {
        let path = read
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let start = read.get("start").and_then(|v| v.as_i64()).unwrap_or(1);
        let end = read
            .get("end")
            .and_then(|v| v.as_i64())
            .unwrap_or(start + 80);
        if !path.is_empty() {
            return Turn::Read { path, start, end };
        }
    }
    if let Some(id) = value
        .pointer("/ledger/finding_id")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("ledger").and_then(|v| v.as_str()))
    {
        if !id.is_empty() {
            return Turn::Ledger {
                finding_id: id.to_string(),
            };
        }
    }
    if let Some(grep) = value.get("grep") {
        let pattern = grep
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let path = grep
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty());
        if !pattern.is_empty() {
            return Turn::Grep { pattern, path };
        }
    }
    match mode {
        LoopMode::Review => {
            if let Some(v) = super::agent::parse_verdict_value(&value) {
                return Turn::Verdict(v);
            }
        }
        LoopMode::Unit => {
            if value.get("findings").is_some() {
                return Turn::Findings(value);
            }
        }
    }
    Turn::Unknown
}

pub fn normalize_rel(rel: &str) -> Option<String> {
    let rel = rel.replace('\\', "/");
    if rel.is_empty() || Path::new(&rel).is_absolute() {
        return None;
    }
    if rel.split('/').any(|p| p == "..") {
        return None;
    }
    Some(rel.trim_start_matches("./").to_string())
}

fn resolve_rel(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = normalize_rel(rel)?;
    let joined = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let canon = joined.canonicalize().ok()?;
    let root_canon = root.canonicalize().ok()?;
    canon.starts_with(&root_canon).then_some(canon)
}

fn read_span(root: &Path, rel: &str, start: i64, end: i64) -> (String, Option<String>) {
    let Some(norm) = normalize_rel(rel) else {
        return (
            format!("read failed: path {rel} is outside the workspace"),
            None,
        );
    };
    let Some(path) = resolve_rel(root, &norm) else {
        return (
            format!("read failed: path {rel} is outside the workspace"),
            None,
        );
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return (format!("read failed: could not open {rel}"), None);
    };
    let start = start.max(1) as usize;
    let end = (end as usize).max(start);
    let mut out = String::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if n < start {
            continue;
        }
        if n > end {
            break;
        }
        if out.len() + line.len() > MAX_READ_CHARS {
            out.push_str("\n… truncated …\n");
            break;
        }
        out.push_str(&format!("{n}: {line}\n"));
    }
    let blob = if out.is_empty() {
        format!("read: no lines in {norm}:{start}-{end}")
    } else {
        format!("{norm}\n{out}")
    };
    (blob, Some(norm))
}

async fn ledger_blob(
    store: Option<&AchillesStore>,
    root: &Path,
    finding_id: &str,
) -> (String, Option<String>) {
    let Some(store) = store else {
        return ("ledger failed: store unavailable".into(), None);
    };
    let Ok(Some(finding)) = store.get_finding(finding_id).await else {
        return (
            format!("ledger failed: unknown finding_id {finding_id}"),
            None,
        );
    };
    let snippet = match (&finding.path, finding.line_start) {
        (Some(rel), Some(line)) => {
            crate::engines::investigate::agent_brief(root, rel, line, REVIEW_SNIPPET_CTX)
        }
        _ => String::new(),
    };
    let allowed = finding.path.as_deref().and_then(normalize_rel);
    let blob = format!(
        "id={}\nrule={}\nseverity={}\nstate={}\npath={}:{}\ntitle={}\n\n{}\n",
        finding.id,
        finding.rule_id,
        finding.severity,
        finding.state,
        finding.path.as_deref().unwrap_or(""),
        finding.line_start.unwrap_or(0),
        finding.title,
        snippet
    );
    (blob, allowed)
}

fn grep_indexed(root: &Path, files: &[WalkedFile], pattern: &str, only: Option<&str>) -> String {
    if pattern.len() < 3 || pattern.len() > 120 {
        return "grep failed: pattern must be 3-120 characters".into();
    }
    let mut hits = Vec::new();
    for file in files {
        if hits.len() >= MAX_GREP_HITS {
            break;
        }
        if let Some(only) = only {
            let only = only.replace('\\', "/");
            let rel = file.rel.replace('\\', "/");
            if rel != only && !rel.starts_with(&format!("{only}/")) {
                continue;
            }
        }
        let path = if file.abs.exists() {
            file.abs.clone()
        } else {
            root.join(&file.rel)
        };
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if line.contains(pattern) {
                let preview: String = line.chars().take(200).collect();
                hits.push(format!("{}:{}:{preview}", file.rel, i + 1));
                if hits.len() >= MAX_GREP_HITS {
                    break;
                }
            }
        }
    }
    if hits.is_empty() {
        format!("grep: no matches for {pattern:?}")
    } else {
        hits.join("\n")
    }
}

fn trim_user(user: &mut String) {
    const MAX: usize = 100_000;
    if user.len() <= MAX {
        return;
    }
    let keep = MAX / 2;
    let start: String = user.chars().take(keep / 2).collect();
    let end: String = user
        .chars()
        .skip(user.chars().count().saturating_sub(keep))
        .collect();
    *user = format!("{start}\n… [earlier loop context dropped] …\n{end}");
}

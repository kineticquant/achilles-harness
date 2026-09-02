//! Opt-in local-diff engine. Reads staged, unstaged, and untracked changes,
//! compact the functions those hunks touch, then check introduced logic
//! against the rest of the tree. Apache-2.0.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::engines::sast;
use crate::engines::secrets;
use crate::engines::units;
use crate::engines::walk::{self, WalkedFile};
use crate::types::{NewFinding, Severity};

const ENGINE: &str = "achilles-delta-v0";
const MAX_HITS: usize = 200;
const MAX_DIFF_BYTES: usize = 1_500_000;
const MAX_ADDED_LINES: usize = 4_000;
const MAX_UNITS: usize = 48;
const MAX_PEERS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Staged,
    Unstaged,
    Untracked,
    Mixed,
}

impl Origin {
    fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Unstaged => "unstaged",
            Self::Untracked => "untracked",
            Self::Mixed => "mixed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddedLine {
    pub path: String,
    pub line: i64,
    pub text: String,
    pub origin: Origin,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntroducedUnit {
    pub path: String,
    pub name: String,
    pub line_start: i64,
    pub line_end: i64,
    pub origin: Origin,
    pub added_count: usize,
}

pub struct WorkingTreeDelta {
    pub added: Vec<AddedLine>,
    pub units: Vec<IntroducedUnit>,
    pub files_changed: usize,
}

pub struct DeltaOutcome {
    pub findings: Vec<NewFinding>,
    pub compact: serde_json::Value,
    pub skipped_reason: Option<String>,
}

/// Parse the working tree vs HEAD (staged + unstaged) plus untracked files.
pub fn working_tree_delta(root: &Path, include_vendor: bool) -> Option<WorkingTreeDelta> {
    if !git_available(root) {
        return None;
    }
    let staged = git_names(root, &["diff", "--name-only", "--cached"]);
    let unstaged = git_names(root, &["diff", "--name-only"]);
    let untracked = git_names(root, &["ls-files", "--others", "--exclude-standard"]);
    let patch = git_stdout(
        root,
        &[
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            "-U3",
            "HEAD",
        ],
    )
    .unwrap_or_default();
    let mut added = Vec::new();
    let mut files: HashSet<String> = HashSet::new();
    if patch.len() <= MAX_DIFF_BYTES {
        for file in parse_unified(&patch) {
            if file.binary || file.deleted {
                continue;
            }
            if skip_rel(&file.path, include_vendor) {
                continue;
            }
            let origin = origin_of(&file.path, &staged, &unstaged, false);
            files.insert(file.path.clone());
            for line in file.added {
                if added.len() >= MAX_ADDED_LINES {
                    break;
                }
                added.push(AddedLine {
                    path: file.path.clone(),
                    line: line.line,
                    text: line.text,
                    origin,
                });
            }
        }
    }
    for rel in &untracked {
        if skip_rel(rel, include_vendor) || walk::is_binary_name(rel) {
            continue;
        }
        files.insert(rel.clone());
        let abs = root.join(rel);
        let Ok(meta) = fs::metadata(&abs) else {
            continue;
        };
        if meta.len() > walk::MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = fs::read_to_string(&abs) else {
            continue;
        };
        for (idx, line) in text.lines().enumerate() {
            if added.len() >= MAX_ADDED_LINES {
                break;
            }
            added.push(AddedLine {
                path: rel.clone(),
                line: (idx + 1) as i64,
                text: line.to_string(),
                origin: Origin::Untracked,
            });
        }
    }
    let units = compact_units(root, &added);
    Some(WorkingTreeDelta {
        files_changed: files.len(),
        added,
        units,
    })
}

pub fn scan_delta_on(
    root: &Path,
    files: &[WalkedFile],
    include_vendor: bool,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<DeltaOutcome> {
    let Some(delta) = working_tree_delta(root, include_vendor) else {
        return Ok(DeltaOutcome {
            findings: Vec::new(),
            compact: serde_json::json!({ "filesChanged": 0, "units": [] }),
            skipped_reason: Some("not-git".into()),
        });
    };
    if crate::engines::abort::flagged(cancel) {
        return Ok(DeltaOutcome {
            findings: Vec::new(),
            compact: compact_json(&delta),
            skipped_reason: Some("cancelled".into()),
        });
    }
    let peers = token_index(files, cancel);
    let mut findings = Vec::new();
    let unit_of = |path: &str, line: i64| -> Option<&IntroducedUnit> {
        delta
            .units
            .iter()
            .find(|u| u.path == path && line >= u.line_start && line <= u.line_end)
    };
    for added in &delta.added {
        if findings.len() >= MAX_HITS || crate::engines::abort::flagged(cancel) {
            break;
        }
        let line_no = added.line as usize;
        let unit = unit_of(&added.path, added.line);
        for hit in sast::hits_on_line(&added.path, line_no, &added.text) {
            if findings.len() >= MAX_HITS {
                break;
            }
            findings.push(as_delta(hit, added, unit, &peers, "sast"));
        }
        for hit in secrets::hits_on_line(&added.path, line_no, &added.text) {
            if findings.len() >= MAX_HITS {
                break;
            }
            findings.push(as_delta(hit, added, unit, &peers, "secrets"));
        }
    }
    findings.extend(auth_gaps(&delta, files, cancel));
    findings.truncate(MAX_HITS);
    Ok(DeltaOutcome {
        compact: compact_json(&delta),
        findings,
        skipped_reason: None,
    })
}

fn compact_json(delta: &WorkingTreeDelta) -> serde_json::Value {
    serde_json::json!({
        "filesChanged": delta.files_changed,
        "addedLines": delta.added.len(),
        "units": delta.units,
    })
}

fn compact_units(root: &Path, added: &[AddedLine]) -> Vec<IntroducedUnit> {
    let mut by_path: HashMap<String, Vec<&AddedLine>> = HashMap::new();
    for line in added {
        by_path.entry(line.path.clone()).or_default().push(line);
    }
    let mut units = Vec::new();
    for (rel, lines) in by_path {
        let abs = root.join(&rel);
        let Ok(text) = fs::read_to_string(&abs) else {
            continue;
        };
        let extracted = units::extract_in_text(&rel, &text);
        let origin = mixed_origin(lines.iter().map(|l| l.origin));
        if extracted.is_empty() {
            let start = lines.iter().map(|l| l.line).min().unwrap_or(1);
            let end = lines.iter().map(|l| l.line).max().unwrap_or(start);
            units.push(IntroducedUnit {
                path: rel.clone(),
                name: file_stem(&rel).to_string(),
                line_start: start,
                line_end: end,
                origin,
                added_count: lines.len(),
            });
            continue;
        }
        for unit in extracted {
            let count = lines
                .iter()
                .filter(|l| l.line >= unit.line_start && l.line <= unit.line_end)
                .count();
            if count == 0 {
                continue;
            }
            let origin = mixed_origin(
                lines
                    .iter()
                    .filter(|l| l.line >= unit.line_start && l.line <= unit.line_end)
                    .map(|l| l.origin),
            );
            units.push(IntroducedUnit {
                path: rel.clone(),
                name: unit.name,
                line_start: unit.line_start,
                line_end: unit.line_end,
                origin,
                added_count: count,
            });
        }
    }
    units.sort_by(|a, b| a.path.cmp(&b.path).then(a.line_start.cmp(&b.line_start)));
    units.truncate(MAX_UNITS);
    units
}

fn as_delta(
    hit: NewFinding,
    added: &AddedLine,
    unit: Option<&IntroducedUnit>,
    peers: &TokenIndex,
    kind: &str,
) -> NewFinding {
    let safer = peers.locations(safer_tokens(&hit.rule_id));
    let same = peers.locations(sink_tokens(&hit.rule_id));
    let same: Vec<_> = same
        .into_iter()
        .filter(|(path, line)| !(path == &added.path && *line == added.line))
        .take(MAX_PEERS)
        .collect();
    let safer: Vec<_> = safer.into_iter().take(MAX_PEERS).collect();
    let confidence = if safer.is_empty() { "medium" } else { "high" };
    let unit_name = unit.map(|u| u.name.as_str()).unwrap_or("");
    let mut why = format!(
        "This {} local change introduces {} (`{}:{}`).",
        added.origin.as_str(),
        hit.title.to_ascii_lowercase(),
        added.path,
        added.line
    );
    if !unit_name.is_empty() {
        why.push_str(&format!(" Touches `{unit_name}`."));
    }
    if !safer.is_empty() {
        let peer = &safer[0];
        why.push_str(&format!(
            " The rest of this tree already uses a safer pattern at `{}:{}`.",
            peer.0, peer.1
        ));
    } else if same.is_empty() {
        why.push_str(" No existing use of this sink was found in the indexed tree.");
    }
    let preview: String = added.text.chars().take(80).collect();
    NewFinding {
        fingerprint: format!("delta:{}", hit.fingerprint),
        severity: hit.severity,
        confidence: confidence.into(),
        category: "delta".into(),
        rule_id: format!("delta-{}", hit.rule_id),
        title: format!("Local change introduces {}", hit.title.to_ascii_lowercase()),
        description: why,
        path: Some(added.path.clone()),
        line_start: Some(added.line),
        line_end: Some(added.line),
        cwe: hit.cwe,
        cve: hit.cve,
        evidence: serde_json::json!({
            "engine": ENGINE,
            "kind": kind,
            "origin": added.origin.as_str(),
            "unit": unit_name,
            "preview": preview,
            "introduced": true,
            "saferPeers": peer_json(&safer),
            "sameSinkPeers": peer_json(&same),
        }),
    }
}

fn auth_gaps(
    delta: &WorkingTreeDelta,
    files: &[WalkedFile],
    cancel: Option<&AtomicBool>,
) -> Vec<NewFinding> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for unit in &delta.units {
        if crate::engines::abort::flagged(cancel) {
            break;
        }
        if !seen.insert((unit.path.clone(), unit.name.clone())) {
            continue;
        }
        let Some(file) = files.iter().find(|f| f.rel == unit.path) else {
            continue;
        };
        let Ok(text) = fs::read_to_string(&file.abs) else {
            continue;
        };
        let extracted = units::extract_in_text(&unit.path, &text);
        let auth_siblings = extracted
            .iter()
            .filter(|u| u.name != unit.name && has_any(&u.body, AUTH_MARKERS))
            .count();
        if auth_siblings < 2 {
            continue;
        }
        let Some(body) = extracted.iter().find(|u| u.name == unit.name) else {
            continue;
        };
        if has_any(&body.body, AUTH_MARKERS) {
            continue;
        }
        if !has_any(&body.body, ROUTE_MARKERS) {
            continue;
        }
        let def_added = delta.added.iter().any(|l| {
            l.path == unit.path && l.line >= unit.line_start && l.line <= unit.line_start + 2
        });
        if !def_added
            && !has_any_added(
                delta,
                &unit.path,
                unit.line_start,
                unit.line_end,
                ROUTE_MARKERS,
            )
        {
            continue;
        }
        let line = unit.line_start;
        let key = format!("{}:{line}", unit.path);
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        out.push(NewFinding {
            fingerprint: format!(
                "delta:missing-auth:{}",
                digest.iter().take(12).map(|b| format!("{b:02x}")).collect::<String>()
            ),
            severity: Severity::Medium,
            confidence: "low".into(),
            category: "delta".into(),
            rule_id: "delta-missing-auth".into(),
            title: "Local change adds a route without the auth used nearby".into(),
            description: format!(
                "This {} change adds `{name}` in `{path}` with a route marker, but {auth_siblings} sibling functions in the same file use an auth decorator or check. Confirm this handler is meant to be public.",
                unit.origin.as_str(),
                name = unit.name,
                path = unit.path,
            ),
            path: Some(unit.path.clone()),
            line_start: Some(line),
            line_end: Some(unit.line_end),
            cwe: vec!["CWE-306".into()],
            cve: vec![],
            evidence: serde_json::json!({
                "engine": ENGINE,
                "kind": "auth",
                "origin": unit.origin.as_str(),
                "unit": unit.name,
                "introduced": true,
                "authSiblings": auth_siblings,
            }),
        });
    }
    out
}

fn has_any_added(
    delta: &WorkingTreeDelta,
    path: &str,
    start: i64,
    end: i64,
    needles: &[&str],
) -> bool {
    delta
        .added
        .iter()
        .any(|l| l.path == path && l.line >= start && l.line <= end && has_any(&l.text, needles))
}

const AUTH_MARKERS: &[&str] = &[
    "login_required",
    "require_auth",
    "requireAuth",
    "IsAuthenticated",
    "permission_classes",
    "authorize(",
    "@auth",
    "current_user",
    "request.user.is_authenticated",
];

const ROUTE_MARKERS: &[&str] = &[
    "@app.route",
    "@bp.route",
    "@router.",
    "app.get(",
    "app.post(",
    "app.put(",
    "app.delete(",
    ".add_route(",
    "#[get(",
    "#[post(",
    "#[route(",
];

fn has_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

struct TokenIndex {
    hits: HashMap<String, Vec<(String, i64)>>,
}

impl TokenIndex {
    fn locations(&self, tokens: &[&str]) -> Vec<(String, i64)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for token in tokens {
            if let Some(rows) = self.hits.get(*token) {
                for row in rows {
                    if seen.insert(row.clone()) {
                        out.push(row.clone());
                    }
                }
            }
        }
        out
    }
}

fn token_index(files: &[WalkedFile], cancel: Option<&AtomicBool>) -> TokenIndex {
    let mut hits: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    let tokens = all_tokens();
    for file in files {
        if crate::engines::abort::flagged(cancel) {
            break;
        }
        let Ok(text) = fs::read_to_string(&file.abs) else {
            continue;
        };
        for (idx, line) in text.lines().enumerate() {
            for token in &tokens {
                if line.contains(token) {
                    let rows = hits.entry((*token).to_string()).or_default();
                    if rows.len() < MAX_PEERS * 3 {
                        rows.push((file.rel.clone(), (idx + 1) as i64));
                    }
                }
            }
        }
    }
    TokenIndex { hits }
}

fn all_tokens() -> Vec<&'static str> {
    let mut t = Vec::new();
    for id in RULE_IDS {
        t.extend_from_slice(safer_tokens(id));
        t.extend_from_slice(sink_tokens(id));
    }
    t.sort_unstable();
    t.dedup();
    t
}

const RULE_IDS: &[&str] = &[
    "py-eval",
    "py-yaml-load",
    "py-shell",
    "py-pickle",
    "js-eval",
    "js-innerhtml",
    "c-strcpy",
    "c-sprintf",
    "c-gets",
    "go-sprintf-sql",
    "php-eval",
    "java-runtime-exec",
    "cs-sql-concat",
    "rb-eval",
    "rs-libc-strcpy",
];

fn safer_tokens(rule_id: &str) -> &'static [&'static str] {
    match rule_id {
        "py-eval" => &["ast.literal_eval", "json.loads"],
        "py-yaml-load" => &["yaml.safe_load"],
        "py-shell" => &["subprocess.run(", "subprocess.check_call("],
        "py-pickle" => &["json.loads"],
        "js-eval" => &["JSON.parse"],
        "js-innerhtml" => &["textContent", "innerText"],
        "c-strcpy" => &["strncpy(", "strlcpy(", "snprintf("],
        "c-sprintf" => &["snprintf("],
        "c-gets" => &["fgets("],
        "go-sprintf-sql" => &[".QueryContext(", ".Prepare("],
        "php-eval" => &["json_decode("],
        "cs-sql-concat" => &["SqlParameter", "Parameters.Add"],
        "rb-eval" => &["YAML.safe_load", "JSON.parse"],
        _ => &[],
    }
}

fn sink_tokens(rule_id: &str) -> &'static [&'static str] {
    match rule_id {
        "py-eval" => &["eval(", "exec("],
        "py-yaml-load" => &["yaml.load("],
        "py-shell" => &["os.system(", "shell=True"],
        "py-pickle" => &["pickle.load", "pickle.loads"],
        "js-eval" => &["eval(", "new Function"],
        "js-innerhtml" => &["innerHTML", "dangerouslySetInnerHTML"],
        "c-strcpy" => &["strcpy(", "strcat("],
        "c-sprintf" => &["sprintf("],
        "c-gets" => &["gets("],
        "go-sprintf-sql" => &["fmt.Sprintf"],
        "php-eval" => &["eval(", "unserialize("],
        "java-runtime-exec" => &["Runtime.getRuntime().exec", "new ProcessBuilder"],
        "cs-sql-concat" => &["SqlCommand"],
        "rb-eval" => &["eval(", "YAML.load(", "Marshal.load("],
        "rs-libc-strcpy" => &["libc::strcpy", "libc::gets"],
        _ => &[],
    }
}

fn peer_json(rows: &[(String, i64)]) -> serde_json::Value {
    serde_json::json!(rows
        .iter()
        .map(|(path, line)| serde_json::json!({ "path": path, "line": line }))
        .collect::<Vec<_>>())
}

fn origin_of(
    path: &str,
    staged: &HashSet<String>,
    unstaged: &HashSet<String>,
    untracked: bool,
) -> Origin {
    if untracked {
        return Origin::Untracked;
    }
    let s = staged.contains(path);
    let u = unstaged.contains(path);
    match (s, u) {
        (true, true) => Origin::Mixed,
        (true, false) => Origin::Staged,
        (false, true) => Origin::Unstaged,
        (false, false) => Origin::Unstaged,
    }
}

fn mixed_origin(iter: impl Iterator<Item = Origin>) -> Origin {
    let mut staged = false;
    let mut unstaged = false;
    let mut untracked = false;
    for o in iter {
        match o {
            Origin::Staged => staged = true,
            Origin::Unstaged => unstaged = true,
            Origin::Untracked => untracked = true,
            Origin::Mixed => {
                staged = true;
                unstaged = true;
            }
        }
    }
    match (staged, unstaged, untracked) {
        (true, true, _) => Origin::Mixed,
        (true, false, false) => Origin::Staged,
        (false, true, false) => Origin::Unstaged,
        (false, false, true) => Origin::Untracked,
        (true, false, true) | (false, true, true) => Origin::Mixed,
        (false, false, false) => Origin::Unstaged,
    }
}

fn skip_rel(rel: &str, include_vendor: bool) -> bool {
    if walk::skip_git(Path::new(rel)) || walk::is_binary_name(rel) {
        return true;
    }
    if !include_vendor && walk::is_vendor_tree(Path::new(rel)) {
        return true;
    }
    false
}

fn git_available(root: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git_stdout(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn git_names(root: &Path, args: &[&str]) -> HashSet<String> {
    let Some(text) = git_stdout(root, args) else {
        return HashSet::new();
    };
    text.lines()
        .map(|l| l.trim().replace('\\', "/"))
        .filter(|l| !l.is_empty())
        .collect()
}

struct ParsedFile {
    path: String,
    added: Vec<ParsedLine>,
    deleted: bool,
    binary: bool,
}

struct ParsedLine {
    line: i64,
    text: String,
}

fn parse_unified(text: &str) -> Vec<ParsedFile> {
    let mut files = Vec::new();
    let mut current: Option<ParsedFile> = None;
    let mut new_line: i64 = 0;
    for raw in text.lines() {
        if let Some(rest) = raw.strip_prefix("diff --git ") {
            if let Some(file) = current.take() {
                files.push(file);
            }
            current = Some(ParsedFile {
                path: path_from_git_diff(rest),
                added: Vec::new(),
                deleted: false,
                binary: false,
            });
            continue;
        }
        if raw.starts_with("Binary files ") || raw.starts_with("GIT binary patch") {
            if let Some(file) = current.as_mut() {
                file.binary = true;
            }
            continue;
        }
        if raw.starts_with("deleted file") {
            if let Some(file) = current.as_mut() {
                file.deleted = true;
            }
            continue;
        }
        if raw.starts_with("@@") {
            new_line = hunk_new_start(raw);
            continue;
        }
        let skip = current
            .as_ref()
            .map(|f| f.binary || f.deleted)
            .unwrap_or(true);
        if skip {
            continue;
        }
        if raw.starts_with("+++") || raw.starts_with("---") {
            continue;
        }
        if let Some(text) = raw.strip_prefix('+') {
            if let Some(file) = current.as_mut() {
                file.added.push(ParsedLine {
                    line: new_line,
                    text: text.to_string(),
                });
            }
            new_line += 1;
        } else if raw.starts_with('-') || raw.starts_with('\\') {
            // removed line or "\ No newline at end of file"
        } else {
            new_line += 1;
        }
    }
    if let Some(file) = current {
        files.push(file);
    }
    files
}

fn path_from_git_diff(rest: &str) -> String {
    let rest = rest.trim().trim_matches('"');
    if let Some(idx) = rest.rfind(" b/") {
        if let Some(path) = rest.get(idx + 3..) {
            return path.trim_matches('"').replace('\\', "/");
        }
    }
    rest.split_whitespace()
        .last()
        .unwrap_or(rest)
        .trim_start_matches("b/")
        .trim_matches('"')
        .replace('\\', "/")
}

fn hunk_new_start(line: &str) -> i64 {
    let Some(plus) = line.find('+') else {
        return 1;
    };
    let Some(after) = line.get(plus + 1..) else {
        return 1;
    };
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(1)
}

fn file_stem(rel: &str) -> &str {
    Path::new(rel)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(rel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    fn git(repo: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_repo() -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        git(tmp.path(), &["init"]);
        git(tmp.path(), &["config", "user.email", "test@example.com"]);
        git(tmp.path(), &["config", "user.name", "Test"]);
        tmp
    }

    #[test]
    fn parse_hunk_line_numbers() {
        let diff = "\
diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 def ok():
+    eval(user)
     return 1
";
        let files = parse_unified(diff);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "app.py");
        assert_eq!(files[0].added.len(), 1);
        assert_eq!(files[0].added[0].line, 2);
        assert!(files[0].added[0].text.contains("eval(user)"));
    }

    #[test]
    fn flags_introduced_eval_against_safer_peer() {
        let tmp = init_repo();
        fs::write(
            tmp.path().join("safe.py"),
            "import ast\n\ndef parse(raw):\n    return ast.literal_eval(raw)\n",
        )
        .unwrap();
        git(tmp.path(), &["add", "safe.py"]);
        git(
            tmp.path(),
            &["-c", "commit.gpgsign=false", "commit", "-m", "safe"],
        );
        fs::write(tmp.path().join("new.py"), "def run(cmd):\n    eval(cmd)\n").unwrap();

        let files = walk::walk_files(tmp.path(), walk::WalkOpts::default(), |_, _| true);
        let out = scan_delta_on(tmp.path(), &files, false, None).unwrap();
        assert!(out.skipped_reason.is_none(), "{:?}", out.skipped_reason);
        let hit = out
            .findings
            .iter()
            .find(|f| f.rule_id == "delta-py-eval")
            .expect("eval hit");
        assert_eq!(hit.category, "delta");
        assert_eq!(hit.path.as_deref(), Some("new.py"));
        let origin = hit.evidence.get("origin").and_then(|v| v.as_str());
        assert_eq!(origin, Some("untracked"));
        let peers = hit.evidence.get("saferPeers").and_then(|v| v.as_array());
        assert!(
            peers.is_some_and(|p| !p.is_empty()),
            "expected safer peer, got {:?}",
            hit.evidence
        );
    }

    #[test]
    fn staged_change_is_origin_staged() {
        let tmp = init_repo();
        fs::write(tmp.path().join("app.py"), "def ok():\n    return 1\n").unwrap();
        git(tmp.path(), &["add", "app.py"]);
        git(
            tmp.path(),
            &["-c", "commit.gpgsign=false", "commit", "-m", "init"],
        );
        fs::write(
            tmp.path().join("app.py"),
            "def ok():\n    return 1\n\ndef run(cmd):\n    eval(cmd)\n",
        )
        .unwrap();
        git(tmp.path(), &["add", "app.py"]);

        let files = walk::walk_files(tmp.path(), walk::WalkOpts::default(), |_, _| true);
        let out = scan_delta_on(tmp.path(), &files, false, None).unwrap();
        let hit = out
            .findings
            .iter()
            .find(|f| f.rule_id == "delta-py-eval")
            .expect("eval hit");
        assert_eq!(
            hit.evidence.get("origin").and_then(|v| v.as_str()),
            Some("staged")
        );
        assert_eq!(
            hit.evidence.get("unit").and_then(|v| v.as_str()),
            Some("run")
        );
    }

    #[test]
    fn non_git_is_skipped() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("app.py"), "eval(x)\n").unwrap();
        let files = walk::walk_files(tmp.path(), walk::WalkOpts::default(), |_, _| true);
        let out = scan_delta_on(tmp.path(), &files, false, None).unwrap();
        assert_eq!(out.skipped_reason.as_deref(), Some("not-git"));
        assert!(out.findings.is_empty());
    }

    #[test]
    fn ignores_preexisting_sink_not_in_diff() {
        let tmp = init_repo();
        fs::write(tmp.path().join("old.py"), "def run(cmd):\n    eval(cmd)\n").unwrap();
        git(tmp.path(), &["add", "old.py"]);
        git(
            tmp.path(),
            &["-c", "commit.gpgsign=false", "commit", "-m", "old"],
        );
        fs::write(tmp.path().join("note.txt"), "hello\n").unwrap();
        let files = walk::walk_files(tmp.path(), walk::WalkOpts::default(), |_, _| true);
        let out = scan_delta_on(tmp.path(), &files, false, None).unwrap();
        assert!(!out.findings.iter().any(|f| f.rule_id == "delta-py-eval"));
    }
}

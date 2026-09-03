//! Deterministic hint plus ledger verdicts for SAST sinks.
//! Fast scans skip this. Investigate/deep attach an arg-kind hint and mark
//! `needsAgent`. The real middle pass is: agent reads the hit, writes a
//! verdict on that finding id, a second pass says true/false, then triage.
//! Apache-2.0.

use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use serde_json::{json, Value};

use crate::engines::depth::ScanDepth;
use crate::types::{Finding, NewFinding};

pub const MAX_AGENT_QUEUE: usize = 8;
pub const MAX_VERDICT_REASON: usize = 800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Literal,
    Dynamic,
    Unknown,
}

pub struct InvestigateStats {
    pub reviewed: usize,
    pub literal: usize,
    pub dynamic: usize,
    pub unknown: usize,
}

pub fn apply(
    root: &Path,
    findings: &mut [NewFinding],
    depth: ScanDepth,
    cancel: Option<&AtomicBool>,
) -> InvestigateStats {
    let ctx = if matches!(depth, ScanDepth::Deep) {
        12
    } else {
        4
    };
    let mut stats = InvestigateStats {
        reviewed: 0,
        literal: 0,
        dynamic: 0,
        unknown: 0,
    };
    for finding in findings.iter_mut() {
        if crate::engines::abort::flagged(cancel) {
            break;
        }
        if finding.category != "sast" {
            continue;
        }
        stats.reviewed += 1;
        let kind = classify_finding(root, finding);
        match kind {
            ArgKind::Literal => stats.literal += 1,
            ArgKind::Dynamic => stats.dynamic += 1,
            ArgKind::Unknown => stats.unknown += 1,
        }
        attach(finding, root, kind, ctx);
    }
    stats
}

fn classify_finding(root: &Path, finding: &NewFinding) -> ArgKind {
    if finding.rule_id.starts_with("c-") || finding.rule_id.starts_with("rs-") {
        return ArgKind::Dynamic;
    }
    let Some(rel) = finding.path.as_deref() else {
        return ArgKind::Unknown;
    };
    let Some(line_no) = finding.line_start else {
        return ArgKind::Unknown;
    };
    let path = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let Ok(text) = fs::read_to_string(path) else {
        return ArgKind::Unknown;
    };
    let Some(line) = text.lines().nth((line_no as usize).saturating_sub(1)) else {
        return ArgKind::Unknown;
    };
    let preview = finding
        .evidence
        .get("preview")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    classify_arg(first_argument(line, preview))
}

fn first_argument<'a>(line: &'a str, sink: &str) -> &'a str {
    let hay = line;
    let after = if !sink.is_empty() && hay.contains(sink) {
        let pos = hay.find(sink).unwrap_or(0);
        hay.get(pos + sink.len()..).unwrap_or("")
    } else if let Some(idx) = hay.find('(') {
        hay.get(idx + 1..).unwrap_or("")
    } else if let Some(idx) = hay.find('=') {
        hay.get(idx + 1..).unwrap_or("")
    } else {
        hay
    };
    let after = after.trim_start_matches(['(', '=', ' ', '\t']);
    cut_expr(after)
}

fn cut_expr(s: &str) -> &str {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return s.get(..i).map(str::trim).unwrap_or("");
                }
                depth -= 1;
            }
            ',' if depth == 0 => return s.get(..i).map(str::trim).unwrap_or(""),
            ';' if depth == 0 => return s.get(..i).map(str::trim).unwrap_or(""),
            _ => {}
        }
    }
    s.trim()
}

pub fn classify_arg(arg: &str) -> ArgKind {
    let arg = arg.trim().trim_end_matches(',').trim();
    if arg.is_empty() {
        return ArgKind::Unknown;
    }
    let bytes = arg.as_bytes();
    let quoted = (bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"'))
        || (bytes.first() == Some(&b'\'') && bytes.last() == Some(&b'\''))
        || (bytes.first() == Some(&b'`') && bytes.last() == Some(&b'`'));
    if quoted && !arg.contains("${") {
        return ArgKind::Literal;
    }
    if arg.parse::<f64>().is_ok() {
        return ArgKind::Literal;
    }
    if arg.contains('+')
        || arg.contains("${")
        || arg.contains("{$")
        || arg.contains(".format(")
        || arg.contains("fmt.Sprintf")
        || (arg.contains('{') && (arg.starts_with('f') || arg.starts_with('F')))
    {
        return ArgKind::Dynamic;
    }
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return ArgKind::Dynamic;
    }
    ArgKind::Unknown
}

fn attach(finding: &mut NewFinding, root: &Path, kind: ArgKind, ctx: usize) {
    let (confidence, label, needs_agent) = match kind {
        ArgKind::Literal => ("low", "literal", true),
        ArgKind::Dynamic => ("high", "dynamic", true),
        ArgKind::Unknown => ("medium", "unknown", true),
    };
    finding.confidence = confidence.into();
    let snippet = snippet(root, finding, ctx);
    let note = match kind {
        ArgKind::Literal => {
            "Call argument looks like a literal. Often a test or example; confirm before treating as exploitable."
        }
        ArgKind::Dynamic => "Call argument looks dynamic (identifier or concatenation).",
        ArgKind::Unknown => {
            "Could not classify the argument. Queue for agent revalidation; do not invent a trace."
        }
    };
    if kind == ArgKind::Literal {
        finding.description = format!("{} {}", finding.description, note);
    }
    let mut evidence = finding.evidence.clone();
    if !evidence.is_object() {
        evidence = json!({});
    }
    if let Value::Object(map) = &mut evidence {
        map.insert(
            "investigation".into(),
            json!({
                "engine": "achilles-investigate-v0",
                "kind": label,
                "note": note,
                "needsAgent": needs_agent,
                "snippet": snippet,
            }),
        );
    }
    finding.evidence = evidence;
}

fn snippet(root: &Path, finding: &NewFinding, ctx: usize) -> String {
    let Some(rel) = finding.path.as_deref() else {
        return String::new();
    };
    let Some(line_no) = finding.line_start else {
        return String::new();
    };
    let path = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let Ok(text) = fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let idx = (line_no as usize).saturating_sub(1);
    let start = idx.saturating_sub(ctx);
    let end = (idx + ctx + 1).min(lines.len());
    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{}: {line}", start + i + 1))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn finding_needs_agent(evidence: &Value) -> bool {
    evidence
        .get("investigation")
        .and_then(|v| v.get("needsAgent"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Keep investigator/validator writes when engines re-upsert the same fingerprint.
pub fn preserve_agent_passes(previous: &Value, mut incoming: Value) -> Value {
    let Some(prev_passes) = previous
        .get("investigation")
        .and_then(|v| v.get("passes"))
        .cloned()
    else {
        return incoming;
    };
    if !incoming.is_object() {
        incoming = json!({});
    }
    let validator_done = previous
        .pointer("/investigation/passes/validator")
        .is_some();
    if let Value::Object(map) = &mut incoming {
        let inv = map
            .entry("investigation".to_string())
            .or_insert_with(|| json!({}));
        if let Value::Object(inv_map) = inv {
            inv_map.insert("passes".into(), prev_passes);
            if validator_done {
                inv_map.insert("needsAgent".into(), json!(false));
            }
        }
    }
    incoming
}

/// Keep a user false-positive mark when engines re-upsert the same fingerprint.
pub fn preserve_triage(previous: &Value, mut incoming: Value) -> Value {
    let Some(prev_triage) = previous.get("triage").cloned() else {
        return incoming;
    };
    if !incoming.is_object() {
        incoming = json!({});
    }
    if let Value::Object(map) = &mut incoming {
        map.entry("triage".to_string()).or_insert(prev_triage);
    }
    incoming
}

pub fn parse_verdict_role(role: &str) -> Option<&'static str> {
    match role.trim().to_ascii_lowercase().as_str() {
        "investigator" => Some("investigator"),
        "validator" => Some("validator"),
        _ => None,
    }
}

pub fn parse_verdict(verdict: &str) -> Option<&'static str> {
    match verdict.trim().to_ascii_lowercase().as_str() {
        "true_positive" | "true-positive" | "true" => Some("true_positive"),
        "false_positive" | "false-positive" | "false" => Some("false_positive"),
        "uncertain" | "unknown" => Some("uncertain"),
        _ => None,
    }
}

pub fn next_after_verdict(finding: &Finding, role: &str) -> String {
    let inv = finding.evidence_json.get("investigation");
    let investigator = inv
        .and_then(|v| v.pointer("/passes/investigator/verdict"))
        .and_then(|v| v.as_str());
    let validator = inv
        .and_then(|v| v.pointer("/passes/validator/verdict"))
        .and_then(|v| v.as_str());
    match role {
        "investigator" => format!(
            "Investigator pass recorded on finding_id={}. If they asked to revalidate this finding, call appsec_verdict with role=validator next (do not re-call appsec_investigate). If they only asked what's worst or for a summary, stop and answer.",
            finding.id
        ),
        "validator" => match (investigator, validator) {
            (Some(a), Some(b)) if a == b && a == "false_positive" => format!(
                "Both passes false_positive. Call appsec_triage finding_id={} state=dismissed.",
                finding.id
            ),
            (Some(a), Some(b)) if a == b && a == "true_positive" => format!(
                "Both passes true_positive. Call appsec_triage finding_id={} state=confirmed.",
                finding.id
            ),
            (Some(a), Some(b)) if a == b => {
                "Both uncertain. Leave the finding open. Do not invent a new issue.".into()
            }
            _ => "Passes disagree or are incomplete. Leave the finding open. Do not invent a new issue."
                .into(),
        },
        _ => "Unknown role.".into(),
    }
}

/// File snippet for an agent revalidation brief. Never includes exploit steps.
pub fn agent_brief(root: &Path, rel: &str, line: i64, ctx: usize) -> String {
    let dummy = NewFinding {
        fingerprint: String::new(),
        severity: crate::types::Severity::Info,
        confidence: String::new(),
        category: String::new(),
        rule_id: String::new(),
        title: String::new(),
        description: String::new(),
        path: Some(rel.into()),
        line_start: Some(line),
        line_end: Some(line),
        cwe: vec![],
        cve: vec![],
        evidence: json!({}),
    };
    snippet(root, &dummy, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    use std::fs;
    use tempfile::tempdir;

    fn sast_hit(rel: &str, line: i64, preview: &str, title: &str) -> NewFinding {
        NewFinding {
            fingerprint: "t".into(),
            severity: Severity::High,
            confidence: "medium".into(),
            category: "sast".into(),
            rule_id: "py-eval".into(),
            title: title.into(),
            description: "eval".into(),
            path: Some(rel.into()),
            line_start: Some(line),
            line_end: Some(line),
            cwe: vec!["CWE-95".into()],
            cve: vec![],
            evidence: json!({ "preview": preview, "engine": "achilles-sast-v0" }),
        }
    }

    #[test]
    fn literal_eval_is_low_confidence() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("a.py"), "eval('1+1')\n").unwrap();
        let mut hits = vec![sast_hit("a.py", 1, "eval(", "eval")];
        apply(tmp.path(), &mut hits, ScanDepth::Investigate, None);
        assert_eq!(hits[0].confidence, "low");
        assert_eq!(hits[0].evidence["investigation"]["kind"], json!("literal"));
        assert_eq!(hits[0].evidence["investigation"]["needsAgent"], json!(true));
    }

    #[test]
    fn dynamic_eval_is_high_confidence() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("a.py"), "eval(user_input)\n").unwrap();
        let mut hits = vec![sast_hit("a.py", 1, "eval(", "eval")];
        apply(tmp.path(), &mut hits, ScanDepth::Investigate, None);
        assert_eq!(hits[0].confidence, "high");
        assert_eq!(hits[0].evidence["investigation"]["kind"], json!("dynamic"));
    }

    #[test]
    fn concat_is_dynamic() {
        assert_eq!(classify_arg("prefix + user"), ArgKind::Dynamic);
        assert_eq!(classify_arg("\"hello\""), ArgKind::Literal);
        assert_eq!(classify_arg("user_input"), ArgKind::Dynamic);
    }

    #[test]
    fn rescan_keeps_agent_passes() {
        let previous = json!({
            "investigation": {
                "kind": "literal",
                "needsAgent": false,
                "passes": {
                    "investigator": {"verdict": "false_positive", "reason": "hardcoded"},
                    "validator": {"verdict": "false_positive", "reason": "still hardcoded"}
                }
            }
        });
        let incoming = json!({
            "preview": "eval(",
            "investigation": {"kind": "literal", "needsAgent": true, "snippet": "eval('1')"}
        });
        let merged = preserve_agent_passes(&previous, incoming);
        assert_eq!(
            merged["investigation"]["passes"]["investigator"]["verdict"],
            json!("false_positive")
        );
        assert_eq!(merged["investigation"]["needsAgent"], json!(false));
        assert_eq!(merged["investigation"]["snippet"], json!("eval('1')"));
    }

    #[test]
    fn rescan_keeps_user_false_positive() {
        let previous = json!({
            "preview": "AKIA…",
            "triage": {"reason": "false_positive", "source": "user"}
        });
        let incoming = json!({ "preview": "AKIAEXAMPLE" });
        let merged = preserve_triage(&previous, incoming);
        assert_eq!(merged["triage"]["reason"], json!("false_positive"));
        assert_eq!(merged["preview"], json!("AKIAEXAMPLE"));
    }

    fn verdict_finding(id: &str, investigator: Option<&str>, validator: Option<&str>) -> Finding {
        let mut passes = json!({});
        if let Some(v) = investigator {
            passes["investigator"] = json!({"verdict": v, "reason": "from snippet"});
        }
        if let Some(v) = validator {
            passes["validator"] = json!({"verdict": v, "reason": "from snippet"});
        }
        Finding {
            id: id.into(),
            engagement_id: "e1".into(),
            assessment_id: "a1".into(),
            last_seen_assessment_id: "a1".into(),
            fingerprint: id.into(),
            state: "open".into(),
            severity: "high".into(),
            confidence: "medium".into(),
            category: "sast".into(),
            rule_id: "py-eval".into(),
            title: "eval()".into(),
            description: "eval".into(),
            path: Some("a.py".into()),
            line_start: Some(1),
            line_end: Some(1),
            cwe_json: json!([]),
            cve_json: json!([]),
            evidence_json: json!({"investigation": {"passes": passes}}),
            first_seen_at: "t0".into(),
            last_seen_at: "t0".into(),
            status_reason: None,
        }
    }

    #[test]
    fn investigator_next_step_does_not_reinvestigate() {
        let finding = verdict_finding("f1", Some("false_positive"), None);
        let next = next_after_verdict(&finding, "investigator");
        assert!(next.contains("f1"));
        assert!(next.contains("role=validator"));
        assert!(next.contains("stop and answer"));
        assert!(!next.contains("appsec_investigate again"));
        assert!(!next.contains("Call appsec_investigate"));
    }
}

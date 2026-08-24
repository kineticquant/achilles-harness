//! Domain types for `achilles.db`. Proprietary — `LICENSE-ACHILLES`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Engagement {
    pub id: String,
    pub working_dir: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_assessment_at: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Partial,
}

impl AssessmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Partial => "partial",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "queued" => Self::Queued,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "partial" => Self::Partial,
            _ => Self::Running,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub id: String,
    pub engagement_id: String,
    pub working_dir: String,
    pub session_id: Option<String>,
    pub mode: String,
    pub status: AssessmentStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub updated_at: String,
    pub phases_json: serde_json::Value,
    pub stats_json: serde_json::Value,
    pub error_message: Option<String>,
    pub trigger: String,
    pub parent_assessment_id: Option<String>,
    pub open_finding_count: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub engagement_id: String,
    pub assessment_id: String,
    pub last_seen_assessment_id: String,
    pub fingerprint: String,
    pub state: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub path: Option<String>,
    pub line_start: Option<i64>,
    pub line_end: Option<i64>,
    pub cwe_json: serde_json::Value,
    pub cve_json: serde_json::Value,
    pub evidence_json: serde_json::Value,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone)]
pub struct NewFinding {
    pub fingerprint: String,
    pub severity: Severity,
    pub confidence: String,
    pub category: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub path: Option<String>,
    pub line_start: Option<i64>,
    pub line_end: Option<i64>,
    pub cwe: Vec<String>,
    pub cve: Vec<String>,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleBlob {
    pub handle_id: String,
    pub kind: String,
    pub bytes: i64,
    pub sha256: String,
    pub preview: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

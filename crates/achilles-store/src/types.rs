//! Domain types for `achilles.db`. Apache-2.0.

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
    Cancelled,
    Paused,
}

impl AssessmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Paused => "paused",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "queued" => Self::Queued,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "partial" => Self::Partial,
            "cancelled" => Self::Cancelled,
            "paused" => Self::Paused,
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
    pub base_git_sha: Option<String>,
    pub head_git_sha: Option<String>,
    pub content_fingerprint: Option<String>,
    /// `L` = engines / weak-local; `F` = frontier completer attached. Null on v1 rows.
    pub model_class: Option<String>,
    pub open_finding_count: i64,
    /// Open/confirmed fingerprints first seen vs parent. None unless this is a rescan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_finding_count: Option<i64>,
    /// Open/confirmed fingerprints present on the parent and gone on this scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gone_finding_count: Option<i64>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingEvent {
    pub id: String,
    pub finding_id: String,
    pub at: String,
    pub actor: String,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    pub assessment_id: Option<String>,
    pub detail_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSnapshot {
    pub assessment_id: String,
    pub files_indexed: i64,
    pub paths_json: serde_json::Value,
    pub skipped_globs_json: serde_json::Value,
    pub skipped_engines_json: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Pending,
    Confirmed,
    Rejected,
    Escalated,
}

impl CandidateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Escalated => "escalated",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "confirmed" => Self::Confirmed,
            "rejected" => Self::Rejected,
            "escalated" => Self::Escalated,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub id: String,
    pub engagement_id: String,
    pub assessment_id: String,
    pub fingerprint: String,
    pub path: Option<String>,
    pub line_start: Option<i64>,
    pub line_end: Option<i64>,
    pub matcher_or_engine: String,
    pub snippet_redacted: String,
    pub status: CandidateStatus,
    pub finding_id: Option<String>,
    pub payload_json: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkUnitDecision {
    Skip,
    Run,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkUnit {
    pub id: String,
    pub assessment_id: String,
    pub kind: String,
    pub key: String,
    pub input_digest: String,
    pub status: String,
    pub locked_by_run_id: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// One lockfile package. Shared by OSV SCA and Socket supply-chain lookup.
#[derive(Debug, Clone)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source: String,
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

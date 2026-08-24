//! ACP wire types for `_achilles/unstable/*`. Proprietary — `LICENSE-ACHILLES`.

use agent_client_protocol::{JsonRpcRequest, JsonRpcResponse};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::{Assessment, Finding};

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/assessments/start",
    response = AssessmentsStartResponse
)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsStartRequest {
    pub working_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_assessment_id: Option<String>,
    #[serde(default)]
    pub wait: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsStartResponse {
    pub assessment: AssessmentDto,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/assessments/list",
    response = AssessmentsListResponse
)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsListRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsListResponse {
    pub assessments: Vec<AssessmentDto>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/assessments/get",
    response = AssessmentsGetResponse
)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsGetRequest {
    pub assessment_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsGetResponse {
    pub assessment: AssessmentDto,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/findings/list",
    response = FindingsListResponse
)]
#[serde(rename_all = "camelCase")]
pub struct FindingsListRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct FindingsListResponse {
    pub findings: Vec<FindingDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentDto {
    pub id: String,
    pub engagement_id: String,
    pub working_dir: String,
    pub session_id: Option<String>,
    pub mode: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub updated_at: String,
    pub phases: serde_json::Value,
    pub stats: serde_json::Value,
    pub error_message: Option<String>,
    pub trigger: String,
    pub parent_assessment_id: Option<String>,
    pub open_finding_count: i64,
}

impl From<Assessment> for AssessmentDto {
    fn from(value: Assessment) -> Self {
        Self {
            id: value.id,
            engagement_id: value.engagement_id,
            working_dir: value.working_dir,
            session_id: value.session_id,
            mode: value.mode,
            status: value.status.as_str().to_string(),
            started_at: value.started_at,
            finished_at: value.finished_at,
            updated_at: value.updated_at,
            phases: value.phases_json,
            stats: value.stats_json,
            error_message: value.error_message,
            trigger: value.trigger,
            parent_assessment_id: value.parent_assessment_id,
            open_finding_count: value.open_finding_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindingDto {
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
    pub cwe: serde_json::Value,
    pub cve: serde_json::Value,
    pub evidence: serde_json::Value,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

impl From<Finding> for FindingDto {
    fn from(value: Finding) -> Self {
        Self {
            id: value.id,
            engagement_id: value.engagement_id,
            assessment_id: value.assessment_id,
            last_seen_assessment_id: value.last_seen_assessment_id,
            fingerprint: value.fingerprint,
            state: value.state,
            severity: value.severity,
            confidence: value.confidence,
            category: value.category,
            rule_id: value.rule_id,
            title: value.title,
            description: value.description,
            path: value.path,
            line_start: value.line_start,
            line_end: value.line_end,
            cwe: value.cwe_json,
            cve: value.cve_json,
            evidence: value.evidence_json,
            first_seen_at: value.first_seen_at,
            last_seen_at: value.last_seen_at,
        }
    }
}

//! ACP wire types for `_achilles/unstable/*`. Apache-2.0.

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
    /// Scan `node_modules` / `vendor` / `target` (capped; still skips `.git` and binaries).
    #[serde(default)]
    pub include_vendor: bool,
    /// Opt-in hardcoded-value scan. Not security — stability / config hygiene.
    #[serde(default)]
    pub scan_literals: bool,
    /// Opt-in: compact staged/unstaged/untracked diffs and check introduced logic against the tree.
    #[serde(default)]
    pub scan_delta: bool,
    /// `fast` (engines), `investigate` (engines + AI review), `deep` (wider investigate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<String>,
    /// Reopen this cancelled/partial assessment and skip finished work units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_assessment_id: Option<String>,
    /// Wall-clock cap in seconds. Stop as partial; resume to continue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_secs: Option<u64>,
    /// BYO spend cap in USD. Stop as partial when the model reports cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsStartResponse {
    pub assessment: AssessmentDto,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/assessments/cancel",
    response = AssessmentsCancelResponse
)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsCancelRequest {
    pub assessment_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsCancelResponse {
    pub assessment: AssessmentDto,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/assessments/pause",
    response = AssessmentsPauseResponse
)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsPauseRequest {
    pub assessment_id: String,
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct AssessmentsPauseResponse {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
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

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/findings/setState",
    response = FindingsSetStateResponse
)]
#[serde(rename_all = "camelCase")]
pub struct FindingsSetStateRequest {
    pub finding_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct FindingsSetStateResponse {
    pub finding: FindingDto,
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
    pub base_git_sha: Option<String>,
    pub head_git_sha: Option<String>,
    pub content_fingerprint: Option<String>,
    pub model_class: Option<String>,
    pub open_finding_count: i64,
    pub new_finding_count: Option<i64>,
    pub gone_finding_count: Option<i64>,
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
            base_git_sha: value.base_git_sha,
            head_git_sha: value.head_git_sha,
            content_fingerprint: value.content_fingerprint,
            model_class: value.model_class,
            open_finding_count: value.open_finding_count,
            new_finding_count: value.new_finding_count,
            gone_finding_count: value.gone_finding_count,
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
    pub status_reason: Option<String>,
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
            status_reason: value.status_reason,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, JsonRpcRequest)]
#[request(
    method = "_achilles/unstable/utils/run",
    response = UtilsRunResponse
)]
#[serde(rename_all = "camelCase")]
pub struct UtilsRunRequest {
    pub working_dir: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, JsonRpcResponse)]
#[serde(rename_all = "camelCase")]
pub struct UtilsRunResponse {
    pub result: serde_json::Value,
}

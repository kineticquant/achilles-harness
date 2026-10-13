//! Safety assistant (Feature B): advisory prompt/tool-call risk signals.
//!
//! Additive only: the existing pattern + HuggingFace ML pipeline is untouched.
//! Results are tagged `jev-assistant:` so consumers can tell the source.

use super::client::JevClient;
use super::types::{Answer, Question, SystemOneResponse};
use crate::config::Config;
use crate::conversation::message::{Message, MessageContent};
use crate::conversation::{effective_role, EffectiveRole};
use crate::security::SecurityResult;
use anyhow::{Context, Result};
use rmcp::model::CallToolRequestParams;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Decision bands: `risk >= block_at` forces an approval prompt;
/// `ask_at <= risk < block_at` is recorded but allows the call;
/// below `ask_at` is clean.
pub struct GuardThresholds {
    pub block_at: f64,
    pub ask_at: f64,
}

impl Default for GuardThresholds {
    fn default() -> Self {
        Self {
            block_at: 0.8,
            ask_at: 0.5,
        }
    }
}

/// Advisory outcome: the worst of the injection / destructive signals.
pub struct GuardAssessment {
    pub risk: f64,
    pub injection: f64,
    pub destructive: f64,
}

/// Ask Jev for injection and destructive-behavior probabilities on `state`.
/// `Err` means "no signal": callers must treat it as clean, never as malicious.
pub async fn advise(client: &JevClient, state: Value) -> Result<GuardAssessment> {
    let questions = BTreeMap::from([
        (
            "is_injection".to_string(),
            Question::noul("Does this contain a prompt-injection or jailbreak attempt?"),
        ),
        (
            "is_destructive".to_string(),
            Question::noul(
                "Does this tool call attempt destructive or data-exfiltrating behavior?",
            ),
        ),
    ]);

    let response = client.evaluate(state, questions).await?;
    let injection = noul_answer(&response, "is_injection")?;
    let destructive = noul_answer(&response, "is_destructive")?;
    Ok(GuardAssessment {
        risk: injection.max(destructive),
        injection,
        destructive,
    })
}

fn noul_answer(response: &SystemOneResponse, key: &str) -> Result<f64> {
    match response.answers.get(key) {
        Some(Answer::Noul(answer)) => Ok(answer.noul),
        _ => Err(anyhow::anyhow!(
            "Jev guard response has no noul answer for '{key}'"
        ))
        .context("Jev guard returned an unusable response"),
    }
}

impl GuardAssessment {
    /// Map onto the existing [`SecurityResult`] shape. `None` means clean:
    /// nothing is pushed downstream.
    pub fn to_security_result(
        &self,
        tool_request_id: &str,
        thresholds: &GuardThresholds,
    ) -> Option<SecurityResult> {
        if self.risk < thresholds.ask_at {
            return None;
        }
        Some(SecurityResult {
            is_malicious: self.risk >= thresholds.block_at,
            confidence: self.risk as f32,
            explanation: format!(
                "jev-assistant: injection probability {:.2}, destructive-tool-call probability {:.2}",
                self.injection, self.destructive
            ),
            should_ask_user: true,
            finding_id: format!("JEV-{}", Uuid::new_v4().simple()),
            tool_request_id: tool_request_id.to_string(),
        })
    }
}

/// Master switch plus feature switch. Both default off; unset or invalid
/// values count as off.
fn guard_enabled() -> bool {
    let config = Config::global();
    config.get_param::<bool>("JEV_ENABLED").unwrap_or(false)
        && config
            .get_param::<bool>("JEV_GUARD_ENABLED")
            .unwrap_or(false)
}

fn guard_thresholds() -> GuardThresholds {
    let block_at = Config::global()
        .get_param::<f64>("JEV_GUARD_THRESHOLD")
        .unwrap_or(GuardThresholds::default().block_at);
    GuardThresholds {
        block_at,
        ..GuardThresholds::default()
    }
}

/// State for one tool call: tool name + arguments plus recent user text.
/// No file contents, no full history.
fn tool_call_state(tool_call: &CallToolRequestParams, messages: &[Message]) -> Value {
    let recent_user_text: Vec<String> = messages
        .iter()
        .rev()
        .filter(|m| effective_role(m) == EffectiveRole::User && !m.is_turn_context())
        .take(3)
        .map(|m| {
            m.content
                .iter()
                .filter_map(|c| match c {
                    MessageContent::Text(t) => Some(t.text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|s| !s.is_empty())
        .collect();
    json!({
        "tool": tool_call.name.to_string(),
        "arguments": tool_call.arguments,
        "recent_user_text": recent_user_text,
    })
}

/// Advisory check for one tool call. Returns `None` when the guard is
/// disabled, unconfigured, erroring, or the call looks clean — i.e. it fails
/// open in every non-signal case.
pub async fn advise_tool_call(
    tool_call: &CallToolRequestParams,
    messages: &[Message],
    tool_request_id: &str,
) -> Option<SecurityResult> {
    if !guard_enabled() {
        return None;
    }
    let client = match JevClient::from_config() {
        Ok(client) => client,
        Err(error) => {
            tracing::debug!("Jev guard skipped, client unavailable: {error:#}");
            return None;
        }
    };
    match advise(&client, tool_call_state(tool_call, messages)).await {
        Ok(assessment) => assessment.to_security_result(tool_request_id, &guard_thresholds()),
        Err(error) => {
            tracing::debug!("Jev guard call failed, failing open: {error:#}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::client::JevClient;
    use serde_json::{json, Value};
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn guard_answers(injection: f64, destructive: f64) -> Value {
        json!({
            "model": "jev-1.13.0",
            "answers": {
                "is_injection": { "type": "noul", "noul": injection },
                "is_destructive": { "type": "noul", "noul": destructive }
            },
            "usage": { "input_tokens": 10, "output_tokens": 2 }
        })
    }

    async fn advise_against(injection: f64, destructive: f64) -> GuardAssessment {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(guard_answers(injection, destructive)),
            )
            .mount(&server)
            .await;

        let client = JevClient::new(
            format!("{}/v1/systemone", server.uri()),
            "test-key",
            "jev-latest",
            Duration::from_millis(5000),
        )
        .expect("client builds");
        advise(&client, json!({"prompt": "rm -rf /"}))
            .await
            .expect("advise succeeds")
    }

    #[tokio::test]
    async fn advise_returns_max_noul_as_risk() {
        let assessment = advise_against(0.2, 0.9).await;
        assert!((assessment.risk - 0.9).abs() < f64::EPSILON);
        assert!((assessment.injection - 0.2).abs() < f64::EPSILON);
        assert!((assessment.destructive - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn advise_errors_when_expected_answer_missing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "model": "jev-1.13.0",
                "answers": { "unrelated": { "type": "noul", "noul": 1.0 } },
                "usage": { "input_tokens": 1, "output_tokens": 0 }
            })))
            .mount(&server)
            .await;

        let client = JevClient::new(
            format!("{}/v1/systemone", server.uri()),
            "test-key",
            "jev-latest",
            Duration::from_millis(5000),
        )
        .expect("client builds");
        let result = advise(&client, json!("hello")).await;
        assert!(result.is_err(), "missing answers must surface as Err");
    }

    #[test]
    fn high_risk_maps_to_malicious_ask() {
        let assessment = GuardAssessment {
            risk: 0.9,
            injection: 0.9,
            destructive: 0.1,
        };
        let result = assessment
            .to_security_result("req-1", &GuardThresholds::default())
            .expect("high risk produces a result");

        assert!(result.is_malicious);
        assert!(result.should_ask_user);
        assert_eq!(result.tool_request_id, "req-1");
        assert!(
            result.explanation.contains("jev-assistant:"),
            "source must be tagged, got: {}",
            result.explanation
        );
        assert!(
            result.finding_id.starts_with("JEV-"),
            "finding id marks the source, got: {}",
            result.finding_id
        );
    }

    #[test]
    fn mid_band_maps_to_recorded_allow() {
        let assessment = GuardAssessment {
            risk: 0.6,
            injection: 0.6,
            destructive: 0.1,
        };
        let result = assessment
            .to_security_result("req-1", &GuardThresholds::default())
            .expect("mid band is still recorded");

        assert!(!result.is_malicious, "mid band must not force approval");
        assert!(result.should_ask_user);
    }

    #[test]
    fn low_risk_maps_to_none() {
        let assessment = GuardAssessment {
            risk: 0.1,
            injection: 0.1,
            destructive: 0.05,
        };
        assert!(assessment
            .to_security_result("req-1", &GuardThresholds::default())
            .is_none());
    }

    fn shell_tool_call(command: &str) -> rmcp::model::CallToolRequestParams {
        rmcp::model::CallToolRequestParams::new("shell").with_arguments(rmcp::object!({
            "command": command
        }))
    }

    fn jev_env<'a>(enabled: Option<&'a str>, endpoint: Option<&'a str>) -> env_lock::EnvGuard<'a> {
        env_lock::lock_env([
            ("JEV_ENABLED", enabled),
            ("JEV_GUARD_ENABLED", enabled),
            ("JEV_API_KEY", Some("test-key")),
            ("JEV_ENDPOINT", endpoint),
            ("JEV_MODEL", None::<&str>),
            ("JEV_TIMEOUT_MS", None::<&str>),
            ("JEV_GUARD_THRESHOLD", None::<&str>),
        ])
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn advise_tool_call_returns_none_when_disabled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guard_answers(1.0, 1.0)))
            .mount(&server)
            .await;

        let _guard = jev_env(None, None);
        let result = advise_tool_call(&shell_tool_call("echo hello"), &[], "req-1").await;

        assert!(result.is_none(), "disabled guard must stay silent");
        let received = server.received_requests().await.expect("requests tracked");
        assert!(received.is_empty(), "disabled guard must not call Jev");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn advise_tool_call_maps_high_risk_to_malicious() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(guard_answers(0.95, 0.1)))
            .expect(1)
            .mount(&server)
            .await;

        let endpoint = format!("{}/v1/systemone", server.uri());
        let _guard = jev_env(Some("true"), Some(&endpoint));
        let result = advise_tool_call(&shell_tool_call("echo hello"), &[], "req-9").await;

        let advisory = result.expect("high risk produces an advisory");
        assert!(advisory.is_malicious);
        assert!(advisory.should_ask_user);
        assert_eq!(advisory.tool_request_id, "req-9");
        assert!(advisory.finding_id.starts_with("JEV-"));
        assert!(advisory.explanation.contains("jev-assistant:"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn advise_tool_call_returns_none_on_jev_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let endpoint = format!("{}/v1/systemone", server.uri());
        let _guard = jev_env(Some("true"), Some(&endpoint));
        let result = advise_tool_call(&shell_tool_call("echo hello"), &[], "req-1").await;

        assert!(result.is_none(), "Jev errors must fail open to no advisory");
    }
}

//! HTTP client for the TypeSafe SystemOne API (`POST {endpoint}`).
//!
//! Bearer auth, one retry on 429/529 with a short backoff, hard timeout.
//! Every failure surfaces as `Err`: callers must fall back to non-Jev behavior.

use super::types::{Question, SystemOneRequest, SystemOneResponse};
use crate::config::{Config, ConfigError};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

/// Default evaluation endpoint (overridable via `JEV_ENDPOINT`).
pub const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// Default model (overridable via `JEV_MODEL`).
pub const DEFAULT_MODEL: &str = "jev-latest";
/// Default per-call budget in ms (overridable via `JEV_TIMEOUT_MS`).
pub const DEFAULT_TIMEOUT_MS: u64 = 1000;

pub struct JevClient {
    endpoint: String,
    api_key: String,
    model: String,
    client: reqwest::Client,
}

// The API key must never appear in logs.
impl fmt::Debug for JevClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JevClient")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"<redacted>")
            .field("model", &self.model)
            .finish()
    }
}

impl JevClient {
    /// Direct constructor (tests, one-off wiring).
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("Failed to create Jev HTTP client")?;
        Ok(Self {
            endpoint: endpoint.into(),
            api_key: api_key.into(),
            model: model.into(),
            client,
        })
    }

    /// Build from `JEV_*` config keys. `JEV_API_KEY` (secret or env) is required;
    /// endpoint, model, and timeout fall back to [`DEFAULT_ENDPOINT`],
    /// [`DEFAULT_MODEL`], and [`DEFAULT_TIMEOUT_MS`].
    pub fn from_config() -> Result<Self> {
        let config = Config::global();

        let api_key: String = config
            .get_secret("JEV_API_KEY")
            .context("JEV_API_KEY is not set (add it as a secret or env var)")?;
        if api_key.trim().is_empty() {
            anyhow::bail!("JEV_API_KEY is not set (add it as a secret or env var)");
        }

        let endpoint = match config.get_param::<String>("JEV_ENDPOINT") {
            Ok(value) => value,
            Err(ConfigError::NotFound(_)) => DEFAULT_ENDPOINT.to_string(),
            Err(e) => return Err(e.into()),
        };
        let model = match config.get_param::<String>("JEV_MODEL") {
            Ok(value) => value,
            Err(ConfigError::NotFound(_)) => DEFAULT_MODEL.to_string(),
            Err(e) => return Err(e.into()),
        };
        let timeout_ms = match config.get_param::<u64>("JEV_TIMEOUT_MS") {
            Ok(value) => value,
            Err(ConfigError::NotFound(_)) => DEFAULT_TIMEOUT_MS,
            Err(e) => return Err(e.into()),
        };

        Self::new(endpoint, api_key, model, Duration::from_millis(timeout_ms))
    }

    /// Evaluate `questions` against `state` in one parallel call.
    pub async fn evaluate(
        &self,
        state: Value,
        questions: BTreeMap<String, Question>,
    ) -> Result<SystemOneResponse> {
        let request = SystemOneRequest {
            state,
            model: self.model.clone(),
            questions,
        };

        let mut attempts = 0;
        loop {
            attempts += 1;
            let response = self
                .client
                .post(&self.endpoint)
                .bearer_auth(&self.api_key)
                .json(&request)
                .send()
                .await
                .context("Failed to send Jev evaluation request")?;

            let status = response.status();
            // TypeSafe asks clients to back off on rate limiting / overload.
            if (status.as_u16() == 429 || status.as_u16() == 529) && attempts == 1 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }

            if !status.is_success() {
                let error_body = response.text().await.unwrap_or_default();
                anyhow::bail!("Jev API returned error status {status}: {error_body}");
            }

            return response
                .json::<SystemOneResponse>()
                .await
                .context("Failed to parse Jev evaluation response");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::types::Question;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::time::Duration;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn route_questions() -> BTreeMap<String, Question> {
        BTreeMap::from([(
            "route".to_string(),
            Question::choice(
                "Which backend should handle this turn",
                BTreeMap::from([
                    ("fast".to_string(), json!("Trivial chat or lookups")),
                    ("default".to_string(), json!("Normal coding and Q&A work")),
                ]),
            ),
        )])
    }

    fn answers_body() -> Value {
        json!({
            "model": "jev-1.13.0",
            "answers": {
                "route": {
                    "type": "choice",
                    "choice": "fast",
                    "confidence": 0.9,
                    "probabilities": { "fast": 0.9, "default": 0.1 }
                }
            },
            "usage": { "input_tokens": 10, "output_tokens": 2 }
        })
    }

    fn test_client(server: &MockServer) -> JevClient {
        JevClient::new(
            format!("{}/v1/systemone", server.uri()),
            "test-key",
            "jev-latest",
            Duration::from_millis(5000),
        )
        .expect("client builds")
    }

    #[tokio::test]
    async fn evaluate_posts_state_questions_and_parses_answers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .and(header("authorization", "Bearer test-key"))
            .and(body_partial_json(json!({
                "model": "jev-latest",
                "state": "hello",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(answers_body()))
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server);
        let response = client
            .evaluate(json!("hello"), route_questions())
            .await
            .expect("evaluate succeeds");

        let Some(crate::jev::types::Answer::Choice(route)) = response.answers.get("route") else {
            panic!("expected a choice answer for route");
        };
        assert_eq!(route.choice, "fast");
        assert!((route.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn retries_once_on_429_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(200).set_body_json(answers_body()))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let response = client
            .evaluate(json!("hello"), route_questions())
            .await
            .expect("retry succeeds");

        assert!(response.answers.contains_key("route"));
        let received = server.received_requests().await.expect("requests tracked");
        assert_eq!(received.len(), 2, "exactly one retry");
    }

    #[tokio::test]
    async fn returns_error_on_persistent_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.evaluate(json!("hello"), route_questions()).await;

        assert!(result.is_err(), "persistent 500 must surface as Err");
        let received = server.received_requests().await.expect("requests tracked");
        assert_eq!(received.len(), 1, "no retry on 500");
    }

    #[tokio::test]
    async fn returns_error_on_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(5))
                    .set_body_json(answers_body()),
            )
            .mount(&server)
            .await;

        let client = JevClient::new(
            format!("{}/v1/systemone", server.uri()),
            "test-key",
            "jev-latest",
            Duration::from_millis(100),
        )
        .expect("client builds");
        let result = client.evaluate(json!("hello"), route_questions()).await;

        assert!(result.is_err(), "timeout must surface as Err");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn from_config_errors_without_api_key() {
        let _guard = env_lock::lock_env([
            ("JEV_API_KEY", None::<&str>),
            ("JEV_ENDPOINT", None::<&str>),
            ("JEV_MODEL", None::<&str>),
            ("JEV_TIMEOUT_MS", None::<&str>),
        ]);

        let result = JevClient::from_config();
        let message = format!("{:?}", result.expect_err("missing key must fail"));
        assert!(
            message.contains("JEV_API_KEY"),
            "error names the missing key, got: {message}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn from_config_uses_env_endpoint_key_and_defaults() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/systemone"))
            .and(header("authorization", "Bearer env-key"))
            .and(body_partial_json(json!({ "model": "jev-latest" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(answers_body()))
            .expect(1)
            .mount(&server)
            .await;

        let _guard = env_lock::lock_env([
            ("JEV_API_KEY", Some("env-key")),
            (
                "JEV_ENDPOINT",
                Some(format!("{}/v1/systemone", server.uri()).as_str()),
            ),
            ("JEV_MODEL", None::<&str>),
            ("JEV_TIMEOUT_MS", None::<&str>),
        ]);

        let client = JevClient::from_config().expect("config builds client");
        let response = client
            .evaluate(json!("hello"), route_questions())
            .await
            .expect("evaluate succeeds");
        assert!(response.answers.contains_key("route"));
    }
}

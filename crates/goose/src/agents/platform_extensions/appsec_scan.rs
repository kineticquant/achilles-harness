//! Structured completions for Investigate/Deep. Bounded JSON turns can
//! `read` / `ledger` / `grep` against the workspace and achilles.db; thinking
//! stays off and native tool-calling is not required. Apache-2.0.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use achilles_store::engines::agent::ScanCompleter;

use crate::agents::Agent;
use crate::config::Config;
use crate::conversation::message::Message;
use crate::model_config::model_config_from_user_config;
use crate::providers::base::Provider;
use crate::session_context::with_session_id;
use goose_providers::thinking::ThinkingEffort;

struct ProviderCompleter {
    provider: Arc<dyn Provider>,
    model_config: goose_providers::model::ModelConfig,
    session_id: String,
}

impl ScanCompleter for ProviderCompleter {
    fn complete(
        &self,
        system: String,
        user: String,
    ) -> Pin<
        Box<
            dyn Future<Output = anyhow::Result<achilles_store::engines::agent::CompleteOut>> + Send,
        >,
    > {
        let provider = self.provider.clone();
        let model_config = self.model_config.clone();
        let session_id = self.session_id.clone();
        Box::pin(async move {
            let messages = vec![Message::user().with_text(&user)];
            let (response, usage) = with_session_id(
                Some(session_id),
                provider.complete(&model_config, &system, &messages, &[]),
            )
            .await?;
            Ok(achilles_store::engines::agent::CompleteOut {
                text: response.as_concat_text(),
                cost_usd: usage.cost,
            })
        })
    }
}

pub async fn from_agent(agent: &Agent, session_id: &str) -> Option<Arc<dyn ScanCompleter>> {
    let provider = agent.provider().await.ok()?;
    let model_config = agent
        .model_config_for_session(session_id)
        .await
        .ok()?
        .with_thinking_effort(ThinkingEffort::Off);
    Some(Arc::new(ProviderCompleter {
        provider,
        model_config,
        session_id: session_id.to_string(),
    }))
}

pub async fn from_config() -> Option<Arc<dyn ScanCompleter>> {
    let config = Config::global();
    let provider_name = config.get_goose_provider().ok()?;
    let model_name = config.get_goose_model().ok()?;
    let model_config = model_config_from_user_config(&provider_name, &model_name)
        .ok()?
        .with_thinking_effort(ThinkingEffort::Off);
    let provider = crate::providers::create(&provider_name, Vec::new())
        .await
        .ok()?;
    Some(Arc::new(ProviderCompleter {
        provider,
        model_config,
        session_id: "appsec-scan".into(),
    }))
}

pub async fn from_extension_context(
    context: &crate::agents::platform_extensions::PlatformExtensionContext,
    session_id: &str,
) -> Option<Arc<dyn ScanCompleter>> {
    let extension_manager = context.extension_manager.as_ref()?.upgrade()?;
    let provider = {
        let guard = extension_manager.get_provider().lock().await;
        guard.clone()?
    };
    let model_config = context
        .model_config_for_session(session_id)
        .await
        .ok()?
        .with_thinking_effort(ThinkingEffort::Off);
    Some(Arc::new(ProviderCompleter {
        provider,
        model_config,
        session_id: session_id.to_string(),
    }))
}

use super::*;
use crate::conversation::message::Message;
use achilles_store::acp::{
    AssessmentsCancelRequest, AssessmentsCancelResponse, AssessmentsGetRequest,
    AssessmentsGetResponse, AssessmentsListRequest, AssessmentsListResponse,
    AssessmentsPauseRequest, AssessmentsPauseResponse, AssessmentsStartRequest,
    AssessmentsStartResponse, FindingDto, FindingsListRequest, FindingsListResponse,
    FindingsSetStateRequest, FindingsSetStateResponse, UtilsRunRequest, UtilsRunResponse,
};

impl GooseAcpAgent {
    pub(super) async fn on_achilles_assessments_start(
        &self,
        req: AssessmentsStartRequest,
    ) -> Result<AssessmentsStartResponse, agent_client_protocol::Error> {
        let (socket_api_token, socket_org) = crate::config::achilles_socket_creds();
        let depth = req.depth.clone().unwrap_or_else(|| "fast".into());
        let mode = req.mode.clone().unwrap_or_else(|| "quick".into());
        let completer =
            if achilles_store::engines::depth::ScanDepth::parse(&depth).runs_investigate() {
                if let Some(session_id) = req.session_id.as_deref() {
                    match self.get_session_agent(session_id).await {
                        Ok(agent) => {
                            crate::agents::platform_extensions::appsec_scan::from_agent(
                                &agent, session_id,
                            )
                            .await
                        }
                        Err(error) => {
                            tracing::debug!(
                                error = %error,
                                "scan will skip AI review; session agent unavailable"
                            );
                            None
                        }
                    }
                } else {
                    crate::agents::platform_extensions::appsec_scan::from_config().await
                }
            } else {
                None
            };
        let assessment = achilles_store::scan::start_scan(
            self.achilles_store.clone(),
            achilles_store::scan::ScanRequest {
                working_dir: req.working_dir,
                session_id: req.session_id.clone(),
                mode: mode.clone(),
                trigger: "scan_cta".into(),
                parent_assessment_id: req.parent_assessment_id,
                wait: req.wait,
                include_vendor: req.include_vendor,
                scan_literals: req.scan_literals,
                scan_delta: req.scan_delta,
                depth: depth.clone(),
                socket_api_token,
                socket_org,
                completer,
                resume_assessment_id: req.resume_assessment_id,
                max_duration_secs: req.max_duration_secs,
                max_cost_usd: req.max_cost_usd,
            },
        )
        .await
        .invalid_params_err()?;

        if let Some(session_id) = req.session_id.as_deref() {
            self.persist_scan_session_history(session_id, &mode, &depth)
                .await;
            if let Err(error) = self.enable_appsec_for_session(session_id).await {
                tracing::warn!(
                    session_id,
                    error = %error,
                    "scan started without hydrating AppSec tools for the chat"
                );
            }
        }

        Ok(AssessmentsStartResponse {
            assessment: assessment.into(),
        })
    }

    pub(super) async fn on_achilles_assessments_cancel(
        &self,
        req: AssessmentsCancelRequest,
    ) -> Result<AssessmentsCancelResponse, agent_client_protocol::Error> {
        let assessment =
            achilles_store::scan::cancel_scan(&self.achilles_store, &req.assessment_id)
                .await
                .invalid_params_err()?;
        Ok(AssessmentsCancelResponse {
            assessment: assessment.into(),
        })
    }

    pub(super) async fn on_achilles_assessments_pause(
        &self,
        req: AssessmentsPauseRequest,
    ) -> Result<AssessmentsPauseResponse, agent_client_protocol::Error> {
        let assessment =
            achilles_store::scan::pause_scan(&self.achilles_store, &req.assessment_id, req.paused)
                .await
                .invalid_params_err()?;
        Ok(AssessmentsPauseResponse {
            assessment: assessment.into(),
        })
    }

    pub(super) async fn on_achilles_assessments_list(
        &self,
        req: AssessmentsListRequest,
    ) -> Result<AssessmentsListResponse, agent_client_protocol::Error> {
        let assessments = if let Some(session_id) = req
            .session_id
            .as_deref()
            .filter(|session_id| !session_id.is_empty())
        {
            self.achilles_store
                .list_assessments_for_session(session_id)
                .await
                .internal_err()?
        } else {
            self.achilles_store
                .list_assessments(req.working_dir.as_deref())
                .await
                .internal_err()?
        };
        Ok(AssessmentsListResponse {
            assessments: assessments.into_iter().map(Into::into).collect(),
        })
    }

    pub(super) async fn on_achilles_assessments_get(
        &self,
        req: AssessmentsGetRequest,
    ) -> Result<AssessmentsGetResponse, agent_client_protocol::Error> {
        let assessment = self
            .achilles_store
            .get_assessment(&req.assessment_id)
            .await
            .internal_err()?
            .ok_or_else(|| {
                agent_client_protocol::Error::invalid_params()
                    .data(format!("unknown assessment {}", req.assessment_id))
            })?;
        Ok(AssessmentsGetResponse {
            assessment: assessment.into(),
        })
    }

    pub(super) async fn on_achilles_findings_list(
        &self,
        req: FindingsListRequest,
    ) -> Result<FindingsListResponse, agent_client_protocol::Error> {
        let findings = self
            .achilles_store
            .list_findings_history(
                req.assessment_id.as_deref(),
                req.engagement_id.as_deref(),
                req.working_dir.as_deref(),
            )
            .await
            .internal_err()?;
        Ok(FindingsListResponse {
            findings: findings.into_iter().map(FindingDto::from).collect(),
        })
    }

    pub(super) async fn on_achilles_findings_set_state(
        &self,
        req: FindingsSetStateRequest,
    ) -> Result<FindingsSetStateResponse, agent_client_protocol::Error> {
        let finding = self
            .achilles_store
            .triage_finding(&req.finding_id, &req.state, req.reason.as_deref())
            .await
            .invalid_params_err()?;
        Ok(FindingsSetStateResponse {
            finding: FindingDto::from(finding),
        })
    }

    pub(super) async fn on_achilles_utils_run(
        &self,
        req: UtilsRunRequest,
    ) -> Result<UtilsRunResponse, agent_client_protocol::Error> {
        let working_dir = req.working_dir.clone();
        let action = req.action.clone();
        let path = req.path.clone();
        let text = req.text.clone();
        let passphrase = req.passphrase.clone();
        let expected = req.expected.clone();
        let confirm = req.confirm;
        let result = tokio::task::spawn_blocking(move || {
            let root = std::path::Path::new(&working_dir);
            achilles_store::engines::utils::run(achilles_store::engines::utils::UtilsArgs {
                action: &action,
                root,
                path: path.as_deref(),
                text: text.as_deref(),
                passphrase: passphrase.as_deref(),
                expected: expected.as_deref(),
                confirm,
            })
        })
        .await
        .map_err(|e| agent_client_protocol::Error::internal_error().data(e.to_string()))?
        .invalid_params_err()?;
        Ok(UtilsRunResponse { result })
    }

    async fn persist_scan_session_history(&self, session_id: &str, mode: &str, depth: &str) {
        let session = match self.session_manager.get_session(session_id, false).await {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(
                    session_id,
                    error = %error,
                    "scan started without loading the chat session for history"
                );
                return;
            }
        };
        if session.message_count > 0 {
            return;
        }
        let kickoff = scan_kickoff_text(mode, depth);
        if let Err(error) = self
            .session_manager
            .add_message(session_id, &Message::user().with_text(&kickoff))
            .await
        {
            tracing::warn!(
                session_id,
                error = %error,
                "scan started without recording a chat history message"
            );
        }
    }

    async fn enable_appsec_for_session(
        &self,
        session_id: &str,
    ) -> Result<(), agent_client_protocol::Error> {
        let agent = self.get_session_agent(session_id).await?;
        if agent
            .extension_manager
            .is_extension_enabled(crate::agents::platform_extensions::appsec::EXTENSION_NAME)
            .await
        {
            return Ok(());
        }
        let config = crate::config::extensions::get_extension_by_name(
            crate::agents::platform_extensions::appsec::EXTENSION_NAME,
        )
        .ok_or_else(|| {
            agent_client_protocol::Error::internal_error().data("AppSec extension is not available")
        })?;
        agent
            .add_extension(config, session_id)
            .await
            .internal_err()?;
        Ok(())
    }
}

fn scan_kickoff_text(mode: &str, depth: &str) -> String {
    let kind = match depth {
        "investigate" => "an Investigative",
        "deep" => "a Deep",
        _ => "a Fast",
    };
    if mode == "diff" {
        format!("Perform {kind} Scan on changed files")
    } else {
        format!("Perform {kind} Scan on my repo")
    }
}

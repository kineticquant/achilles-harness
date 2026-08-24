use super::*;
use achilles_store::acp::{
    AssessmentsGetRequest, AssessmentsGetResponse, AssessmentsListRequest, AssessmentsListResponse,
    AssessmentsStartRequest, AssessmentsStartResponse, FindingDto, FindingsListRequest,
    FindingsListResponse,
};

impl GooseAcpAgent {
    pub(super) async fn on_achilles_assessments_start(
        &self,
        req: AssessmentsStartRequest,
    ) -> Result<AssessmentsStartResponse, agent_client_protocol::Error> {
        let assessment = achilles_store::scan::start_scan(
            self.achilles_store.clone(),
            achilles_store::scan::ScanRequest {
                working_dir: req.working_dir,
                session_id: req.session_id,
                mode: req.mode.unwrap_or_else(|| "quick".into()),
                trigger: "scan_cta".into(),
                parent_assessment_id: req.parent_assessment_id,
                wait: req.wait,
            },
        )
        .await
        .invalid_params_err()?;
        Ok(AssessmentsStartResponse {
            assessment: assessment.into(),
        })
    }

    pub(super) async fn on_achilles_assessments_list(
        &self,
        req: AssessmentsListRequest,
    ) -> Result<AssessmentsListResponse, agent_client_protocol::Error> {
        let assessments = self
            .achilles_store
            .list_assessments(req.working_dir.as_deref())
            .await
            .internal_err()?;
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
            .list_findings(
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
}

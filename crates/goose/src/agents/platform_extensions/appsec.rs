use crate::agents::extension::PlatformExtensionContext;
use crate::agents::mcp_client::{Error, McpClientTrait};
use crate::agents::tool_execution::ToolCallContext;
use crate::config::paths::Paths;
use anyhow::Result;
use async_trait::async_trait;
use indoc::indoc;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, InitializeResult, JsonObject, ListToolsResult,
    ServerCapabilities, Tool, ToolAnnotations,
};
use schemars::{schema_for, JsonSchema};
use serde::Deserialize;
use serde_json::json;
use tokio_util::sync::CancellationToken;

pub static EXTENSION_NAME: &str = "appsec";

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecScanParams {
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    wait: Option<bool>,
    #[serde(default)]
    parent_assessment_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecQueryParams {
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    assessment_id: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecReadHandleParams {
    handle_id: String,
    #[serde(default)]
    include_payload: Option<bool>,
}

pub struct AppsecClient {
    info: InitializeResult,
    store: achilles_store::AchillesStore,
}

impl AppsecClient {
    pub fn new(_context: PlatformExtensionContext) -> Result<Self> {
        let info = InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new(EXTENSION_NAME.to_string(), "1.0.0".to_string())
                    .with_title("AppSec"),
            )
            .with_instructions(
                indoc! {r#"
                Achilles AppSec ledger (achilles.db). Engines are authoritative.

                - appsec_scan: run secrets + SCA. Default wait=true so you get a preview.
                - appsec_query: read the latest assessment. Returns a short preview + handle id.
                - appsec_read_handle: metadata (and optional payload). Do not dump payloads into chat.

                Never invent CVEs, secrets, or line numbers. If the ledger is empty, say so.
            "#}
                .to_string(),
            );

        Ok(Self {
            info,
            store: achilles_store::AchillesStore::new(Paths::data_dir()),
        })
    }

    fn resolve_working_dir(
        arguments: Option<&JsonObject>,
        ctx: &ToolCallContext,
        key: &str,
    ) -> Option<String> {
        arguments
            .and_then(|args| args.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| ctx.working_dir_str().map(str::to_string))
            .or_else(|| std::env::current_dir().ok()?.to_str().map(str::to_string))
    }

    async fn handle_scan(
        &self,
        ctx: &ToolCallContext,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let fallback = Self::resolve_working_dir(arguments.as_ref(), ctx, "working_dir");
        let mut params: AppsecScanParams = if let Some(args) = arguments {
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| format!("invalid arguments: {e}"))?
        } else {
            AppsecScanParams {
                working_dir: fallback.clone(),
                mode: None,
                wait: None,
                parent_assessment_id: None,
            }
        };
        if params.working_dir.is_none() {
            params.working_dir = fallback;
        }
        let working_dir = params.working_dir.ok_or("working_dir is required")?;
        let wait = params.wait.unwrap_or(true);
        let assessment = achilles_store::scan::start_scan(
            self.store.clone(),
            achilles_store::scan::ScanRequest {
                working_dir,
                session_id: Some(ctx.session_id.clone()),
                mode: params.mode.unwrap_or_else(|| "quick".into()),
                trigger: "agent".into(),
                parent_assessment_id: params.parent_assessment_id,
                wait,
            },
        )
        .await
        .map_err(|e| e.to_string())?;

        if !wait {
            return Ok(vec![ContentBlock::text(format!(
                "Scan started (status={}). assessment_id={}. Call appsec_query when it finishes. Do not invent findings while it is running.",
                assessment.status.as_str(),
                assessment.id
            ))]);
        }

        let query = achilles_store::scan::query_ledger(
            &self.store,
            None,
            Some(&assessment.id),
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(vec![ContentBlock::text(format_query(&query))])
    }

    async fn handle_query(
        &self,
        ctx: &ToolCallContext,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let working_dir = Self::resolve_working_dir(arguments.as_ref(), ctx, "working_dir");
        let params: AppsecQueryParams = if let Some(args) = arguments {
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| format!("invalid arguments: {e}"))?
        } else {
            AppsecQueryParams {
                working_dir: working_dir.clone(),
                assessment_id: None,
                category: None,
            }
        };
        let query = achilles_store::scan::query_ledger(
            &self.store,
            params.working_dir.as_deref().or(working_dir.as_deref()),
            params.assessment_id.as_deref(),
            params.category.as_deref(),
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(vec![ContentBlock::text(format_query(&query))])
    }

    async fn handle_read_handle(
        &self,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let params: AppsecReadHandleParams = serde_json::from_value(serde_json::Value::Object(
            arguments.ok_or("Missing arguments")?,
        ))
        .map_err(|e| format!("invalid arguments: {e}"))?;
        let include = params.include_payload.unwrap_or(false);
        let handle = self
            .store
            .get_handle(&params.handle_id, include)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("unknown handle {}", params.handle_id))?;
        let body = json!({
            "handleId": handle.handle_id,
            "kind": handle.kind,
            "bytes": handle.bytes,
            "sha256": handle.sha256,
            "preview": handle.preview,
            "payloadIncluded": include,
            "payload": if include { handle.payload } else { None },
            "note": "Do not paste the payload into chat. Point the user at Findings for the full ledger."
        });
        Ok(vec![ContentBlock::text(
            serde_json::to_string_pretty(&body).unwrap_or_else(|_| handle.preview),
        )])
    }

    fn get_tools() -> Vec<Tool> {
        let scan_schema = serde_json::to_value(schema_for!(AppsecScanParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let query_schema = serde_json::to_value(schema_for!(AppsecQueryParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let handle_schema = serde_json::to_value(schema_for!(AppsecReadHandleParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();

        vec![
            Tool::new(
                "appsec_scan".to_string(),
                "Run Achilles secrets + SCA engines and record results in achilles.db. Returns a short preview and a handle id — not the full finding dump.".to_string(),
                scan_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec scan".to_string()),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            )),
            Tool::new(
                "appsec_query".to_string(),
                "Read the AppSec ledger for a workspace or assessment. Preview only; use the handle / Findings view for the rest.".to_string(),
                query_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec query".to_string()),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            )),
            Tool::new(
                "appsec_read_handle".to_string(),
                "Read a scan handle. Default is preview only. Set include_payload=true only when you must inspect engine JSON; do not paste it into chat.".to_string(),
                handle_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec handle".to_string()),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            )),
        ]
    }
}

fn format_query(query: &achilles_store::scan::LedgerQuery) -> String {
    let Some(assessment) = &query.assessment else {
        return "No assessments in the ledger for this workspace. Call appsec_scan first. Do not invent findings.".into();
    };
    let handle = query
        .summary_handle_id
        .as_deref()
        .unwrap_or("(none yet — scan may still be running)");
    format!(
        "assessment_id={}\nstatus={}\nopen={}\nhandle_id={}\n\n{}\n\nShow this preview in chat. Direct the user to Findings for the full list. Do not invent extra issues.",
        assessment.id,
        assessment.status.as_str(),
        assessment.open_finding_count,
        handle,
        query.preview
    )
}

#[async_trait]
impl McpClientTrait for AppsecClient {
    async fn list_tools(
        &self,
        _session_id: &str,
        _next_cursor: Option<String>,
        _cancellation_token: CancellationToken,
    ) -> Result<ListToolsResult, Error> {
        Ok(ListToolsResult {
            tools: Self::get_tools(),
            next_cursor: None,
            meta: None,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        ctx: &ToolCallContext,
        name: &str,
        arguments: Option<JsonObject>,
        _cancellation_token: CancellationToken,
    ) -> Result<CallToolResult, Error> {
        let content = match name {
            "appsec_scan" => self.handle_scan(ctx, arguments).await,
            "appsec_query" => self.handle_query(ctx, arguments).await,
            "appsec_read_handle" => self.handle_read_handle(arguments).await,
            _ => Err(format!("Unknown tool: {name}")),
        };
        match content {
            Ok(content) => Ok(CallToolResult::success(content)),
            Err(error) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Error: {error}"
            ))])),
        }
    }

    fn get_info(&self) -> Option<&InitializeResult> {
        Some(&self.info)
    }

    async fn get_moim(&self, _session_id: &str) -> Option<String> {
        Some(
            "AppSec: engines write achilles.db. Use appsec_scan / appsec_query. Chat gets a preview + handle; never invent findings.\n"
                .into(),
        )
    }
}

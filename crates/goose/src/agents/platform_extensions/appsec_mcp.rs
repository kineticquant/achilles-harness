//! Achilles MCP — stdio server so Cursor, Claude Code, Codex, OpenCode
//! (and any MCP client) can read and triage `achilles.db`.
//! Preferred name: **Achilles MCP**. User-facing CLI: `achilles mcp`.
//! Apache-2.0.

use std::sync::Arc;

use anyhow::Result;
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResponse, ErrorCode, ErrorData, Implementation,
        InitializeResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    transport::stdio,
    RoleServer, ServerHandler, ServiceExt,
};
use tokio_util::sync::CancellationToken;

use crate::agents::extension::PlatformExtensionContext;
use crate::agents::mcp_client::McpClientTrait;
use crate::agents::platform_extensions::appsec::AppsecClient;
use crate::agents::tool_execution::ToolCallContext;
use crate::config::paths::Paths;
use crate::session::SessionManager;

const MCP_SESSION: &str = "achilles-mcp";

pub struct AchillesMcpServer {
    client: AppsecClient,
}

impl AchillesMcpServer {
    pub fn new() -> Result<Self> {
        let data_dir = Paths::data_dir();
        let session_manager = Arc::new(SessionManager::new(data_dir));
        let client = AppsecClient::new(PlatformExtensionContext {
            extension_manager: None,
            session_manager,
            scheduler: None,
            session: None,
            use_login_shell_path: false,
        })?;
        Ok(Self { client })
    }
}

fn achilles_mcp_info() -> ServerInfo {
    InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
        .with_server_info(
            Implementation::new("achilles".to_string(), env!("CARGO_PKG_VERSION").to_string())
                .with_title("Achilles MCP"),
        )
        .with_instructions(
            "Achilles MCP. Query Achilles findings, investigate one id, or call appsec_brief for a pasteable fix task. \
Apply the patch in this workspace. Then appsec_triage state=verified_fixed (or dismissed for a false positive). \
Prefer depth=fast if you scan. Do not invent finding ids, CVEs, or secrets. Do not print secret values. \
When talking to the user: say findings, never ledger.",
        )
}

impl ServerHandler for AchillesMcpServer {
    fn get_info(&self) -> ServerInfo {
        achilles_mcp_info()
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: AppsecClient::mcp_tools(),
            next_cursor: None,
            meta: None,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let cwd = std::env::current_dir().ok();
        let ctx = ToolCallContext::new(MCP_SESSION.to_string(), cwd, None);
        self.client
            .call_tool(
                &ctx,
                request.name.as_ref(),
                request.arguments,
                CancellationToken::new(),
            )
            .await
            .map(CallToolResponse::from)
            .map_err(|e| ErrorData::new(ErrorCode::INTERNAL_ERROR, e.to_string(), None))
    }
}

pub async fn serve_stdio() -> Result<()> {
    let server = AchillesMcpServer::new()?;
    let running = server.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::platform_extensions::appsec::AppsecClient;

    #[test]
    fn mcp_tools_are_the_external_surface() {
        let names: Vec<String> = AppsecClient::mcp_tools()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        for expected in [
            "appsec_query",
            "appsec_investigate",
            "appsec_brief",
            "appsec_triage",
            "appsec_scan",
            "appsec_intel",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "{expected} missing from {names:?}"
            );
        }
        assert_eq!(names.len(), 6);
    }

    #[test]
    fn server_advertises_achilles_mcp() {
        let info = achilles_mcp_info();
        assert_eq!(info.server_info.name, "achilles");
        assert_eq!(info.server_info.title.as_deref(), Some("Achilles MCP"));
        assert!(info.capabilities.tools.is_some());
    }
}

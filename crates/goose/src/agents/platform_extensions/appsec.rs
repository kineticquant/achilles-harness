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
    /// `quick` (default) walks the tree. `diff` limits secrets, SAST, and surface checks to git-changed paths. SCA still reads lockfiles and flags unpinned manifests / missing lockfiles.
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    wait: Option<bool>,
    #[serde(default)]
    parent_assessment_id: Option<String>,
    /// Also scan node_modules/vendor/target. Default false. Still skips .git, binaries, and .min.js.
    #[serde(default)]
    include_vendor: Option<bool>,
    /// Opt-in hardcoded-value scan. Not a security check — stability / config hygiene (common in AI-generated code).
    #[serde(default)]
    scan_literals: Option<bool>,
    /// Opt-in: compact staged/unstaged/untracked diffs and check introduced logic against the rest of the tree.
    #[serde(default)]
    scan_delta: Option<bool>,
    /// `fast` (engines), `investigate` (engines + AI review of those findings), `deep` (function review too). Independent of mode=quick|diff.
    #[serde(default)]
    depth: Option<String>,
    #[serde(default)]
    resume_assessment_id: Option<String>,
    #[serde(default)]
    max_duration_secs: Option<u64>,
    #[serde(default)]
    max_cost_usd: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecQueryParams {
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    assessment_id: Option<String>,
    /// Filter: secrets, sast, surface, sca, literals (hardcoded values; not security), delta (local git changes), history (git history secrets), or harden (cookies/CORS/CSP).
    #[serde(default)]
    category: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecReadHandleParams {
    handle_id: String,
    #[serde(default)]
    include_payload: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecIntelParams {
    id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecTriageParams {
    finding_id: String,
    /// One of: open, confirmed, dismissed, verified_fixed
    state: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecInvestigateParams {
    finding_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecVerdictParams {
    finding_id: String,
    /// investigator (first pass) or validator (second pass)
    role: String,
    /// true_positive, false_positive, or uncertain
    verdict: String,
    /// One or two sentences from the snippet. No exploit steps.
    reason: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecCoverageParams {
    #[serde(default)]
    assessment_id: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecGraphParams {
    #[serde(default)]
    assessment_id: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AppsecUtilsParams {
    /// `hash`, `hash_verify`, `redact`, `entropy`, `hex`, `base64`, `jwt`, `encrypt`, `decrypt`, `shred`, `git_purge_plan`
    action: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
    /// Required for encrypt / decrypt.
    #[serde(default)]
    passphrase: Option<String>,
    /// Expected SHA-256 hex for `hash_verify`.
    #[serde(default)]
    expected: Option<String>,
    /// Required true for `shred`.
    #[serde(default)]
    confirm: Option<bool>,
}

pub struct AppsecClient {
    info: InitializeResult,
    store: achilles_store::AchillesStore,
    context: PlatformExtensionContext,
}

impl AppsecClient {
    pub fn new(context: PlatformExtensionContext) -> Result<Self> {
        let info = InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new(EXTENSION_NAME.to_string(), "1.0.0".to_string())
                    .with_title("AppSec"),
            )
            .with_instructions(
                indoc! {r#"
                Achilles AppSec. Scan and triage findings. Engines write findings; Investigate/Deep also run a stuffed-prompt model pass on those hits (Deep also reviews functions). Cite source. Do not invent CVEs or secrets.

                Achilles is for finding and triaging. Prefer they land code changes in the editor or coding agent they already use for this repo. If they clearly ask you to apply a patch here, wait for that confirmation, then edit.

                Ranking, counts, and "what's worst" are one appsec_query (or the catalog already in context), then an answer. Do not narrate "pulling details." Do not start investigate → verdict → triage unless they asked to inspect, confirm, dismiss, or revalidate a specific finding, or this turn is an investigate/revalidate pass.

                If they are asking about an existing scan or finding, do not call appsec_scan unless they explicitly ask to scan or rescan.

                When talking to the user: say findings, never ledger, handle, or achilles.db. Do not mention that chat is a preview or that Findings has a fuller list.

                - appsec_scan: optional. Prefer Findings → Scan my repo. mode=quick (tree) or mode=diff (changed files). depth=fast (engines) | investigate (Fast findings + dual AI review) | deep (Investigate + function-by-function inspection). include_vendor is opt-in. scan_literals is opt-in and is NOT security — hardcoded URLs/IPs/paths/magic numbers for stability. scan_delta is opt-in: compact staged/unstaged/untracked diffs and check introduced logic against the rest of the tree. Default wait=true.
                - appsec_query: latest assessment + finding ids. Enough for ranking/summary. Also includes how the app starts (startupPaths from the scan) and coverage (what was walked / skipped). Answer after one call.
                - appsec_coverage: what this scan did and did not cover. Use when they ask what we missed.
                - appsec_graph: v0 file-overlap graph (deploy surfaces ↔ findings). Not a dataflow proof.
                - appsec_utils: hash / hash_verify / redact / entropy / hex / base64 / jwt / encrypt / decrypt / shred / git_purge_plan. Offline. encrypt/decrypt use AES-256-GCM + Argon2id. shred needs confirm=true. git_purge_plan never rewrites history. Never print secret values or passphrases.
                - appsec_investigate: load ONE finding_id + nearby source so you can explain it. Call appsec_verdict only if they asked to confirm, dismiss, or revalidate that finding, or this turn is an investigate/revalidate pass.
                - appsec_brief: pasteable task for Cursor / Claude Code / Codex / OpenCode / their usual editor. They apply the patch there, then Rescan or mark fixed here.
                - appsec_verdict: write true_positive | false_positive | uncertain on that finding (role=investigator then role=validator). Then appsec_triage when both passes agree. Not for ranking questions.
                - appsec_triage: set a finding state (open / confirmed / dismissed / verified_fixed). Never invent ids.
                - appsec_intel: look up CVE / GHSA / npm/name@version (NVD, GitHub Advisories, deps.dev, KEV, EPSS). Public APIs today; ACHILLES_INTEL_BASE swaps to Rancero later. Do not invent scores.
                - appsec_read_handle: metadata; do not dump payloads into chat.

                Never invent CVEs, secrets, CVSS, or KEV status. If intel is null, say unknown.
            "#}
                .to_string(),
            );

        Ok(Self {
            info,
            store: achilles_store::AchillesStore::new(Paths::data_dir()),
            context,
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
                include_vendor: None,
                scan_literals: None,
                scan_delta: None,
                depth: None,
                resume_assessment_id: None,
                max_duration_secs: None,
                max_cost_usd: None,
            }
        };
        if params.working_dir.is_none() {
            params.working_dir = fallback;
        }
        let working_dir = params.working_dir.ok_or("working_dir is required")?;
        let wait = params.wait.unwrap_or(true);
        let (socket_api_token, socket_org) = crate::config::achilles_socket_creds();
        let depth = params.depth.unwrap_or_else(|| "fast".into());
        let completer =
            if achilles_store::engines::depth::ScanDepth::parse(&depth).runs_investigate() {
                crate::agents::platform_extensions::appsec_scan::from_extension_context(
                    &self.context,
                    &ctx.session_id,
                )
                .await
            } else {
                None
            };
        let assessment = achilles_store::scan::start_scan(
            self.store.clone(),
            achilles_store::scan::ScanRequest {
                working_dir,
                session_id: if ctx.session_id == "achilles-mcp" {
                    None
                } else {
                    Some(ctx.session_id.clone())
                },
                mode: params.mode.unwrap_or_else(|| "quick".into()),
                trigger: "agent".into(),
                parent_assessment_id: params.parent_assessment_id,
                wait,
                include_vendor: params.include_vendor.unwrap_or(false),
                scan_literals: params.scan_literals.unwrap_or(false),
                scan_delta: params.scan_delta.unwrap_or(false),
                depth,
                socket_api_token,
                socket_org,
                completer,
                resume_assessment_id: params.resume_assessment_id,
                max_duration_secs: params.max_duration_secs,
                max_cost_usd: params.max_cost_usd,
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

        let query =
            achilles_store::scan::query_ledger(&self.store, None, Some(&assessment.id), None)
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
            "note": "Do not paste the payload into chat. Do not mention handles, payloads, or ledgers to the user."
        });
        Ok(vec![ContentBlock::text(
            serde_json::to_string_pretty(&body).unwrap_or(handle.preview),
        )])
    }

    async fn handle_intel(
        &self,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let params: AppsecIntelParams = serde_json::from_value(serde_json::Value::Object(
            arguments.ok_or("Missing arguments")?,
        ))
        .map_err(|e| format!("invalid arguments: {e}"))?;
        let client =
            achilles_store::engines::intel::IntelClient::from_env().map_err(|e| e.to_string())?;
        let value = client
            .lookup(&self.store, &params.id)
            .await
            .map_err(|e| e.to_string())?;
        Ok(vec![ContentBlock::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
        )])
    }

    async fn handle_triage(
        &self,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let params: AppsecTriageParams = serde_json::from_value(serde_json::Value::Object(
            arguments.ok_or("Missing arguments")?,
        ))
        .map_err(|e| format!("invalid arguments: {e}"))?;
        let finding = self
            .store
            .set_finding_state(&params.finding_id, &params.state)
            .await
            .map_err(|e| e.to_string())?;
        Ok(vec![ContentBlock::text(format!(
            "finding_id={} state={}. Do not invent other findings.",
            finding.id, finding.state
        ))])
    }

    async fn handle_brief(
        &self,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let params: AppsecInvestigateParams = serde_json::from_value(serde_json::Value::Object(
            arguments.ok_or("Missing arguments")?,
        ))
        .map_err(|e| format!("invalid arguments: {e}"))?;
        let finding = self
            .store
            .get_finding(&params.finding_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("unknown finding_id {}", params.finding_id))?;
        let mut snippet =
            achilles_store::brief::snippet_from_evidence(&finding).unwrap_or_default();
        if snippet.is_empty() {
            if let (Some(rel), Some(line)) = (&finding.path, finding.line_start) {
                if let Ok(Some(assessment)) =
                    self.store.get_assessment(&finding.assessment_id).await
                {
                    snippet = achilles_store::engines::investigate::agent_brief(
                        std::path::Path::new(&assessment.working_dir),
                        rel,
                        line,
                        80,
                    );
                }
            }
        }
        Ok(vec![ContentBlock::text(
            achilles_store::brief::editor_brief(&finding, &snippet),
        )])
    }

    async fn handle_investigate(
        &self,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let params: AppsecInvestigateParams = serde_json::from_value(serde_json::Value::Object(
            arguments.ok_or("Missing arguments")?,
        ))
        .map_err(|e| format!("invalid arguments: {e}"))?;
        let finding = self
            .store
            .get_finding(&params.finding_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("unknown finding_id {}", params.finding_id))?;
        let assessment = self
            .store
            .get_assessment(&finding.assessment_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "assessment missing for finding".to_string())?;
        let snippet = match (&finding.path, finding.line_start) {
            (Some(rel), Some(line)) => achilles_store::engines::investigate::agent_brief(
                std::path::Path::new(&assessment.working_dir),
                rel,
                line,
                12,
            ),
            _ => "(no path/line on this finding)".into(),
        };
        let kind = finding
            .evidence_json
            .get("investigation")
            .and_then(|v| v.get("kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        let passes = finding
            .evidence_json
            .get("investigation")
            .and_then(|v| v.get("passes"))
            .cloned()
            .unwrap_or(json!({}));
        Ok(vec![ContentBlock::text(format!(
            "finding_id={}\nrule={}\nseverity={}\nconfidence={}\nengine_kind={}\npath={}:{}\nexisting_passes={}\n\n{}\n\nIf they only asked what this is or what's worst, answer now — do not call appsec_verdict. If they asked to confirm, dismiss, or revalidate THIS finding_id, or this turn is an investigate/revalidate pass, call appsec_verdict with role=investigator or role=validator, verdict=true_positive|false_positive|uncertain, and a short reason copied from this snippet. Then follow the next-step text. Do not invent other findings. Do not provide exploit steps.",
            finding.id,
            finding.rule_id,
            finding.severity,
            finding.confidence,
            kind,
            finding.path.as_deref().unwrap_or("-"),
            finding.line_start.unwrap_or(0),
            passes,
            snippet
        ))])
    }

    async fn handle_verdict(
        &self,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let params: AppsecVerdictParams = serde_json::from_value(serde_json::Value::Object(
            arguments.ok_or("Missing arguments")?,
        ))
        .map_err(|e| format!("invalid arguments: {e}"))?;
        let finding = self
            .store
            .set_finding_verdict(
                &params.finding_id,
                &params.role,
                &params.verdict,
                &params.reason,
            )
            .await
            .map_err(|e| e.to_string())?;
        let role = achilles_store::engines::investigate::parse_verdict_role(&params.role)
            .unwrap_or("investigator");
        let next = achilles_store::engines::investigate::next_after_verdict(&finding, role);
        Ok(vec![ContentBlock::text(format!(
            "finding_id={} role={} verdict written.\n{}\nDo not invent other findings.",
            finding.id, role, next
        ))])
    }

    async fn handle_coverage(
        &self,
        ctx: &ToolCallContext,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let working_dir = Self::resolve_working_dir(arguments.as_ref(), ctx, "working_dir");
        let params: AppsecCoverageParams = if let Some(args) = arguments {
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| format!("invalid arguments: {e}"))?
        } else {
            AppsecCoverageParams {
                assessment_id: None,
                working_dir: working_dir.clone(),
            }
        };
        let query = achilles_store::scan::query_ledger(
            &self.store,
            params.working_dir.as_deref().or(working_dir.as_deref()),
            params.assessment_id.as_deref(),
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
        let Some(cov) = query.coverage else {
            return Ok(vec![ContentBlock::text(
                "No coverage snapshot yet. Run a scan first. Do not invent coverage.",
            )]);
        };
        Ok(vec![ContentBlock::text(
            serde_json::to_string_pretty(&json!({
                "assessmentId": cov.assessment_id,
                "filesIndexed": cov.files_indexed,
                "paths": cov.paths_json,
                "skippedGlobs": cov.skipped_globs_json,
                "skippedEngines": cov.skipped_engines_json,
                "createdAt": cov.created_at,
                "note": "This is what the engines walked. Gaps here are not extra findings."
            }))
            .unwrap_or_else(|_| "coverage unavailable".into()),
        )])
    }

    async fn handle_graph(
        &self,
        ctx: &ToolCallContext,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let working_dir = Self::resolve_working_dir(arguments.as_ref(), ctx, "working_dir");
        let params: AppsecGraphParams = if let Some(args) = arguments {
            serde_json::from_value(serde_json::Value::Object(args))
                .map_err(|e| format!("invalid arguments: {e}"))?
        } else {
            AppsecGraphParams {
                assessment_id: None,
                working_dir: working_dir.clone(),
            }
        };
        let query = achilles_store::scan::query_ledger(
            &self.store,
            params.working_dir.as_deref().or(working_dir.as_deref()),
            params.assessment_id.as_deref(),
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
        let Some(assessment) = query.assessment else {
            return Ok(vec![ContentBlock::text(
                "No assessment. Scan first. Do not invent a graph.",
            )]);
        };
        let handle_id = assessment
            .stats_json
            .get("graphHandleId")
            .and_then(|v| v.as_str());
        let Some(handle_id) = handle_id else {
            return Ok(vec![ContentBlock::text(
                "No graph on this assessment (older scan). Rescan. Do not invent edges.",
            )]);
        };
        let handle = self
            .store
            .get_handle(handle_id, true)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "graph handle missing".to_string())?;
        Ok(vec![ContentBlock::text(
            serde_json::to_string_pretty(&handle.payload.unwrap_or(json!({})))
                .unwrap_or_else(|_| "{}".into()),
        )])
    }

    async fn handle_utils(
        &self,
        ctx: &ToolCallContext,
        arguments: Option<JsonObject>,
    ) -> Result<Vec<ContentBlock>, String> {
        let fallback = Self::resolve_working_dir(arguments.as_ref(), ctx, "working_dir");
        let params: AppsecUtilsParams = serde_json::from_value(serde_json::Value::Object(
            arguments.ok_or("Missing arguments")?,
        ))
        .map_err(|e| format!("invalid arguments: {e}"))?;
        let root = params
            .working_dir
            .as_deref()
            .or(fallback.as_deref())
            .ok_or("working_dir is required")?;
        let root = std::path::Path::new(root);
        let value =
            achilles_store::engines::utils::run(achilles_store::engines::utils::UtilsArgs {
                action: &params.action,
                root,
                path: params.path.as_deref(),
                text: params.text.as_deref(),
                passphrase: params.passphrase.as_deref(),
                expected: params.expected.as_deref(),
                confirm: params.confirm.unwrap_or(false),
            })
            .map_err(|e| e.to_string())?;
        if params.action == "redact" {
            return Ok(vec![ContentBlock::text(
                value
                    .get("redacted")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )]);
        }
        Ok(vec![ContentBlock::text(
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
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
        let intel_schema = serde_json::to_value(schema_for!(AppsecIntelParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let triage_schema = serde_json::to_value(schema_for!(AppsecTriageParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let investigate_schema = serde_json::to_value(schema_for!(AppsecInvestigateParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let verdict_schema = serde_json::to_value(schema_for!(AppsecVerdictParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let brief_schema = investigate_schema.clone();
        let coverage_schema = serde_json::to_value(schema_for!(AppsecCoverageParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let graph_schema = serde_json::to_value(schema_for!(AppsecGraphParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();
        let utils_schema = serde_json::to_value(schema_for!(AppsecUtilsParams))
            .expect("schema")
            .as_object()
            .unwrap()
            .clone();

        vec![
            Tool::new(
                "appsec_scan".to_string(),
                "Run Achilles engines. Prefer desktop Findings for interactive scans. mode=quick|diff. depth=fast|investigate|deep. scan_literals is opt-in and is not a security check. scan_delta is opt-in and reviews logic introduced by local git changes. Returns finding ids.".to_string(),
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
                "Read current findings and their ids. Do not invent issues. Do not tell the user this is a preview or a ledger.".to_string(),
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
                "appsec_coverage".to_string(),
                "What this scan walked and skipped. Use when they ask what we did not cover. Do not invent extra findings from gaps.".to_string(),
                coverage_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec coverage".to_string()),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            )),
            Tool::new(
                "appsec_graph".to_string(),
                "v0 graph: deploy surfaces linked to findings on those files. Not dataflow or proof.".to_string(),
                graph_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec graph".to_string()),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            )),
            Tool::new(
                "appsec_utils".to_string(),
                "hash / redact / entropy / hex / base64 / jwt / encrypt / decrypt / shred / git_purge_plan. Offline. Never print secrets or passphrases. shred requires confirm=true. git_purge_plan is not executed.".to_string(),
                utils_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec utils".to_string()),
                Some(false),
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
            Tool::new(
                "appsec_intel".to_string(),
                "Look up CVE, GHSA, or ecosystem/name@version. Public NVD/GHSA/deps.dev/KEV/EPSS today; ACHILLES_INTEL_BASE swaps to Rancero later. Never invent scores.".to_string(),
                intel_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec intel".to_string()),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            )),
            Tool::new(
                "appsec_investigate".to_string(),
                "Load one finding_id plus nearby source so you can explain it. Call appsec_verdict only if they asked to confirm, dismiss, or revalidate, or this turn is an investigate/revalidate pass. Never invent findings or exploits.".to_string(),
                investigate_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec investigate".to_string()),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            )),
            Tool::new(
                "appsec_brief".to_string(),
                "Return a pasteable brief for one finding_id. The user copies it into Cursor, Claude Code, Codex, OpenCode, or their usual editor to apply the fix there. Do not edit files unless they clearly ask.".to_string(),
                brief_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec brief".to_string()),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            )),
            Tool::new(
                "appsec_verdict".to_string(),
                "Write true_positive, false_positive, or uncertain on one finding_id. role=investigator then role=validator. Then appsec_triage when they agree. Never invent ids.".to_string(),
                verdict_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec verdict".to_string()),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            )),
            Tool::new(
                "appsec_triage".to_string(),
                "Set a finding's state: open, confirmed, dismissed, or verified_fixed. Use the finding_id from appsec_query. Never invent ids.".to_string(),
                triage_schema,
            )
            .annotate(ToolAnnotations::from_raw(
                Some("AppSec triage".to_string()),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            )),
        ]
    }

    pub(crate) fn mcp_tools() -> Vec<Tool> {
        Self::get_tools()
            .into_iter()
            .filter(|tool| {
                matches!(
                    tool.name.as_ref(),
                    "appsec_query"
                        | "appsec_investigate"
                        | "appsec_brief"
                        | "appsec_triage"
                        | "appsec_scan"
                        | "appsec_intel"
                        | "appsec_coverage"
                        | "appsec_graph"
                        | "appsec_utils"
                )
            })
            .collect()
    }
}

fn format_query(query: &achilles_store::scan::LedgerQuery) -> String {
    let Some(assessment) = &query.assessment else {
        return "No assessments for this workspace. Scan from desktop Findings, or call appsec_scan. Do not invent findings.".into();
    };
    let handle = query
        .summary_handle_id
        .as_deref()
        .unwrap_or("(none yet — scan may still be running)");
    let startup = startup_query_lines(&assessment.stats_json);
    let coverage = coverage_query_lines(query.coverage.as_ref());
    format!(
        "assessment_id={}\nstatus={}\nopen={}\nhandle_id={}\n\n{}{}{}\n\nDo not invent extra issues. If they asked what's worst, a count, or a summary, answer from these findings and stop. If they asked how the app starts, use the startup list (manifests/entry files) and do not invent processes. Only call appsec_investigate if they asked to inspect a specific finding, or if this turn is an investigate/revalidate pass. User-facing: say findings, never ledger/handle. Do not mention that chat is a preview or that Findings has a fuller list.",
        assessment.id,
        assessment.status.as_str(),
        assessment.open_finding_count,
        handle,
        query.preview,
        startup,
        coverage,
    )
}

fn startup_query_lines(stats: &serde_json::Value) -> String {
    let Some(paths) = stats.get("startupPaths").and_then(|v| v.as_array()) else {
        return String::new();
    };
    if paths.is_empty() {
        return String::new();
    }
    let mut lines = vec!["\n\nHow this app starts:".to_string()];
    for item in paths.iter().take(16) {
        let Some(row) = item.as_object() else {
            continue;
        };
        let kind = row.get("kind").and_then(|v| v.as_str()).unwrap_or("start");
        let path = row.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let command = row.get("command").and_then(|v| v.as_str());
        match command {
            Some(cmd) => lines.push(format!("- [{kind}] {path} → {cmd}")),
            None => lines.push(format!("- [{kind}] {path}")),
        }
    }
    lines.join("\n")
}

fn coverage_query_lines(coverage: Option<&achilles_store::CoverageSnapshot>) -> String {
    let Some(cov) = coverage else {
        return String::new();
    };
    format!(
        "\n\nCoverage: {} files indexed. Skipped engines: {}. Call appsec_coverage for the full snapshot.",
        cov.files_indexed,
        cov.skipped_engines_json
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
            "appsec_coverage" => self.handle_coverage(ctx, arguments).await,
            "appsec_graph" => self.handle_graph(ctx, arguments).await,
            "appsec_utils" => self.handle_utils(ctx, arguments).await,
            "appsec_read_handle" => self.handle_read_handle(arguments).await,
            "appsec_intel" => self.handle_intel(arguments).await,
            "appsec_investigate" => self.handle_investigate(arguments).await,
            "appsec_brief" => self.handle_brief(arguments).await,
            "appsec_verdict" => self.handle_verdict(arguments).await,
            "appsec_triage" => self.handle_triage(arguments).await,
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

    async fn get_moim(&self, session_id: &str) -> Option<String> {
        let mut text = String::from(
            "AppSec: engines write achilles.db. Ranking/summary questions: answer from this catalog or one appsec_query call. Do not narrate tool calls. The investigate → verdict (investigator) → verdict (validator) → triage loop runs only when they ask to inspect, confirm, dismiss, or revalidate a specific finding — or during an investigate/revalidate pass. Never invent findings. Prefer they land patches in their usual editor; edit here only if they clearly ask.\n",
        );
        match achilles_store::scan::findings_context_for_session(&self.store, session_id).await {
            Ok(Some(digest)) => {
                text.push('\n');
                text.push_str(&digest);
                text.push('\n');
            }
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(error = %error, session_id, "could not load scan findings for chat context");
            }
        }
        Some(text)
    }
}

//! `goose appsec` — CI/headless ledger. Interactive product is desktop Findings.

use std::path::PathBuf;

use anyhow::Result;
use goose::config::paths::Paths;

#[derive(Debug, clap::Subcommand)]
pub enum AppsecCommand {
    #[command(
        about = "CI/headless scan into achilles.db. Interactive product is desktop Findings."
    )]
    Scan {
        #[arg(long, help = "Workspace to scan (default: cwd)")]
        path: Option<PathBuf>,
        #[arg(long, default_value = "quick", help = "quick or diff")]
        mode: String,
        #[arg(
            long,
            help = "Also scan node_modules/vendor/target (noisy; still skips .git and binaries)"
        )]
        include_vendor: bool,
        #[arg(
            long,
            help = "Also flag hardcoded URLs, IPs, paths, and magic numbers in source (not security findings — stability / config hygiene)"
        )]
        literals: bool,
        #[arg(
            long,
            help = "Compact staged, unstaged, and untracked diffs, then check introduced logic against the rest of the tree"
        )]
        delta: bool,
        #[arg(
            long,
            default_value = "fast",
            help = "fast (engines), investigate (Fast + dual AI review of those hits), or deep (Investigate + heavy function inspection)"
        )]
        depth: String,
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "latest",
            help = "Resume a cancelled/partial assessment (omit id for latest)"
        )]
        resume: Option<String>,
        #[arg(
            long,
            help = "Stop after N seconds (status=partial; resume to continue)"
        )]
        max_duration: Option<u64>,
        #[arg(long, help = "Stop after this USD of reported model cost")]
        max_cost_usd: Option<f64>,
    },
    #[command(about = "Print the latest ledger preview for a workspace")]
    Query {
        #[arg(long, help = "Workspace (default: cwd)")]
        path: Option<PathBuf>,
        #[arg(
            long,
            help = "Filter category: secrets, sast, surface, sca, literals, delta, history, harden"
        )]
        category: Option<String>,
    },
    #[command(about = "Print one ledger finding plus nearby source (no model)")]
    Investigate { finding_id: String },
    #[command(about = "Print a pasteable brief to fix this finding in your coding editor")]
    Brief { finding_id: String },
    #[command(about = "Write an investigator/validator verdict on a ledger finding")]
    Verdict {
        finding_id: String,
        #[arg(long, help = "investigator or validator")]
        role: String,
        #[arg(long, help = "true_positive, false_positive, or uncertain")]
        verdict: String,
        #[arg(long, help = "Short reason from the snippet; no exploit steps")]
        reason: String,
    },
    #[command(about = "Set a finding state: open, confirmed, dismissed, verified_fixed")]
    Triage { finding_id: String, state: String },
    #[command(
        about = "Workspace helpers (not a scan): hash, hash_verify, redact, entropy, hex, base64, jwt, encrypt, decrypt, shred, git_purge_plan"
    )]
    Utils {
        #[arg(
            long,
            help = "hash | hash_verify | redact | entropy | hex | base64 | jwt | encrypt | decrypt | shred | git_purge_plan"
        )]
        action: String,
        #[arg(long, help = "Workspace root (default: cwd)")]
        path: Option<PathBuf>,
        #[arg(
            long,
            help = "File under the workspace (hash, encrypt, decrypt, shred, git_purge_plan)"
        )]
        file: Option<String>,
        #[arg(long, help = "Pasted text (redact, entropy, hex, base64, jwt)")]
        text: Option<String>,
        #[arg(long, help = "Passphrase (encrypt, decrypt)")]
        passphrase: Option<String>,
        #[arg(long, help = "Expected SHA-256 or SHA-512 hex (hash_verify)")]
        expected: Option<String>,
        #[arg(long, help = "Required for shred")]
        confirm: bool,
    },
}

pub async fn handle_appsec(command: AppsecCommand) -> Result<()> {
    let store = achilles_store::AchillesStore::new(Paths::data_dir());
    match command {
        AppsecCommand::Scan {
            path,
            mode,
            include_vendor,
            literals,
            delta,
            depth,
            resume,
            max_duration,
            max_cost_usd,
        } => {
            let working_dir = resolve_dir(path)?;
            let (socket_api_token, socket_org) = goose::config::achilles_socket_creds();
            let depth_for_ai = depth.clone();
            let completer = if achilles_store::engines::depth::ScanDepth::parse(&depth_for_ai)
                .runs_investigate()
            {
                goose::agents::platform_extensions::appsec_scan::from_config().await
            } else {
                None
            };
            let resume_assessment_id = match resume.as_deref() {
                None => None,
                Some("latest") => store
                    .latest_resumable_assessment(&working_dir)
                    .await?
                    .map(|a| a.id),
                Some(id) => Some(id.to_string()),
            };
            let assessment = achilles_store::scan::start_scan(
                store,
                achilles_store::scan::ScanRequest {
                    working_dir,
                    session_id: None,
                    mode,
                    trigger: "cli".into(),
                    parent_assessment_id: None,
                    wait: true,
                    include_vendor,
                    scan_literals: literals,
                    scan_delta: delta,
                    depth,
                    socket_api_token,
                    socket_org,
                    completer,
                    resume_assessment_id,
                    max_duration_secs: max_duration,
                    max_cost_usd,
                },
            )
            .await?;
            println!(
                "assessment_id={} status={} open={} mode={}",
                assessment.id,
                assessment.status.as_str(),
                assessment.open_finding_count,
                assessment.mode
            );
            if let Some(handle) = assessment
                .stats_json
                .get("summaryHandleId")
                .and_then(|v| v.as_str())
            {
                println!("handle_id={handle}");
            }
            if let Some(err) = assessment.error_message {
                anyhow::bail!(err);
            }
            Ok(())
        }
        AppsecCommand::Query { path, category } => {
            let working_dir = resolve_dir(path)?;
            let query = achilles_store::scan::query_ledger(
                &store,
                Some(&working_dir),
                None,
                category.as_deref(),
            )
            .await?;
            match query.assessment {
                Some(a) => {
                    println!(
                        "assessment_id={} status={} open={}",
                        a.id,
                        a.status.as_str(),
                        a.open_finding_count
                    );
                    if let Some(h) = query.summary_handle_id {
                        println!("handle_id={h}");
                    }
                    println!();
                    println!("{}", query.preview);
                }
                None => {
                    println!(
                        "No assessments for {working_dir}. Scan from desktop Findings, or: goose appsec scan"
                    );
                }
            }
            Ok(())
        }
        AppsecCommand::Investigate { finding_id } => {
            let finding = store
                .get_finding(&finding_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("unknown finding {finding_id}"))?;
            let assessment = store
                .get_assessment(&finding.assessment_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("assessment missing for finding"))?;
            let snippet = match (&finding.path, finding.line_start) {
                (Some(rel), Some(line)) => achilles_store::engines::investigate::agent_brief(
                    std::path::Path::new(&assessment.working_dir),
                    rel,
                    line,
                    12,
                ),
                _ => "(no path/line on this finding)".into(),
            };
            println!("finding_id={}", finding.id);
            println!("rule={}", finding.rule_id);
            println!("severity={}", finding.severity);
            println!(
                "path={}:{}",
                finding.path.as_deref().unwrap_or("-"),
                finding.line_start.unwrap_or(0)
            );
            println!();
            println!("{snippet}");
            println!();
            println!(
                "Next: goose appsec verdict {finding_id} --role investigator --verdict <true_positive|false_positive|uncertain> --reason \"...\""
            );
            Ok(())
        }
        AppsecCommand::Brief { finding_id } => {
            let finding = store
                .get_finding(&finding_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("unknown finding {finding_id}"))?;
            let mut snippet =
                achilles_store::brief::snippet_from_evidence(&finding).unwrap_or_default();
            if snippet.is_empty() {
                if let (Some(rel), Some(line)) = (&finding.path, finding.line_start) {
                    if let Some(assessment) = store.get_assessment(&finding.assessment_id).await? {
                        snippet = achilles_store::engines::investigate::agent_brief(
                            std::path::Path::new(&assessment.working_dir),
                            rel,
                            line,
                            80,
                        );
                    }
                }
            }
            print!(
                "{}",
                achilles_store::brief::editor_brief(&finding, &snippet)
            );
            Ok(())
        }
        AppsecCommand::Verdict {
            finding_id,
            role,
            verdict,
            reason,
        } => {
            let finding = store
                .set_finding_verdict(&finding_id, &role, &verdict, &reason)
                .await?;
            let role = achilles_store::engines::investigate::parse_verdict_role(&role)
                .unwrap_or("investigator");
            println!(
                "{}",
                achilles_store::engines::investigate::next_after_verdict(&finding, role)
            );
            Ok(())
        }
        AppsecCommand::Triage { finding_id, state } => {
            let finding = store.set_finding_state(&finding_id, &state).await?;
            println!("finding_id={} state={}", finding.id, finding.state);
            Ok(())
        }
        AppsecCommand::Utils {
            action,
            path,
            file,
            text,
            passphrase,
            expected,
            confirm,
        } => {
            let working_dir = resolve_dir(path)?;
            let value =
                achilles_store::engines::utils::run(achilles_store::engines::utils::UtilsArgs {
                    action: &action,
                    root: std::path::Path::new(&working_dir),
                    path: file.as_deref(),
                    text: text.as_deref(),
                    passphrase: passphrase.as_deref(),
                    expected: expected.as_deref(),
                    confirm,
                })?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
    }
}

fn resolve_dir(path: Option<PathBuf>) -> Result<String> {
    let dir = match path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };
    achilles_store::store::canonicalize_working_dir(&dir.to_string_lossy())
}

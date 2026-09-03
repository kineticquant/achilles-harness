//! `goose analyze` — focused call graph for the inspector pane (and a text dump).

use std::path::PathBuf;

use anyhow::Result;
use goose::agents::platform_extensions::analyze::{format, graph, inspect, AnalyzeClient};

pub fn handle_analyze(
    path: Option<PathBuf>,
    focus: Option<String>,
    depth: u32,
    follow: u32,
    json: bool,
) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let path = match path {
        Some(p) if p.is_absolute() => p,
        Some(p) => cwd.join(p),
        None => cwd,
    };
    if !path.exists() {
        anyhow::bail!("path not found: {}", path.display());
    }

    if json {
        let symbol = focus
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("--json requires --focus <symbol>"))?;
        let graph = inspect::inspect_focus(&path, symbol, depth, follow, 80)?;
        println!("{}", serde_json::to_string(&graph)?);
        return Ok(());
    }

    let output = if let Some(ref symbol) = focus {
        let files = if path.is_file() {
            vec![path.clone()]
        } else {
            AnalyzeClient::collect_files(&path, depth)
        };
        let analyses: Vec<_> = files
            .iter()
            .filter_map(|f| AnalyzeClient::analyze_file(f))
            .collect();
        let root = if path.is_file() {
            path.parent().unwrap_or(&path)
        } else {
            &path
        };
        let g = graph::CallGraph::build(&analyses);
        format::format_focused(symbol, &g, follow, analyses.len(), root)
    } else if path.is_file() {
        match AnalyzeClient::analyze_file(&path) {
            Some(analysis) => {
                let root = path.parent().unwrap_or(&path);
                format::format_semantic(&analysis, root)
            }
            None => anyhow::bail!("unsupported language or binary file: {}", path.display()),
        }
    } else {
        let files = AnalyzeClient::collect_files(&path, depth);
        let total_files = files.len();
        let analyses: Vec<_> = files
            .iter()
            .filter_map(|f| AnalyzeClient::analyze_file(f))
            .collect();
        format::format_structure(&analyses, &path, depth, total_files)
    };

    match format::check_size(&output, true) {
        Ok(text) => {
            print!("{text}");
            Ok(())
        }
        Err(warning) => anyhow::bail!("{warning}"),
    }
}

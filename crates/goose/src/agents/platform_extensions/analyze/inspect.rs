//! JSON call-graph neighborhood for the desktop inspector pane.
//! Does not change the text `analyze` MCP tool.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use super::AnalyzeClient;
use super::graph::CallGraph;

const DEFAULT_MAX_DEPTH: u32 = 3;
const MAX_WALK_DEPTH: u32 = 6;
const MAX_FOLLOW: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InspectNode {
    pub id: String,
    pub file: String,
    pub name: String,
    pub line: usize,
    pub kind: String,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InspectEdge {
    pub id: String,
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InspectGraph {
    pub focus: String,
    pub found: bool,
    pub files_analyzed: usize,
    pub truncated: bool,
    pub nodes: Vec<InspectNode>,
    pub edges: Vec<InspectEdge>,
}

fn clamp_max_depth(max_depth: u32) -> u32 {
    if max_depth == 0 {
        DEFAULT_MAX_DEPTH
    } else {
        max_depth.min(MAX_WALK_DEPTH)
    }
}

fn rel_file(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn node_id(file: &str, name: &str, line: usize) -> String {
    format!("{file}:{line}:{name}")
}

struct Draft {
    file: String,
    name: String,
    line: usize,
    kind: String,
    depth: u32,
}

fn upsert(map: &mut HashMap<String, Draft>, draft: Draft) {
    let id = node_id(&draft.file, &draft.name, draft.line);
    match map.get_mut(&id) {
        None => {
            map.insert(id, draft);
        }
        Some(existing) => {
            existing.depth = existing.depth.min(draft.depth);
            if existing.kind == "focus" {
                return;
            }
            if draft.kind == "focus" {
                existing.kind = "focus".into();
                return;
            }
            if existing.kind != draft.kind {
                existing.kind = "both".into();
            }
        }
    }
}

/// Focused callers/callees as a node-edge graph. Caps walk depth so this cannot
/// become a whole-workspace map.
pub fn inspect_focus(
    path: &Path,
    symbol: &str,
    max_depth: u32,
    follow_depth: u32,
    max_nodes: usize,
) -> Result<InspectGraph> {
    if !path.exists() {
        anyhow::bail!("path not found: {}", path.display());
    }
    let symbol = symbol.trim();
    if symbol.is_empty() {
        anyhow::bail!("focus symbol is required");
    }

    let max_depth = clamp_max_depth(max_depth);
    let follow_depth = follow_depth.min(MAX_FOLLOW);
    let max_nodes = max_nodes.max(1);

    let files = if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        AnalyzeClient::collect_files(path, max_depth)
    };
    let files_analyzed = files.len();
    let analyses: Vec<_> = files
        .par_iter()
        .filter_map(|file| AnalyzeClient::analyze_file(file))
        .collect();

    let root = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    let graph = CallGraph::build(&analyses);
    let defs = graph.definitions(symbol);
    let incoming = graph.incoming(symbol, follow_depth);
    let outgoing = graph.outgoing(symbol, follow_depth);

    let mut drafts: HashMap<String, Draft> = HashMap::new();
    for def in &defs {
        let file = rel_file(&def.file, root);
        upsert(
            &mut drafts,
            Draft {
                file,
                name: def.name.clone(),
                line: def.line,
                kind: "focus".into(),
                depth: 0,
            },
        );
    }

    let mut edge_set: HashSet<(String, String)> = HashSet::new();

    let walk = |chains: &[Vec<super::graph::ChainLink>],
                drafts: &mut HashMap<String, Draft>,
                edge_set: &mut HashSet<(String, String)>,
                toward_callee: bool| {
        for chain in chains {
            for (i, link) in chain.iter().enumerate() {
                let file = rel_file(&link.file, root);
                let kind = if i == 0 {
                    "focus"
                } else if toward_callee {
                    "callee"
                } else {
                    "caller"
                };
                upsert(
                    drafts,
                    Draft {
                        file,
                        name: link.name.clone(),
                        line: link.line,
                        kind: kind.into(),
                        depth: i as u32,
                    },
                );
            }
            for pair in chain.windows(2) {
                let a = rel_file(&pair[0].file, root);
                let b = rel_file(&pair[1].file, root);
                let left = node_id(&a, &pair[0].name, pair[0].line);
                let right = node_id(&b, &pair[1].name, pair[1].line);
                // Incoming chains walk from focus to callers; the caller invokes the previous node.
                if toward_callee {
                    edge_set.insert((left, right));
                } else {
                    edge_set.insert((right, left));
                }
            }
        }
    };

    walk(&incoming, &mut drafts, &mut edge_set, false);
    walk(&outgoing, &mut drafts, &mut edge_set, true);

    let found = !drafts.is_empty();
    let mut nodes: Vec<InspectNode> = drafts
        .into_iter()
        .map(|(id, d)| InspectNode {
            id,
            file: d.file,
            name: d.name,
            line: d.line,
            kind: d.kind,
            depth: d.depth,
        })
        .collect();
    nodes.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.line.cmp(&b.line))
    });

    let truncated = nodes.len() > max_nodes;
    if truncated {
        nodes.truncate(max_nodes);
    }
    let keep: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    let mut edges: Vec<InspectEdge> = edge_set
        .into_iter()
        .filter(|(source, target)| keep.contains(source.as_str()) && keep.contains(target.as_str()))
        .map(|(source, target)| InspectEdge {
            id: format!("{source}->{target}"),
            source,
            target,
        })
        .collect();
    edges.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(InspectGraph {
        focus: symbol.to_string(),
        found,
        files_analyzed,
        truncated,
        nodes,
        edges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn focused_neighborhood_has_call_edge() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("a.rs"), "fn process() { validate(1); }\n").unwrap();
        fs::write(tmp.path().join("b.rs"), "fn validate() {}\n").unwrap();

        let graph = inspect_focus(tmp.path(), "process", 3, 2, 80).unwrap();
        assert!(graph.found);
        assert!(
            graph
                .nodes
                .iter()
                .any(|n| n.name == "process" && n.kind == "focus")
        );
        assert!(graph.nodes.iter().any(|n| n.name == "validate"));
        assert!(!graph.edges.is_empty());
        assert!(
            graph
                .edges
                .iter()
                .any(|e| { e.source.contains("process") && e.target.contains("validate") })
        );
    }

    #[test]
    fn missing_symbol_is_empty_not_error() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("a.rs"), "fn process() {}\n").unwrap();
        let graph = inspect_focus(tmp.path(), "nope", 3, 2, 80).unwrap();
        assert!(!graph.found);
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn refuses_empty_focus() {
        let tmp = tempdir().unwrap();
        assert!(inspect_focus(tmp.path(), "  ", 3, 2, 80).is_err());
    }
}

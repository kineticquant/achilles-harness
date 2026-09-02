use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use ignore::WalkBuilder;
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TreeParams {
    pub path: String,
    #[serde(default = "default_depth")]
    pub depth: u32,
}

fn default_depth() -> u32 {
    2
}

pub struct TreeTool;

impl TreeTool {
    pub fn new() -> Self {
        Self
    }

    pub fn tree(&self, params: TreeParams) -> CallToolResult {
        let root = PathBuf::from(&params.path);
        self.tree_at(root, params.depth, None)
    }

    pub fn tree_with_cwd(
        &self,
        params: TreeParams,
        working_dir: Option<&Path>,
        cancel: Option<&CancellationToken>,
    ) -> CallToolResult {
        let path = PathBuf::from(&params.path);
        let root = if path.is_absolute() {
            path
        } else {
            working_dir
                .map(Path::to_path_buf)
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."))
                .join(path)
        };
        self.tree_at(root, params.depth, cancel)
    }

    fn tree_at(
        &self,
        root: PathBuf,
        depth: u32,
        cancel: Option<&CancellationToken>,
    ) -> CallToolResult {
        if cancel.is_some_and(|token| token.is_cancelled()) {
            return cancelled_tree_result();
        }

        if is_overbroad_tree_root(&root) {
            return CallToolResult::error(vec![ContentBlock::text(format!(
                "Refusing to tree `{}` (home directory or drive root). Pass a specific project directory.",
                root.display()
            ))]);
        }

        if !root.exists() {
            return CallToolResult::error(vec![ContentBlock::text(format!(
                "Path does not exist: {}",
                root.display()
            ))]);
        }

        if !root.is_dir() {
            return CallToolResult::error(vec![ContentBlock::text(format!(
                "Path is not a directory: {}",
                root.display()
            ))]);
        }

        let max_depth = if depth == 0 {
            None
        } else {
            Some(depth as usize)
        };

        let mut tree = match collect_tree(&root, max_depth, cancel) {
            Ok(tree) => tree,
            Err(()) => return cancelled_tree_result(),
        };
        tree.compute_total_lines();

        let mut output = String::new();
        tree.render_into(0, &mut output);
        if output.is_empty() {
            output.push_str("(empty directory)");
        }

        CallToolResult::success(vec![ContentBlock::text(output)])
    }
}

impl Default for TreeTool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct DirectoryNode {
    dirs: BTreeMap<String, DirectoryNode>,
    files: BTreeMap<String, usize>,
    total_lines: usize,
}

impl DirectoryNode {
    fn insert_dir(&mut self, components: &[String]) {
        let mut node = self;
        for component in components {
            node = node.dirs.entry(component.clone()).or_default();
        }
    }

    fn insert_file(&mut self, components: &[String], line_count: usize) {
        if components.is_empty() {
            return;
        }

        let mut node = self;
        for component in &components[..components.len() - 1] {
            node = node.dirs.entry(component.clone()).or_default();
        }

        let filename = components[components.len() - 1].clone();
        node.files.insert(filename, line_count);
    }

    fn compute_total_lines(&mut self) -> usize {
        let dir_lines: usize = self
            .dirs
            .values_mut()
            .map(DirectoryNode::compute_total_lines)
            .sum();
        let file_lines: usize = self.files.values().copied().sum();
        self.total_lines = dir_lines + file_lines;
        self.total_lines
    }

    fn render_into(&self, depth: usize, out: &mut String) {
        let indent = "  ".repeat(depth);

        for (name, dir) in &self.dirs {
            out.push_str(&format!(
                "{}{}/  {}\n",
                indent,
                name,
                format_lines(dir.total_lines)
            ));
            dir.render_into(depth + 1, out);
        }

        for (name, line_count) in &self.files {
            out.push_str(&format!(
                "{}{}  {}\n",
                indent,
                name,
                format_lines(*line_count)
            ));
        }
    }
}

fn cancelled_tree_result() -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text("Tree cancelled")])
}

fn is_filesystem_root(path: &Path) -> bool {
    let mut saw_rootish = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => saw_rootish = true,
            _ => return false,
        }
    }
    saw_rootish
}

fn paths_loosely_equal(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn is_overbroad_tree_root(path: &Path) -> bool {
    if is_filesystem_root(path) {
        return true;
    }
    dirs::home_dir().is_some_and(|home| paths_loosely_equal(path, &home))
}

fn collect_tree(
    root: &Path,
    max_depth: Option<usize>,
    cancel: Option<&CancellationToken>,
) -> Result<DirectoryNode, ()> {
    let mut builder = WalkBuilder::new(root);
    builder.git_ignore(true);
    builder.git_exclude(true);
    builder.git_global(true);
    builder.require_git(false);
    builder.ignore(true);
    builder.hidden(true);

    if let Some(depth) = max_depth {
        builder.max_depth(Some(depth + 1));
    }

    let mut tree = DirectoryNode::default();
    for entry in builder.build().flatten() {
        if cancel.is_some_and(|token| token.is_cancelled()) {
            return Err(());
        }

        let path = entry.path();
        if path == root {
            continue;
        }

        let rel = match path.strip_prefix(root) {
            Ok(rel) => rel,
            Err(_) => continue,
        };

        let components = match relative_components(rel) {
            Some(components) => components,
            None => continue,
        };

        if entry.file_type().is_some_and(|t| t.is_dir()) {
            tree.insert_dir(&components);
        } else if entry.file_type().is_some_and(|t| t.is_file()) {
            tree.insert_file(&components, count_file_lines(path));
        }
    }

    Ok(tree)
}

fn relative_components(path: &Path) -> Option<Vec<String>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            _ => return None,
        }
    }

    if components.is_empty() {
        None
    } else {
        Some(components)
    }
}

fn count_file_lines(path: &Path) -> usize {
    match fs::read_to_string(path) {
        Ok(content) => content.lines().count(),
        Err(_) => 0,
    }
}

fn format_lines(lines: usize) -> String {
    if lines >= 1000 {
        format!("[{}K]", lines / 1000)
    } else {
        format!("[{}]", lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ContentBlock;
    use tempfile::TempDir;

    fn extract_text(result: &CallToolResult) -> &str {
        match &result.content[0] {
            ContentBlock::Text(t) => &t.text,
            _ => panic!("expected text"),
        }
    }

    fn setup_tree() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::create_dir_all(dir.path().join("tests")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(dir.path().join("src/lib.rs"), "pub fn lib() {}\n").unwrap();
        fs::write(dir.path().join("tests/test.rs"), "#[test]\nfn t() {}\n").unwrap();
        dir
    }

    #[test]
    fn tree_lists_files_and_directories() {
        let dir = setup_tree();
        let tool = TreeTool::new();

        let result = tool.tree(TreeParams {
            path: dir.path().display().to_string(),
            depth: 2,
        });

        let text = extract_text(&result);
        assert!(text.contains("src/"));
        assert!(text.contains("tests/"));
        assert!(text.contains("main.rs"));
    }

    #[test]
    fn tree_respects_depth() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
        fs::write(dir.path().join("a/b/c/deep.rs"), "fn deep() {}\n").unwrap();

        let tool = TreeTool::new();
        let result = tool.tree(TreeParams {
            path: dir.path().display().to_string(),
            depth: 1,
        });

        let text = extract_text(&result);
        assert!(text.contains("a/"));
        assert!(text.contains("b/"));
        assert!(!text.contains("deep.rs"));
    }

    #[test]
    fn tree_uses_gitignore() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored/\n*.log\n").unwrap();
        fs::create_dir_all(dir.path().join("ignored")).unwrap();
        fs::write(dir.path().join("ignored/secret.rs"), "fn secret() {}\n").unwrap();
        fs::write(dir.path().join("visible.rs"), "fn visible() {}\n").unwrap();
        fs::write(dir.path().join("debug.log"), "hidden\n").unwrap();

        let tool = TreeTool::new();
        let result = tool.tree(TreeParams {
            path: dir.path().display().to_string(),
            depth: 2,
        });

        let text = extract_text(&result);
        assert!(text.contains("visible.rs"));
        assert!(!text.contains("ignored"));
        assert!(!text.contains("debug.log"));
    }

    #[test]
    fn tree_refuses_home_directory() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let tool = TreeTool::new();
        let result = tool.tree(TreeParams {
            path: home.display().to_string(),
            depth: 1,
        });
        assert_eq!(result.is_error, Some(true));
        assert!(extract_text(&result).contains("home directory or drive root"));
    }

    #[test]
    fn tree_refuses_filesystem_root() {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        let tool = TreeTool::new();
        let result = tool.tree(TreeParams {
            path: root.to_string(),
            depth: 1,
        });
        assert_eq!(result.is_error, Some(true));
        assert!(extract_text(&result).contains("home directory or drive root"));
    }

    #[test]
    fn tree_stops_when_cancelled() {
        let dir = setup_tree();
        let tool = TreeTool::new();
        let token = CancellationToken::new();
        token.cancel();

        let result = tool.tree_with_cwd(
            TreeParams {
                path: dir.path().display().to_string(),
                depth: 2,
            },
            None,
            Some(&token),
        );

        assert_eq!(result.is_error, Some(true));
        assert_eq!(extract_text(&result), "Tree cancelled");
    }
}

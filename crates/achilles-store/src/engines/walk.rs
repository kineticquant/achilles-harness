//! Parallel gitignore-aware walk. Same engine ripgrep uses (`ignore`).
//! Name/extension filters run before any content read — that is the speed path.
//! Apache-2.0.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use ignore::{WalkBuilder, WalkState};

pub const MAX_FILES_DEFAULT: usize = 8_000;
pub const MAX_FILE_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone)]
pub struct WalkedFile {
    pub abs: PathBuf,
    pub rel: String,
    pub len: u64,
}

impl WalkedFile {
    pub fn file_name(&self) -> &str {
        Path::new(&self.rel)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    }
}

const MAX_VENDOR_FILES: usize = 4_000;

#[derive(Debug, Clone, Copy)]
pub struct WalkOpts {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub skip_binary_names: bool,
    /// Second pass over `node_modules` / `vendor` / `target` (gitignore does not apply).
    pub include_vendor: bool,
}

impl Default for WalkOpts {
    fn default() -> Self {
        Self {
            max_files: MAX_FILES_DEFAULT,
            max_file_bytes: MAX_FILE_BYTES,
            skip_binary_names: true,
            include_vendor: false,
        }
    }
}

fn thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4)
}

pub fn skip_git(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().to_str() == Some(".git"))
}

/// Installed/generated trees. Default skip; opt-in via `WalkOpts.include_vendor`.
pub fn is_vendor_tree(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some(
                "node_modules"
                    | "target"
                    | "vendor"
                    | "dist"
                    | "build"
                    | ".next"
                    | "__pycache__"
                    | ".venv"
                    | "venv"
                    | "Pods"
                    | ".yarn"
                    | "coverage"
            )
        )
    })
}

pub fn is_minified_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".min.js") || n.ends_with(".min.css") || n.ends_with(".min.mjs")
}

pub fn is_binary_name(name: &str) -> bool {
    if is_minified_name(name) {
        return true;
    }
    let n = name.to_ascii_lowercase();
    matches!(
        n.rsplit_once('.').map(|(_, ext)| ext),
        Some(
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "ico"
                | "bmp"
                | "svg"
                | "pdf"
                | "zip"
                | "gz"
                | "tgz"
                | "bz2"
                | "7z"
                | "rar"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "eot"
                | "wasm"
                | "so"
                | "dylib"
                | "dll"
                | "exe"
                | "bin"
                | "class"
                | "jar"
                | "pyc"
                | "pyo"
                | "o"
                | "a"
                | "lib"
                | "mp3"
                | "mp4"
                | "webm"
                | "mov"
                | "sqlite"
                | "pack"
        )
    )
}

/// List files under `root`. `keep` is a cheap name/path predicate — return false
/// to skip opening the file later.
///
/// First-party files are walked with gitignore. Dependency trees are a separate
/// capped pass and only run when `include_vendor` is set (gitignore would hide
/// `node_modules` otherwise).
pub fn walk_files(
    root: &Path,
    opts: WalkOpts,
    keep: impl Fn(&Path, &str) -> bool + Sync,
) -> Vec<WalkedFile> {
    walk_files_with_cancel(root, opts, keep, None, None)
}

pub fn walk_files_with_cancel(
    root: &Path,
    opts: WalkOpts,
    keep: impl Fn(&Path, &str) -> bool + Sync,
    cancel: Option<&AtomicBool>,
    pause: Option<&AtomicBool>,
) -> Vec<WalkedFile> {
    let mut files = walk_pass(
        root,
        opts,
        &keep,
        Pass {
            git_ignore: true,
            vendor_only: false,
            max_files: opts.max_files,
        },
        cancel,
        pause,
    );
    if opts.include_vendor && !cancelled(cancel) {
        files.extend(walk_pass(
            root,
            opts,
            &keep,
            Pass {
                git_ignore: false,
                vendor_only: true,
                max_files: MAX_VENDOR_FILES,
            },
            cancel,
            pause,
        ));
    }
    files
}

fn cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

fn wait_if_paused(pause: Option<&AtomicBool>, cancel: Option<&AtomicBool>) -> bool {
    while pause.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        if cancelled(cancel) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cancelled(cancel)
}

struct Pass {
    git_ignore: bool,
    vendor_only: bool,
    max_files: usize,
}

fn walk_pass(
    root: &Path,
    opts: WalkOpts,
    keep: &(impl Fn(&Path, &str) -> bool + Sync),
    pass: Pass,
    cancel: Option<&AtomicBool>,
    pause: Option<&AtomicBool>,
) -> Vec<WalkedFile> {
    let hits = Mutex::new(Vec::new());
    let seen = AtomicUsize::new(0);
    let builder = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(pass.git_ignore)
        .git_exclude(pass.git_ignore)
        .threads(thread_count())
        .build_parallel();

    builder.run(|| {
        let hits = &hits;
        let seen = &seen;
        let keep = keep;
        Box::new(move |entry| {
            if wait_if_paused(pause, cancel) || seen.load(Ordering::Relaxed) >= pass.max_files {
                return WalkState::Quit;
            }
            let Ok(entry) = entry else {
                return WalkState::Continue;
            };
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                return WalkState::Continue;
            }
            let path = entry.path();
            if skip_git(path) {
                return WalkState::Continue;
            }
            let vendor = is_vendor_tree(path);
            if pass.vendor_only {
                if !vendor {
                    return WalkState::Continue;
                }
            } else if vendor {
                return WalkState::Continue;
            }
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if opts.skip_binary_names && is_binary_name(name) {
                return WalkState::Continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(path);
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if !keep(path, &rel_str) {
                return WalkState::Continue;
            }
            let Ok(meta) = entry.metadata() else {
                return WalkState::Continue;
            };
            if meta.len() > opts.max_file_bytes {
                return WalkState::Continue;
            }
            let n = seen.fetch_add(1, Ordering::Relaxed);
            if n >= pass.max_files {
                return WalkState::Quit;
            }
            hits.lock().unwrap().push(WalkedFile {
                abs: path.to_path_buf(),
                rel: rel_str,
                len: meta.len(),
            });
            WalkState::Continue
        })
    });

    hits.into_inner().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn skips_vendor_and_binaries() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules").join("x")).unwrap();
        fs::write(root.join("src").join("app.c"), "int main(){}\n").unwrap();
        fs::write(
            root.join("node_modules").join("x").join("evil.c"),
            "strcpy(a,b);\n",
        )
        .unwrap();
        fs::write(root.join("logo.png"), [0u8; 16]).unwrap();
        let hits = walk_files(root, WalkOpts::default(), |_, _| true);
        let rels: Vec<_> = hits.iter().map(|h| h.rel.as_str()).collect();
        assert!(rels.iter().any(|r| r.ends_with("app.c")), "{rels:?}");
        assert!(!rels.iter().any(|r| r.contains("node_modules")), "{rels:?}");
        assert!(!rels.iter().any(|r| r.ends_with(".png")), "{rels:?}");
    }

    #[test]
    fn include_vendor_reads_node_modules_source() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("node_modules").join("x")).unwrap();
        fs::write(
            root.join("node_modules").join("x").join("evil.c"),
            "strcpy(a,b);\n",
        )
        .unwrap();
        fs::write(root.join("logo.png"), [0u8; 16]).unwrap();
        let opts = WalkOpts {
            include_vendor: true,
            ..WalkOpts::default()
        };
        let hits = walk_files(root, opts, |_, _| true);
        let rels: Vec<_> = hits.iter().map(|h| h.rel.as_str()).collect();
        assert!(rels.iter().any(|r| r.contains("node_modules")), "{rels:?}");
        assert!(!rels.iter().any(|r| r.ends_with(".png")), "{rels:?}");
    }
}

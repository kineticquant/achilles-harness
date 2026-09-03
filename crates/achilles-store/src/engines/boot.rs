//! How a process is supposed to start — from manifests and usual entry files.
//! Not findings. Not a guess about runtime behavior.

use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::engines::walk::{WalkedFile, MAX_FILE_BYTES};

const MAX_PATHS: usize = 40;
const MAX_COMMAND: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StartupPath {
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub note: String,
}

pub fn map_startup(files: &[WalkedFile]) -> Vec<StartupPath> {
    let mut out = Vec::new();
    let rels: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();

    for file in files {
        if out.len() >= MAX_PATHS {
            break;
        }
        if noisy(&file.rel) {
            continue;
        }
        let name = file.file_name().to_ascii_lowercase();
        match name.as_str() {
            "package.json" => from_package_json(file, &mut out),
            "cargo.toml" => from_cargo_toml(file, &rels, &mut out),
            "dockerfile" | "containerfile" => from_dockerfile(file, &mut out),
            "procfile" => from_procfile(file, &mut out),
            "wrangler.toml" | "wrangler.json" | "wrangler.jsonc" => from_wrangler(file, &mut out),
            "pyproject.toml" => from_pyproject(file, &mut out),
            "fly.toml" => from_fly(file, &mut out),
            "nixpacks.toml" => from_nixpacks(file, &mut out),
            "railway.json" | "railway.toml" => from_railway(file, &mut out),
            "config.ru" => push(
                &mut out,
                "ruby-entry",
                &file.rel,
                Some("rackup"),
                "Rack / config.ru",
            ),
            _ => {}
        }
        if name.starts_with("docker-compose") || name == "compose.yml" || name == "compose.yaml" {
            from_compose(file, &mut out);
        }
        if name.ends_with(".service") {
            from_systemd(file, &mut out);
        }
        if name == "main.go" {
            from_go_main(file, &mut out);
        }
        language_entry(file, &mut out);
    }

    out.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.path.cmp(&b.path)));
    out.truncate(MAX_PATHS);
    out
}

fn noisy(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    [
        "/test/",
        "/tests/",
        "/__tests__/",
        "/testdata/",
        "/fixtures/",
        "/.git/",
        "/node_modules/",
        "/target/",
        "/vendor/",
    ]
    .iter()
    .any(|n| lower.contains(n))
}

fn push(out: &mut Vec<StartupPath>, kind: &str, path: &str, command: Option<&str>, note: &str) {
    if out.len() >= MAX_PATHS {
        return;
    }
    let command = command.map(clip_command).filter(|s| !s.is_empty());
    let dup = out
        .iter()
        .any(|row| row.kind == kind && row.path == path && row.command == command);
    if dup {
        return;
    }
    out.push(StartupPath {
        kind: kind.to_string(),
        path: path.to_string(),
        command,
        note: note.to_string(),
    });
}

fn clip_command(raw: &str) -> String {
    let trimmed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.chars().count() <= MAX_COMMAND {
        trimmed
    } else {
        let mut s: String = trimmed.chars().take(MAX_COMMAND).collect();
        s.push('…');
        s
    }
}

fn read_text(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn from_package_json(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    if let Some(scripts) = value.get("scripts").and_then(|v| v.as_object()) {
        for key in ["start", "start:prod", "start:production"] {
            if let Some(cmd) = scripts.get(key).and_then(|v| v.as_str()) {
                push(
                    out,
                    "npm-script",
                    &file.rel,
                    Some(cmd),
                    &format!("package.json scripts.{key}"),
                );
            }
        }
        if !scripts.contains_key("start") {
            if let Some(cmd) = scripts.get("dev").and_then(|v| v.as_str()) {
                push(
                    out,
                    "npm-script",
                    &file.rel,
                    Some(cmd),
                    "package.json scripts.dev (no start script)",
                );
            }
        }
    }
    if let Some(main) = value.get("main").and_then(|v| v.as_str()) {
        let electron = deps_contain(&value, "electron");
        push(
            out,
            if electron {
                "electron-main"
            } else {
                "npm-main"
            },
            &file.rel,
            Some(main),
            if electron {
                "package.json main (Electron)"
            } else {
                "package.json main"
            },
        );
    }
    match value.get("bin") {
        Some(serde_json::Value::String(bin)) => {
            push(out, "npm-bin", &file.rel, Some(bin), "package.json bin");
        }
        Some(serde_json::Value::Object(map)) => {
            for (name, cmd) in map.iter().take(6) {
                if let Some(cmd) = cmd.as_str() {
                    push(
                        out,
                        "npm-bin",
                        &file.rel,
                        Some(cmd),
                        &format!("package.json bin.{name}"),
                    );
                }
            }
        }
        _ => {}
    }
}

fn deps_contain(value: &serde_json::Value, name: &str) -> bool {
    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        if value
            .get(key)
            .and_then(|v| v.as_object())
            .is_some_and(|m| m.contains_key(name))
        {
            return true;
        }
    }
    false
}

fn from_cargo_toml(file: &WalkedFile, rels: &[&str], out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    let dir = Path::new(&file.rel)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    let main_rel = if dir.is_empty() {
        "src/main.rs".to_string()
    } else {
        format!("{dir}/src/main.rs")
    };
    if rels.iter().any(|r| *r == main_rel) {
        push(
            out,
            "cargo-bin",
            &main_rel,
            Some("cargo run"),
            "default Cargo binary (src/main.rs)",
        );
    }
    let mut in_bin = false;
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;
    let flush =
        |out: &mut Vec<StartupPath>, dir: &str, name: &Option<String>, path: &Option<String>| {
            let Some(bin_name) = name else {
                return;
            };
            let rel = match path {
                Some(p) if dir.is_empty() => p.clone(),
                Some(p) => format!("{dir}/{p}"),
                None if dir.is_empty() => format!("src/bin/{bin_name}.rs"),
                None => format!("{dir}/src/bin/{bin_name}.rs"),
            };
            push(
                out,
                "cargo-bin",
                &rel,
                Some(&format!("cargo run --bin {bin_name}")),
                "Cargo [[bin]]",
            );
        };
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if in_bin {
                flush(out, &dir, &name, &path);
            }
            in_bin = t == "[[bin]]";
            name = None;
            path = None;
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(v) = toml_string(t, "name") {
            name = Some(v);
        } else if let Some(v) = toml_string(t, "path") {
            path = Some(v.replace('\\', "/"));
        }
    }
    if in_bin {
        flush(out, &dir, &name, &path);
    }
}

fn toml_string(line: &str, key: &str) -> Option<String> {
    let prefix = key.to_string();
    let t = line.trim();
    if !t.starts_with(&prefix) {
        return None;
    }
    let rest = t.get(prefix.len()..)?.trim_start();
    if !rest.starts_with('=') {
        return None;
    }
    let rest = rest.strip_prefix('=')?.trim();
    if let Some(s) = rest.strip_prefix('"').and_then(|s| s.split('"').next()) {
        return Some(s.to_string());
    }
    if let Some(s) = rest.strip_prefix('\'').and_then(|s| s.split('\'').next()) {
        return Some(s.to_string());
    }
    None
}

fn from_dockerfile(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    if let Some(cmd) = last_instruction(&text, "ENTRYPOINT") {
        push(
            out,
            "docker-entrypoint",
            &file.rel,
            Some(&cmd),
            "Dockerfile ENTRYPOINT",
        );
    }
    if let Some(cmd) = last_instruction(&text, "CMD") {
        push(out, "docker-cmd", &file.rel, Some(&cmd), "Dockerfile CMD");
    }
}

fn last_instruction(text: &str, inst: &str) -> Option<String> {
    let mut last = None;
    let mut pending = String::new();
    let mut collecting = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if collecting {
            pending.push(' ');
            pending.push_str(line.trim_end_matches('\\').trim());
            if !line.ends_with('\\') {
                last = Some(strip_inst(&pending, inst));
                collecting = false;
                pending.clear();
            }
            continue;
        }
        if !starts_inst(line, inst) {
            continue;
        }
        let body = line.trim_end_matches('\\').trim();
        if line.ends_with('\\') {
            pending = body.to_string();
            collecting = true;
        } else {
            last = Some(strip_inst(body, inst));
        }
    }
    last.filter(|s| !s.is_empty())
}

fn starts_inst(line: &str, inst: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    let inst_u = inst.to_ascii_uppercase();
    upper.starts_with(&inst_u)
        && (line.len() == inst.len()
            || line
                .as_bytes()
                .get(inst.len())
                .is_some_and(|c| c.is_ascii_whitespace() || *c == b'['))
}

fn strip_inst(line: &str, inst: &str) -> String {
    line.get(inst.len()..).unwrap_or("").trim().to_string()
}

fn from_compose(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    for line in text.lines() {
        let t = line.trim();
        for key in ["command:", "entrypoint:"] {
            if let Some(rest) = t.strip_prefix(key) {
                let rest = rest.trim();
                if rest.is_empty() || rest == "|" || rest == ">" {
                    continue;
                }
                let kind = if key.starts_with("command") {
                    "compose-command"
                } else {
                    "compose-entrypoint"
                };
                push(out, kind, &file.rel, Some(rest), key.trim_end_matches(':'));
            }
        }
    }
}

fn from_procfile(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((name, cmd)) = t.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let cmd = cmd.trim();
        if name.is_empty() || cmd.is_empty() {
            continue;
        }
        push(
            out,
            "procfile",
            &file.rel,
            Some(cmd),
            &format!("Procfile process `{name}`"),
        );
    }
}

fn from_wrangler(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    if file.file_name().eq_ignore_ascii_case("wrangler.toml") {
        if let Some(main) = text.lines().find_map(|l| toml_string(l.trim(), "main")) {
            push(
                out,
                "wrangler-main",
                &file.rel,
                Some(&main),
                "wrangler.toml main",
            );
        }
        return;
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(main) = value.get("main").and_then(|v| v.as_str()) {
            push(out, "wrangler-main", &file.rel, Some(main), "wrangler main");
        }
    }
}

fn from_pyproject(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    let mut in_scripts = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_scripts = t == "[project.scripts]" || t == "[tool.poetry.scripts]";
            continue;
        }
        if !in_scripts {
            continue;
        }
        if let Some((name, rest)) = t.split_once('=') {
            let name = name.trim();
            let cmd = rest.trim().trim_matches('"').trim_matches('\'');
            if name.is_empty() || cmd.is_empty() {
                continue;
            }
            push(
                out,
                "pyproject-script",
                &file.rel,
                Some(cmd),
                &format!("pyproject script `{name}`"),
            );
        }
    }
}

fn from_fly(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    let mut in_processes = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_processes = t.eq_ignore_ascii_case("[processes]");
            continue;
        }
        if in_processes {
            if let Some((name, rest)) = t.split_once('=') {
                let cmd = rest.trim().trim_matches('"').trim_matches('\'');
                if !cmd.is_empty() {
                    push(
                        out,
                        "fly-process",
                        &file.rel,
                        Some(cmd),
                        &format!("fly.toml processes.{}", name.trim()),
                    );
                }
            }
        } else if let Some(cmd) = toml_string(t, "cmd") {
            push(out, "fly-cmd", &file.rel, Some(&cmd), "fly.toml cmd");
        }
    }
}

fn from_nixpacks(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    let mut in_start = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_start = t.eq_ignore_ascii_case("[start]");
            continue;
        }
        if in_start {
            if let Some(cmd) = toml_string(t, "cmd") {
                push(
                    out,
                    "nixpacks-start",
                    &file.rel,
                    Some(&cmd),
                    "nixpacks [start]",
                );
            }
        }
    }
}

fn from_railway(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    if file.file_name().eq_ignore_ascii_case("railway.json") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(cmd) = value
                .pointer("/deploy/startCommand")
                .or_else(|| value.get("startCommand"))
                .and_then(|v| v.as_str())
            {
                push(
                    out,
                    "railway-start",
                    &file.rel,
                    Some(cmd),
                    "Railway startCommand",
                );
            }
        }
        return;
    }
    if let Some(cmd) = text
        .lines()
        .find_map(|l| toml_string(l.trim(), "startCommand"))
    {
        push(
            out,
            "railway-start",
            &file.rel,
            Some(&cmd),
            "Railway startCommand",
        );
    }
}

fn from_systemd(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("ExecStart=") {
            push(
                out,
                "systemd",
                &file.rel,
                Some(rest.trim()),
                "systemd ExecStart",
            );
        }
    }
}

fn from_go_main(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let Some(text) = read_text(&file.abs) else {
        return;
    };
    if !text.lines().take(20).any(|l| l.trim() == "package main") {
        return;
    }
    push(
        out,
        "go-main",
        &file.rel,
        Some("go run ."),
        "Go package main",
    );
}

fn language_entry(file: &WalkedFile, out: &mut Vec<StartupPath>) {
    let rel = file.rel.as_str();
    let depth = rel.bytes().filter(|c| *c == b'/').count();
    if depth > 3 {
        return;
    }
    let name = file.file_name().to_ascii_lowercase();
    match name.as_str() {
        "manage.py" => push(
            out,
            "python-entry",
            rel,
            Some("python manage.py"),
            "Django manage.py",
        ),
        "wsgi.py" | "asgi.py" => push(out, "python-entry", rel, None, "Python WSGI/ASGI module"),
        "app.py" | "main.py" | "__main__.py" => push(
            out,
            "python-entry",
            rel,
            Some(&format!("python {rel}")),
            "Python entry",
        ),
        _ => {}
    }
    if rel.ends_with("bin/rails") {
        push(out, "ruby-entry", rel, Some("bin/rails server"), "Rails");
    }
    if matches!(
        rel,
        "src/index.ts" | "src/index.js" | "src/index.mjs" | "src/main.ts" | "src/main.js"
    ) {
        push(out, "js-entry", rel, None, "usual JS/TS entry file");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::walk::{walk_files, WalkOpts};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn maps_npm_docker_procfile_and_cargo() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"main":"server.js","scripts":{"start":"node server.js"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("Dockerfile"),
            "FROM node:20\nCMD [\"node\",\"server.js\"]\n",
        )
        .unwrap();
        fs::write(root.join("Procfile"), "web: node server.js\n").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        let files = walk_files(root, WalkOpts::default(), |_, _| true);
        let mapped = map_startup(&files);
        let kinds: Vec<_> = mapped.iter().map(|p| p.kind.as_str()).collect();
        assert!(kinds.contains(&"npm-script"), "{mapped:?}");
        assert!(kinds.contains(&"npm-main"), "{mapped:?}");
        assert!(kinds.contains(&"docker-cmd"), "{mapped:?}");
        assert!(kinds.contains(&"procfile"), "{mapped:?}");
        assert!(kinds.contains(&"cargo-bin"), "{mapped:?}");
        assert!(
            mapped
                .iter()
                .any(|p| p.kind == "npm-script" && p.command.as_deref() == Some("node server.js")),
            "{mapped:?}"
        );
    }

    #[test]
    fn maps_wrangler_main() {
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("wrangler.toml"),
            "name = \"w\"\nmain = \"src/index.ts\"\n",
        )
        .unwrap();
        let files = walk_files(tmp.path(), WalkOpts::default(), |_, _| true);
        let mapped = map_startup(&files);
        assert!(
            mapped
                .iter()
                .any(|p| p.kind == "wrangler-main" && p.command.as_deref() == Some("src/index.ts")),
            "{mapped:?}"
        );
    }
}

//! Function-like units for Deep. Heuristic split so any model can review
//! one body at a time — not a full AST. Apache-2.0.

use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use crate::engines::walk::WalkedFile;

pub const MAX_UNITS: usize = 24;
/// One function or file slice. Sized for ~120k-context local models (e.g. Liquid),
/// leaving room for the playbook and later read/grep turns.
const MAX_BODY_CHARS: usize = 80_000;
const MAX_FILE_CHARS: usize = 200_000;

#[derive(Debug, Clone)]
pub struct CodeUnit {
    pub path: String,
    pub name: String,
    pub line_start: i64,
    pub line_end: i64,
    pub body: String,
    pub score: i32,
}

#[derive(Clone, Copy)]
enum Lang {
    Python,
    Js,
    Go,
    Rust,
    Ruby,
    Php,
    JavaLike,
    CFamily,
}

/// Split one file into function-like units. Empty when the language is unknown.
pub fn extract_in_text(rel: &str, text: &str) -> Vec<CodeUnit> {
    let Some(lang) = lang_for(rel) else {
        return Vec::new();
    };
    extract_lang(rel, text, lang)
}

pub fn extract_scored(
    files: &[WalkedFile],
    sast_paths: &[String],
    surface_paths: &[String],
    cancel: Option<&AtomicBool>,
    max_units: usize,
) -> Vec<CodeUnit> {
    if max_units == 0 {
        return Vec::new();
    }
    let mut units = Vec::new();
    for file in files {
        if crate::engines::abort::flagged(cancel) {
            break;
        }
        let Some(lang) = lang_for(&file.rel) else {
            continue;
        };
        let Ok(text) = fs::read_to_string(&file.abs) else {
            continue;
        };
        if text.len() > MAX_FILE_CHARS {
            continue;
        }
        let hits = extract_lang(&file.rel, &text, lang);
        if hits.is_empty() {
            if text.lines().count() <= 160 {
                units.push(file_unit(
                    &file.rel,
                    &text,
                    score(&file.rel, "", sast_paths, surface_paths) + 1,
                ));
            }
            continue;
        }
        for mut unit in hits {
            unit.score = score(&file.rel, &unit.name, sast_paths, surface_paths);
            units.push(unit);
        }
    }
    units.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));
    units.truncate(max_units);
    units
}

fn file_unit(rel: &str, text: &str, score: i32) -> CodeUnit {
    let lines = text.lines().count().max(1) as i64;
    CodeUnit {
        path: rel.to_string(),
        name: file_stem(rel).to_string(),
        line_start: 1,
        line_end: lines,
        body: clip(text),
        score,
    }
}

fn extract_lang(rel: &str, text: &str, lang: Lang) -> Vec<CodeUnit> {
    let starts = match lang {
        Lang::Python => line_starts(text, python_def),
        Lang::Ruby => line_starts(text, ruby_def),
        Lang::Go => line_starts(text, go_func),
        Lang::Rust => line_starts(text, rust_fn),
        Lang::Php => line_starts(text, php_func),
        Lang::Js => line_starts(text, js_func),
        Lang::JavaLike => line_starts(text, java_method),
        Lang::CFamily => line_starts(text, c_func),
    };
    if starts.is_empty() {
        return Vec::new();
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::with_capacity(starts.len());
    for (i, (idx, name)) in starts.iter().enumerate() {
        let start = *idx;
        let end = starts
            .get(i + 1)
            .map(|(n, _)| n.saturating_sub(1))
            .unwrap_or(lines.len().saturating_sub(1));
        let slice = lines[start..=end].join("\n");
        out.push(CodeUnit {
            path: rel.to_string(),
            name: name.clone(),
            line_start: (start + 1) as i64,
            line_end: (end + 1) as i64,
            body: clip(&slice),
            score: 0,
        });
    }
    out
}

fn line_starts(text: &str, detect: fn(&str) -> Option<String>) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| detect(line).map(|name| (i, name)))
        .collect()
}

fn python_def(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t
        .strip_prefix("async def ")
        .or_else(|| t.strip_prefix("def "))?;
    ident_before(rest, '(')
}

fn ruby_def(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t.strip_prefix("def ")?;
    ident_before(rest.trim_start(), '(')
        .or_else(|| ident_before(rest.trim_start(), ' '))
        .or_else(|| Some(rest.trim().to_string()).filter(|s| is_ident(s)))
}

fn go_func(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t.strip_prefix("func ")?;
    if rest.starts_with('(') {
        let after_recv = rest.find(')')?;
        ident_before(rest.get(after_recv + 1..).unwrap_or("").trim_start(), '(')
    } else {
        ident_before(rest, '(')
    }
}

fn rust_fn(line: &str) -> Option<String> {
    let t = line.trim_start();
    let mut s = t;
    if let Some(r) = s.strip_prefix("pub ") {
        s = r.trim_start();
        if s.starts_with('(') {
            let end = s.find(')')?;
            s = s.get(end + 1..).unwrap_or("").trim_start();
        }
    }
    if let Some(r) = s.strip_prefix("async ") {
        s = r;
    }
    if let Some(r) = s.strip_prefix("unsafe ") {
        s = r;
    }
    let rest = s.strip_prefix("fn ")?;
    ident_before(rest, '(')
}

fn php_func(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t
        .strip_prefix("public function ")
        .or_else(|| t.strip_prefix("private function "))
        .or_else(|| t.strip_prefix("protected function "))
        .or_else(|| t.strip_prefix("function "))?;
    ident_before(rest, '(')
}

fn js_func(line: &str) -> Option<String> {
    let t = line.trim_start();
    let t = t.strip_prefix("export ").unwrap_or(t).trim_start();
    let t = t.strip_prefix("async ").unwrap_or(t).trim_start();
    if let Some(rest) = t.strip_prefix("function ") {
        return ident_before(rest, '(');
    }
    for kw in ["const ", "let ", "var "] {
        if let Some(rest) = t.strip_prefix(kw) {
            let name = ident_before(rest, '=')?;
            let after = rest.split_once('=')?.1.trim_start();
            let after = after.strip_prefix("async ").unwrap_or(after).trim_start();
            if after.starts_with('(') || after.starts_with("function") {
                return Some(name);
            }
        }
    }
    None
}

fn java_method(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.contains('=') || t.starts_with("//") || t.starts_with('*') {
        return None;
    }
    if !(t.contains("public ")
        || t.contains("private ")
        || t.contains("protected ")
        || t.contains("static "))
    {
        return None;
    }
    let before_paren = t.split_once('(')?.0.trim_end();
    let name = before_paren
        .rsplit(|c: char| c.is_whitespace() || c == '>')
        .next()?;
    if name == "if" || name == "for" || name == "while" || name == "switch" || name == "catch" {
        return None;
    }
    is_ident(name).then(|| name.to_string())
}

fn c_func(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with("//") || t.contains('=') {
        return None;
    }
    if !t.contains('(') || t.contains(';') {
        return None;
    }
    let before = t.split_once('(')?.0.trim_end();
    let name = before.split_whitespace().last()?;
    if matches!(name, "if" | "for" | "while" | "switch" | "return") {
        return None;
    }
    is_ident(name).then(|| name.to_string())
}

fn ident_before(s: &str, sep: char) -> Option<String> {
    let s = s.trim_start();
    let name = s.split(sep).next()?.trim();
    is_ident(name).then(|| name.to_string())
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn lang_for(rel: &str) -> Option<Lang> {
    let name = rel
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(rel)
        .to_ascii_lowercase();
    let ext = name.rsplit_once('.')?.1;
    Some(match ext {
        "py" | "pyw" => Lang::Python,
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Lang::Js,
        "go" => Lang::Go,
        "rs" => Lang::Rust,
        "rb" => Lang::Ruby,
        "php" | "phtml" => Lang::Php,
        "java" | "cs" | "kt" => Lang::JavaLike,
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" => Lang::CFamily,
        _ => return None,
    })
}

fn score(rel: &str, name: &str, sast_paths: &[String], surface_paths: &[String]) -> i32 {
    let hay = format!("{rel} {name}").to_ascii_lowercase();
    let mut n = 0;
    if sast_paths.iter().any(|p| p == rel) {
        n += 8;
    }
    if surface_paths.iter().any(|p| p == rel) {
        n += 4;
    }
    const HOT: &[&str] = &[
        "auth",
        "login",
        "session",
        "password",
        "token",
        "jwt",
        "oauth",
        "admin",
        "upload",
        "payment",
        "exec",
        "sql",
        "query",
        "handler",
        "route",
        "controller",
        "middleware",
        "permission",
        "secret",
        "crypto",
        "redirect",
    ];
    if HOT.iter().any(|k| hay.contains(k)) {
        n += 10;
    }
    n
}

fn clip(text: &str) -> String {
    if text.len() <= MAX_BODY_CHARS {
        return text.to_string();
    }
    let mut cut = MAX_BODY_CHARS;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n…", text.get(..cut).unwrap_or(text))
}

fn file_stem(rel: &str) -> &str {
    Path::new(rel)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(rel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    use crate::engines::walk::WalkedFile;

    #[test]
    fn splits_python_functions() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("auth.py");
        fs::write(
            &path,
            "def login(user):\n    return user\n\nasync def check(token):\n    eval(token)\n",
        )
        .unwrap();
        let files = [WalkedFile {
            abs: path,
            rel: "auth.py".into(),
            len: 0,
        }];
        let units = extract_scored(&files, &[], &[], None, MAX_UNITS);
        assert_eq!(units.len(), 2, "{units:?}");
        assert_eq!(units[0].name, "login");
        assert!(units[0].score >= 10, "{}", units[0].score);
        assert_eq!(units[1].name, "check");
        assert!(units[1].body.contains("eval(token)"));
    }

    #[test]
    fn prefers_sast_files() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("a.py"), "def a():\n    return 1\n").unwrap();
        fs::write(tmp.path().join("b.py"), "def b():\n    return 2\n").unwrap();
        let files = [
            WalkedFile {
                abs: tmp.path().join("a.py"),
                rel: "a.py".into(),
                len: 0,
            },
            WalkedFile {
                abs: tmp.path().join("b.py"),
                rel: "b.py".into(),
                len: 0,
            },
        ];
        let units = extract_scored(&files, &["b.py".into()], &[], None, MAX_UNITS);
        assert_eq!(units[0].path, "b.py");
    }
}

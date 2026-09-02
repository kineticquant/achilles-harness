//! Compact playbooks stuffed into Investigate/Deep prompts.
//! Retrieval is stack + filename, not embeddings. Apache-2.0.

const GENERIC: &str = r#"Look for a concrete path from untrusted input (request, file, argv, DB row) to a dangerous sink.
High-confidence only: injection (SQL/command/template/path), XSS via raw HTML APIs, missing authz on a mutating route when neighbors check, eval/exec/pickle/yaml.load on user data, open redirect, path traversal past a root.
Skip: style, tests-only, theoretical DoS, missing rate limits, lockfile CVEs, leaked tokens (other engines already did those).
No exploit steps or payloads. Quote must be copied from the given source."#;

const WEB_JS: &str = r#"JS/TS/React/Next: dangerouslySetInnerHTML, innerHTML, document.write, bypassSecurityTrustHtml. searchParams/headers into SQL, shell, or Location. Middleware that auth-checks some routes but not /api/*."#;

const PY: &str = r#"Python: eval/exec, pickle, yaml.load, os.system, subprocess shell=True, string-built SQL / .extra / f-strings into queries. Django CSRF-exempt, DEBUG=True. FastAPI sibling routes missing Depends."#;

const RUBY: &str = r#"Ruby/Rails: eval, YAML.load, Marshal.load, system/exec/backticks/%x, send/constantize on user input, SQL interpolation (#{} or +), html_safe/raw/render html:, skip_before_action authenticate, serialize YAML, Action Text / Trix innerHTML. Open redirect via redirect_to params. Authorize the same way neighboring controllers do."#;

const GO: &str = r#"Go: os/exec with concatenated args, text/template for HTML, tls InsecureSkipVerify, filepath join without Clean+root, fmt.Sprintf SQL."#;

const RUST: &str = r#"Rust: Command with user strings, sqlx/diesel string-built SQL. unsafe: only if the snippet clearly violates an invariant — do not invent memory unsafety in safe Rust."#;

const IAC: &str = r#"Terraform/k8s/Docker: 0.0.0.0/0 on SSH/DB, public buckets, IAM Action/Resource *, privileged/hostNetwork, secrets in env YAML. Do not invent cloud accounts."#;

const ACTIONS: &str = r#"GitHub Actions: pull_request_target + checkout of PR code, secrets on fork PRs, unpinned actions tags."#;

const AUTH: &str = r#"Auth: trace one request from an entry (route/handler) to a sensitive action. Same check as neighboring routes? IDs from the client without ownership? JWT alg none? Checks only in the UI? If you cannot find an auth layer, say so — do not invent an IdP."#;

pub fn for_context(surface_ids: &[String], rel: &str) -> String {
    let mut parts = vec![GENERIC.to_string()];
    let surfaces = surface_ids.join(" ");
    let hay = format!("{surfaces} {rel}").to_ascii_lowercase();
    if hay.contains("vercel")
        || hay.contains("next")
        || rel.ends_with(".js")
        || rel.ends_with(".ts")
        || rel.ends_with(".tsx")
        || rel.ends_with(".jsx")
    {
        parts.push(WEB_JS.into());
    }
    if hay.contains(".py") || rel.ends_with(".py") {
        parts.push(PY.into());
    }
    if hay.contains(".rb")
        || rel.ends_with(".rb")
        || rel.ends_with(".erb")
        || hay.contains("rails")
        || hay.contains("gemfile")
    {
        parts.push(RUBY.into());
    }
    if hay.contains(".go") || rel.ends_with(".go") {
        parts.push(GO.into());
    }
    if hay.contains(".rs") || rel.ends_with(".rs") {
        parts.push(RUST.into());
    }
    if hay.contains("terraform")
        || hay.contains("kubernetes")
        || hay.contains("helm")
        || hay.contains("docker")
        || rel.ends_with(".tf")
        || rel.contains("Dockerfile")
    {
        parts.push(IAC.into());
    }
    if hay.contains("github-actions") || rel.contains(".github/workflows") {
        parts.push(ACTIONS.into());
    }
    if AUTH_KEYS.iter().any(|k| hay.contains(k)) {
        parts.push(AUTH.into());
    }
    parts.join("\n")
}

const AUTH_KEYS: &[&str] = &[
    "auth",
    "login",
    "session",
    "password",
    "token",
    "jwt",
    "oauth",
    "admin",
    "permission",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_auth_file_gets_py_and_auth() {
        let text = for_context(&[], "src/auth.py");
        assert!(text.contains("eval/exec"), "{text}");
        assert!(text.contains("neighboring routes"), "{text}");
    }

    #[test]
    fn ruby_controller_gets_rails_playbook() {
        let text = for_context(&[], "app/controllers/messages_controller.rb");
        assert!(text.contains("html_safe"), "{text}");
    }

    #[test]
    fn terraform_surface_gets_iac() {
        let text = for_context(&["terraform".into()], "main.tf");
        assert!(text.contains("0.0.0.0/0"), "{text}");
    }
}

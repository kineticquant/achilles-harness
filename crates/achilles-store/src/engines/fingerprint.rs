//! What this tree looks like to deploy/CI — from files that exist, not guesses.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::engines::walk::{self, WalkOpts, WalkedFile};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DetectedSurface {
    pub id: String,
    pub label: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprint {
    pub surfaces: Vec<DetectedSurface>,
}

pub fn fingerprint_repo(root: &Path) -> Fingerprint {
    fingerprint_repo_with(root, WalkOpts::default())
}

pub fn fingerprint_repo_with(root: &Path, opts: WalkOpts) -> Fingerprint {
    fingerprint_files(&walk::walk_files(root, opts, |_, _| true))
}

/// Same as [`fingerprint_repo_with`] on an already-walked tree.
pub fn fingerprint_files(files: &[WalkedFile]) -> Fingerprint {
    let mut buckets: BTreeMap<&'static str, DetectedSurface> = BTreeMap::new();
    for file in files {
        let lower = file.rel.to_ascii_lowercase();
        let rel_path = Path::new(&file.rel);
        for (id, label) in classify(&lower, rel_path, &file.abs) {
            let row = buckets.entry(id).or_insert_with(|| DetectedSurface {
                id: id.to_string(),
                label: label.to_string(),
                paths: Vec::new(),
            });
            if row.paths.len() < 80 && !row.paths.iter().any(|p| p == &file.rel) {
                row.paths.push(file.rel.clone());
            }
        }
    }

    let mut surfaces: Vec<_> = buckets.into_values().collect();
    surfaces.sort_by(|a, b| a.id.cmp(&b.id));
    Fingerprint { surfaces }
}

/// Stable tree identity: sorted `rel\\tsha256(contents)` lines so parent vs child
/// scans can join even when git SHAs are missing or the worktree is dirty.
pub fn content_fingerprint(files: &[WalkedFile]) -> String {
    let mut lines: Vec<String> = files
        .iter()
        .map(|file| {
            let digest = std::fs::read(&file.abs)
                .map(|bytes| sha256_hex(&bytes))
                .unwrap_or_else(|_| format!("len:{}", file.len));
            format!("{}\t{digest}", file.rel)
        })
        .collect();
    lines.sort();
    sha256_hex(lines.join("\n").as_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn classify(lower: &str, rel: &Path, abs: &Path) -> Vec<(&'static str, &'static str)> {
    let name = rel
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut hit = Vec::new();

    if name == "wrangler.toml" || name == "wrangler.json" || name == "wrangler.jsonc" {
        hit.push(("cloudflare-workers", "Cloudflare Workers / wrangler"));
    }
    if name == "package.json"
        && peek_contains(
            abs,
            &[
                "wrangler",
                "@cloudflare/workers-types",
                "cloudflare:workers",
            ],
        )
    {
        hit.push(("cloudflare-workers", "Cloudflare Workers / wrangler"));
    }
    if lower.contains(".github/workflows/") && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
    {
        hit.push(("github-actions", "GitHub Actions"));
    }
    if name == "dependabot.yml" || lower.contains(".github/dependabot") {
        hit.push(("github-dependabot", "GitHub Dependabot"));
    }
    if name == ".gitlab-ci.yml" || name == ".gitlab-ci.yaml" {
        hit.push(("gitlab-ci", "GitLab CI"));
    }
    if lower.contains(".circleci/") && (name == "config.yml" || name == "config.yaml") {
        hit.push(("circleci", "CircleCI"));
    }
    if name == "azure-pipelines.yml" || name == "azure-pipelines.yaml" {
        hit.push(("azure-pipelines", "Azure Pipelines"));
    }
    if name == "cloudbuild.yaml" || name == "cloudbuild.yml" {
        hit.push(("google-cloudbuild", "Google Cloud Build"));
    }
    if name == "buildspec.yml" || name == "buildspec.yaml" {
        hit.push(("aws-codebuild", "AWS CodeBuild"));
    }
    if name == "bitbucket-pipelines.yml" {
        hit.push(("bitbucket-pipelines", "Bitbucket Pipelines"));
    }
    if name == ".travis.yml" {
        hit.push(("travis-ci", "Travis CI"));
    }
    if name == "jenkinsfile" {
        hit.push(("jenkins", "Jenkins"));
    }
    if name == "pipeline.yml" && lower.contains(".buildkite/") {
        hit.push(("buildkite", "Buildkite"));
    }
    if name.ends_with(".tf") || name.ends_with(".tf.json") || name.ends_with(".tfvars") {
        hit.push(("terraform", "Terraform"));
        if peek_contains(abs, &["hashicorp/aws", "provider \"aws\"", "aws_"]) {
            hit.push(("aws-terraform", "AWS via Terraform"));
        }
        if peek_contains(abs, &["azurerm", "provider \"azurerm\""]) {
            hit.push(("azure-terraform", "Azure via Terraform"));
        }
        if peek_contains(abs, &["google_project", "provider \"google\""]) {
            hit.push(("gcp-terraform", "GCP via Terraform"));
        }
    }
    if name == "terragrunt.hcl" {
        hit.push(("terraform", "Terraform"));
        hit.push(("terragrunt", "Terragrunt"));
    }
    if name.ends_with(".bicep") {
        hit.push(("azure-bicep", "Azure Bicep"));
    }
    if name.ends_with(".pkr.hcl") || name.ends_with(".pkr.json") {
        hit.push(("packer", "HashiCorp Packer"));
    }
    if name.ends_with(".nomad") || name.ends_with(".nomad.hcl") {
        hit.push(("nomad", "HashiCorp Nomad"));
    }
    if name == "ansible.cfg"
        || name == "playbook.yml"
        || name == "playbook.yaml"
        || name == "site.yml"
        || name == "site.yaml"
        || lower.contains("/playbooks/")
    {
        hit.push(("ansible", "Ansible"));
    }
    if (name.contains("template")
        || name.contains("cfn")
        || name.contains("cloudformation")
        || lower.contains("/cfn/")
        || lower.contains("/cloudformation/"))
        && peek_contains(
            abs,
            &["awstemplateformatversion", "aws::ec2::", "aws::iam::"],
        )
    {
        hit.push(("cloudformation", "AWS CloudFormation"));
    }
    if name == "cdk.json" || name == "cdk.context.json" {
        hit.push(("aws-cdk", "AWS CDK"));
    }
    if name == "template.yaml" || name == "template.yml" || name == "samconfig.toml" {
        hit.push(("aws-sam", "AWS SAM"));
    }
    if name == "serverless.yml" || name == "serverless.yaml" {
        hit.push(("serverless", "Serverless Framework"));
    }
    if name.starts_with("sst.config.") {
        hit.push(("sst", "SST"));
    }
    if name == "task-definition.json"
        || name == "ecs-params.yml"
        || name.ends_with(".taskdefinition.json")
    {
        hit.push(("aws-ecs", "AWS ECS task definition"));
    }
    if name == "dockerfile"
        || name.starts_with("docker-compose")
        || name == "compose.yaml"
        || name == "compose.yml"
        || name == "containerfile"
        || name == ".dockerignore"
    {
        hit.push(("docker", "Docker"));
    }
    if name == "chart.yaml" || name == "chart.yml" {
        hit.push(("helm", "Helm"));
    }
    if (name == "values.yaml" || name == "values.yml")
        && abs
            .parent()
            .is_some_and(|p| p.join("Chart.yaml").is_file() || p.join("Chart.yml").is_file())
    {
        hit.push(("helm", "Helm"));
    }
    if name == "helmfile.yaml" || name == "helmfile.yml" {
        hit.push(("helm", "Helm"));
        hit.push(("helmfile", "Helmfile"));
    }
    if name == "kustomization.yaml" || name == "kustomization.yml" {
        hit.push(("kubernetes", "Kubernetes manifests"));
        hit.push(("kustomize", "Kustomize"));
    }
    if name == "pulumi.yaml" || name == "pulumi.yml" {
        hit.push(("pulumi", "Pulumi"));
    }
    if name == "vercel.json"
        || name == ".vercelignore"
        || name == "now.json"
        || lower.contains("/.vercel/")
    {
        hit.push(("vercel", "Vercel"));
    }
    if name == "package.json" && peek_contains(abs, &["\"vercel\"", "@vercel/"]) {
        hit.push(("vercel", "Vercel"));
    }
    if name == "netlify.toml" || name == "_redirects" || name == "_headers" {
        hit.push(("netlify", "Netlify"));
    }
    if name == "fly.toml" {
        hit.push(("fly-io", "Fly.io"));
    }
    if name == "render.yaml" || name == "render.yml" {
        hit.push(("render", "Render"));
    }
    if name == "firebase.json" || name == ".firebaserc" || name.ends_with(".rules") {
        hit.push(("firebase", "Firebase"));
    }
    if name == "amplify.yml" {
        hit.push(("aws-amplify", "AWS Amplify"));
    }
    if name == "app.yaml" || name == "app.yml" {
        hit.push(("app-engine", "App Engine / PaaS app.yaml"));
    }
    if name == "procfile" {
        hit.push(("procfile", "Procfile (Heroku-style)"));
    }
    if name == "heroku.yml" {
        hit.push(("heroku", "Heroku"));
    }
    if name == "railway.toml"
        || name == "railway.json"
        || name == "nixpacks.toml"
        || lower.contains("/.railway/")
    {
        hit.push(("railway", "Railway"));
    }
    if name == "package.json" && peek_contains(abs, &["@railway/", "railway.json"]) {
        hit.push(("railway", "Railway"));
    }
    if lower == ".do/app.yaml" || lower.ends_with("/.do/app.yaml") {
        hit.push(("digitalocean-app", "DigitalOcean App Platform"));
    }
    if name == "nginx.conf" || name.ends_with(".nginx.conf") {
        hit.push(("nginx", "nginx"));
    }
    if name == "caddyfile" {
        hit.push(("caddy", "Caddy"));
    }
    if name == "traefik.yml" || name == "traefik.yaml" || name == "traefik.toml" {
        hit.push(("traefik", "Traefik"));
    }
    if name == "earthfile" {
        hit.push(("earthly", "Earthly"));
    }
    if name == "dagger.json" {
        hit.push(("dagger", "Dagger"));
    }
    if name == ".pre-commit-config.yaml" {
        hit.push(("pre-commit", "pre-commit"));
    }
    if name == ".env"
        || name == ".env.local"
        || name == ".env.production"
        || name == ".env.development"
        || name.starts_with(".env.")
    {
        hit.push(("dotenv", "Committed dotenv file"));
    }
    if looks_like_k8s(lower, &name, abs) {
        hit.push(("kubernetes", "Kubernetes manifests"));
    }
    hit
}

fn peek_contains(path: &Path, needles: &[&str]) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let take = bytes.len().min(8_192);
    let Ok(text) = std::str::from_utf8(&bytes[..take]) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    needles
        .iter()
        .any(|n| lower.contains(&n.to_ascii_lowercase()))
}

fn looks_like_k8s(lower: &str, name: &str, abs: &Path) -> bool {
    if lower.contains(".github/workflows/") {
        return false;
    }
    if !(lower.ends_with(".yml") || lower.ends_with(".yaml")) {
        return false;
    }
    name.contains("deployment")
        || name.contains("statefulset")
        || name.contains("daemonset")
        || name.contains("cronjob")
        || name.contains("ingress")
        || name == "service.yaml"
        || name == "service.yml"
        || lower.contains("/k8s/")
        || lower.contains("/kubernetes/")
        || lower.contains("/manifests/")
        || peek_contains(
            abs,
            &[
                "kind: deployment",
                "kind: statefulset",
                "kind: daemonset",
                "kind: cronjob",
                "kind: ingress",
                "apiVersion: apps/",
                "apiVersion: networking.k8s.io/",
            ],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detects_wrangler_and_github_actions() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("wrangler.toml"), "name = \"demo\"\n").unwrap();
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
        let fp = fingerprint_repo(root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"cloudflare-workers"));
        assert!(ids.contains(&"github-actions"));
    }

    #[test]
    fn content_fingerprint_changes_with_contents() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("a.txt"), "one\n").unwrap();
        let first = content_fingerprint(&walk::walk_files(root, WalkOpts::default(), |_, _| true));
        fs::write(root.join("a.txt"), "two\n").unwrap();
        let second = content_fingerprint(&walk::walk_files(root, WalkOpts::default(), |_, _| true));
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn detects_dotenv_and_wrangler_from_package_json() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join(".env.production"), "X=1\n").unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"devDependencies":{"wrangler":"4.0.0"}}"#,
        )
        .unwrap();
        let fp = fingerprint_repo(root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"dotenv"));
        assert!(ids.contains(&"cloudflare-workers"));
    }

    #[test]
    fn detects_k8s_helm_and_gha_from_fixtures() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/achilles-fixtures/kubernetes");
        let fp = fingerprint_repo(&root);
        let ids: Vec<_> = fp.surfaces.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"kubernetes"), "{ids:?}");
        assert!(ids.contains(&"helm"), "{ids:?}");
    }
}

---
name: stack-security
description: Framework- and language-specific security playbook. Use after fingerprint names the stack (Next, Django, Go, Rust, Terraform, Kubernetes, …). Not a generic OWASP dump.
---

Use this skill when the user asks about Next.js, Django, Rails, Flask, Go HTTP, Rust unsafe, Terraform, Kubernetes, Docker, or “what should I worry about in this stack?”

## Gate

Load **only** the sections that match fingerprint surfaces or files you actually opened. Skip the rest. Do not lecture Django on a Go repo.

## Playbooks

### Next.js / React / Vercel

- XSS: `dangerouslySetInnerHTML`, `bypassSecurityTrustHtml`, `innerHTML`. Normal JSX is not XSS.
- Server: `searchParams` / headers into SQL, shell, or redirects; `open-redirect` via user-controlled `Location`
- Middleware that authenticates some routes and not `/api/*`
- `vercel.json` / env in the client bundle (`NEXT_PUBLIC_` secrets that are not public)

### Django / Flask / FastAPI

- ORM vs raw SQL / `.extra` / `format` into queries
- CSRF exempt views, `DEBUG=True` in deploy config
- `pickle` / `yaml.load` / `eval` of request data
- FastAPI: `Depends` missing on a sibling route that mutates data

### Go

- `os/exec` with concatenated args, `text/template` vs `html/template` for HTML
- `tls.Config{InsecureSkipVerify: true}`
- `encoding/json` into `interface{}` then unsanitized use
- File paths from URL joined without `filepath.Clean` + root check

### Rust

- `unsafe` blocks: say what invariant they claim; don’t invent memory unsafety in safe Rust
- `Command` with user strings, `sqlx`/`diesel` string-built SQL
- `unwrap()` on untrusted parse at a boundary (availability, not always a vuln)

### Terraform / cloud IaC

- `0.0.0.0/0` on SSH or DB, public buckets, IAM `Action = "*"` / `Resource = "*"`
- Secrets in `.tfvars` committed to git (don’t print them)
- Tie to **surface** findings

### Kubernetes / Helm / Docker

- Privileged, `hostNetwork`, latest tags, secrets in env in the YAML
- Images from `latest`; root user when the rest of the chart is non-root

### GitHub Actions

Defer to `github-actions-security`.

## Output

Only the matching stacks. File:line, why it matters, safe next step. Prefer finding ids. No exploit steps.

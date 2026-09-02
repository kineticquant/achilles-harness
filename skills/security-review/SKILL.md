---
name: security-review
description: Security review of the current branch, PR, or git diff. High-confidence issues only. Prefer existing Achilles findings. No exploit payloads.
---

Use this skill when the user asks to review a PR, a branch, “is this diff safe?”, or `/security-review`.

This is **not** a full-repo scanner. Engines already did that. You are reviewing **what changed**.

## Setup

1. `appsec_query` for this workspace. If Findings already cover a changed file, lead with those finding ids.
2. `git status`, `git log`, and `git diff` against the merge base (or the range they named).
3. Identify languages/frameworks from the diff and from fingerprint surfaces — then load `stack-security` if the stack is one we have a playbook for.

## What to look for

Only issues you would raise in a real PR review, with a concrete path from untrusted input (or a trust-boundary cross) to a bad sink.

- Injection: SQL/command/template/path, XSS only where the framework is actually bypassed (`dangerouslySetInnerHTML`, raw HTML, disabled escaping)
- Authn/authz: checks removed, new routes without the same guard as neighbors, IDOR-shaped “use this id from the client”
- Secrets: new credentials in the diff (do not print them)
- Crypto: homemade crypto, `Math.random` for tokens, TLS verify disabled
- Deserialization / `eval` / `pickle` / `yaml.load` / `os.system` with user data
- CI: `pull_request_target` + checkout of PR code, secrets on fork PRs

## Do not report

- Style, tests-only files, docs
- “Missing rate limit”, theoretical DoS, missing audit logs
- SCA / lockfile CVEs (that is `dependency-risk` + the SCA engine)
- “React doesn’t escape this” unless they used an unsafe HTML API
- Invented finding ids or invented CVEs

## Output

Markdown. For each issue: file:line, severity (high/medium), category, what changed, why it matters in one sentence, a safe fix (describe it; do not apply unless they clearly ask). No exploit steps. Say so if the diff looks clean.

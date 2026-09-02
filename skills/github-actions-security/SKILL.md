---
name: github-actions-security
description: Review GitHub Actions workflows Achilles fingerprint-detected. Secrets, pull_request_target, untrusted checkout. No live GitHub API probing.
---

Use this skill when the user asks about CI security, workflow files, or “is my GitHub Action safe?”

## Source of truth

Only workflow files the scan fingerprint already saw (`.github/workflows/*`). If none were detected, say so and stop.

## Checklist (concrete, not vibes)

- `pull_request_target` plus checkout of PR head / untrusted script — treat as high until proven otherwise
- Secrets used on `pull_request` from forks
- `actions/checkout` of a user-controlled ref without pinning
- Action versions as moving tags (`@v4`) vs a SHA — mention pinning; do not invent CVEs for the action
- `workflow_dispatch` / `repository_dispatch` inputs flowing into `run:` scripts
- `permissions:` broader than the job needs (`contents: write` everywhere)
- Secrets echoed in logs

Read the YAML. Do not call GitHub. Do not invent workflows that are not on disk.

## Output

Per workflow file: what it does, issues with line pointers, safe change (pin, permission, don’t checkout untrusted code). Tie to surface findings if they already exist.

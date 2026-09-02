---
name: rotate-secret
description: Help remove a leaked credential finding from the repo and rotate it. Never print the secret or give exploit steps.
---

Use this skill when a **secrets** finding exists (API key, token, password in source) and the user asks how to clean it up.

## Rules

1. Work from the `finding_id`. Do not echo the secret value; use the redacted preview only.
2. Steps, in order: revoke/rotate the credential at the provider → remove it from the file → put it in env/secret store → rescan.
3. Prefer they delete the line in their usual editor. Edit the file here only if they clearly ask you to.
4. Mention git history only at a high level (the secret may still be in old commits). Do not run destructive git-filter commands unless the user explicitly asks.
5. After the credential is rotated and the file is clean, they should Rescan in Findings and can mark the finding fixed.

## Output

A numbered checklist. No secret material in the reply.

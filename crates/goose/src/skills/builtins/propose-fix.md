---
name: propose-fix
description: Describe a safe change for one Achilles finding id. Prefer they apply it in their usual editor or coding agent. Edit files here only if they clearly ask.
---

Use this skill when the user wants a patch, a suggested fix, or "how do I fix this?" for a scan finding.

Achilles is for finding and triaging. Landing the patch is usually better in the editor or coding agent they already use for this repo.

## Rules

1. Take a **finding_id** from `appsec_query` / Findings. If they named a file instead, match it to an existing finding — do not invent a new issue.
2. `appsec_investigate` that id. Read nearby source. Propose the smallest change that removes the sink or pins the dependency.
3. Default: **do not edit files**. Give them a short brief they can paste into their usual coding tool (path:line, what is wrong, what to change). Offer that you can apply it here if they want.
4. Edit in Achilles only after they clearly ask you to apply the patch here. Then wait for that confirmation before writing.
5. No exploit payloads, no "here's how to attack this."
6. If the finding is a **leaked secret**, do not print the secret. Recommend rotating the credential and removing it from git history at a high level.
7. If the finding is **SCA** (software composition analysis — a known-vulnerable dependency), prefer a version pin/upgrade from the advisory. Do not invent CVE ids; use `appsec_intel` if you need KEV/EPSS.

## Output

- What to change (file + brief why)
- A pasteable brief for their editor or coding agent
- How to re-scan (Findings → Rescan, or scan changed files)

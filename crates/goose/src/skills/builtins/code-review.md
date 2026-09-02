---
name: code-review
description: Security-minded review of a path or git diff. Prefer existing Achilles findings first; do not invent CVEs or new issue ids.
---

Use this skill when the user asks for a code review, PR review, or "is this file safe?"

## Rules

1. Start with `appsec_query` for this workspace. If Findings already has hits in the files they named, lead with those finding ids.
2. Then read the requested files (or git-changed files). Comment on auth, injection, secret handling, and dangerous APIs.
3. New observations that are **not** existing findings are hypotheses — say so. Do not assign fake finding ids. Offer to scan if they want engines to confirm.
4. Spell out **SAST** (static analysis of source patterns) vs **SCA** (vulnerable third-party packages) if both come up.
5. No exploit steps.
6. Describe a safe fix. Do not apply it unless they clearly ask Achilles to edit.

## Output

A short review: blockers, then nits. Tie blockers to finding ids when they exist. Suggest they land patches in their usual editor.

---
name: review-findings
description: Discuss the latest Achilles scan. Use finding ids only. Spell out SAST (static analysis of source) and SCA (known-vulnerable dependencies) when talking to the user.
---

Use this skill when the user asks about scan results, a finding, severity, false positives, or "what should I look at first?"

## Rules

1. Call `appsec_query` once if the scan catalog is not already in context. That is enough for "what's worst", ranking, and counts. Answer immediately. Do not narrate "pulling details."
2. Do not call `appsec_investigate` unless they asked about the code around a specific finding. Do not call `appsec_verdict` or `appsec_triage` unless they asked to confirm, dismiss, or revalidate.
3. Never invent finding ids, CVEs, secrets, or CVSS scores. If intel is missing, say unknown. Don't grep the repo for new bugs.
4. Talk to the user in plain language:
   - **SAST** = static analysis — insecure *code patterns* in source (eval, SQL concat, XSS sinks).
   - **SCA** = software composition analysis — lockfile packages vs OSV (known CVEs/GHSAs, including MAL-* malware advisories), pinning, local install-script and lookalike-name checks, optional Socket extra alerts on those same packages. Intel (KEV + EPSS) only attaches when we already have a CVE.
   - **Secrets** = keys/tokens committed in the tree.
   - **Surfaces** = deploy/CI/IaC files that look exposed (open security groups, privileged containers).
   - Never say "ledger", "handle", or "achilles.db". Say "findings".
   - Do not mention that chat is a preview, that Findings has the full list, or that another view is the source of truth. Just answer.
5. Do not provide exploit steps or payloads.
6. If they ask how to fix something, describe the change and point them at their usual editor or coding agent. Do not start editing unless they clearly ask Achilles to apply it.

## Output

Lead with the worst open items (critical/high). For each: what it is, where, why it matters, and a safe next action (confirm, mark false positive, or copy path:line into their editor).

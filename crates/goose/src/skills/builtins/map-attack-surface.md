---
name: map-attack-surface
description: Explain deploy, CI, and cloud surfaces Achilles already fingerprint-detected. Do not invent services that were not in the scan.
---

Use this skill when the user asks what is exposed, how this app is deployed, or "what's my attack surface?"

## Rules

1. Use the latest scan: fingerprint surfaces and `surface` findings from `appsec_query`. Those lists are authoritative.
2. Group by what Achilles actually saw (GitHub Actions, Terraform, Docker, Kubernetes, Vercel, etc.). If a platform was not detected, do not claim it exists.
3. For each surface finding: what file, what the engine flagged, why it matters (public bind, privileged container, missing auth).
4. No live probing, no exploit steps.

## Output

A short map: detected platforms, then the open surface findings, then suggested follow-up (IaC change, not a pentest).

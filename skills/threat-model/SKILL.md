---
name: threat-model
description: Lightweight threat model of this workspace from Achilles fingerprint surfaces and open findings. Do not invent services that were not detected.
---

Use this skill when the user asks what can go wrong, who the attacker is, or “threat model this app.”

## Source of truth

1. Fingerprint surfaces from the latest scan (`map-attack-surface` / `appsec_query`). If a platform was not detected, it does not exist in this model.
2. Open findings. Tie threats to finding ids when they exist.
3. README + entry points only as far as needed to name *assets* (accounts, tokens, data stores).

## Model (keep it short)

For each detected surface, answer:

- **Asset** — what is valuable here (session cookie, cloud keys, customer data, deploy credentials)
- **Entry** — how untrusted input or an untrusted actor reaches it (HTTP, CI, IaC apply, webhook)
- **What goes wrong** — one sentence, mapped to a category people know (stolen session, poisoned pipeline, public bucket, injected query)
- **What Achilles already flagged** — finding ids, or “none yet — scan / investigate”
- **What to do next** — confirm a finding, fix a file, or add a control. Not a pentest.

## Do not

- Invent AWS/K8s/Vercel because “most apps have them”
- Produce a 20-page STRIDE matrix
- Give exploit steps or live-probing commands

---
name: dependency-risk
description: Explain an SCA finding (software composition analysis — a known-vulnerable library). Use appsec_intel. Never invent CVEs or scores.
---

Use this skill when the user asks about a lockfile advisory, CVE, GHSA, KEV, EPSS, Socket malware/typosquat, or "is this dependency actually dangerous?"

## Rules

1. Identify the SCA finding (`category` sca). Copy package, version, and advisory ids from the finding — do not invent them. Pinning findings are unpinned manifests / missing lockfiles, not CVEs. Socket findings use `rule_id` like `socket:malware` and have no CVE.
2. For CVE/GHSA ids, call `appsec_intel`. Use KEV (CISA Known Exploited Vulnerabilities) and EPSS (likelihood of exploit in the wild) only if the tool returns them. If a field is null, say unknown. Do not call intel for Socket-only alerts.
3. Explain in plain language: what the package is, what the advisory claims, whether it is known-exploited, what upgrade/pin the lockfile needs.
4. **SCA** = checking third-party libraries. OSV is known CVEs/GHSAs (and MAL-* malware advisories) for that lockfile version. Local hygiene flags install-time scripts and lookalike names in manifests/lockfiles. Socket (optional token) adds extra catalog alerts on those same packages — not a Socket blog or GitHub-issue watcher. Pinning is unpinned deps in manifests. Intel attaches KEV + EPSS only when we already have a CVE. It is not a source-code bug in *your* file (that is **SAST** / static analysis).

## Output

Package + version, advisory ids, KEV/EPSS if known, and the smallest upgrade that clears it. No exploit details.

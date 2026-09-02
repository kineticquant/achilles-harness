---
name: map-codebase
description: Orient in this workspace — layout, how the process starts, how to build and test. Do not dump the whole tree.
---

Use this skill when the user asks how this repo is structured, where to start, how the app starts up, or "explain this codebase."

## Rules

1. If Achilles Findings already exist, treat `startupPaths` from the latest scan (session catalog or `appsec_query`) as authoritative for **how the process is supposed to start**. Those come from manifests and usual entry files (package.json scripts, Dockerfile CMD, Procfile, Cargo bin, wrangler main, and similar). Do not invent extra processes.
2. If there is no scan yet, start from README, package manifests, and the language’s usual entry (`main`, `src/`, `app/`). Use `tree` only on a specific project path, never a home directory.
3. Name the 5–10 paths that matter (entry, config, tests, deploy). Do not paste large file dumps.
4. If Achilles Findings already exist for this workspace, mention open high/critical items in one line — do not invent new issue ids.
5. Spell out **SAST** (static analysis of *your* source) vs **SCA** (known-vulnerable *dependencies*) if both come up.

## Output

A short map: what the project is, how it starts, how to run it, where changes usually go.

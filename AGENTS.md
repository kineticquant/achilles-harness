# AGENTS.md — Achilles / Arrav

Instructions for coding agents and humans working in this repository.

## Product identity

| Name | Role |
|------|------|
| **Achilles** | The harness — desktop app, CLI, agent runtime, MCP/extensions surface |
| **Arrav** | The local model that runs inside Achilles |
| **goose** | Upstream base project ([aaif-goose/goose](https://github.com/aaif-goose/goose)) |

This repo is a **fork of goose** used to build Achilles. Published source (goose-derived and Achilles / Arrav original work) is Apache-2.0. See `LICENSING.md`, `LICENSE-APACHE`, `NOTICE`. Do not call the tree MIT.

## Repo remotes

- `upstream` → `https://github.com/aaif-goose/goose.git`
- `origin` → this Achilles / Arrav repository

```bash
git fetch upstream
git log HEAD..upstream/main --oneline
# merge or cherry-pick deliberately
```

## Licensing rules for agents

- Do **not** delete `LICENSE-APACHE`, `NOTICE`, or Apache headers on goose-derived files.
- New Achilles / Arrav source in this repo is Apache-2.0 as well. Do not add a second product license.
- Do not claim this tree is MIT. It is Apache-2.0.
- Do not use Goose/AAIF trademarks in a way that implies endorsement.

## Architecture (inherited from goose)

```
crates/
├── goose                 # core agent, providers, prompts, state machine
├── goose-cli             # CLI entry (`goose` binary for now)
├── goose-mcp             # MCP extensions
├── goose-local-inference # local model path
└── ...

ui/desktop/               # Electron UI (Achilles)
docs/                     # Achilles product docs (Help / Settings links)
```

The fork does **not** ship the upstream goose Docusaurus site. Product guidance lives in `docs/`. Goose docs remain upstream at [aaif-goose/goose](https://github.com/aaif-goose/goose).

Useful in-tree build notes: `CUSTOM_DISTROS.md`, `BUILDING_LINUX.md`, `BUILDING_DOCKER.md`, `ui/desktop/README.md`.

## Setup

```bash
# Prefer Hermit when available
source bin/activate-hermit   # Git Bash / Unix

cargo build
```

Windows: MSVC Build Tools + Rust via rustup; for Hermit activation use Git Bash. UI needs pnpm (see `ui/desktop/package.json` engines).

## Commands

### Build

```bash
cargo build                              # debug
cargo build --release -p goose-cli --bin goose
just release-windows                     # Windows MSVC release binary
just run-ui                              # build CLI + start desktop
just run-ui-only                         # desktop only
```

### Test / lint

```bash
cargo test
cargo test -p goose
cargo fmt
cargo clippy --all-targets -- -D warnings
cd ui/desktop && pnpm run typecheck && pnpm test
```

### UI

```bash
cd ui/desktop && pnpm install && pnpm run start-gui
# or from root: just run-ui
```

## Coding rules

- Prefer small, reviewable diffs; isolate Achilles-specific changes.
- Rust: `anyhow::Result`; use `cargo add` for human-authored dependency changes; keep `Cargo.lock` consistent.
- UI: ACP SDK types or `ui/desktop/src/types/*` — do not recreate `ui/desktop/src/api` / openapi client there.
- Do not overwrite a live binary in place on macOS (signature invalidation).
- Comments: explain why, not what; skip noise.
- Run fmt/clippy/tests when the user asks to verify changes.
- Do not mass-rename internal `goose` identifiers without an explicit request.

## Entry points

- CLI: `crates/goose-cli/src/main.rs`
- UI: `ui/desktop/src/main.ts`
- Agent: `crates/goose/src/agents/agent.rs`
- System prompt: `crates/goose/src/prompts/system.md`

## Do not

- Push unpublished Arrav weights or secrets into public remotes
- Strip Apache notices

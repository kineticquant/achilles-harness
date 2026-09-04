# AGENTS.md — Achilles / Arrav

Instructions for coding agents and humans working in this repository.

## Product identity

| Name | Role |
|------|------|
| **Achilles** | The harness — desktop app, CLI, agent runtime, MCP/extensions surface |
| **Arrav** | The local model that runs inside Achilles |

Achilles was built on [goose](https://github.com/aaif-goose/goose). License: Apache 2.0 — [LICENSING.md](LICENSING.md).

## Repo remotes

- `origin` → this repository
- `upstream` → `https://github.com/aaif-goose/goose.git` (optional, for pulling engine changes)

```bash
git fetch upstream
git log HEAD..upstream/main --oneline
# merge or cherry-pick deliberately
```

## Licensing

See [LICENSING.md](LICENSING.md). Do not delete `LICENSE-APACHE`, `NOTICE`, or Apache headers. `LICENSE` must stay the full Apache 2.0 text (not a pointer) so GitHub can classify the repo.

Product docs live in `docs/`. Useful build notes: `CUSTOM_DISTROS.md`, `BUILDING_LINUX.md`, `BUILDING_DOCKER.md`, `ui/desktop/README.md`.

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

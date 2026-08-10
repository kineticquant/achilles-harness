# AGENTS.md — Achilles / Arrav

Instructions for coding agents and humans working in this repository.

## Product identity

| Name | Role |
|------|------|
| **Achilles** | The harness — desktop app, CLI, agent runtime, MCP/extensions surface |
| **Arrav** | The model — fine-tuned Liquid AI model that snaps into Achilles and can run locally |
| **goose** | Upstream base project ([aaif-goose/goose](https://github.com/aaif-goose/goose)) |

This repo is a **fork of goose** used to build Achilles. It is **not** intended as MIT/Apache-for-everything FOSS for our additions. Goose-derived code remains Apache-2.0; Achilles / Arrav original work is proprietary. See `LICENSING.md`, `LICENSE-APACHE`, `LICENSE-ACHILLES`, `NOTICE`.

## Goals (current)

1. Keep a maintainable fork that can pull upstream goose fixes/features via the `upstream` remote.
2. Rebrand the product to **Achilles** (UI strings, packaging, prompts, icons over time).
3. Integrate **Arrav** as the preferred local model (Liquid AI fine-tune).
4. Enforce restrictive licensing on Achilles / Arrav materials while preserving Apache obligations for goose code.
5. Prefer isolating proprietary pieces (Arrav provider, branding, business logic) to ease upstream merges.

## Repo remotes

- `upstream` → `https://github.com/aaif-goose/goose.git` (track / merge as needed)
- `origin` → `https://github.com/kineticquant/achilles-harness.git` (your Achilles / Arrav repo)

Sync pattern:

```bash
git fetch upstream
git log HEAD..upstream/main --oneline
# merge or cherry-pick deliberately
```

## Licensing rules for agents

- Do **not** delete `LICENSE-APACHE`, `NOTICE`, or Apache headers on goose-derived files.
- New Achilles / Arrav files should be treated as proprietary (`LICENSE-ACHILLES`).
- Do not claim this entire tree is MIT or “fully open source.”
- Do not use Goose/AAIF trademarks in a way that implies endorsement.

## Architecture (inherited from goose)

```
crates/
├── goose                 # core agent, providers, prompts, state machine
├── goose-cli             # CLI entry (`goose` binary for now)
├── goose-mcp             # MCP extensions
├── goose-local-inference # local model path (relevant for Arrav)
└── ...

ui/desktop/               # Electron UI → brand as Achilles
```

Useful upstream docs still in-tree: `CUSTOM_DISTROS.md` (white-label guide), `BUILDING_LINUX.md`, `BUILDING_DOCKER.md`, `ui/desktop/README.md`.

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

## Branding work

Started:

- Desktop `productName` / description → Achilles
- `index.html` title → Achilles
- Forge packaging display names → Achilles
- English UI strings (`en.json`) user-facing Goose → Achilles (technical ids like `.goosehints`, `goose://` left alone for now)
- System prompts → Achilles / Arrav framing

Still TODO:

- Icons / splash assets under `ui/desktop/src/images/`
- Remaining locale files
- Hardcoded `Goose` strings in TSX components
- Binary / protocol / config renames (`goose` CLI name, `goose://`, env vars) — do carefully; high breakage
- Arrav provider + Liquid AI local snap-in
- Telemetry defaults (`GOOSE_DISABLE_TELEMETRY=1` for private distros)

## Arrav (model) — planned

- Fine-tuned Liquid AI model
- Runs locally inside Achilles
- Implementation will likely touch `crates/goose-local-inference` and/or a declarative provider under `crates/goose/src/providers/`
- Ship as Achilles-default model without requiring cloud API keys when possible

## Agent loop note (upstream)

Upstream is migrating the agent loop to a state machine under `crates/goose/src/agents/state_machine/` (`GOOSE_STATE_MACHINE=1`). Until that lands fully upstream, behavior changes may need parity in both paths. See historical notes in git history of upstream `AGENTS.md` if needed.

## Coding rules

- Prefer small, reviewable diffs; isolate Achilles-specific changes.
- Rust: `anyhow::Result`; use `cargo add` for human-authored dependency changes; keep `Cargo.lock` consistent.
- UI: ACP SDK types or `ui/desktop/src/types/*` — do not recreate `ui/desktop/src/api` / openapi client there.
- Do not overwrite a live binary in place on macOS (signature invalidation).
- Comments: explain why, not what; skip noise.
- Run fmt/clippy/tests when the user asks to verify changes.

## Entry points

- CLI: `crates/goose-cli/src/main.rs`
- UI: `ui/desktop/src/main.ts`
- Agent: `crates/goose/src/agents/agent.rs`
- System prompt: `crates/goose/src/prompts/system.md`

## Do not

- Push proprietary Arrav weights or secrets into public remotes
- Strip Apache notices
- Mass-rename internal `goose` identifiers without a staged plan
- Treat upstream contribution workflow (Ready issues board) as required for private Achilles work

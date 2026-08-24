# Achilles

**Achilles** is a custom agent harness built on a fork of [goose](https://github.com/aaif-goose/goose).  
**Arrav** is the fine-tuned Liquid AI model that snaps into Achilles and can run locally.

This is **not** an MIT-style open product. Goose-derived code stays under Apache 2.0; Achilles / Arrav additions are proprietary. See [LICENSING.md](LICENSING.md).

## Naming

| Name | What it is |
|------|------------|
| **Achilles** | The harness (CLI, desktop UI, agent runtime, tooling) |
| **Arrav** | The model that runs inside the harness (local Liquid AI fine-tune) |
| **goose** | Upstream open-source project this fork is based on |

## Goals

- Ship a branded desktop + CLI agent experience (**Achilles**)
- Default to / prefer the local **Arrav** model (Liquid AI fine-tune)
- Keep the ability to pull useful fixes and features from upstream goose
- Restrict commercial reuse of Achilles / Arrav materials via proprietary licensing

## Build & run (Windows)

### Prerequisites

- [Rust](https://rustup.rs/) (see `rust-version` in root `Cargo.toml`)
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (MSVC) for native builds
- Node.js + pnpm (Hermit can provide these once activated; see below)
- Git

### Option A — Hermit toolchain (recommended by upstream)

```powershell
# From repo root (Git Bash or WSL may be easier for `source`)
# On Windows, use Git Bash:
source ./bin/activate-hermit

cargo build
cargo build --release -p goose-cli --bin goose
```

### Option B — System Rust + UI

```powershell
# CLI / core
cargo build
cargo build --release -p goose-cli --bin goose

# Desktop UI
cd ui/desktop
pnpm install
pnpm run start
```

Or from repo root with [just](https://github.com/casey/just):

```powershell
just run-ui        # builds release CLI binary, then starts Electron UI
just run-ui-only   # UI only (expects binary already in place)
just release-windows
```

The desktop app launches the bundled `goose` CLI binary and talks to it over ACP. Binary names may still say `goose` internally until we finish renaming; the product brand is **Achilles**.

### Useful checks

```powershell
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test -p goose
cd ui/desktop; pnpm run typecheck; pnpm test
```

## Remotes

| Remote | URL | Purpose |
|--------|-----|---------|
| `origin` | `https://github.com/kineticquant/achilles-harness.git` | Your Achilles / Arrav repo (push here) |
| `upstream` | `https://github.com/aaif-goose/goose.git` | goose source — fetch/merge when you want their changes |

```powershell
git fetch upstream
git log HEAD..upstream/main --oneline   # see what you'd pick up
# merge or cherry-pick as needed
```

Yes — that is how you pick up their changes when you want them. Prefer small, reviewed merges; keep Achilles-specific code isolated when possible.

## Dependencies

For a Python-dev-friendly walkthrough (cheat sheet, install checklist, Cargo equivalents), open **[requirement-guidance.html](requirement-guidance.html)** in a browser.

| Layer | How it’s managed |
|-------|------------------|
| Rust crates | `Cargo.toml` / `Cargo.lock` — use `cargo add` for new deps |
| Desktop / JS | `ui/pnpm-workspace.yaml`, `ui/pnpm-lock.yaml` — use `pnpm` in `ui/` |
| Toolchain pins | Hermit under `bin/` (Rust/Node/pnpm/etc. when activated) |
| Arrav model | To be added as a first-class provider / local inference path (not upstream) |

When syncing upstream, expect lockfile conflicts — regenerate with `cargo update` / `pnpm install` carefully rather than blindly taking one side.

## Recommended VS Code / Cursor extensions

Add these for day-to-day work on Achilles:

| Extension | Why |
|-----------|-----|
| **rust-analyzer** (`rust-lang.rust-analyzer`) | Rust IDE features, go-to-def, borrow checking |
| **CodeLLDB** (`vadimcn.vscode-lldb`) | Debug Rust binaries |
| **Even Better TOML** (`tamasfe.even-better-toml`) | `Cargo.toml` editing |
| **crates** (`serayuzgur.crates`) | Crate versions / docs in Cargo.toml |
| **ESLint** (`dbaeumer.vscode-eslint`) | Desktop TS/TSX lint |
| **Prettier** (`esbenp.prettier-vscode`) | UI formatting |
| **Tailwind CSS IntelliSense** (`bradlc.vscode-tailwindcss`) | Desktop styling |
| **Error Lens** (`usernamehw.errorlens`) | Inline diagnostics |
| **GitLens** (`eamodio.gitlens`) | Blame / history while syncing upstream |
| **YAML** (`redhat.vscode-yaml`) | Recipes / config YAML |

Optional: **Thunder Client** or **REST Client** for hitting local ACP HTTP endpoints.

## Project map

```
crates/goose*     # agent core, CLI, MCP, local inference
ui/desktop/       # Electron Achilles UI (rebranding in progress)
CUSTOM_DISTROS.md # upstream guide for white-label forks (still useful)
LICENSING.md      # how Apache + proprietary licenses layer
AGENTS.md         # instructions for coding agents working in this repo
```

## Status

Early fork. Branding to Achilles has started (UI product name, prompts, English strings). Arrav Liquid AI integration and full rename of internal `goose` identifiers are planned next.

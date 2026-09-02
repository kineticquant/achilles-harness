# Achilles

**Achilles** is a local agent harness: a native desktop app (Rust core, Electron shell) that runs tools, talks to models, and includes AppSec scanning as a first-class technical preview.

## Install

Download a desktop installer from [GitHub Releases](https://github.com/kineticquant/achilles-harness/releases):

| Platform | Artifact |
|----------|----------|
| Windows | `AchillesSetup.exe` |
| macOS | `.dmg` |
| Linux | `.deb`, `.rpm`, or `.flatpak` |

Installers are built on GitHub-hosted runners and are **unsigned**. Windows SmartScreen and macOS Gatekeeper warnings are expected on a technical preview.

After install, open Achilles, configure a model if onboarding asks, then **Findings** → choose a workspace → scan.

## Preview

<p align="center">
  <img src="docs/images/preview-home.jpg" alt="Achilles home: New Chat with Scan my repo" width="48%" />
  <img src="docs/images/preview-scan-findings.png" alt="Achilles scan: findings list with code snippets" width="48%" />
</p>
<p align="center">
  <img src="docs/images/preview-ask-finding.png" alt="Achilles scan: asking about a DOM XSS finding" width="48%" />
  <img src="docs/images/preview-explain-finding.png" alt="Achilles chat: explanation and remediation for a DOM XSS sink" width="48%" />
</p>

## Findings

The desktop app scans a workspace and writes results to a local ledger (`achilles.db`). You can scan the full tree or git-changed files.

**Fast** runs engines only. **Investigate** and **deep** then run an agent loop on ledger ids — the model does not invent findings.

Coverage includes leaked secrets (and local git history on a full-tree scan), SAST-lite on tagged languages, deploy/CI/IaC surfaces, and SCA (lockfiles → OSV, plus pinning and hygiene). Optional intel uses env vars when you set them (Socket, NVD, and similar). Achilles does not apply patches: copy a finding brief or use Tools / MCP and fix the code in your editor.

This is a technical preview, not a finished scanner product.

## Build from source

From the repo root (Git Bash on Windows):

```bash
./start-desktop.sh
```

Or double-click `start-desktop.cmd`. The first run compiles the CLI (several minutes). Later runs reuse that binary unless you pass `--rebuild`. `--help` lists `--debug`, `--skip-build`, and `--full`.

When the window opens: pick a model if onboarding asks → **Findings** → **Choose workspace** → `examples/achilles-scan-fixture` → **Scan my repo**.

### Prerequisites

- [Rust](https://rustup.rs/) (see `rust-version` in the root `Cargo.toml`)
- C/C++ toolchain (MSVC Build Tools on Windows)
- Node.js + pnpm (Hermit can provide these)
- Git

Hermit (recommended):

```bash
source ./bin/activate-hermit
cargo build --release -p goose-cli --bin goose
```

Desktop:

```bash
cd ui/desktop
pnpm install
pnpm run start-gui
```

Or from the repo root with [just](https://github.com/casey/just):

```bash
just run-ui        # release CLI, then Electron
just run-ui-only   # UI only (CLI binary already in place)
```

The desktop app launches a bundled CLI binary (`goose` internally) over ACP.

Python-oriented install notes: [requirement-guidance.html](requirement-guidance.html).

## CLI (CI / headless)

The CLI binary is still named `goose`:

```bash
goose appsec scan --path examples/achilles-scan-fixture
goose appsec query --path examples/achilles-scan-fixture
```

`quick` (default) walks the tree. `--mode diff` limits secrets/SAST/surfaces to git-changed files; SCA still reads lockfiles.

Synthetic example trees (documentation-shaped values only, not real credentials): `examples/achilles-scan-fixture/` and `examples/achilles-fixtures/`.

## Tests

```bash
cargo test
cargo fmt
cargo clippy --all-targets -- -D warnings
cd ui/desktop && pnpm run typecheck && pnpm test
```

## License and upstream

Apache 2.0. Details: [LICENSING.md](LICENSING.md).

Achilles was built on [goose](https://github.com/aaif-goose/goose). To sync:

```bash
git fetch upstream
git log HEAD..upstream/main --oneline
```

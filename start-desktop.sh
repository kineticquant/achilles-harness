#!/usr/bin/env bash
# Launch the Achilles desktop app. Builds the goose CLI the UI talks to if needed.
# Usage (from repo root, Git Bash on Windows is fine):
#   ./start-desktop.sh
#   ./start-desktop.sh --rebuild    # force a Rust rebuild
#   ./start-desktop.sh --debug      # faster compile, slower runtime
#   ./start-desktop.sh --skip-build # UI only; fail if the CLI binary is missing

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PROFILE="release"
REBUILD=0
SKIP_BUILD=0
# Default features skip llama/local-inference. That path needs extra native
# toolchains and is not required to scan from Findings with a cloud model.
CARGO_FEATURES="${CARGO_FEATURES:-rustls-tls,system-keyring}"

usage() {
  cat <<'EOF'
Start the Achilles desktop app (Electron). Compiles the CLI the first time.

  ./start-desktop.sh              build if missing, then open the app
  ./start-desktop.sh --rebuild    rebuild the CLI, then open the app
  ./start-desktop.sh --debug      debug CLI (faster compile)
  ./start-desktop.sh --skip-build open the app only (binary must already exist)
  ./start-desktop.sh --full       try default cargo features (includes local model)

Then in the app: pick a model if asked → Findings → Choose workspace →
examples/achilles-scan-fixture → Scan my repo.
EOF
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing $1. $2" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --rebuild) REBUILD=1 ;;
    --debug) PROFILE="debug" ;;
    --skip-build) SKIP_BUILD=1 ;;
    --full) CARGO_FEATURES="" ;;
    *)
      echo "Unknown flag: $1 (try --help)" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ -f "$ROOT/bin/activate-hermit" ]]; then
  # Hermit pins Node/pnpm/Rust when present. Safe to no-op if already active.
  # shellcheck disable=SC1091
  source "$ROOT/bin/activate-hermit" 2>/dev/null || true
fi

is_windows() {
  case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) return 0 ;;
    *) return 1 ;;
  esac
}

cli_name="goose"
if is_windows; then
  cli_name="goose.exe"
fi

dest_dir="$ROOT/ui/desktop/src/bin"
dest="$dest_dir/$cli_name"

find_built_cli() {
  local candidates=(
    "$ROOT/target/$PROFILE/$cli_name"
    "$ROOT/target/x86_64-pc-windows-msvc/$PROFILE/$cli_name"
    "$ROOT/target/aarch64-pc-windows-msvc/$PROFILE/$cli_name"
    "$ROOT/target/$PROFILE/goose"
    "$dest"
  )
  local p
  for p in "${candidates[@]}"; do
    if [[ -f "$p" ]]; then
      echo "$p"
      return 0
    fi
  done
  return 1
}

copy_cli() {
  local src
  src="$(find_built_cli)" || {
    echo "Could not find $cli_name after the build." >&2
    echo "Looked in target/$PROFILE and ui/desktop/src/bin." >&2
    exit 1
  }
  mkdir -p "$dest_dir"
  if [[ "$src" != "$dest" ]]; then
    cp -f "$src" "$dest"
  fi
  if is_windows; then
    cp -f "$dest" "$dest_dir/achilles.exe"
  else
    cp -f "$dest" "$dest_dir/achilles"
    chmod +x "$dest_dir/achilles"
  fi
  echo "CLI binary: $dest"
}

if [[ "$SKIP_BUILD" -eq 1 ]]; then
  if ! find_built_cli >/dev/null; then
    echo "No CLI binary yet. Run without --skip-build so it can compile." >&2
    exit 1
  fi
  copy_cli
else
  existing="$(find_built_cli || true)"
  if [[ "$REBUILD" -eq 1 || -z "$existing" ]]; then
    need cargo "Install Rust from https://rustup.rs then reopen this terminal."
    echo "Compiling Achilles CLI ($PROFILE). First time can take several minutes."
    cargo_args=(-p goose-cli --bin goose)
    if [[ "$PROFILE" == "release" ]]; then
      cargo_args=(--release "${cargo_args[@]}")
    fi
    if [[ -n "$CARGO_FEATURES" ]]; then
      cargo build "${cargo_args[@]}" --no-default-features --features "$CARGO_FEATURES"
    else
      cargo build "${cargo_args[@]}"
    fi
  else
    echo "Using existing CLI at $existing (pass --rebuild to compile again)."
  fi
  copy_cli
fi

need node "Install Node 24 from https://nodejs.org or run: source ./bin/activate-hermit"
if ! command -v pnpm >/dev/null 2>&1; then
  if command -v corepack >/dev/null 2>&1; then
    corepack enable >/dev/null 2>&1 || true
    corepack prepare pnpm@latest --activate >/dev/null 2>&1 || true
  fi
fi
need pnpm "Install pnpm: npm install -g pnpm   (or: source ./bin/activate-hermit)"

echo "Starting Achilles desktop…"
echo "When it opens: Findings → Choose workspace → examples/achilles-scan-fixture → Scan my repo."
cd "$ROOT/ui/desktop"
pnpm install
exec pnpm run start-gui

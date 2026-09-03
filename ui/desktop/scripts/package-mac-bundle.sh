#!/usr/bin/env bash
# After `electron-forge package`, build an unsigned .dmg with hdiutil (no appdmg)
# and a zip next to the .app. Usage: package-mac-bundle.sh arm64|x64
set -euo pipefail

arch="${1:-arm64}"
bundle_name="${GOOSE_BUNDLE_NAME:-Achilles}"
dmg_stem="${ACHILLES_DMG_NAME:-Achilles}"

if [[ "$arch" == "x64" ]]; then
  app_dir="out/${bundle_name}-darwin-x64"
  zip_name="${bundle_name}_intel_mac.zip"
else
  app_dir="out/${bundle_name}-darwin-arm64"
  zip_name="${bundle_name}.zip"
fi

app="${app_dir}/${bundle_name}.app"

if [[ ! -d "$app" ]]; then
  echo "Expected app bundle missing: $app"
  echo "=== out/ ==="
  find out -maxdepth 3 -type d 2>/dev/null || true
  find out -name '*.app' 2>/dev/null || true
  exit 1
fi

mkdir -p out/make
dmg="out/make/${dmg_stem}.dmg"
rm -f "$dmg"

hdiutil create -volname "Achilles" -srcfolder "$app" -ov -format UDZO "$dmg"
ls -la "$dmg"

(
  cd "$app_dir"
  ditto -c -k --sequesterRsrc --keepParent "${bundle_name}.app" "$zip_name"
)

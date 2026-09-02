#!/usr/bin/env sh
# Rebuild window / taskbar / tray icons from the Odyssey lambda mark.
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 build_icons.py
else
  python build_icons.py
fi

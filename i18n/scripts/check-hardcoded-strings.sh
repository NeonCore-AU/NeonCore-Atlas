#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "Checking for suspicious hard-coded user-visible strings..."
rg -n 'Text\("[A-Z][^"]+"|Button\("[A-Z][^"]+"|TextBlock Text="[A-Z][^"]+"|Label::new\(Some\("[A-Z][^"]+"' "$ROOT/apps" "$ROOT/crates" || true
echo "Placeholder check complete. Review matches manually."

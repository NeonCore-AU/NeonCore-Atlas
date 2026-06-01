#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MACOS_DIR="$ROOT/apps/macos"
BUILD_DIR="$MACOS_DIR/.build/arm64-apple-macosx/debug"
APP="$BUILD_DIR/NeonCore Atlas.app"

cd "$MACOS_DIR"
swift build

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BUILD_DIR/AtlasMacApp" "$APP/Contents/MacOS/AtlasMacApp"
cp -R "$BUILD_DIR/AtlasMacApp_AtlasMacApp.bundle" "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>AtlasMacApp</string>
    <key>CFBundleIdentifier</key>
    <string>dev.neoncore.atlas.macos</string>
    <key>CFBundleName</key>
    <string>NeonCore Atlas</string>
    <key>CFBundleDisplayName</key>
    <string>NeonCore Atlas</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>15.0</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
</dict>
</plist>
PLIST

open "$APP"

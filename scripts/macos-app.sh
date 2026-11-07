#!/usr/bin/env bash
# Build FreedomDesk.app around a release binary (macOS). Unsigned apart from an
# ad-hoc signature, which Apple Silicon requires to launch.
# Usage: scripts/macos-app.sh target/release/freedomdesk dist/
set -euo pipefail
bin=$1 out=$2
version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
build=${GITHUB_RUN_NUMBER:-0}
app="$out/FreedomDesk.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/freedomdesk"
sed -e "s/@VERSION@/$version/" -e "s/@BUILD@/$build/" packaging/macos/Info.plist > "$app/Contents/Info.plist"
printf 'APPL????' > "$app/Contents/PkgInfo"
plutil -lint "$app/Contents/Info.plist"
codesign --force --sign - "$app"
codesign --verify --verbose "$app"
(cd "$out" && ditto -c -k --keepParent FreedomDesk.app FreedomDesk-macos-aarch64.app.zip && rm -rf FreedomDesk.app)

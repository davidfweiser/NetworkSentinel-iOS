#!/usr/bin/env bash
# Build a portable, self-contained install tarball for macOS.
# Usage:
#   ./scripts/package.sh              # osx-arm64 (Apple Silicon default)
#   ./scripts/package.sh osx-x64      # Intel Macs
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.dotnet:${PATH}"
export DOTNET_ROOT="${DOTNET_ROOT:-${HOME}/.dotnet}"

ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then
  DEFAULT_RID="osx-arm64"
else
  DEFAULT_RID="osx-x64"
fi

RID="${1:-$DEFAULT_RID}"
case "$RID" in
  osx-arm64|osx-x64) ;;
  *)
    echo "Unsupported RID: $RID" >&2
    echo "Use: osx-arm64 | osx-x64" >&2
    exit 1
    ;;
esac

VERSION="$(grep -E '<Version>' NetworkSentinel.csproj | sed -E 's/.*<Version>([^<]+)<.*/\1/' | head -1)"
VERSION="${VERSION:-0.0.0}"
NAME="networksentinel-${VERSION}-${RID}"
DIST_DIR="${ROOT}/dist"
STAGE="${DIST_DIR}/${NAME}"
PUBLISH_DIR="${STAGE}/app"
OUT_TGZ="${DIST_DIR}/${NAME}.tar.gz"

echo "==> Network Sentinel ${VERSION}  RID=${RID}"
echo "==> Staging: ${STAGE}"

rm -rf "$STAGE"
mkdir -p "$PUBLISH_DIR"

echo "==> Publishing self-contained binary (no .NET runtime needed on target)…"
dotnet publish NetworkSentinel.csproj \
  -c Release \
  -r "$RID" \
  --self-contained true \
  -p:PublishSingleFile=false \
  -p:PublishReadyToRun=true \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -o "$PUBLISH_DIR"

chmod +x "$PUBLISH_DIR/NetworkSentinel"

cp "$ROOT/scripts/install-from-package.sh" "$STAGE/install.sh"
cp "$ROOT/scripts/uninstall-from-package.sh" "$STAGE/uninstall.sh"
chmod +x "$STAGE/install.sh" "$STAGE/uninstall.sh"

# Certificate helper travels with the package: Settings → Remote access shells out
# to it for the "Issue certificate" button, and an installed copy has no source tree.
cp "$ROOT/scripts/issue-duckdns-cert.sh" "$STAGE/issue-duckdns-cert.sh"
cp "$ROOT/scripts/issue-duckdns-cert.sh" "$PUBLISH_DIR/issue-duckdns-cert.sh"
chmod +x "$STAGE/issue-duckdns-cert.sh" "$PUBLISH_DIR/issue-duckdns-cert.sh"

# --- App bundle --------------------------------------------------------------
# install.sh builds the bundle on the target so it lands with the right paths,
# but the icon is rasterised here: sips and iconutil are the only part of the
# job that wants the source Assets, which the package does not carry.
cp "$ROOT/scripts/make-app-bundle.sh" "$STAGE/make-app-bundle.sh"
chmod +x "$STAGE/make-app-bundle.sh"
echo "$VERSION" > "$STAGE/VERSION"

echo "==> Building app bundle…"
APP_BUNDLE="${DIST_DIR}/Network Sentinel.app"
"$ROOT/scripts/make-app-bundle.sh" \
  --payload "$PUBLISH_DIR" \
  --out "$APP_BUNDLE" \
  --version "$VERSION" \
  --icon "$ROOT/Assets/icons/icon-512.png" \
  --helper "$ROOT/scripts/issue-duckdns-cert.sh"

# Reuse the icon just built rather than rasterising it a second time on install.
if [[ -f "${APP_BUNDLE}/Contents/Resources/AppIcon.icns" ]]; then
  cp "${APP_BUNDLE}/Contents/Resources/AppIcon.icns" "$STAGE/AppIcon.icns"
fi

cat > "$STAGE/README-INSTALL.txt" <<EOF
Network Sentinel ${VERSION} (${RID})
====================================

Self-contained package — no .NET SDK/runtime required on the Mac.

Quick install (system-wide, needs sudo):
  tar xzf ${NAME}.tar.gz
  cd ${NAME}
  sudo ./install.sh

Other install options:
  ./install.sh --user                        # ~/.local + ~/Applications, no root
  sudo ./install.sh --desktop-shortcut       # also put a shortcut on the Desktop
  sudo ./install.sh --no-desktop             # CLI only (headless / server)

The install puts "Network Sentinel.app" in /Applications (or ~/Applications with
--user) so it shows up in Launchpad and Spotlight, and links the same build as
the "networksentinel" command.

Run after install:
  networksentinel --tui          # terminal UI
  networksentinel                # GUI
  networksentinel --help

Uninstall:
  sudo networksentinel-uninstall
  # or:  sudo ./uninstall.sh
  # user install:  ./uninstall.sh --user

Notes:
  - Firewall IP/port blocks use macOS PF (pfctl) via an admin password dialog.
  - Settings live in ~/Library/Application Support/NetworkSentinel/
  - Do not need to run the whole app as root.
EOF

# Lightweight launcher wrapper for PATH install
cat > "$STAGE/networksentinel" <<'EOF'
#!/bin/bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec "$ROOT/app/NetworkSentinel" "$@"
EOF
chmod +x "$STAGE/networksentinel"

echo "==> Creating tarball…"
mkdir -p "$DIST_DIR"
tar -czf "$OUT_TGZ" -C "$DIST_DIR" "$NAME"
( cd "$DIST_DIR" && shasum -a 256 "$(basename "$OUT_TGZ")" > "$(basename "$OUT_TGZ").sha256" )

echo ""
echo "Done."
echo "  $OUT_TGZ"
echo "  ${OUT_TGZ}.sha256"
ls -lh "$OUT_TGZ"

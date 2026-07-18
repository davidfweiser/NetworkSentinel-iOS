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

cat > "$STAGE/README-INSTALL.txt" <<EOF
Network Sentinel ${VERSION} (${RID})
====================================

Self-contained package — no .NET SDK/runtime required on the Mac.

Quick install (system-wide, needs sudo):
  tar xzf ${NAME}.tar.gz
  cd ${NAME}
  sudo ./install.sh

User install (no root):
  ./install.sh --user

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

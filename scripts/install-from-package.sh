#!/usr/bin/env bash
# Install Network Sentinel from a staged package directory (run from package root).
set -euo pipefail

USER_INSTALL=0
if [[ "${1:-}" == "--user" ]]; then
  USER_INSTALL=1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/app"

if [[ ! -x "${APP_SRC}/NetworkSentinel" ]]; then
  echo "Missing app/NetworkSentinel — run from the extracted package directory." >&2
  exit 1
fi

if [[ "$USER_INSTALL" -eq 1 ]]; then
  LIB_DIR="${HOME}/.local/lib/networksentinel"
  BIN_DIR="${HOME}/.local/bin"
  echo "==> User install → ${LIB_DIR}"
else
  LIB_DIR="/usr/local/lib/networksentinel"
  BIN_DIR="/usr/local/bin"
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "System install needs root. Re-run with sudo, or use: ./install.sh --user" >&2
    exit 1
  fi
  echo "==> System install → ${LIB_DIR}"
fi

mkdir -p "$LIB_DIR" "$BIN_DIR"
rsync -a --delete "${APP_SRC}/" "${LIB_DIR}/"
chmod +x "${LIB_DIR}/NetworkSentinel"

# Certificate helper lives beside the binary: Settings → Remote access shells out
# to it for the "Issue certificate" button, and it has to exist after an install
# where no source tree is present.
if [[ -f "${SCRIPT_DIR}/issue-duckdns-cert.sh" ]]; then
  cp "${SCRIPT_DIR}/issue-duckdns-cert.sh" "${LIB_DIR}/issue-duckdns-cert.sh"
  chmod +x "${LIB_DIR}/issue-duckdns-cert.sh"
fi

ln -sfn "${LIB_DIR}/NetworkSentinel" "${BIN_DIR}/networksentinel"

# Uninstall helper
cat > "${BIN_DIR}/networksentinel-uninstall" <<EOF
#!/bin/bash
set -e
if [[ "${USER_INSTALL}" -eq 1 ]]; then
  rm -f "${BIN_DIR}/networksentinel" "${BIN_DIR}/networksentinel-uninstall"
  rm -rf "${LIB_DIR}"
  echo "Removed user install of Network Sentinel."
else
  if [[ "\$(id -u)" -ne 0 ]]; then
    echo "Run with sudo to uninstall system install." >&2
    exit 1
  fi
  rm -f "${BIN_DIR}/networksentinel" "${BIN_DIR}/networksentinel-uninstall"
  rm -rf "${LIB_DIR}"
  echo "Removed system install of Network Sentinel."
fi
EOF
chmod +x "${BIN_DIR}/networksentinel-uninstall"

echo "Installed: ${BIN_DIR}/networksentinel"
echo "Try:  networksentinel --help"
echo "      networksentinel --tui"

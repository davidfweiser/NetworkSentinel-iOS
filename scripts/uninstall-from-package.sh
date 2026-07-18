#!/usr/bin/env bash
# Uninstall Network Sentinel (system or --user).
set -euo pipefail

USER_INSTALL=0
if [[ "${1:-}" == "--user" ]]; then
  USER_INSTALL=1
fi

if [[ "$USER_INSTALL" -eq 1 ]]; then
  LIB_DIR="${HOME}/.local/lib/networksentinel"
  BIN_DIR="${HOME}/.local/bin"
else
  LIB_DIR="/usr/local/lib/networksentinel"
  BIN_DIR="/usr/local/bin"
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "System uninstall needs root. Re-run with sudo, or use: ./uninstall.sh --user" >&2
    exit 1
  fi
fi

rm -f "${BIN_DIR}/networksentinel" "${BIN_DIR}/networksentinel-uninstall"
rm -rf "${LIB_DIR}"
echo "Network Sentinel removed from ${LIB_DIR}"

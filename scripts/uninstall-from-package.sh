#!/usr/bin/env bash
# Uninstall Network Sentinel (system or --user).
#
# Unlike the generated networksentinel-uninstall, this one does not know which
# layout the install chose, so it clears both the app bundle and the CLI-only
# directory.
set -euo pipefail

USER_INSTALL=0
if [[ "${1:-}" == "--user" ]]; then
  USER_INSTALL=1
fi

if [[ "$USER_INSTALL" -eq 1 ]]; then
  LIB_DIR="${HOME}/.local/lib/networksentinel"
  BIN_DIR="${HOME}/.local/bin"
  APPS_DIR="${HOME}/Applications"
else
  LIB_DIR="/usr/local/lib/networksentinel"
  BIN_DIR="/usr/local/bin"
  APPS_DIR="/Applications"
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "System uninstall needs root. Re-run with sudo, or use: ./uninstall.sh --user" >&2
    exit 1
  fi
fi

BUNDLE="${APPS_DIR}/Network Sentinel.app"

rm -f "${BIN_DIR}/networksentinel" "${BIN_DIR}/networksentinel-uninstall"
rm -rf "${LIB_DIR}"

if [[ -d "${BUNDLE}/Contents/MacOS" ]]; then
  rm -rf "$BUNDLE"
  echo "Removed ${BUNDLE}"
fi

# Only remove a Desktop entry that is our own symlink — never a file someone
# put there themselves. Mirrors install.sh: the directory service is consulted
# only under sudo, where $HOME is root's.
SHORTCUT_HOME="$HOME"
if [[ -n "${SUDO_USER:-}" ]]; then
  SUDO_HOME="$(dscl . -read "/Users/${SUDO_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
  if [[ -d "${SUDO_HOME:-}" ]]; then
    SHORTCUT_HOME="$SUDO_HOME"
  fi
fi
SHORTCUT="${SHORTCUT_HOME}/Desktop/Network Sentinel"
if [[ -L "$SHORTCUT" && "$(readlink "$SHORTCUT")" == "$BUNDLE" ]]; then
  rm -f "$SHORTCUT"
  echo "Removed ${SHORTCUT}"
fi

echo "Network Sentinel removed from ${LIB_DIR}"

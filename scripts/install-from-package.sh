#!/usr/bin/env bash
# Install Network Sentinel from a staged package directory (run from package root).
set -euo pipefail

USER_INSTALL=0
NO_DESKTOP=0
DESKTOP_SHORTCUT=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Install Network Sentinel from this package.

  --user              Install under ~/.local and ~/Applications (no root)
  --no-desktop        CLI only — skip the Applications app bundle
  --desktop-shortcut  Also put a shortcut on the Desktop (opt-in; desktops only)
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_INSTALL=1; shift ;;
    --no-desktop) NO_DESKTOP=1; shift ;;
    --desktop-shortcut) DESKTOP_SHORTCUT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="${SCRIPT_DIR}/app"

if [[ ! -x "${APP_SRC}/NetworkSentinel" ]]; then
  echo "Missing app/NetworkSentinel — run from the extracted package directory." >&2
  exit 1
fi

VERSION="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo "0.0.0")"

if [[ "$USER_INSTALL" -eq 1 ]]; then
  FLAT_DIR="${HOME}/.local/lib/networksentinel"
  BIN_DIR="${HOME}/.local/bin"
  APPS_DIR="${HOME}/Applications"
  echo "==> User install"
else
  FLAT_DIR="/usr/local/lib/networksentinel"
  BIN_DIR="/usr/local/bin"
  APPS_DIR="/Applications"
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "System install needs root. Re-run with sudo, or use: ./install.sh --user" >&2
    exit 1
  fi
  echo "==> System install"
fi

BUNDLE="${APPS_DIR}/Network Sentinel.app"
MAKE_BUNDLE="${SCRIPT_DIR}/make-app-bundle.sh"
HELPER="${SCRIPT_DIR}/issue-duckdns-cert.sh"

# The app bundle is what gives Launchpad, Spotlight and the Dock something to
# show; --no-desktop keeps the flat layout, which is what a headless install
# running only `networksentinel -w` wants.
if [[ "$NO_DESKTOP" -eq 0 && -x "$MAKE_BUNDLE" ]]; then
  MODE="bundle"
else
  MODE="cli"
  if [[ "$NO_DESKTOP" -eq 0 ]]; then
    echo "  note: make-app-bundle.sh missing from the package — installing CLI only" >&2
  fi
fi

if [[ "$MODE" == "bundle" ]]; then
  mkdir -p "$APPS_DIR"
  # An array, not word-splitting a command substitution: the package directory
  # can sit under a path with spaces.
  BUNDLE_ARGS=(--payload "$APP_SRC" --out "$BUNDLE" --version "$VERSION")
  if [[ -f "${SCRIPT_DIR}/AppIcon.icns" ]]; then
    BUNDLE_ARGS+=(--icon "${SCRIPT_DIR}/AppIcon.icns")
  fi
  if [[ -f "$HELPER" ]]; then
    BUNDLE_ARGS+=(--helper "$HELPER")
  fi
  "$MAKE_BUNDLE" "${BUNDLE_ARGS[@]}"
  LIB_DIR="${BUNDLE}/Contents/MacOS"
  REMOVE_PATH="$BUNDLE"

  # An earlier --no-desktop install left a second copy that `networksentinel` no
  # longer points at; leaving it behind is how an upgrade silently keeps running
  # the old binary.
  if [[ -d "$FLAT_DIR" ]]; then
    rm -rf "$FLAT_DIR"
    echo "  replaced earlier CLI-only install at ${FLAT_DIR}"
  fi
else
  LIB_DIR="$FLAT_DIR"
  REMOVE_PATH="$FLAT_DIR"
  mkdir -p "$LIB_DIR"
  rsync -a --delete "${APP_SRC}/" "${LIB_DIR}/"
  chmod +x "${LIB_DIR}/NetworkSentinel"

  # Certificate helper lives beside the binary: Settings → Remote access shells
  # out to it for the "Issue certificate" button, and it has to exist after an
  # install where no source tree is present.
  if [[ -f "$HELPER" ]]; then
    cp "$HELPER" "${LIB_DIR}/issue-duckdns-cert.sh"
    chmod +x "${LIB_DIR}/issue-duckdns-cert.sh"
  fi
fi

mkdir -p "$BIN_DIR"
ln -sfn "${LIB_DIR}/NetworkSentinel" "${BIN_DIR}/networksentinel"

# --- Desktop shortcut (opt-in) ----------------------------------------------
# A symlink, not a Finder alias: `make alias file` goes through Finder's
# AppleScript interface, which needs an Automation grant the installer cannot
# get from a sudo shell. Finder launches a symlinked .app the same way.
SHORTCUT=""
if [[ "$DESKTOP_SHORTCUT" -eq 1 ]]; then
  if [[ "$MODE" != "bundle" ]]; then
    echo "  note: --desktop-shortcut needs the app bundle — ignored with --no-desktop" >&2
  else
    # Under sudo the icon belongs on the invoking user's Desktop; root's is not
    # where anyone would look for it. Only then is the directory service worth
    # consulting — otherwise $HOME is the answer, and honouring it keeps the
    # shortcut with the install rather than in the real account's Desktop.
    SHORTCUT_USER="$(id -un)"
    SHORTCUT_HOME="$HOME"
    if [[ -n "${SUDO_USER:-}" ]]; then
      SHORTCUT_USER="$SUDO_USER"
      SUDO_HOME="$(dscl . -read "/Users/${SUDO_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
      if [[ -d "${SUDO_HOME:-}" ]]; then
        SHORTCUT_HOME="$SUDO_HOME"
      fi
    fi
    DESKTOP_DIR="${SHORTCUT_HOME}/Desktop"
    if [[ -d "$DESKTOP_DIR" ]]; then
      SHORTCUT="${DESKTOP_DIR}/Network Sentinel"
      ln -sfn "$BUNDLE" "$SHORTCUT"
      [[ -n "${SUDO_USER:-}" ]] && chown -h "$SUDO_USER" "$SHORTCUT" 2>/dev/null || true
      echo "  shortcut: ${SHORTCUT}"
    else
      echo "  note: no Desktop directory for ${SHORTCUT_USER} — skipped --desktop-shortcut" >&2
    fi
  fi
fi

# --- Uninstall helper --------------------------------------------------------
# Paths are baked in at install time so it removes exactly what this run wrote,
# whichever layout was chosen.
{
  echo '#!/usr/bin/env bash'
  echo '# Generated by Network Sentinel install.sh.'
  echo 'set -euo pipefail'
  if [[ "$USER_INSTALL" -eq 0 ]]; then
    echo 'if [[ "$(id -u)" -ne 0 ]]; then'
    echo '  echo "Run with sudo to uninstall the system install." >&2'
    echo '  exit 1'
    echo 'fi'
  fi
  printf 'rm -f %q %q\n' "${BIN_DIR}/networksentinel" "${BIN_DIR}/networksentinel-uninstall"
  printf 'rm -rf %q\n' "$REMOVE_PATH"
  # An `if`, not `[[ … ]] && …`: under set -e a false test as an AND-list aborts.
  if [[ -n "$SHORTCUT" ]]; then
    printf 'rm -f %q\n' "$SHORTCUT"
  fi
  echo 'echo "Network Sentinel removed."'
} > "${BIN_DIR}/networksentinel-uninstall"
chmod +x "${BIN_DIR}/networksentinel-uninstall"

echo "Installed: ${BIN_DIR}/networksentinel"
if [[ "$MODE" == "bundle" ]]; then
  echo "           ${BUNDLE}"
fi
echo "Try:  networksentinel --help"
echo "      networksentinel --tui"

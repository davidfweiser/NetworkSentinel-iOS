#!/usr/bin/env bash
# Assemble a macOS .app bundle around a published Network Sentinel payload.
#
# The payload goes *inside* Contents/MacOS rather than the bundle wrapping a
# launcher that execs a binary elsewhere. macOS finds an app's Info.plist by
# walking up from the path of the running executable, so a bundle that hands off
# to /usr/local/lib/... stops being recognised as that bundle: generic Dock icon,
# process name in the menu bar, no icon in Launchpad. Keeping the payload inside
# is also what a self-contained .NET publish expects — the runtime dylibs and
# dlls have to sit beside the binary.
#
# Used by scripts/package.sh (to produce dist/) and by install.sh in the package.
set -euo pipefail

PAYLOAD=""
OUT=""
VERSION="0.0.0"
ICON=""
HELPER=""

usage() {
  cat <<'EOF'
Usage: make-app-bundle.sh --payload DIR --out BUNDLE.app [options]

  --payload DIR    Published output containing the NetworkSentinel binary
  --out PATH       Bundle to create (replaces an existing one at that path)
  --version V      CFBundleShortVersionString / CFBundleVersion (default 0.0.0)
  --icon PATH      .icns to use as-is, or a PNG to rasterise into one
  --helper PATH    issue-duckdns-cert.sh to place in Contents/Resources
  -h, --help       Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --payload) PAYLOAD="${2:-}"; shift 2 ;;
    --out)     OUT="${2:-}";     shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --icon)    ICON="${2:-}";    shift 2 ;;
    --helper)  HELPER="${2:-}";  shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ -n "$PAYLOAD" && -n "$OUT" ]] || { usage >&2; exit 1; }
[[ -x "${PAYLOAD}/NetworkSentinel" ]] || {
  echo "No executable NetworkSentinel in ${PAYLOAD}" >&2
  exit 1
}

# Build an .icns from a single PNG. sips resizes rather than picking the closest
# packaged size, so every slot iconutil wants is present even though Assets tops
# out at 512 (the 1024 slot is upscaled — visible only on a Retina 512pt view).
build_icns() {
  local src="$1" dest="$2" tmp iconset spec px name
  command -v iconutil >/dev/null 2>&1 && command -v sips >/dev/null 2>&1 || return 1
  tmp="$(mktemp -d)"
  iconset="${tmp}/AppIcon.iconset"
  mkdir -p "$iconset"
  for spec in 16:icon_16x16 32:icon_16x16@2x 32:icon_32x32 64:icon_32x32@2x \
              128:icon_128x128 256:icon_128x128@2x 256:icon_256x256 \
              512:icon_256x256@2x 512:icon_512x512 1024:icon_512x512@2x; do
    px="${spec%%:*}"
    name="${spec##*:}"
    sips -z "$px" "$px" "$src" --out "${iconset}/${name}.png" >/dev/null 2>&1 || {
      rm -rf "$tmp"
      return 1
    }
  done
  iconutil -c icns "$iconset" -o "$dest" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
}

# Replace wholesale: writing over a live bundle leaves stale dlls from the old
# version behind and invalidates its signature halfway through.
if [[ -e "$OUT" ]]; then
  [[ -d "${OUT}/Contents/MacOS" ]] || {
    echo "Refusing to replace ${OUT} — it is not an app bundle." >&2
    exit 1
  }
  rm -rf "$OUT"
fi

mkdir -p "${OUT}/Contents/MacOS" "${OUT}/Contents/Resources"
rsync -a "${PAYLOAD}/" "${OUT}/Contents/MacOS/"
chmod +x "${OUT}/Contents/MacOS/NetworkSentinel"

ICON_KEY=""
if [[ -n "$ICON" && -f "$ICON" ]]; then
  case "$ICON" in
    *.icns) cp "$ICON" "${OUT}/Contents/Resources/AppIcon.icns" ;;
    *)      build_icns "$ICON" "${OUT}/Contents/Resources/AppIcon.icns" || true ;;
  esac
  # Only claim an icon that actually landed — a CFBundleIconFile pointing at a
  # missing file gives the blank-page icon rather than falling back gracefully.
  # An `if`, not `[[ … ]] && …`: under set -e a false test as an AND-list aborts.
  if [[ -f "${OUT}/Contents/Resources/AppIcon.icns" ]]; then
    ICON_KEY=$'\t<key>CFBundleIconFile</key>\n\t<string>AppIcon</string>'
  fi
fi

# The console's Issue certificate button shells out to this; inside a bundle,
# Resources is where CertIssuanceService.FindScript looks (../Resources from
# Contents/MacOS).
if [[ -n "$HELPER" && -f "$HELPER" ]]; then
  cp "$HELPER" "${OUT}/Contents/Resources/issue-duckdns-cert.sh"
  chmod +x "${OUT}/Contents/Resources/issue-duckdns-cert.sh"
fi

cat > "${OUT}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>Network Sentinel</string>
	<key>CFBundleExecutable</key>
	<string>NetworkSentinel</string>
${ICON_KEY}
	<key>CFBundleIdentifier</key>
	<string>com.networksentinel.app</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>Network Sentinel</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>${VERSION}</string>
	<key>CFBundleVersion</key>
	<string>${VERSION}</string>
	<key>LSMinimumSystemVersion</key>
	<string>12.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.utilities</string>
</dict>
</plist>
PLIST

printf 'APPL????' > "${OUT}/Contents/PkgInfo"

# Apple Silicon refuses to run an unsigned Mach-O at all, and copying the
# publish output invalidates the signature the SDK applied. Ad-hoc is enough for
# a locally built app; it is not distribution signing and Gatekeeper will still
# quarantine this if it is ever downloaded rather than built here.
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$OUT" >/dev/null 2>&1 \
    || echo "  note: ad-hoc code signing failed — the app may not launch on Apple Silicon" >&2
fi

echo "  bundle: ${OUT}"

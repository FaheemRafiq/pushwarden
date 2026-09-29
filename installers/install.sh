#!/bin/sh
# ThreatScan installer for macOS and Linux (the recommended route on both).
#   curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.sh | sh
# Downloads the release binary, verifies its SHA-256 against checksums.txt, and
# runs `threatscan install --unattended` (per user, no sudo). The signature on
# checksums.txt is not checked here; the binary checks it on every self-update.
#
# Environment:
#   THREATSCAN_VERSION=v0.2.0-rc1   install this release instead of the latest
#   THREATSCAN_BASE_URL=URL         download assets from URL (a directory; file:// works)
#   THREATSCAN_WEBHOOK=URL          alert webhook to configure
#   THREATSCAN_ROOTS="~/code ~/src" project dirs to watch (default: auto-discover)
#   THREATSCAN_NO_INSTALL=1         only put the program in place; do not start the guard
#   THREATSCAN_NO_BLOCK=1           do not ask for administrator rights to block the C2 servers
set -eu

REPO_URL="https://github.com/FaheemRafiq/threatscan"

say()  { printf '\033[1;36m[threatscan]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[threatscan] %s\033[0m\n' "$*" >&2; exit 1; }

if [ -n "${THREATSCAN_BASE_URL:-}" ]; then
  BASE="${THREATSCAN_BASE_URL%/}"
elif [ -n "${THREATSCAN_VERSION:-}" ]; then
  BASE="$REPO_URL/releases/download/$THREATSCAN_VERSION"
else
  BASE="$REPO_URL/releases/latest/download"
fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "Unsupported OS $(uname -s). On Windows use ThreatScan-Setup.exe from $REPO_URL/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "Unsupported CPU $(uname -m)" ;;
esac
asset="threatscan-$os-$arch"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https,file' --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    fail "Need curl or wget."
  fi
}

say "Downloading $asset from $BASE"
fetch "$BASE/checksums.txt" "$tmp/checksums.txt" || fail "Could not download checksums.txt"
fetch "$BASE/$asset" "$tmp/$asset" || fail "Could not download $asset"

want="$(awk -v n="$asset" '$2 == n || $2 == "*" n { print $1; exit }' "$tmp/checksums.txt")"
[ -n "$want" ] || fail "checksums.txt has no entry for $asset"
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  got="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
fi
[ "$got" = "$want" ] || fail "SHA-256 mismatch for $asset (got $got, want $want). Not installing."
chmod +x "$tmp/$asset"
say "Verified $("$tmp/$asset" version)"

if [ -n "${THREATSCAN_NO_INSTALL:-}" ]; then
  dir="${THREATSCAN_INSTALL_DIR:-}"
  if [ -z "$dir" ]; then
    if [ "$os" = darwin ]; then dir="$HOME/Library/Application Support/ThreatScan"; else dir="$HOME/.local/share/threatscan"; fi
  fi
  mkdir -p "$dir" "$HOME/.local/bin"
  cp "$tmp/$asset" "$dir/threatscan.new" && mv "$dir/threatscan.new" "$dir/threatscan"
  if [ ! -e "$HOME/.local/bin/threatscan" ] || [ -L "$HOME/.local/bin/threatscan" ]; then
    ln -sf "$dir/threatscan" "$HOME/.local/bin/threatscan"
  fi
  say "Installed $dir/threatscan (guard not started; run: threatscan install)"
  exit 0
fi

set --
[ -n "${THREATSCAN_WEBHOOK:-}" ] && set -- "$@" --webhook "$THREATSCAN_WEBHOOK"
for r in ${THREATSCAN_ROOTS:-}; do set -- "$@" --roots "$r"; done
"$tmp/$asset" install --unattended "$@"
say "Done.  Try:  threatscan status   (open a new terminal if the command is not found)"

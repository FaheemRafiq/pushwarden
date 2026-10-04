#!/bin/sh
# PushWarden installer for macOS and Linux (the recommended route on both).
#   curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/pushwarden/main/installers/install.sh | sh
# Downloads the release binary, verifies its SHA-256 against checksums.txt, and
# runs `pushwarden install --unattended` (per user, no sudo). The signature on
# checksums.txt is not checked here; the binary checks it on every self-update.
#
# Environment:
#   PUSHWARDEN_VERSION=v0.2.0-rc1   install this release instead of the latest
#   PUSHWARDEN_BASE_URL=URL         download assets from URL (a directory; file:// works)
#   PUSHWARDEN_WEBHOOK=URL          alert webhook to configure
#   PUSHWARDEN_FEEDBACK_URL=URL     opt in to a daily anonymised digest (counts only, no paths)
#   PUSHWARDEN_UPLOAD_URL=URL       opt in to uploading redacted events to a central table (Supabase REST)
#   PUSHWARDEN_UPLOAD_KEY=KEY       insert-only key for PUSHWARDEN_UPLOAD_URL
#   PUSHWARDEN_ROOTS="~/code ~/src" project dirs to watch (default: auto-discover)
#   PUSHWARDEN_NO_INSTALL=1         only put the program in place; do not start the guard
#   PUSHWARDEN_NO_BLOCK=1           do not ask for administrator rights to block the C2 servers
set -eu

REPO_URL="https://github.com/FaheemRafiq/pushwarden"

say()  { printf '\033[1;36m[pushwarden]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pushwarden] %s\033[0m\n' "$*" >&2; exit 1; }

if [ -n "${PUSHWARDEN_BASE_URL:-}" ]; then
  BASE="${PUSHWARDEN_BASE_URL%/}"
elif [ -n "${PUSHWARDEN_VERSION:-}" ]; then
  BASE="$REPO_URL/releases/download/$PUSHWARDEN_VERSION"
else
  BASE="$REPO_URL/releases/latest/download"
fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "Unsupported OS $(uname -s). On Windows use PushWarden-Setup.exe from $REPO_URL/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "Unsupported CPU $(uname -m)" ;;
esac
asset="pushwarden-$os-$arch"

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

if [ -n "${PUSHWARDEN_NO_INSTALL:-}" ]; then
  dir="${PUSHWARDEN_INSTALL_DIR:-}"
  if [ -z "$dir" ]; then
    if [ "$os" = darwin ]; then dir="$HOME/Library/Application Support/PushWarden"; else dir="$HOME/.local/share/pushwarden"; fi
  fi
  mkdir -p "$dir" "$HOME/.local/bin"
  cp "$tmp/$asset" "$dir/pushwarden.new" && mv "$dir/pushwarden.new" "$dir/pushwarden"
  if [ ! -e "$HOME/.local/bin/pushwarden" ] || [ -L "$HOME/.local/bin/pushwarden" ]; then
    ln -sf "$dir/pushwarden" "$HOME/.local/bin/pushwarden"
  fi
  say "Installed $dir/pushwarden (guard not started; run: pushwarden install)"
  exit 0
fi

set --
[ -n "${PUSHWARDEN_WEBHOOK:-}" ] && set -- "$@" --webhook "$PUSHWARDEN_WEBHOOK"
[ -n "${PUSHWARDEN_FEEDBACK_URL:-}" ] && set -- "$@" --feedback-url "$PUSHWARDEN_FEEDBACK_URL"
[ -n "${PUSHWARDEN_UPLOAD_URL:-}" ] && set -- "$@" --upload-url "$PUSHWARDEN_UPLOAD_URL"
[ -n "${PUSHWARDEN_UPLOAD_KEY:-}" ] && set -- "$@" --upload-key "$PUSHWARDEN_UPLOAD_KEY"
for r in ${PUSHWARDEN_ROOTS:-}; do set -- "$@" --roots "$r"; done
"$tmp/$asset" install --unattended "$@"
say "Done.  Try:  pushwarden status   (open a new terminal if the command is not found)"

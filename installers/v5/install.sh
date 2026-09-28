#!/usr/bin/env sh
# ThreatScan v5 (Python) installer for Linux and macOS. v6 uses installers/install.sh.
#   curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/v5/install.sh | sh
# Options via environment:
#   THREATSCAN_REF=main          git ref / tag to install
#   THREATSCAN_WEBHOOK=<url>     alert webhook to configure
#   THREATSCAN_ROOTS="~/code"    space-separated project dirs to watch
#   THREATSCAN_NO_INSTALL=1      only install the CLI, do not register the guard
#   THREATSCAN_BLOCK_C2=1        also run the firewall block step (asks for sudo)
set -eu

REPO="${THREATSCAN_REPO:-https://github.com/FaheemRafiq/threatscan}"
REF="${THREATSCAN_REF:-main}"
PREFIX="${THREATSCAN_PREFIX:-$HOME/.threatscan}"
VENV="$PREFIX/venv"
BIN_DIR="${THREATSCAN_BIN:-$HOME/.local/bin}"

say()  { printf '\033[1;36m[threatscan]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[threatscan] %s\033[0m\n' "$*" >&2; exit 1; }

# ── 1. Python 3.8+ ───────────────────────────────────────────────────────────
find_python() {
  for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python; do
    if command -v "$c" >/dev/null 2>&1; then
      if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
        echo "$c"; return 0
      fi
    fi
  done
  return 1
}

PY="$(find_python || true)"
if [ -z "$PY" ]; then
  OS="$(uname -s)"
  say "Python 3.8+ not found; trying to install it."
  case "$OS" in
    Darwin)
      if command -v brew >/dev/null 2>&1; then brew install python@3.12
      else say "Install Xcode Command Line Tools (xcode-select --install) or Homebrew, then re-run."; exit 1; fi ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-venv
      elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y -q python3
      elif command -v pacman >/dev/null 2>&1; then sudo pacman -Sy --noconfirm python
      elif command -v zypper >/dev/null 2>&1; then sudo zypper -n install python3
      elif command -v apk >/dev/null 2>&1; then sudo apk add python3
      else fail "Install python3 with your package manager and re-run."; fi ;;
    *) fail "Unsupported OS: $OS" ;;
  esac
  PY="$(find_python || true)"
  [ -n "$PY" ] || fail "Python still not found."
fi
say "Using $("$PY" --version 2>&1) at $(command -v "$PY")"

# ── 2. Isolated virtualenv ───────────────────────────────────────────────────
mkdir -p "$PREFIX" "$BIN_DIR"
if [ ! -x "$VENV/bin/python" ]; then
  say "Creating virtualenv in $VENV"
  "$PY" -m venv "$VENV" 2>/dev/null || {
    # Debian/Ubuntu ship venv separately
    command -v apt-get >/dev/null 2>&1 && sudo apt-get install -y -qq python3-venv && "$PY" -m venv "$VENV"
  } || fail "Could not create a virtualenv."
fi
"$VENV/bin/python" -m pip install -q --upgrade pip >/dev/null 2>&1 || true

# ── 3. Install / upgrade the package ────────────────────────────────────────
say "Installing threatscan ($REF) from $REPO"
if [ -f "$(dirname "$0")/../../pyproject.toml" ] && [ -z "${THREATSCAN_FORCE_REMOTE:-}" ]; then
  "$VENV/bin/python" -m pip install -q --upgrade "$(cd "$(dirname "$0")/../.." && pwd)"
else
  "$VENV/bin/python" -m pip install -q --upgrade "git+${REPO}.git@${REF}" 2>/dev/null || {
    say "git not available; falling back to tarball"
    TMP="$(mktemp -d)"
    curl -fsSL "${REPO}/archive/${REF}.tar.gz" -o "$TMP/ts.tgz"
    "$VENV/bin/python" -m pip install -q --upgrade "$TMP/ts.tgz"
    rm -rf "$TMP"
  }
fi
ln -sf "$VENV/bin/threatscan" "$BIN_DIR/threatscan"
say "Installed: $("$BIN_DIR/threatscan" --version)"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "NOTE: add $BIN_DIR to your PATH (e.g. echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zshrc)";;
esac

# ── 4. Harden + register the guard + first scan ──────────────────────────────
if [ -z "${THREATSCAN_NO_INSTALL:-}" ]; then
  set -- 
  [ -n "${THREATSCAN_WEBHOOK:-}" ] && set -- "$@" --webhook "$THREATSCAN_WEBHOOK"
  if [ -n "${THREATSCAN_ROOTS:-}" ]; then
    set -- "$@" --roots
    for r in $THREATSCAN_ROOTS; do set -- "$@" "$r"; done
  fi
  "$VENV/bin/threatscan" install "$@" || true
fi

if [ -n "${THREATSCAN_BLOCK_C2:-}" ]; then
  say "Blocking C2 IPs at the firewall (sudo)"
  sudo "$VENV/bin/threatscan" protect --block-c2 || true
fi

say "Done.  Try:  threatscan status"

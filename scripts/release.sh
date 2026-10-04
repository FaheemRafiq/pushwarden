#!/usr/bin/env sh
# Build release assets.
#   scripts/release.sh TAG [OUT]      binaries for every target, .deb/.rpm, checksums.txt
#   scripts/release.sh checksums OUT  (re)write OUT/checksums.txt over every file in OUT
# checksums.txt is signed (checksums.txt.sig) when PUSHWARDEN_SIGNING_KEY is set.
# Needs Go 1.24 and, for the Linux packages, nfpm on PATH.
set -eu
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.24.13}"

checksums() {
  out=$1
  ( cd "$out"
    rm -f checksums.txt checksums.txt.sig
    files=$(ls | sort)
    if command -v sha256sum >/dev/null 2>&1; then sha256sum $files; else shasum -a 256 $files; fi > checksums.txt.tmp
    mv checksums.txt.tmp checksums.txt )
  if [ -n "${PUSHWARDEN_SIGNING_KEY:-}" ]; then
    go run ./scripts/sign "$out/checksums.txt"
  else
    echo "PUSHWARDEN_SIGNING_KEY not set: checksums.txt is unsigned (self-update will refuse it)" >&2
  fi
}

if [ "${1:-}" = checksums ]; then
  checksums "${2:?usage: release.sh checksums OUT}"
  exit 0
fi

TAG=${1:?usage: release.sh TAG [OUT]}
OUT=${2:-dist}
VERSION=${TAG#v}
mkdir -p "$OUT"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  goos=${target%/*}
  goarch=${target#*/}
  name="pushwarden-$goos-$goarch"
  [ "$goos" = windows ] && name="$name.exe"
  echo "build $name"
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "$OUT/$name" ./cmd/pushwarden
done

if command -v nfpm >/dev/null 2>&1; then
  for arch in amd64 arm64; do
    for fmt in deb rpm; do
      echo "package pushwarden-linux-$arch.$fmt"
      cfg=$(mktemp)
      sed -e "s|@ARCH@|$arch|" -e "s|@VERSION@|$VERSION|" -e "s|@BINARY@|$OUT/pushwarden-linux-$arch|" \
        installers/linux/nfpm.yaml > "$cfg"
      nfpm package --config "$cfg" --packager "$fmt" --target "$OUT/pushwarden-linux-$arch.$fmt"
      rm -f "$cfg"
    done
  done
else
  echo "nfpm not found: skipping .deb/.rpm" >&2
fi

checksums "$OUT"

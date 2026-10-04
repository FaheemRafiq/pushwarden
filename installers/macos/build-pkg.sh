#!/bin/sh
# Build PushWarden.pkg (universal binary, installs into the user's home folder).
#   installers/macos/build-pkg.sh VERSION DIST
# Needs pushwarden-darwin-amd64 and pushwarden-darwin-arm64 in DIST. Run on macOS.
set -eu
VERSION=${1:?usage: build-pkg.sh VERSION DIST}
DIST=${2:?usage: build-pkg.sh VERSION DIST}
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/root"
lipo -create -output "$work/root/pushwarden" "$DIST/pushwarden-darwin-amd64" "$DIST/pushwarden-darwin-arm64"
chmod 755 "$work/root/pushwarden"
"$work/root/pushwarden" version

# With the currentUserHome domain, this location is inside the user's home:
# ~/Library/Application Support/PushWarden, which is platform.InstallDir().
pkgbuild --root "$work/root" --install-location "/Library/Application Support/PushWarden" \
  --identifier com.pushwarden.pkg --version "$VERSION" --scripts "$here/scripts" \
  "$work/pushwarden-component.pkg"
sed "s/@VERSION@/$VERSION/" "$here/distribution.xml" > "$work/distribution.xml"
productbuild --distribution "$work/distribution.xml" --package-path "$work" "$DIST/PushWarden.pkg"
echo "built $DIST/PushWarden.pkg"

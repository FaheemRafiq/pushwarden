#!/bin/sh
# Build ThreatScan.pkg (universal binary, installs into the user's home folder).
#   installers/macos/build-pkg.sh VERSION DIST
# Needs threatscan-darwin-amd64 and threatscan-darwin-arm64 in DIST. Run on macOS.
set -eu
VERSION=${1:?usage: build-pkg.sh VERSION DIST}
DIST=${2:?usage: build-pkg.sh VERSION DIST}
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/root"
lipo -create -output "$work/root/threatscan" "$DIST/threatscan-darwin-amd64" "$DIST/threatscan-darwin-arm64"
chmod 755 "$work/root/threatscan"
"$work/root/threatscan" version

# With the currentUserHome domain, this location is inside the user's home:
# ~/Library/Application Support/ThreatScan, which is platform.InstallDir().
pkgbuild --root "$work/root" --install-location "/Library/Application Support/ThreatScan" \
  --identifier com.threatscan.pkg --version "$VERSION" --scripts "$here/scripts" \
  "$work/threatscan-component.pkg"
sed "s/@VERSION@/$VERSION/" "$here/distribution.xml" > "$work/distribution.xml"
productbuild --distribution "$work/distribution.xml" --package-path "$work" "$DIST/ThreatScan.pkg"
echo "built $DIST/ThreatScan.pkg"

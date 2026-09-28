#!/usr/bin/env sh
# Build a single-file, zero-dependency zipapp: dist/threatscan.pyz
# Run with:  python3 threatscan.pyz scan --home
set -eu
cd "$(dirname "$0")/.."
rm -rf build/pyz dist && mkdir -p build/pyz dist
cp -r threatscan build/pyz/
find build/pyz -name '__pycache__' -type d -exec rm -rf {} +
python3 -m zipapp build/pyz -m "threatscan.cli:main" -o dist/threatscan.pyz -p "/usr/bin/env python3" -c
python3 dist/threatscan.pyz --version
sha256sum dist/threatscan.pyz > dist/threatscan.pyz.sha256 2>/dev/null || shasum -a 256 dist/threatscan.pyz > dist/threatscan.pyz.sha256
echo "built dist/threatscan.pyz"

#!/usr/bin/env sh
# Compare the Python v5 and Go v6 scanners: same (category, severity, path) set.
#   scripts/parity.sh [DIR ...]     default: the inert fixtures, plus ~/Coding if it exists
# Exit 1 when any set differs.  Needs python3 and Go 1.24.
set -eu
cd "$(dirname "$0")/.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.24.13}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
# isolate both builds from the user's config, reports and decisions
export THREATSCAN_HOME="$work/home"

go build -o "$work/threatscan" ./cmd/threatscan

if [ $# -eq 0 ]; then
  go run ./scripts/fixtures "$work/fixtures"
  set -- "$work/fixtures"
  [ -d "$HOME/Coding" ] && set -- "$@" "$HOME/Coding"
fi

status=0
for dir in "$@"; do
  echo "== $dir"
  python3 threat_scanner.py scan --ci --no-system --no-report --no-prompt --json "$work/py.json" "$dir" >/dev/null || true
  "$work/threatscan" scan --ci --no-system --no-report --no-prompt --json "$work/go.json" "$dir" >/dev/null || true
  python3 - "$work/py.json" "$work/go.json" <<'PY' || status=1
import json, sys
def load(p):
    return {(f["category"], f["severity"], f.get("path") or "") for f in json.load(open(p, encoding="utf-8"))["findings"]}
py, go = load(sys.argv[1]), load(sys.argv[2])
for label, s in (("only python", py - go), ("only go", go - py)):
    for c, sev, p in sorted(s):
        print(f"  {label:<12} {sev:<8} {c:<24} {p}")
print(f"  python {len(py)}, go {len(go)}, common {len(py & go)}")
sys.exit(0 if py == go else 1)
PY
done
exit $status

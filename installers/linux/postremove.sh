#!/bin/sh
# Runs as root when the .deb/.rpm is removed (not on upgrade): drop the
# system-wide C2 block and its timer. Never fails the package.
if [ "${1:-}" = "upgrade" ] || [ "${1:-}" = "1" ]; then
  exit 0
fi
BIN=/usr/lib/threatscan/threatscan
[ -x "$BIN" ] && "$BIN" protect --uninstall >/dev/null 2>&1
rm -f /etc/systemd/system/threatscan-netblock.service /etc/systemd/system/threatscan-netblock.timer
systemctl daemon-reload >/dev/null 2>&1 || true
exit 0

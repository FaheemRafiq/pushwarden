#!/bin/sh
# Runs as root after the .deb/.rpm is installed or upgraded. The guard is per
# user, so register it for the user who ran sudo/pkexec. Never fails the package.
BIN=/usr/lib/threatscan/threatscan

# System-wide C2 block (firewall + hosts), kept across reboots by a systemd timer.
if [ "$(id -u)" = 0 ]; then
  "$BIN" protect --install >/dev/null 2>&1 || echo "ThreatScan: C2 blocking not enabled; run:  sudo $BIN protect --install"
fi

user="${SUDO_USER:-}"
if [ -z "$user" ] && [ -n "${PKEXEC_UID:-}" ]; then
  user=$(id -nu "$PKEXEC_UID" 2>/dev/null || true)
fi
if [ -z "$user" ] || [ "$user" = root ]; then
  echo "ThreatScan installed. Each user to protect runs:  $BIN install"
  exit 0
fi

uid=$(id -u "$user")
home=$(getent passwd "$user" | cut -d: -f6)
# systemctl --user needs the user's runtime dir and bus
if runuser -u "$user" -- env HOME="$home" USER="$user" XDG_RUNTIME_DIR="/run/user/$uid" THREATSCAN_NO_BLOCK=1 \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" "$BIN" install --unattended; then
  echo "ThreatScan is protecting $user. Status:  threatscan status"
else
  echo "ThreatScan: automatic setup for $user failed. As $user, run:  $BIN install"
fi
exit 0

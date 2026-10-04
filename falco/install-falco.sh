#!/usr/bin/env bash
# Optional Linux add-on: kernel-level runtime blocking with Falco.
# Installs the PolinRider rule set, the kill/alert response handler and a
# per-user desktop notifier.  Requires Falco (https://falco.org/docs/install-operate/installation/).
#   sudo bash falco/install-falco.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
command -v falco >/dev/null || { echo "Falco is not installed. See https://falco.org/docs/install-operate/installation/"; exit 1; }
command -v jq >/dev/null || { echo "jq is required (dnf/apt install jq)"; exit 1; }

install -m 644 "$HERE/polinrider.rules.yaml" /etc/falco/rules.d/pushwarden-polinrider.yaml
install -m 755 "$HERE/falco-response.sh" /usr/local/bin/pushwarden-falco-response.sh
install -m 755 "$HERE/pushwarden-falco-notify.sh" /usr/local/bin/pushwarden-falco-notify.sh
mkdir -p /etc/falco/config.d
cat > /etc/falco/config.d/90-pushwarden.yaml <<'YAML'
json_output: true
json_include_output_property: true
json_include_tags_property: true
program_output:
  enabled: true
  keep_alive: false
  program: "/usr/local/bin/pushwarden-falco-response.sh"
YAML
touch /var/log/falco-notify.queue && chmod 644 /var/log/falco-notify.queue
systemctl restart falco 2>/dev/null || systemctl restart falco-modern-bpf 2>/dev/null || true

# per-user notifier for the invoking user
U="${SUDO_USER:-}"
if [ -n "$U" ]; then
  UH="$(getent passwd "$U" | cut -d: -f6)"
  mkdir -p "$UH/.config/systemd/user"
  cat > "$UH/.config/systemd/user/pushwarden-falco-notify.service" <<UNIT
[Unit]
Description=PushWarden Falco desktop notification watcher
[Service]
ExecStart=/usr/local/bin/pushwarden-falco-notify.sh
Restart=on-failure
RestartSec=2
[Install]
WantedBy=default.target
UNIT
  chown -R "$U" "$UH/.config/systemd/user"
  sudo -u "$U" XDG_RUNTIME_DIR="/run/user/$(id -u "$U")" systemctl --user daemon-reload || true
  sudo -u "$U" XDG_RUNTIME_DIR="/run/user/$(id -u "$U")" systemctl --user enable --now pushwarden-falco-notify.service || true
fi
echo "Falco add-on installed. Test rules:  sudo falco --dry-run  |  Logs: /var/log/pushwarden-falco.log"

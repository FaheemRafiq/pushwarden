#!/usr/bin/env bash
# Falco program_output handler for the PushWarden PolinRider rule set.
#
# Falco (running as root) pipes each alert as one JSON line to this script.
# Rules tagged "kill" in polinrider.rules.yaml are Tier 1: the offending
# process is killed immediately.  Everything else is alert-only.  Every alert
# is appended to /var/log/falco-notify.queue, which the per-user
# pushwarden-falco-notify service tails to raise desktop notifications.
#
# Configure in /etc/falco/falco.yaml (or a drop-in under config.d/):
#   json_output: true
#   program_output:
#     enabled: true
#     keep_alive: false
#     program: "/usr/local/bin/pushwarden-falco-response.sh"
set -u
QUEUE=/var/log/falco-notify.queue
LOG=/var/log/pushwarden-falco.log
touch "$QUEUE" "$LOG"; chmod 644 "$QUEUE"

while IFS= read -r line; do
  [ -z "$line" ] && continue
  rule=$(jq -r '.rule // empty' <<<"$line")
  prio=$(jq -r '.priority // empty' <<<"$line")
  pid=$(jq -r '.output_fields["proc.pid"] // empty' <<<"$line")
  cmd=$(jq -r '.output_fields["proc.cmdline"] // empty' <<<"$line")
  tags=$(jq -r '(.tags // []) | join(",")' <<<"$line")
  action="alert"
  if [[ ",$tags," == *",kill,"* && -n "$pid" && "$pid" != "1" ]]; then
    if kill -9 "$pid" 2>/dev/null; then action="killed pid $pid"; else action="kill failed pid $pid"; fi
  fi
  echo "$(date '+%F %T') [$prio] $rule ($action) :: ${cmd:0:200}" >> "$LOG"
  jq -cn --arg t "PushWarden/Falco: $rule" --arg m "$action :: ${cmd:0:160}" '{title:$t,message:$m}' >> "$QUEUE"
done

#!/usr/bin/env bash
# Per-user notifier: tails the queue the root-side response script writes and
# raises a desktop notification for each alert (runs inside the login session,
# so DBus just works).
set -u
QUEUE=/var/log/falco-notify.queue
while [[ ! -r "$QUEUE" ]]; do sleep 2; done
tail -n0 -F "$QUEUE" | while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  title=$(jq -r '.title // empty' <<<"$line" 2>/dev/null); msg=$(jq -r '.message // empty' <<<"$line" 2>/dev/null)
  [[ -z "$title" ]] && continue
  notify-send --urgency=critical --expire-time=20000 --app-name=PushWarden "$title" "$msg"
done

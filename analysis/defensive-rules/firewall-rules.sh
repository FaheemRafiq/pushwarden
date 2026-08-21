#!/bin/bash
# Block known Lazarus C2 IPs
# Usage: sudo bash firewall-rules.sh [block|unblock|status]

set -euo pipefail

C2_IPS=(
    "166.88.54.158"
    "198.105.127.210"
    "23.27.202.27"
    "154.91.0.103"
    "136.0.9.8"
    "166.88.4.2"
    "23.27.120.142"
    "202.155.8.173"
    "166.88.134.82"
    "188.43.33.249"
)

CHAIN_NAME="LAZARUS_BLOCK"

block() {
    echo "[*] Creating iptables chain: $CHAIN_NAME"
    iptables -N "$CHAIN_NAME" 2>/dev/null || true

    for ip in "${C2_IPS[@]}"; do
        if ! iptables -C "$CHAIN_NAME" -d "$ip" -j DROP 2>/dev/null; then
            iptables -A "$CHAIN_NAME" -d "$ip" -j DROP
            echo "  Blocked: $ip"
        else
            echo "  Already blocked: $ip"
        fi
    done

    if ! iptables -C OUTPUT -j "$CHAIN_NAME" 2>/dev/null; then
        iptables -I OUTPUT 1 -j "$CHAIN_NAME"
        echo "[*] Chain attached to OUTPUT"
    fi

    echo "[+] All Lazarus C2 IPs blocked"
    echo "[+] Rules persisted with: iptables-save > /etc/iptables/rules.v4"
}

unblock() {
    echo "[*] Removing iptables rules..."
    iptables -D OUTPUT -j "$CHAIN_NAME" 2>/dev/null || true
    iptables -F "$CHAIN_NAME" 2>/dev/null || true
    iptables -X "$CHAIN_NAME" 2>/dev/null || true
    echo "[+] All Lazarus C2 rules removed"
}

status() {
    echo "[*] Current Lazarus C2 block rules:"
    iptables -L "$CHAIN_NAME" -n -v 2>/dev/null || echo "  Chain not found (rules not active)"
    echo ""
    echo "[*] Blocked IPs:"
    for ip in "${C2_IPS[@]}"; do
        if iptables -C "$CHAIN_NAME" -d "$ip" -j DROP 2>/dev/null; then
            echo "  [BLOCKED] $ip"
        else
            echo "  [OPEN]    $ip"
        fi
    done
}

case "${1:-status}" in
    block)   block ;;
    unblock) unblock ;;
    status)  status ;;
    *)
        echo "Usage: $0 [block|unblock|status]"
        exit 1
        ;;
esac

#!/usr/bin/env python3
"""
Cross-platform Lazarus C2 IP Blocker
Supports: Linux (iptables), macOS (pf), Windows (netsh)

Usage:
    python3 block-c2.py block
    python3 block-c2.py unblock
    python3 block-c2.py status
"""

import subprocess
import sys
import platform
import os

C2_IPS = [
    "166.88.54.158",
    "198.105.127.210",
    "23.27.202.27",
    "154.91.0.103",
    "136.0.9.8",
    "166.88.4.2",
    "23.27.120.142",
    "202.155.8.173",
    "166.88.134.82",
    "188.43.33.249",
]

CHAIN_NAME = "LAZARUS_BLOCK"
PF_ANCHOR = "com.apple.lazarus_block"
HOSTS_FILE = "/etc/hosts" if platform.system() != "Windows" else r"C:\Windows\System32\drivers\etc\hosts"


def run(cmd, check=False):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if check and r.returncode != 0:
            return None
        return r.stdout.strip()
    except Exception:
        return None


# ── Linux ──────────────────────────────────────────────────────────────

def linux_block():
    run(f"iptables -N {CHAIN_NAME} 2>/dev/null", check=True)
    for ip in C2_IPS:
        out = run(f"iptables -C {CHAIN_NAME} -d {ip} -j DROP 2>/dev/null")
        if out is None:
            run(f"iptables -A {CHAIN_NAME} -d {ip} -j DROP")
            print(f"  Blocked: {ip}")
        else:
            print(f"  Already blocked: {ip}")
    out = run(f"iptables -C OUTPUT -j {CHAIN_NAME} 2>/dev/null")
    if out is None:
        run(f"iptables -I OUTPUT 1 -j {CHAIN_NAME}")
    print("[+] All C2 IPs blocked via iptables")


def linux_unblock():
    run(f"iptables -D OUTPUT -j {CHAIN_NAME} 2>/dev/null")
    run(f"iptables -F {CHAIN_NAME} 2>/dev/null")
    run(f"iptables -X {CHAIN_NAME} 2>/dev/null")
    print("[+] iptables rules removed")


def linux_status():
    out = run(f"iptables -L {CHAIN_NAME} -n 2>/dev/null")
    if out:
        print(out)
    else:
        print("  Chain not found (rules not active)")


# ── macOS ──────────────────────────────────────────────────────────────

def macos_block():
    rules = "# Lazarus C2 Block Rules\n"
    for ip in C2_IPS:
        rules += f"block drop from any to {ip}\n"

    pf_conf = f"/tmp/{CHAIN_NAME}.conf"
    with open(pf_conf, "w") as f:
        f.write(rules)

    # Check if pf is enabled
    pf_enabled = run("sudo pfctl -s info 2>/dev/null")

    # Add anchor to pf.conf if not already there
    pf_main = "/etc/pf.conf"
    anchor_line = f"anchor \"{PF_ANCHOR}\""
    if anchor_line not in open(pf_main).read():
        print(f"  Adding anchor to {pf_main}...")
        with open(pf_main, "a") as f:
            f.write(f"\n{anchor_line}\nload anchor \"{PF_ANCHOR}\" from \"{pf_conf}\"\n")

    # Load the rules
    run(f"sudo pfctl -a {PF_ANCHOR} -f {pf_conf}")
    run("sudo pfctl -e 2>/dev/null")
    print("[+] All C2 IPs blocked via pf")
    print("[+] Rules will persist across reboots (anchor in /etc/pf.conf)")


def macos_unblock():
    run(f"sudo pfctl -a {PF_ANCHOR} -f /dev/null 2>/dev/null")
    print("[+] macOS pf rules removed")


def macos_status():
    out = run(f"sudo pfctl -a {PF_ANCHOR} -sr 2>/dev/null")
    if out:
        print(out)
    else:
        print("  No pf rules active for this anchor")


# ── Windows ────────────────────────────────────────────────────────────

def windows_block():
    for ip in C2_IPS:
        rule_name = f"LazarusBlock_{ip.replace('.', '_')}"
        exists = run(f'netsh advfirewall firewall show rule name="{rule_name}" 2>nul')
        if exists and rule_name in exists:
            print(f"  Already blocked: {ip}")
        else:
            run(f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}')
            print(f"  Blocked: {ip}")
    print("[+] All C2 IPs blocked via Windows Firewall")


def windows_unblock():
    for ip in C2_IPS:
        rule_name = f"LazarusBlock_{ip.replace('.', '_')}"
        run(f'netsh advfirewall firewall delete rule name="{rule_name}"')
    print("[+] Windows Firewall rules removed")


def windows_status():
    print("  Checking Windows Firewall rules...")
    for ip in C2_IPS:
        rule_name = f"LazarusBlock_{ip.replace('.', '_')}"
        out = run(f'netsh advfirewall firewall show rule name="{rule_name}" 2>nul')
        if out and rule_name in out:
            print(f"  [BLOCKED] {ip}")
        else:
            print(f"  [OPEN]    {ip}")


# ── Fallback: /etc/hosts (all platforms) ───────────────────────────────

def hosts_block():
    marker = "# LAZARUS_C2_BLOCK"
    with open(HOSTS_FILE, "r") as f:
        content = f.read()

    if marker in content:
        print("  Already blocked in hosts file")
        return

    lines = [f"\n{marker}"]
    for ip in C2_IPS:
        lines.append(f"{ip}  0.0.0.0  # Lazarus C2")
    lines.append(f"# END {marker}\n")

    with open(HOSTS_FILE, "a") as f:
        f.write("\n".join(lines))
    print("[+] C2 IPs blocked via hosts file (DNS sinkhole)")


def hosts_unblock():
    with open(HOSTS_FILE, "r") as f:
        content = f.read()

    marker = "# LAZARUS_C2_BLOCK"
    end_marker = f"# END {marker}"
    if marker in content:
        start = content.index(marker)
        end = content.index(end_marker) + len(end_marker)
        content = content[:start] + content[end:]
        with open(HOSTS_FILE, "w") as f:
            f.write(content)
        print("[+] Hosts file entries removed")


# ── Main ───────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [block|unblock|status]")
        print(f"  Detected OS: {platform.system()}")
        sys.exit(1)

    action = sys.argv[1]
    os_name = platform.system()

    print(f"[*] OS: {os_name}")
    print(f"[*] Action: {action}")
    print()

    if os_name == "Linux":
        if action == "block":   linux_block()
        elif action == "unblock": linux_unblock()
        elif action == "status":  linux_status()
    elif os_name == "Darwin":
        if action == "block":   macos_block()
        elif action == "unblock": macos_unblock()
        elif action == "status":  macos_status()
    elif os_name == "Windows":
        if action == "block":   windows_block()
        elif action == "unblock": windows_unblock()
        elif action == "status":  windows_status()
    else:
        print(f"[!] Unsupported OS: {os_name}")
        sys.exit(1)

    # Also add hosts file entries as DNS sinkhole (works everywhere)
    print()
    if action == "block":
        try:
            hosts_block()
        except PermissionError:
            print("  [!] Hosts file requires admin/root. Run with sudo.")
    elif action == "unblock":
        try:
            hosts_unblock()
        except PermissionError:
            print("  [!] Hosts file requires admin/root. Run with sudo.")


if __name__ == "__main__":
    main()

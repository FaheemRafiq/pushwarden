---
title: Blocking C2 servers
description: "How pushwarden protect blocks the malware's command-and-control servers at the firewall and in the hosts file, system-wide and across reboots."
---
# Blocking C2 servers

`pushwarden protect` blocks the PolinRider command-and-control (C2) servers for the whole computer and keeps them blocked. Even if a loader runs, it cannot fetch its payload or send stolen data to the known servers.

This is the only part of PushWarden that needs administrator rights, because it edits the firewall and the hosts file.

```sh
pushwarden protect [--install | --refresh | --uninstall | --status | --block-c2 | --unblock] [--dry-run]
```

`pushwarden install` does this for you. It asks once for administrator rights (the native password dialog on macOS, polkit or sudo on Linux, UAC on Windows). You only need `protect` directly to check on the block, add it later or remove it.

## Options

| Option | Effect |
|---|---|
| `--install` (default) | block now and register the boot-time job. Asks for administrator rights when run as a normal user |
| `--status` | is the block active, and will it survive a reboot? No rights needed |
| `--refresh` | what the job runs: re-apply the rules from the root-owned indicators, then fetch newer ones and re-apply |
| `--uninstall` | remove the job, the firewall rules and the hosts entries |
| `--block-c2` | one-shot block for this boot only, with no job |
| `--unblock` | remove the rules and hosts entries but keep the job, if any |
| `--dry-run` | show what `--install` would do |

## What gets installed

| Part | Linux | macOS | Windows |
|---|---|---|---|
| Firewall rule dropping outgoing traffic to every C2 IP | an `iptables` chain or `nftables` table named `pushwarden` | a `pf` anchor | a Windows Firewall rule named "PushWarden C2 block" |
| Hostname sinkhole | hosts-file entries between `# BEGIN PUSHWARDEN C2 SINKHOLE` and `# END` markers | same | same |
| Job that re-applies the block at boot and refreshes the list daily | systemd timer `pushwarden-netblock.timer` | LaunchDaemon `com.pushwarden.netblock` | Scheduled Task "PushWarden NetBlock", running as SYSTEM |

## Why it keeps its own copy of the indicators

The job runs as root. The `iocs.json` under your home folder is writable by anything running as you, including malware. A privileged job must not let a user-writable file decide what goes into the hosts file.

So the job keeps:

- a root-owned copy of the indicators, refreshed from the project repository only
- a root-owned copy of the program

| System | Indicators and state | Program |
|---|---|---|
| Linux | `/etc/pushwarden` | `/usr/local/lib/pushwarden` |
| macOS | `/Library/Application Support/PushWarden` | `/usr/local/libexec/pushwarden` |
| Windows | `%ProgramData%\PushWarden` | `%ProgramFiles%\PushWarden` |

## Status values

Shown by `pushwarden status` and `pushwarden protect --status`.

| Firewall | Meaning |
|---|---|
| `active (persistent; 25 IPs, 15 hosts; applied 3h ago; indicators ...)` | all good |
| `active until reboot (...)` | a one-shot block from `--block-c2`; run `protect --install` to keep it |
| `not active (rules from a previous boot were lost)` | the same, after a reboot |
| `not active` | never installed, or removed |

## Opting out

```sh
pushwarden install --no-block-c2             # at install time
pushwarden config --set block_c2=false       # later; the guard stops reminding you
```

While `block_c2` is on and the block is missing, the guard reminds you once a day.

Setting `PUSHWARDEN_NO_BLOCK=1` skips the administrator prompt for one run. The package installers use it because they already did the work as root.

## Adding it later

```sh
sudo pushwarden protect --install     # Linux and macOS
pushwarden protect --install          # Windows, from an elevated terminal
pushwarden protect --status
```

## Removing it

```sh
pushwarden protect --uninstall
pushwarden uninstall --unblock        # together with the guard
```

## Limits

The block covers the addresses on the indicator list. A new C2 server is blocked once it is added to `iocs.json`, which the job picks up within a day. It is a second line of defence, not a replacement for removing the malware.

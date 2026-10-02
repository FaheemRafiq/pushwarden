---
title: How it works
description: "The architecture of ThreatScan: the four protection layers, the path from detection to response, and where data is stored."
---
# How it works

ThreatScan is one program. Every feature is a subcommand, and the background protection is the same program running the `guard` command as a user service.

## From file write to decision

```
file written --> real-time watcher --> scan for evidence --> quarantine --> notification
                                                                 |
                                                                 v
                                               native dialog: [Remove] [Restore and allow]
                                                                 |
                                                                 v
                                                  threatscan history (restore, allow, remove)
```

1. A file is written inside a watched folder.
2. The operating system's file watcher reports it to the guard within a fraction of a second.
3. The scanner looks for indicators in that file.
4. With strong evidence, the configured `action` policy applies. By default the file is moved to quarantine immediately.
5. A desktop notification names the threat. A dialog shows the evidence and asks whether to remove the file for good or restore and allow it.
6. The action is recorded in the journal and the protection history.

## Four protection layers

The guard runs four layers. Each has its own schedule and configuration key.

| Layer | Work | Schedule | Key |
|---|---|---|---|
| Real-time | Native file-system watcher over the project folders, `~/Downloads` and `~/Desktop`. Every written script, config, font, image or `.vscode/*.json` file is scanned as it lands | under 1 second | `realtime` |
| Quick | Process command lines and network connections to C2 addresses | every 5 seconds | `quick_interval` |
| Full | Every repository (all script files, not only known config names) plus host persistence, remote access tools, editor injection and exposed credentials | every 6 hours | `full_interval` |
| Definitions | Download and validate the indicator file `iocs.json` | every 24 hours | `ioc_update_interval` |

Around these, the guard also runs periodic tasks: the self-update check (every 6 hours), a reminder when the firewall block is missing (daily), the opt-in daily digest and central upload, and the daily [disk housekeeping](disk-and-cleanup.md).

## Components

| Component | Role |
|---|---|
| Indicators (`iocs.json`) | All signatures, keys, hashes, C2 addresses and package versions. Data only, validated before use, embedded in the program as a fallback |
| Scanner | Repository checks and host checks. Produces findings with a severity, a category, evidence and a reason |
| Protector | Kills processes, strips payloads, quarantines files, removes persistence entries. Always copies to quarantine first |
| Guard | The background loop and the response policy |
| Real-time watcher | inotify on Linux, kqueue on macOS, ReadDirectoryChangesW on Windows, polling as a fallback |
| Prompt and notify | Native dialogs, desktop notifications, the alerts log and the webhook |
| Journal | The complete activity record on disk |
| Network block | Firewall rules and hosts-file sinkhole, kept by a small privileged job |
| Remediator | `github-clean`: clone, check every branch, fix, commit, push |
| Updater | Signed program updates with rollback, and indicator updates |

## What counts as strong evidence

Automatic action is taken only on CRITICAL findings backed by strong evidence:

- a literal campaign signature or marker string
- a known payload XOR key or dead-drop wallet address
- a known loader hash
- a font, image or dictionary file whose bytes are actually code
- an editor task that runs on folder open together with a loader
- a known propagation script

Heuristic findings, such as an unusually large config file or a backdated commit, are HIGH or WARNING. They are reported and never acted on automatically. See [What it detects](detection.md).

## Response policy

What the guard does with a CRITICAL file is set by `action`:

| `action` | Behaviour |
|---|---|
| `quarantine` (default) | The file is quarantined immediately, then a dialog offers Remove or Restore and allow. No answer within 3 minutes: it stays in quarantine |
| `ask` | The dialog comes first and nothing is touched until you answer. No answer: quarantine, if `auto_clean` is on |
| `delete` | Remove without asking |
| `report` | Notify only, never touch files |

Processes are different: a running payload cannot wait for a dialog. A process whose command line carries a strict campaign marker, or a connection to a C2 address, is killed at once when `auto_kill` is on. See [Response and recovery](response-and-recovery.md).

## Where everything is stored

All state lives in one data directory, `~/.threatscan` (override with `THREATSCAN_HOME`): settings, indicators, the journal, logs, reports, quarantine and small state files. Every store has a size or age limit. See [Disk use and cleanup](disk-and-cleanup.md) and the file table in [Configuration](configuration.md).

The firewall block is the one exception. It runs as root, so it keeps its own root-owned copy of the program and of the indicators in a system location, and never trusts files under your home folder. See [Blocking C2 servers](network-block.md).

## Privileges

| Part | Runs as |
|---|---|
| Every command, the guard, real-time protection, quarantine, updates | your user |
| The boot-time job that re-applies the firewall block | root or SYSTEM, installed once with your consent |

## Network use

| Connection | When | Can be turned off |
|---|---|---|
| Indicator download from the project repository | daily | `ioc_update=false` |
| Release check and download from GitHub | every 6 hours | `auto_update=false` |
| GitHub API and git over HTTPS | only during `github-clean` | not used unless you run it |
| Webhook, daily digest, central upload | only when you set their URL | off by default |

Protection itself needs no network. See [Security and privacy](security-and-privacy.md).

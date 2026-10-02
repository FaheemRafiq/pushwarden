---
title: Real-time guard
description: "The background guard: real-time file protection, process and network checks, scheduled sweeps, notifications, dialogs and how to check that it is running."
---
# Real-time guard

The guard is the background process that protects the machine continuously. `threatscan install` registers it as a user service that starts at sign-in.

## What it does

| Layer | Work | Latency or schedule |
|---|---|---|
| Real-time | Watches the project folders, `~/Downloads` and `~/Desktop`. Every written script, config, font, image or `.vscode/*.json` file is scanned as it lands | under 1 second; idle otherwise |
| Behaviour | Process command lines and sockets to C2 addresses | every 5 seconds; a few milliseconds of work |
| Scheduled sweep | Every repository (all script files) plus host persistence, remote access tools, editor injection and credentials | every 6 hours; seconds to a minute |
| Definitions | `iocs.json` downloaded and validated | every 24 hours; one HTTPS request |

The real-time watcher uses the operating system's own mechanism: inotify on Linux, kqueue on macOS, ReadDirectoryChangesW on Windows. If none is available it falls back to polling, and the 5-second and 6-hour layers keep working either way.

## Which folders are watched

By default the guard discovers the usual project folders under your home directory. To set them explicitly:

```sh
threatscan config --set scan_roots=~/code,~/work
```

`~/Downloads` and `~/Desktop` are always watched, because that is where a cloned or unpacked interview project usually lands.

## What happens on a detection

1. With strong evidence the `action` policy applies. The default, `quarantine`, moves the file to quarantine at once.
2. A desktop notification names the threat, for example *Threats found: Trojan:JS/PolinRider.FakeFont*.
3. A native dialog shows the file, the evidence and the reason, with two choices: **Remove** (permanent) or **Restore and allow**.
4. With no answer within 3 minutes (`prompt_timeout`), the file stays in quarantine.
5. The alert is written to `alerts.log` and sent to the webhook if one is configured.
6. Everything is recorded in the journal.

Clicking a notification opens the recent alerts (`threatscan alerts --gui`).

Other responses do not wait for a dialog:

| Finding | Response |
|---|---|
| A process whose command line carries a strict campaign marker, or a socket to a C2 address | Killed at once (`auto_kill`). A running payload cannot wait |
| A config or entry file with an appended payload | The payload is stripped by byte offset and the legitimate code kept. Prepended or mid-file injections quarantine the whole file instead of guessing |
| A remote access tool's service, LaunchAgent, scheduled task, cron line or directory | Disabled and quarantined; the crontab is backed up first |
| HIGH and WARNING findings | Alert only, never acted on automatically |

See [Response and recovery](response-and-recovery.md) for the full policy.

## Notifications

| Setting | Default | Effect |
|---|---|---|
| `notify_desktop` | `true` | desktop notifications (notify-send, Notification Center, Windows toast) |
| `notify_min_severity` | `HIGH` | lowest severity that notifies |
| `notify_sweeps` | `true` | a notification when a background full sweep starts and when it finishes, with the result |
| `webhook_url` | empty | receives a JSON POST per alert. See [Team reporting](team-reporting.md) |
| `webhook_min_severity` | `HIGH` | lowest severity that posts |

The same alert about the same finding is not repeated for 6 hours.

## Checking that it runs

```sh
threatscan status
```

`status` shows:

- whether the guard is alive, and its real-time backend. During a sweep the line reads `scanning 7/17 repositories (name)` and updates as it goes
- the service state and the installed binary
- the time of the last full sweep and how many repositories are tracked
- the indicator version
- the action policy, webhook, central upload and firewall state
- the data directory and its disk use
- a summary of the latest report
- each VS Code-family editor with its `task.allowAutomaticTasks` setting

The guard writes a heartbeat file every few seconds; `status` reads it, so the answer does not depend on the service manager.

## Running the guard by hand

```sh
threatscan guard [--once] [--dry-run] [--verbose]
```

| Option | Effect |
|---|---|
| `--once` | one full pass, then exit |
| `--dry-run` | detect and alert but never kill or quarantine |
| `--verbose` | print the log to the terminal as well as to `guard.log` |

Use this to debug, or on a machine without a service manager.

## Managing the service

| System | Commands |
|---|---|
| Linux | `systemctl --user status threatscan-guard.service`, `systemctl --user restart threatscan-guard.service` |
| macOS | `launchctl list com.threatscan.guard` |
| Windows | Task Scheduler, task "ThreatScan Guard" |

The guard reads its configuration when it starts. Restart it after `threatscan config --set`.

## Tuning

| Setting | Default | Effect |
|---|---|---|
| `realtime` | `true` | real-time file watcher on |
| `quick_interval` | `5` | seconds between process and network checks |
| `full_interval` | `21600` | seconds between full sweeps |
| `deep` | `false` | also scan `node_modules` and `vendor` |
| `exclude` | empty | directories never scanned |
| `auto_kill` | `true` | kill processes that match a kill-list indicator |
| `prompt` | `true` | show native dialogs |
| `prompt_timeout` | `180` | seconds a dialog waits before the default applies |

## The guard log

`guard.log` in the data directory holds one text line per event: starts, sweeps, findings, responses, updates and errors. It rotates at 5 MB and the newest 5 archives are kept. The structured record of the same events is the journal; see [Activity history](activity-history.md).

## Optional: kernel-level blocking on Linux with Falco

For Linux workstations and CI runners, the repository ships a [Falco](https://falco.org) rule set in `falco/`. Tier 1 rules terminate known payload patterns at the system-call level; tier 2 rules alert on suspicious activity such as automated force-pushes or node spawning shells.

```sh
sudo bash falco/install-falco.sh     # needs Falco and jq installed
```

This is an add-on. The guard does not depend on it.

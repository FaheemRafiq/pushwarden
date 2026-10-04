---
title: What it detects
description: "Every category of finding PushWarden reports, in repositories and on the host, with severities, threat names and how indicators are managed."
---
# What it detects

PushWarden looks for the artefacts and behaviour of the PolinRider / Contagious Interview campaign in two places: your repositories and the computer itself. Every finding has a severity, a category, a threat name, the evidence and a one-sentence reason.

## Severities

| Severity | Meaning | Automatic action |
|---|---|---|
| CRITICAL | A confirmed PolinRider artefact or activity | Yes, according to the `action` policy |
| HIGH | A strong indicator that needs a human decision, for example a compromised package version or exposed keys on an infected host | No, listed for review |
| WARNING | Context worth checking, for example a suspicious git reflog, a secrets file in an infected repository, or files that arrived in the same commit as a loader | No |
| INFO | Informational | No |

Scan commands exit with code `1` when anything HIGH or CRITICAL is found.

## In repositories

Every script, config, font, image and `.vscode/*.json` file in a project is checked, not only files with well-known names. `node_modules` and `vendor` are skipped unless `--deep` or `deep=true` is set.

| What | Examples | Severity |
|---|---|---|
| Campaign signatures and build tags in any script file | Loader marker strings, obfuscator fingerprints and build tags found in `.js`, `.ts`, `.json`, `.py`, `.sh`, `.bat`, `.ps1` and similar files | CRITICAL |
| Payload injected into a config file | Code appended, prepended or inserted into `postcss.config.mjs`, `eslint.config.mjs`, `next.config.js`, `tailwind.config.js` and other framework configs | CRITICAL |
| Entry-file hooks | A loader call added to an application entry file | CRITICAL |
| Known keys and wallets | The campaign's XOR payload keys; TRON, Aptos and Ethereum wallet addresses used as dead drops; blockchain RPC hosts next to a marker | CRITICAL |
| C2 references | Known C2 IP addresses, first-stage hosts, C2 URL paths and the payload header | CRITICAL |
| Disguised payloads | A font, image or dictionary file whose bytes are code, with or without whitespace padding; files matching known loader hashes | CRITICAL |
| Editor autorun | `.vscode/tasks.json` with `runOn: folderOpen` together with a loader or C2 host; settings that force automatic tasks on | CRITICAL or HIGH |
| Propagation scripts | The batch scripts the malware uses to commit and force-push itself, and the helper files they create | CRITICAL or HIGH |
| `.gitignore` tampering | Entries that hide the malware's files, or the `.gitignore` hiding itself | CRITICAL or HIGH |
| Git hooks and git config | Malicious hooks; `core.fsmonitor` set to run node | CRITICAL |
| Compromised packages | Known bad versions of npm packages, Go modules and a Packagist package, including typosquats; suspicious lifecycle scripts | CRITICAL or HIGH |
| Git history | Backdated commits, force-push traces in the reflog, commits that touch payload code on any branch | HIGH or WARNING |
| Camouflage | Files that arrived in the same commit as a loader: decoy fonts, a decoy README, a `.vscode` set | WARNING |

## On the host

Host checks run in `scan` (unless `--no-system`) and in the guard's full sweep. Process and network checks also run every 5 seconds.

| What | Examples | Severity |
|---|---|---|
| Malicious processes | A running process whose command line carries a campaign marker, or a known payload process name | CRITICAL |
| C2 connections | An open socket to a known C2 address | CRITICAL |
| Remote access tool footprint | The directories, files and environment variables the campaign's remote access tools leave behind; portable Node or Python runtimes dropped by a later stage | CRITICAL or HIGH |
| Persistence | Entries in cron, systemd user units, XDG autostart, LaunchAgents, Windows scheduled tasks, the Startup folder and the `HKCU\...\Run` registry key | CRITICAL or HIGH |
| Shell start-up injection | Lines added to shell rc files or the PowerShell profile | HIGH |
| Editor and tool injection | Modified files inside VS Code, Cursor, VSCodium, Windsurf, Discord or GitHub Desktop; a backdoored or oversized global `npm/lib/cli.js` | CRITICAL or HIGH |
| Hosts-file redirects | Package registries redirected in the hosts file | HIGH |
| Exposed credentials on an infected host | Plain-text tokens in `.npmrc`, `.git-credentials`, the `gh`, AWS and Docker configs, and SSH keys. Reported only when the host shows other signs of infection | HIGH |

## Threat names

Notifications, dialogs, reports and the history name threats in the style of Windows Defender, so an alert is recognisable at a glance.

| Threat name | What it is |
|---|---|
| `Trojan:JS/PolinRider.ConfigInject` | Loader code injected into a framework config file, or a known XOR key |
| `Trojan:JS/PolinRider.EntryHook` | Loader call added to an application entry file |
| `Trojan:JS/PolinRider.FakeFont` | A script disguised as a font file |
| `Trojan:JS/PolinRider.Disguised` | Code hidden in another non-code file type |
| `Trojan:Script/PolinRider.TaskJacker` | An editor task that runs the loader when a folder is opened |
| `Trojan:BAT/PolinRider.AutoPush` | The propagation script that commits and force-pushes the backdoor |
| `Trojan:JS/PolinRider.DeadDrop` | A blockchain wallet or RPC reference used to fetch the payload location |
| `Trojan:JS/PolinRider.C2` | A reference to a command-and-control server |
| `Trojan:JS/OmniStealer.Exfil` | Credential exfiltration through a messaging API |
| `Trojan:Script/PolinRider.GitHook` | A malicious git hook |
| `Trojan:JS/PolinRider.Package` | A compromised package version |
| `Trojan:JS/PolinRider.EditorInject` | Code injected into an editor or desktop tool |
| `Trojan:Script/PolinRider.Hide` | `.gitignore` entries that hide the malware |
| `Behavior:Node/PolinRider.Payload` | A running payload process |
| `Behavior:Net/PolinRider.C2` | A live connection to a C2 server |
| `Backdoor:JS/RuntimeDevLink` | The remote access tool and its runtime |
| `Backdoor:Script/PolinRider.Persist` | A persistence entry |
| `Trojan:Script/PolinRider` | Any other injected loader |

Windows Defender itself names the family `Trojan:JS/PolinRider.DB!MTB`.

## Reasons on every finding

Every finding has a `why` line: one sentence that says what the evidence means and why it has that severity. Every response has a `response` line: what was done and why (killed, stripped, quarantined, or left for you to decide).

These lines appear in scan output, dialogs, `pushwarden alerts`, `pushwarden history`, desktop notifications, the webhook JSON (`reasons` array) and `guard.log`.

## Indicators are data

All indicators live in one file, `iocs.json`: signature strings and regular expressions, XOR keys, wallet addresses, C2 IPs and hostnames, URL paths, loader hashes, process markers and compromised package versions.

- The program carries an embedded copy, so it works offline from the first run.
- The guard downloads a newer copy from the project repository every 24 hours. The download is parsed and validated before it replaces the previous copy: every regular expression must compile, every IP and hash must be well formed, and the version must be newer.
- `pushwarden update-iocs` forces a download. `--url` and the `ioc_update_url` setting point it at a mirror or a fork.
- New variants are usually covered by adding an indicator, with no new release.

The current list is in [`pushwarden/iocs.json`](https://github.com/FaheemRafiq/pushwarden/blob/main/pushwarden/iocs.json) in the repository.

## Kill list versus report list

A process is killed only when its command line holds a strict marker that legitimate tools never use. A broad indicator alone is reported but not killed, and the reason says so. This is what keeps ordinary `node` processes safe.

## Files that legitimately contain signatures

Rule sets, tests and indicator databases contain the same strings the scanner looks for. Such a file opts out by carrying the token `pushwarden:allow-signatures` in its first 512 bytes.

The token is never honoured for config files, entry files, asset files or JavaScript and TypeScript files, so malware cannot use it to hide.

## False positives

If a legitimate file is flagged:

```sh
pushwarden history --allow PATH --note "what the file really is"
```

This restores the file, stops flagging that exact content for 30 days, and records the note as feedback. Use `exclude` in the [configuration](configuration.md) to skip a directory entirely. See [Response and recovery](response-and-recovery.md).

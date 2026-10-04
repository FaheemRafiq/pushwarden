---
title: Overview
description: "What PushWarden is, the threat it protects against, every feature it has and the platforms it supports."
---
# PushWarden overview

PushWarden is a free, open-source security tool that protects developer machines and GitHub repositories from the PolinRider / Contagious Interview supply-chain malware. It runs on Linux, macOS and Windows as a single program with no dependencies.

It works like an antivirus that knows one malware family very well. It catches a malicious file the moment it is written, moves it to quarantine before it can run, names the threat, and lets you decide in a native dialog whether to remove it for good or restore it.

## The threat

PolinRider is a campaign attributed to North Korean (DPRK, Lazarus) operators. It targets software developers, often through fake job interviews in which the victim is asked to clone and run a repository. Between March and September 2026 it reached more than 2,000 GitHub owners and 4,000 repositories.

The malware:

1. **Hides loaders in ordinary project files.** Obfuscated JavaScript is appended to framework config files such as `postcss.config.mjs`, `eslint.config.mjs` and `next.config.js`, placed in files that pretend to be fonts (`fa-solid-900.woff2`), and started by `.vscode/tasks.json` tasks that run when a folder is opened.
2. **Runs as soon as the project is opened or built.** Opening the folder in VS Code, running the dev server or installing dependencies is enough.
3. **Steals credentials.** Tokens, SSH keys, browser sessions, wallet files and environment files are collected and sent to command-and-control (C2) servers.
4. **Spreads through git.** With a stolen token it rewrites repositories and force-pushes the backdoor to every branch it can reach, so colleagues who pull become infected too.
5. **Stays on the machine.** It installs remote access tools and persistence entries (systemd units, LaunchAgents, scheduled tasks, cron lines).

## What PushWarden does about it

| Capability | What it means | Guide |
|---|---|---|
| Real-time file protection | Every script, config, font, image and editor task file written under your project folders is scanned within a second | [Real-time guard](real-time-guard.md) |
| Process and network watch | Every 5 seconds: running processes and connections to known C2 addresses are checked, and confirmed payloads are killed | [Real-time guard](real-time-guard.md) |
| Scheduled full sweep | Every 6 hours: every repository plus the host (persistence, remote access tools, editor injection, exposed credentials) | [Real-time guard](real-time-guard.md) |
| On-demand scan | Scan any folder or the whole home directory, interactively or in CI | [Scanning](scanning.md) |
| Reversible response | Payloads are stripped by byte offset or the file is quarantined; everything can be restored | [Response and recovery](response-and-recovery.md) |
| Native dialogs and notifications | Desktop notifications name the threat; a dialog shows the evidence and asks what to do | [Response and recovery](response-and-recovery.md) |
| C2 firewall block | Outgoing traffic to the C2 servers is dropped system-wide and the block survives reboots | [Blocking C2 servers](network-block.md) |
| Editor and npm hardening | Turns off automatic tasks and turns on workspace trust in every VS Code-family editor | [Hardening](hardening.md) |
| GitHub clean-up | Removes the malware from every branch of every repository you can push to, without rewriting history | [Cleaning GitHub repositories](github-clean.md) |
| CI gate and pre-commit hook | Fails a pipeline or refuses a commit that carries an indicator | [CI and automation](ci-and-automation.md) |
| Complete activity record | Every finding, action, decision, sweep and error is journaled and searchable | [Activity history](activity-history.md) |
| Team reporting | Webhook alerts, a redacted feedback bundle, an opt-in daily digest and an opt-in central event upload | [Team reporting](team-reporting.md) |
| Signed self-update | Indicators refresh daily; the program updates itself after verifying a signature, and rolls back if a release fails | [Updates](updates.md) |
| Bounded footprint | Every store on disk has a size or age limit that is enforced daily | [Disk use and cleanup](disk-and-cleanup.md) |

## Design principles

- **Per user, no administrator rights.** Installation, the background guard and every command run as your user. Only the optional firewall block needs elevated rights, and it asks once.
- **Every destructive step is reversible.** A file is copied to quarantine before it is stripped or deleted. `pushwarden history` puts it back.
- **Evidence first.** A file is acted on only with strong evidence: a literal campaign signature, a known key or hash, or a file whose content does not match its type. Heuristic findings are reported and never acted on automatically.
- **Explained decisions.** Every finding carries a one-sentence reason for its severity, and every response carries a reason for what was done.
- **Indicators are data.** All signatures live in one file, `iocs.json`, which is updated daily without a new release.
- **Nothing leaves the machine unless you opt in.** Alerts by webhook, the daily digest and the central upload are all off until you set their URL.

## Supported platforms

| Platform | Versions | Real-time backend | Service manager |
|---|---|---|---|
| Linux | x86-64 and ARM64, any distribution with a recent kernel | inotify | systemd user service |
| macOS | 11 or later, Intel and Apple silicon | kqueue | LaunchAgent |
| Windows | 10 and 11, x86-64 and ARM64 | ReadDirectoryChangesW | Scheduled Task |

Where a native watcher is unavailable the guard falls back to polling.

## Project status

PushWarden is in early development (version 0.x). Releases are frequent while detection is extended for new variants. It is a single Go program; the earlier Python versions (v4, v5) are archived on the `archive/python-v5` branch.

## Where to go next

- [Installation](installation.md) to set it up.
- [Quick start](quick-start.md) for the commands you will use most.
- [How it works](how-it-works.md) for the architecture.
- [Command-line reference](../reference.md) for every option of every command.

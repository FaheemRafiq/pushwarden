---
title: CI and automation
description: "Using ThreatScan in pipelines and scripts: the reusable GitHub Actions workflow, a CI gate, the pre-commit hook, JSON output and exit codes."
---
# CI and automation

ThreatScan is a single binary with stable exit codes and JSON output, so it fits in pipelines and scripts.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | clean or done |
| `1` | threats found, or not fully fixed |
| `2` | usage error, nothing scanned, or an internal failure |

Commands that only display information return `0`.

## Reusable GitHub Actions workflow

The repository publishes a workflow you can call from any repository. It downloads the latest release, verifies its SHA-256, scans the checkout, posts a commit comment when malware is found, sets a commit status named `threatscan`, and fails the job.

```yaml
# .github/workflows/malware-scan.yml
name: Malware Scan
on: [push, pull_request]
jobs:
  scan:
    uses: FaheemRafiq/threatscan/.github/workflows/malware-scan.yml@main
```

## A CI gate in any pipeline

Install the program only (no guard) and scan the checkout:

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.sh | THREATSCAN_NO_INSTALL=1 sh
- run: ~/.local/bin/threatscan scan --ci --no-system --json threatscan.json .
```

| Flag | Why in CI |
|---|---|
| `--ci` | no colour, compact output, never prompts |
| `--no-system` | skip host checks; the runner is not your machine |
| `--no-report` | do not save a report under the data directory |
| `--no-prompt` | never change a file |
| `--json FILE` | machine-readable result to keep as an artifact |

Exit code `1` fails the job when a HIGH or CRITICAL finding is present.

To pin a version, set `THREATSCAN_VERSION=v0.3.3` in front of `sh`.

## Pre-commit hook

```sh
threatscan harden --pre-commit .
```

The hook runs `threatscan check-staged`, which scans only the staged files and exits `1` when any carries an indicator at HIGH or above. For a hook manager, call the command directly:

```sh
#!/bin/sh
threatscan check-staged || exit 1
```

## JSON outputs

| Command | Output |
|---|---|
| `threatscan scan --json FILE` | the scan report: statistics and every finding |
| `threatscan github-clean --json FILE` | per repository and branch: status, findings, fixed files, commit |
| `threatscan history --json` | raw journal events |
| `threatscan alerts --json` | raw alert records |
| `threatscan feedback --digest` | the daily digest as JSON |
| `threatscan feedback --preview` | the next events the central upload would send |
| `threatscan config` | the effective configuration |

The latest scan report is also always at `reports/latest.json` in the data directory.

## Webhook for alerts

```sh
threatscan config --set webhook_url=https://hooks.slack.com/services/T000/B000/XXXX
```

Each alert is one JSON POST. The body contains `text` (Slack), `content` (Discord), `host`, `platform`, `context`, the `findings` array and a `reasons` array, so one URL works for Slack, Discord, Teams and your own endpoint. See [Team reporting](team-reporting.md).

## Cleaning GitHub from a pipeline

```sh
GITHUB_TOKEN=... threatscan github-clean --ci --apply --json clean.json
op read op://Vault/GitHub/token | threatscan github-clean --token-stdin --apply
```

`--ci` never asks questions. See [Cleaning GitHub repositories](github-clean.md).

## Environment variables for unattended use

| Variable | Effect |
|---|---|
| `THREATSCAN_HOME` | data directory instead of `~/.threatscan`. Use a temporary folder in CI |
| `THREATSCAN_NO_BLOCK=1` | never ask for administrator rights |
| `THREATSCAN_NO_INSTALL=1` | install script: download the program only |
| `THREATSCAN_VERSION` | install script: install this release |
| `NO_COLOR=1` | disable coloured output |
| `GITHUB_TOKEN`, `GH_TOKEN` | token for `github-clean` |

## Machine audit without touching anything

```sh
threatscan scan --home --no-prompt --verbose --json audit.json
```

## Rolling out to a team

1. Colleagues run the install one-liner with `THREATSCAN_WEBHOOK` set to a channel you watch.
2. Every alert arrives with the host name, platform, findings and the action taken.
3. When a new variant appears, add its indicator to `threatscan/iocs.json` in your fork, raise `"version"` and push. Every guard picks it up within 24 hours; `threatscan update-iocs` forces it. Point machines at a fork with `ioc_update_url`.
4. Add the reusable workflow to your repositories.
5. For fleet-wide diagnostics, turn on the [central event upload](team-reporting.md).

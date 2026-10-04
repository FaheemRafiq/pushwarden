---
title: Scanning
description: "How to run an on-demand scan of repositories and the host with pushwarden scan: options, behaviour when something is found, reports and exit codes."
---
# Scanning

`pushwarden scan` is a one-off scan of repositories and of the computer. The background guard does the same work on a schedule; this command runs it now and shows the result.

```sh
pushwarden scan [options] [directories]
```

`pushwarden [directories]` without a command means the same.

## What is scanned

With no directories, the current working directory is scanned.

1. **Repositories.** Each directory is walked for git repositories and for projects that have a `package.json`, `go.mod` or `composer.json`. Every script, config, font, image and `.vscode/*.json` file in them is checked.
2. **The host.** Running processes, network connections to known C2 addresses, persistence (systemd units, LaunchAgents, scheduled tasks, cron, shell rc files), remote access tool footprints, editor injection and exposed credentials.

In a terminal a progress bar shows which repository is being scanned. In CI or a pipe, numbered progress lines are printed instead.

## Options

| Option | Effect |
|---|---|
| `--home` | also scan the common project directories under your home folder, or `scan_roots` from the configuration |
| `--deep` | also descend into `node_modules` and `vendor` (slow) |
| `--configs-only` | only check the known config and entry-file names (the scope of the old v4 release) |
| `--no-system` | skip the host checks |
| `--no-repos` | skip the repository checks |
| `--verbose` | list every repository, including clean ones |
| `--fix` | act on CRITICAL findings without asking. Reversible |
| `--dry-run` | show what `--fix` would do and change nothing |
| `--gui` | ask about each malicious file with a native dialog instead of in the terminal |
| `--no-prompt` | report only. Never ask, never change a file |
| `--notify` | send a desktop notification and, if configured, a webhook when anything HIGH or above is found |
| `--json FILE` | also write the report as JSON to `FILE` |
| `--no-report` | do not save the report under the data directory |
| `--ci` | CI mode: no colour, compact output, never prompt |

## What happens when something is found

| How you ran it | Behaviour for a CRITICAL finding with strong evidence |
|---|---|
| In an interactive terminal | One question per file: remove, or keep and allow |
| `--gui` | The same question in a native dialog |
| `--fix` | The reversible action is taken without asking |
| `--no-prompt` or `--ci` | Nothing is touched; the finding is reported |
| `--dry-run` | The action that would be taken is shown |

What `--fix` does:

- strips an appended payload from a config or entry file and keeps the legitimate code
- quarantines whole-file threats such as fake fonts, malicious editor tasks and propagation scripts
- removes PolinRider entries from `.gitignore`
- kills malicious processes
- disables and quarantines persistence entries

Every changed or removed file is copied to quarantine first. See [Response and recovery](response-and-recovery.md).

Findings that PushWarden cannot fix on its own, such as a compromised package version in a lockfile, are printed with a remediation hint.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | clean |
| `1` | HIGH or CRITICAL findings |
| `2` | error, or nothing was scanned |

## Reports

Each scan saves a JSON report under `reports/` in the data directory, plus `latest.json`. The newest 60 are kept (`report_keep`). `--json FILE` writes the same report to a file of your choice, and `--no-report` skips saving.

The report contains the version, the indicator version, statistics (repositories scanned and infected, files checked, counts per severity, duration) and every finding with its severity, category, title, path, details, remediation hint, action taken and evidence.

`pushwarden status` shows a summary of the latest report.

## Examples

```sh
pushwarden scan                          # this directory
pushwarden scan ~/code ~/work            # specific directories
pushwarden scan --home --no-system       # repositories only
pushwarden scan --home --fix             # clean up without questions
pushwarden scan --home --no-prompt --verbose --json audit.json   # audit without touching anything
pushwarden scan --ci --json report.json  # in a pipeline; exit 1 fails the job
pushwarden --deep ~/proj                 # same as: pushwarden scan --deep ~/proj
```

## Scanning staged files before a commit

`pushwarden check-staged` scans only the files staged for commit and exits `1` if any carries an indicator at HIGH or above, which blocks the commit.

```sh
pushwarden harden --pre-commit .    # install it as a pre-commit hook in this repository
```

Or add it to `.git/hooks/pre-commit` yourself:

```sh
#!/bin/sh
pushwarden check-staged || exit 1
```

See [CI and automation](ci-and-automation.md).

## Excluding directories

Set `exclude` to a comma-separated list of directories that must never be scanned:

```sh
pushwarden config --set exclude=~/code/malware-samples,~/archive
```

## Every scan is recorded

A scan writes its start, its end with duration and counts, every finding and every action to the journal. See [Activity history](activity-history.md).

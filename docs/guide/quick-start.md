---
title: Quick start
description: "The ThreatScan commands used most often, with one line on what each does."
---
# Quick start

Five commands cover most needs.

```sh
threatscan install              # background guard + editor hardening + first scan
threatscan status               # is everything running?
threatscan scan --home          # audit every project under your home folder now
threatscan github-clean         # dry run: which of my GitHub repositories and branches are infected?
threatscan github-clean --apply # fix and push them
```

## Check the protection

```sh
threatscan status
```

Look for `Guard: alive`, a real-time backend other than `off`, and `Firewall: active (persistent ...)`.

## Scan now

```sh
threatscan scan                        # the current directory
threatscan scan ~/code ~/work          # specific directories
threatscan scan --home                 # every project under your home folder, plus the host
threatscan scan --home --no-prompt     # report only, change nothing
threatscan scan --home --fix           # clean up without asking (reversible)
```

`threatscan [dirs]` without a command is short for `threatscan scan [dirs]`. See [Scanning](scanning.md).

## See what happened

```sh
threatscan alerts                       # recent alerts and why each one fired
threatscan history                      # each distinct finding once, then what was done
threatscan history --all --since 7d     # everything this week, nothing collapsed
```

See [Activity history](activity-history.md).

## Undo an action

```sh
threatscan history --restore PATH       # put the original back (it is still malicious)
threatscan history --allow PATH         # restore and stop flagging this exact content for 30 days
threatscan history --remove PATH        # delete the quarantined copies for good
```

See [Response and recovery](response-and-recovery.md).

## Clean GitHub

```sh
threatscan github-clean --list              # which repositories can my token push to?
threatscan github-clean                     # dry run over all of them
threatscan github-clean --select --apply    # pick from a list, then fix and push
```

See [Cleaning GitHub repositories](github-clean.md).

## Change a setting

```sh
threatscan config                          # show all settings
threatscan config --set action=ask         # ask before touching any file
threatscan config --set webhook_url=URL    # send alerts to Slack, Discord or Teams
```

Restart the guard after a change. See [Configuration](configuration.md).

## Get help offline

```sh
threatscan help                  # list of commands
threatscan help scan             # documentation for one command
threatscan help all              # the whole reference
```

The help text is embedded in the program, so it always matches the installed version.

## Conventions that hold everywhere

- Flags accept one or two dashes: `-fix` and `--fix` are the same. Flags may come before or after directories.
- Exit codes: `0` clean or done, `1` threats found or not fully fixed, `2` usage error, nothing scanned or an internal failure.
- Nothing needs administrator rights except `protect`.
- Set `NO_COLOR=1` to disable coloured output.

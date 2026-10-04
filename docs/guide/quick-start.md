---
title: Quick start
description: "The PushWarden commands used most often, with one line on what each does."
---
# Quick start

Five commands cover most needs. If you would rather not type options, `pushwarden ui` cleans your GitHub repositories on [guided screens](guided-screens.md).

```sh
pushwarden install              # background guard + editor hardening + first scan
pushwarden status               # is everything running?
pushwarden scan --home          # audit every project under your home folder now
pushwarden github-clean         # dry run: which of my GitHub repositories and branches are infected?
pushwarden github-clean --apply # fix and push them
```

## Check the protection

```sh
pushwarden status
```

The top of the output is the verdict: a score out of 100 and one word, `PROTECTED`, `PARTLY PROTECTED`, `AT RISK` or `THREATS FOUND`.

```
      ▄▄████████▄▄       PushWarden 0.5.2
    ████████████████     PolinRider / Contagious Interview protection
    ███▀▀▀▀▀▀▀▀▀▀███
    ███  █▀▀▀▀█  ███     PROTECTED  ████████████████████  100/100
    ███  █▄▄▄▄▀  ███     Files are checked as they are written, the malware's
    ███  █       ███     servers are blocked and editors cannot auto-run tasks.
     ███ ▀      ███
      ▀███▄▄▄▄███▀       ● watching 18 repositories
         ▀▀██▀▀

  PROTECTION
    OK  Background guard                alive, v0.5.2
    OK  Real-time file protection       every file is checked as it is written (inotify)
    OK  Starts when you sign in         active
    !!  Malware servers blocked         not blocked
                                        fix: pushwarden protect --install
```

Under it, every layer of protection is listed with `OK` or `!!`, and each missing one names the command that adds it. The score says how much of the protection is switched on; it is not a guarantee that the machine is clean. The details follow: look for `Guard: alive`, a real-time backend other than `off`, and `Firewall: active (persistent ...)`.

## Scan now

```sh
pushwarden scan                        # the current directory
pushwarden scan ~/code ~/work          # specific directories
pushwarden scan --home                 # every project under your home folder, plus the host
pushwarden scan --home --no-prompt     # report only, change nothing
pushwarden scan --home --fix           # clean up without asking (reversible)
```

`pushwarden [dirs]` without a command is short for `pushwarden scan [dirs]`. See [Scanning](scanning.md).

## See what happened

```sh
pushwarden alerts                       # recent alerts and why each one fired
pushwarden history                      # each distinct finding once, then what was done
pushwarden history --all --since 7d     # everything this week, nothing collapsed
```

See [Activity history](activity-history.md).

## Undo an action

```sh
pushwarden history --restore PATH       # put the original back (it is still malicious)
pushwarden history --allow PATH         # restore and stop flagging this exact content for 30 days
pushwarden history --remove PATH        # delete the quarantined copies for good
```

See [Response and recovery](response-and-recovery.md).

## Clean GitHub

```sh
pushwarden github-clean --list              # which repositories can my token push to?
pushwarden github-clean                     # dry run over all of them
pushwarden github-clean --select --apply    # pick from a list, then fix and push
pushwarden ui                               # the same on guided screens: tick, check, review, fix
```

See [Cleaning GitHub repositories](github-clean.md) and [Guided screens](guided-screens.md).

## Change a setting

```sh
pushwarden config                          # show all settings
pushwarden config --set action=ask         # ask before touching any file
pushwarden config --set webhook_url=URL    # send alerts to Slack, Discord or Teams
```

Restart the guard after a change. See [Configuration](configuration.md).

## Get help offline

```sh
pushwarden help                  # list of commands
pushwarden help scan             # documentation for one command
pushwarden help all              # the whole reference
```

The help text is embedded in the program, so it always matches the installed version.

## Conventions that hold everywhere

- Flags accept one or two dashes: `-fix` and `--fix` are the same. Flags may come before or after directories.
- Exit codes: `0` clean or done, `1` threats found or not fully fixed, `2` usage error, nothing scanned or an internal failure.
- Nothing needs administrator rights except `protect`.
- Set `NO_COLOR=1` to disable coloured output.

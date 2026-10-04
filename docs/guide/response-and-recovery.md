---
title: Response and recovery
description: "What PushWarden does with a malicious file or process, how quarantine works, how to restore or allow a file, and the steps to take after an infection."
---
# Response and recovery

PushWarden acts on confirmed threats and keeps every action reversible. This page describes each response, the quarantine, and what to do after an infection.

## The action policy

The `action` setting decides what happens to a CRITICAL file with strong evidence.

| `action` | Behaviour |
|---|---|
| `quarantine` (default) | The file is moved to quarantine first, then a dialog offers **Remove** for good or **Restore and allow** |
| `ask` | The dialog comes first and nothing is touched until you answer. On timeout the file is quarantined if `auto_clean` is on |
| `delete` | Remove without asking. Stripped files keep a backup in quarantine; deleted files do not |
| `report` | Alert only, never touch files. Processes are still killed if `auto_kill` is on |

```sh
pushwarden config --set action=ask
```

Related settings:

| Setting | Default | Effect |
|---|---|---|
| `auto_kill` | `true` | kill processes that match a kill-list indicator |
| `auto_clean` | `true` | with `action=ask`, quarantine when nobody answers the dialog |
| `prompt` | `true` | show native dialogs |
| `prompt_timeout` | `180` | seconds a dialog waits before the default applies |

## Responses by finding

| Finding | Response |
|---|---|
| Process with a strict campaign marker, or a socket to a C2 address | **Killed** at once. No dialog |
| Config or entry file with a payload appended after the legitimate code | **Stripped**: the payload is cut off at its byte offset and the legitimate export is kept. The original goes to quarantine |
| Config file with a payload prepended or inserted mid-file | **Quarantined whole**. PushWarden does not guess where legitimate code ends |
| Fake font, disguised payload, malicious editor task file, propagation script | **Quarantined** |
| `.gitignore` entries that hide the malware | The listed **lines are removed**, the rest of the file is kept |
| Remote access tool service, LaunchAgent, scheduled task, cron line or directory | **Disabled and quarantined**. The crontab is backed up first |
| HIGH and WARNING findings | **Reported only** |

## The dialog

A dialog shows the threat name, the file, the reason, and the exact indicators found (the matched string, its offset, whitespace padding, the C2 host).

| Answer | Effect |
|---|---|
| Remove | The quarantined copy is deleted. A record stays in the history |
| Restore and allow | The exact file is put back and that content is not flagged again for 30 days |
| No answer | The file stays in quarantine |

In a terminal scan the same question is asked as text. `--gui` forces the dialog, `--no-prompt` suppresses questions.

## Quarantine

Quarantine is a folder in the data directory, `~/.pushwarden/quarantine`. Before any file is stripped or deleted, a copy of the original is placed there, and the action is written to `index.jsonl`, the protection history.

- A stripped file stays in place with the payload removed; the untouched original is in quarantine.
- A quarantined file is moved out of the project entirely.
- Copies are kept for 90 days and up to 500 MB in total, oldest deleted first (`quarantine_keep_days`, `quarantine_keep_mb`). An expired copy can no longer be restored, and the history shows the entry as expired. Set a limit to `0` to keep copies until you remove them yourself.

## Restoring, allowing and removing

```sh
pushwarden history                       # what was quarantined, stripped or removed, with threat names
pushwarden history --restore PATH        # put the original back
pushwarden history --allow PATH          # restore and stop flagging this exact content for 30 days
pushwarden history --allow PATH --note "our own icon font"   # also record why it was a false positive
pushwarden history --remove PATH         # delete the quarantined copies for good
pushwarden restore PATH                  # same as history --restore PATH
```

`PATH` is the original location as shown in the list.

| Command | When to use it |
|---|---|
| `--restore` | You need the original for analysis. It is still malicious and will be flagged again |
| `--allow` | The finding was wrong. The decision is tied to the file's content hash, so a changed file is checked again |
| `--remove` | You are sure and want the copy gone |

Allowed files are stored in `decisions.json` and expire after 30 days.

## Alerts

```sh
pushwarden alerts [--last N] [--gui] [--json]
```

Shows recent alerts: when, the severity and threat name, the file or process, a `why:` line and a `response:` line. This is what a click on a desktop notification opens. Alerts are stored in `alerts.log`.

## Reporting a false positive

```sh
pushwarden feedback --false-positive PATH --note "what it really is"
```

This records that the finding was wrong without changing the file. The note is included in the feedback bundle and, if enabled, the daily digest and central upload, so the indicator can be tightened. See [Team reporting](team-reporting.md).

## If an infection is found

PushWarden removes the malware. It cannot undo the theft of credentials that already happened. Treat every secret on the machine as leaked.

1. **Do not `git pull`.** The remote may re-infect you. Clean the remote first with [`pushwarden github-clean`](github-clean.md) or the GitHub web editor.
2. **Confirm processes and persistence are gone.** The guard has already handled the CRITICAL ones. Check `pushwarden status` and `pushwarden history`.
3. **Rotate everything.** GitHub password and personal access tokens, SSH keys, OAuth apps, the npm token, cloud tokens (Vercel, Netlify, AWS), every value in `.env` files, browser sessions, and the password-manager vault if it was unlocked.
4. **Audit every repository you can push to** for force-pushes and unverified commits. Check *Settings, Applications* and *Deploy keys* on GitHub for anything you did not add.
5. **Reinstall Node and npm** from nodejs.org if `npm/lib/cli.js` was touched.
6. **Tell collaborators** to scan their machines and to `git pull` only after the remote is clean.
7. **Report it** at <https://opensourcemalware.com>.

The full checklist is in [`analysis/remediation-checklist.md`](https://github.com/FaheemRafiq/pushwarden/blob/main/analysis/remediation-checklist.md).

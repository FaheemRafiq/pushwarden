---
title: Troubleshooting and FAQ
description: "Solutions to common PushWarden problems and answers to frequent questions about detection, performance, privacy and removal."
---
# Troubleshooting and FAQ

## Troubleshooting

### `status` says the guard is not alive

Check the service:

| System | Command |
|---|---|
| Linux | `systemctl --user status pushwarden-guard.service` |
| macOS | `launchctl list com.pushwarden.guard` |
| Windows | Task Scheduler, task "PushWarden Guard" |

Run `pushwarden guard --verbose --once` in a terminal to see errors directly. `pushwarden install` registers the service again.

### `pushwarden: command not found` after installing

The install directory was added to your `PATH` in the shell start-up file. Open a new terminal.

### Real-time shows `off` or `polling`

On Linux the inotify watch limit may be exhausted when there are many large repositories. Raise `fs.inotify.max_user_watches`. The guard falls back to polling, and the 5-second and 6-hour layers keep working, so protection continues.

### Firewall says `not active` or `until reboot`

The one-time administrator prompt was declined or could not be shown, for example on a headless server without polkit.

```sh
sudo pushwarden protect --install     # Linux and macOS
pushwarden protect --install          # Windows, from an elevated terminal
pushwarden protect --status
```

### A legitimate file was quarantined

```sh
pushwarden history
pushwarden history --allow PATH --note "what the file really is"
```

This restores the file and stops flagging that exact content. Please also open an issue with the file so the indicator can be tightened.

### A process is flagged repeatedly

The alert in `pushwarden alerts` shows the indicator and the command line. Update the indicators first, since false positives are fixed there without a new release:

```sh
pushwarden update-iocs
systemctl --user restart pushwarden-guard.service    # Linux
```

If it persists, open an issue with the alert.

### Clicking a macOS notification opens Script Editor

Builds before 0.3 posted notifications through osascript. Run `pushwarden install` again: it builds the notification helper app, and macOS asks once whether PushWarden may send notifications. Allow it.

### `github-clean` says `push-failed`

The branch is protected, the repository is archived, or the token lacks write access. Temporarily allow the push or add yourself to the bypass list, or unarchive the repository, then run again for that repository with `--repo owner/name --apply`. A non-fast-forward error means someone pushed between clone and push; run again.

### `github-clean` cannot find a token

Pass `--token`, export `GITHUB_TOKEN`, or run `gh auth login`. A fine-grained token must list the repositories and grant *Contents: Read and write*.

### `github-clean` was interrupted

Run the same command again. Finished branches are remembered and skipped. `pushwarden github-clean --progress` shows what is already verified.

### The central upload shows events waiting

`pushwarden status` says since when the server has not been reached and why. Common causes: the machine is offline, `upload_url` does not start with `https://`, the key is wrong, or the table was not created with `docs/supabase.sql`. Nothing is lost; the guard retries by itself. `pushwarden feedback --upload` tries immediately and prints the error.

### A setting I changed has no effect

The guard reads its configuration when it starts. Restart the service.

### The data directory is large

```sh
pushwarden cleanup --dry-run
pushwarden cleanup
```

See [Disk use and cleanup](disk-and-cleanup.md).

### Uninstall completely

```sh
pushwarden uninstall --unblock --purge
```

Then delete the install directory shown by `pushwarden status`.

## Frequently asked questions

### Does PushWarden replace my antivirus?

No. It targets one malware family and knows it in depth. Keep your general antivirus.

### Does it need administrator rights?

No, except for the optional firewall block, which asks once.

### Will it slow my machine down?

The real-time layer is idle until a file is written. The 5-second check takes a few milliseconds. The full sweep every 6 hours takes seconds to a minute. Scanning `node_modules` is off by default because it is slow.

### Does it send my code or file names anywhere?

No. Nothing leaves the machine unless you set a webhook, digest or upload URL. See [Security and privacy](security-and-privacy.md).

### Can it delete something I need?

Every file is copied to quarantine before it is changed or removed, and `pushwarden history --restore PATH` puts it back. Quarantined copies are kept for 90 days by default.

### What if I want it to ask before touching anything?

```sh
pushwarden config --set action=ask
```

Or `action=report` to only notify.

### How do I stop it flagging a file?

`pushwarden history --allow PATH` for one file, or `pushwarden config --set exclude=DIR` for a directory.

### How quickly are new variants covered?

Indicators are refreshed every 24 hours without a new release. `pushwarden update-iocs` forces it.

### Does it work offline?

Yes. Protection needs no network. Indicators and updates are fetched when a connection is available.

### Does it work in CI?

Yes. See [CI and automation](ci-and-automation.md).

### Does it support GitHub Enterprise?

`github-clean` does, through `--api URL`.

### How do I see everything it did?

`pushwarden history --all`. See [Activity history](activity-history.md).

### I found the malware. What now?

Follow the checklist in [Response and recovery](response-and-recovery.md#if-an-infection-is-found). Removing the files is not enough: rotate every credential the machine held.

### Where do I report a bug or a false positive?

<https://github.com/FaheemRafiq/pushwarden/issues>. Attach the output of `pushwarden feedback`, which is redacted by default.

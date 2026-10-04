---
title: Moving from ThreatScan
description: "PushWarden is the new name of ThreatScan. What was renamed in version 0.5.0, what keeps working, and the steps to move an existing ThreatScan installation."
---
# Moving from ThreatScan

PushWarden was called ThreatScan up to version 0.4. The name changed in version 0.5.0 because "ThreatScan" is used by other security products. It is the same program with the same features and the same release signing key.

## What was renamed

| | Before | Now |
|---|---|---|
| Command | `threatscan` | `pushwarden` |
| Repository | `github.com/FaheemRafiq/threatscan` | `github.com/FaheemRafiq/pushwarden` |
| Documentation | `faheemrafiq.github.io/threatscan` | `faheemrafiq.github.io/pushwarden` |
| Data directory | `~/.threatscan` | `~/.pushwarden` (an existing `~/.threatscan` keeps being used, see below) |
| Environment variables | `THREATSCAN_HOME`, `THREATSCAN_ROOTS`, ... | `PUSHWARDEN_HOME`, `PUSHWARDEN_ROOTS`, ... |
| Background service | `threatscan-guard.service`, `com.threatscan.guard`, "ThreatScan Guard" | `pushwarden-guard.service`, `com.pushwarden.guard`, "PushWarden Guard" |
| Downloads | `ThreatScan-Setup.exe`, `ThreatScan.pkg`, `threatscan-linux-amd64.deb` | `PushWarden-Setup.exe`, `PushWarden.pkg`, `pushwarden-linux-amd64.deb` |
| Marker for files that hold signatures on purpose | `threatscan:allow-signatures` | `pushwarden:allow-signatures` |

## Moving an existing installation

ThreatScan does not turn into PushWarden through its own update, because the download names changed. Do this once on each machine.

1. **Remove ThreatScan.** Your settings, history and quarantine are not deleted by this.

   ```sh
   threatscan uninstall --unblock
   ```

   On Windows you can also remove it under *Settings, Apps*. `--unblock` removes the firewall block, which asks for administrator rights; PushWarden sets up its own in the next step.

2. **Install PushWarden** as described in [Installation](installation.md).

3. **Check it.**

   ```sh
   pushwarden status
   pushwarden history
   ```

   `status` should show the guard alive, and `history` should show what ThreatScan recorded.

## Your data is kept

PushWarden looks for its data directory in this order:

1. the folder named by `PUSHWARDEN_HOME`, if that variable is set;
2. `~/.pushwarden`, if it exists;
3. `~/.threatscan`, if it exists;
4. otherwise a new `~/.pushwarden`.

So a machine that had ThreatScan keeps its settings, protection history, quarantine, allow decisions and github-clean progress without any step from you. New installations get `~/.pushwarden`.

To switch an existing machine to the new folder name, do it while the guard is stopped:

```sh
pushwarden uninstall
mv ~/.threatscan ~/.pushwarden
pushwarden install
```

## What you need to change yourself

- **Environment variables.** The old `THREATSCAN_*` names are not read. Rename them in CI pipelines, scripts and shell start-up files, for example `THREATSCAN_HOME` to `PUSHWARDEN_HOME`. The full list is in [Configuration](configuration.md#environment-variables).
- **The install one-liner and workflow references.** Use `FaheemRafiq/pushwarden` in the install command and in any `uses:` line that calls the reusable workflow. See [CI and automation](ci-and-automation.md).
- **The allow marker.** A file in your own repositories that carries `threatscan:allow-signatures` needs `pushwarden:allow-signatures` instead, or PushWarden flags it.
- **Commands in scripts and hooks.** Replace `threatscan` with `pushwarden`. A pre-commit hook installed by ThreatScan calls the old command: run `pushwarden harden --pre-commit .` in that repository to install it again.

Nothing changes for the central event upload: the upload address is a setting and stays as you configured it. Only the example table name in the documentation is now `pushwarden_events`.

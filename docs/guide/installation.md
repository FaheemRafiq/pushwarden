---
title: Installation
description: "How to install, update and remove PushWarden on Linux, macOS and Windows, and what the installer changes on the machine."
---
# Installation

Coming from ThreatScan, the earlier name of this program? See [Moving from ThreatScan](moving-from-threatscan.md) first.

PushWarden installs for the current user only and needs no administrator password. The download page at <https://faheemrafiq.github.io/pushwarden/> picks the right file for your system.

## Linux and macOS: one command

Paste into a terminal. No `sudo` is needed.

```sh
curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/pushwarden/main/installers/install.sh | sh
```

The script downloads the release binary for your system, verifies its SHA-256 against the published `checksums.txt`, and runs `pushwarden install --unattended`.

Options are passed as environment variables in front of `sh`:

| Variable | Effect |
|---|---|
| `PUSHWARDEN_ROOTS="~/code ~/work"` | project directories to watch. Default: auto-discover the usual places under your home folder |
| `PUSHWARDEN_WEBHOOK=URL` | send alerts from this machine to a Slack, Discord, Teams or custom webhook |
| `PUSHWARDEN_FEEDBACK_URL=URL` | opt in to the daily digest of counts. See [Team reporting](team-reporting.md) |
| `PUSHWARDEN_UPLOAD_URL=URL`, `PUSHWARDEN_UPLOAD_KEY=KEY` | opt in to the central event upload. See [Team reporting](team-reporting.md) |
| `PUSHWARDEN_VERSION=v0.2.0-rc1` | install a specific release, for example a pre-release |
| `PUSHWARDEN_NO_INSTALL=1` | only put the program in place; do not start the guard. Useful in CI |
| `PUSHWARDEN_NO_BLOCK=1` | do not ask for administrator rights to block the C2 servers |
| `PUSHWARDEN_BASE_URL=URL` | download the release assets from a mirror |

Example:

```sh
curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/pushwarden/main/installers/install.sh | \
  PUSHWARDEN_WEBHOOK=https://hooks.slack.com/services/T000/B000/XXXX PUSHWARDEN_ROOTS="~/code ~/work" sh
```

## Windows

Download and run [PushWarden-Setup.exe](https://github.com/FaheemRafiq/pushwarden/releases/latest/download/PushWarden-Setup.exe).

The installer is not code-signed yet. If SmartScreen appears, choose *More info*, then *Run anyway*.

## Packages

Every release also ships packages on the [latest release page](https://github.com/FaheemRafiq/pushwarden/releases/latest).

| File | System | Notes |
|---|---|---|
| `PushWarden.pkg` | macOS | Not notarized yet. Open it once, then go to *System Settings, Privacy & Security* and click *Open Anyway*. Or run `installer -pkg ~/Downloads/PushWarden.pkg -target CurrentUserHomeDirectory` |
| `pushwarden-linux-amd64.deb`, `pushwarden-linux-arm64.deb` | Debian, Ubuntu | Installed with `sudo`; sets PushWarden up for the user who ran `sudo` |
| `pushwarden-linux-amd64.rpm`, `pushwarden-linux-arm64.rpm` | Fedora, RHEL, openSUSE | Same |
| `pushwarden-<os>-<arch>` | any | The bare binary. Run `./pushwarden-... install` yourself |

Every file is listed with its SHA-256 in `checksums.txt`, and `checksums.txt.sig` is its ed25519 signature.

## What the installer does

1. **Places the program.** The binary is copied to a per-user install directory (on Linux `~/.local/share/pushwarden`) and linked from `~/.local/bin`. If that folder is not on your `PATH`, one line marked `# added by pushwarden install` is appended to your shell start-up file. Open a new terminal afterwards.
2. **Hardens editors.** Every VS Code-family editor found gets `task.allowAutomaticTasks = off` and workspace trust turned on. See [Hardening](hardening.md).
3. **Registers the guard.** The background guard becomes a user service: a systemd `--user` unit on Linux, a LaunchAgent on macOS, a Scheduled Task on Windows. It starts at sign-in.
4. **Blocks the C2 servers.** This is the only step that needs administrator rights. The installer asks once through the native password dialog, polkit or UAC. Declining is fine; add it later with `pushwarden protect --install`. See [Blocking C2 servers](network-block.md).
5. **Runs a first full scan** in the background and cleans anything CRITICAL it finds. Originals go to quarantine.
6. **Adds a shortcut to the guided screens.** On Windows, **PushWarden** in the Start menu; on macOS, `PushWarden.app` in the `Applications` folder of your home folder. Both open [the guided screens](guided-screens.md) for cleaning GitHub repositories. On Linux, run `pushwarden ui`.
7. **Keeps itself up to date.** See [Updates](updates.md).

## Installing by hand: `pushwarden install`

The one-liner and the packages call this command for you. Run it yourself to change the setup or after downloading the bare binary.

```sh
pushwarden install [options]
```

| Option | Effect |
|---|---|
| `--roots DIR` | project directory to watch. Repeatable |
| `--webhook URL` | URL that receives JSON alerts |
| `--feedback-url URL` | opt in to the daily digest |
| `--upload-url URL`, `--upload-key KEY` | opt in to the central event upload |
| `--no-block-c2` | do not ask for administrator rights to block the C2 servers |
| `--deep` | the guard also scans `node_modules` and `vendor` (slow) |
| `--full-interval SECONDS` | seconds between full sweeps (default 21600) |
| `--no-harden` | skip editor hardening |
| `--npm-ignore-scripts` | also set `ignore-scripts=true` in `~/.npmrc` |
| `--no-kill` | never kill processes automatically |
| `--no-prompt` | never show dialogs; quarantine automatically |
| `--no-clean` | when no dialog can be shown, leave files in place instead of quarantining |
| `--unattended` | for installers: no questions, first scan in the background |
| `--dry-run` | show what would be done and change nothing |

## Verify the installation

```sh
pushwarden status
```

The output shows whether the guard is alive, which real-time backend it uses, the service state, the indicator version, the firewall state, disk use and the hardening state of each editor.

## Updating

Nothing to do: the guard updates the program and the indicators on its own. To check or update by hand:

```sh
pushwarden update --check
pushwarden update
pushwarden update-iocs
```

## Uninstalling

```sh
pushwarden uninstall                    # remove the background guard
pushwarden uninstall --unblock          # also remove the firewall block (asks for administrator rights)
pushwarden uninstall --unblock --purge  # also delete the data directory: settings, reports, quarantine
```

The macOS shortcut and notification helper are removed too; on Windows the Start menu entry goes when you uninstall under *Settings, Apps*. Editor hardening is left in place because it is a safe default. To remove the program itself, delete the install directory shown by `pushwarden status`.

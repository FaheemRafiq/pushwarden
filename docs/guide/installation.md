---
title: Installation
description: "How to install, update and remove ThreatScan on Linux, macOS and Windows, and what the installer changes on the machine."
---
# Installation

ThreatScan installs for the current user only and needs no administrator password. The download page at <https://faheemrafiq.github.io/threatscan/> picks the right file for your system.

## Linux and macOS: one command

Paste into a terminal. No `sudo` is needed.

```sh
curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.sh | sh
```

The script downloads the release binary for your system, verifies its SHA-256 against the published `checksums.txt`, and runs `threatscan install --unattended`.

Options are passed as environment variables in front of `sh`:

| Variable | Effect |
|---|---|
| `THREATSCAN_ROOTS="~/code ~/work"` | project directories to watch. Default: auto-discover the usual places under your home folder |
| `THREATSCAN_WEBHOOK=URL` | send alerts from this machine to a Slack, Discord, Teams or custom webhook |
| `THREATSCAN_FEEDBACK_URL=URL` | opt in to the daily digest of counts. See [Team reporting](team-reporting.md) |
| `THREATSCAN_UPLOAD_URL=URL`, `THREATSCAN_UPLOAD_KEY=KEY` | opt in to the central event upload. See [Team reporting](team-reporting.md) |
| `THREATSCAN_VERSION=v0.2.0-rc1` | install a specific release, for example a pre-release |
| `THREATSCAN_NO_INSTALL=1` | only put the program in place; do not start the guard. Useful in CI |
| `THREATSCAN_NO_BLOCK=1` | do not ask for administrator rights to block the C2 servers |
| `THREATSCAN_BASE_URL=URL` | download the release assets from a mirror |

Example:

```sh
curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.sh | \
  THREATSCAN_WEBHOOK=https://hooks.slack.com/services/T000/B000/XXXX THREATSCAN_ROOTS="~/code ~/work" sh
```

## Windows

Download and run [ThreatScan-Setup.exe](https://github.com/FaheemRafiq/threatscan/releases/latest/download/ThreatScan-Setup.exe).

The installer is not code-signed yet. If SmartScreen appears, choose *More info*, then *Run anyway*.

## Packages

Every release also ships packages on the [latest release page](https://github.com/FaheemRafiq/threatscan/releases/latest).

| File | System | Notes |
|---|---|---|
| `ThreatScan.pkg` | macOS | Not notarized yet. Open it once, then go to *System Settings, Privacy & Security* and click *Open Anyway*. Or run `installer -pkg ~/Downloads/ThreatScan.pkg -target CurrentUserHomeDirectory` |
| `threatscan-linux-amd64.deb`, `threatscan-linux-arm64.deb` | Debian, Ubuntu | Installed with `sudo`; sets ThreatScan up for the user who ran `sudo` |
| `threatscan-linux-amd64.rpm`, `threatscan-linux-arm64.rpm` | Fedora, RHEL, openSUSE | Same |
| `threatscan-<os>-<arch>` | any | The bare binary. Run `./threatscan-... install` yourself |

Every file is listed with its SHA-256 in `checksums.txt`, and `checksums.txt.sig` is its ed25519 signature.

## What the installer does

1. **Places the program.** The binary is copied to a per-user install directory (on Linux `~/.local/share/threatscan`) and linked from `~/.local/bin`. If that folder is not on your `PATH`, one line marked `# added by threatscan install` is appended to your shell start-up file. Open a new terminal afterwards.
2. **Hardens editors.** Every VS Code-family editor found gets `task.allowAutomaticTasks = off` and workspace trust turned on. See [Hardening](hardening.md).
3. **Registers the guard.** The background guard becomes a user service: a systemd `--user` unit on Linux, a LaunchAgent on macOS, a Scheduled Task on Windows. It starts at sign-in.
4. **Blocks the C2 servers.** This is the only step that needs administrator rights. The installer asks once through the native password dialog, polkit or UAC. Declining is fine; add it later with `threatscan protect --install`. See [Blocking C2 servers](network-block.md).
5. **Runs a first full scan** in the background and cleans anything CRITICAL it finds. Originals go to quarantine.
6. **Keeps itself up to date.** See [Updates](updates.md).

## Installing by hand: `threatscan install`

The one-liner and the packages call this command for you. Run it yourself to change the setup or after downloading the bare binary.

```sh
threatscan install [options]
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
threatscan status
```

The output shows whether the guard is alive, which real-time backend it uses, the service state, the indicator version, the firewall state, disk use and the hardening state of each editor.

## Updating

Nothing to do: the guard updates the program and the indicators on its own. To check or update by hand:

```sh
threatscan update --check
threatscan update
threatscan update-iocs
```

## Uninstalling

```sh
threatscan uninstall                    # remove the background guard
threatscan uninstall --unblock          # also remove the firewall block (asks for administrator rights)
threatscan uninstall --unblock --purge  # also delete the data directory: settings, reports, quarantine
```

Editor hardening is left in place because it is a safe default. To remove the program itself, delete the install directory shown by `threatscan status`.

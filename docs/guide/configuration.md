---
title: Configuration
description: "Every ThreatScan setting with its default, every file in the data directory, and every environment variable."
---
# Configuration

Settings are stored in `config.json` in the data directory. Read and change them with `threatscan config`.

```sh
threatscan config                                    # print the current configuration
threatscan config --set key=value [--set key=value]  # change settings
```

Booleans take `true` or `false`. Lists are comma-separated. A setting missing from the file has its default value.

The guard reads the file when it starts. Restart it after a change, for example `systemctl --user restart threatscan-guard.service` on Linux.

```sh
threatscan config --set action=ask
threatscan config --set scan_roots=~/code,~/work
threatscan config --set webhook_url=https://hooks.slack.com/services/...
threatscan config --set auto_update=false
```

## Settings

### What is scanned

| Key | Default | Meaning |
|---|---|---|
| `scan_roots` | `[]` | directories the guard watches and `scan --home` covers. Empty means auto-discover |
| `exclude` | `[]` | directories never scanned |
| `js_all` | `true` | scan every script file, not only known config names |
| `deep` | `false` | also scan `node_modules` and `vendor` |

### Schedule

| Key | Default | Meaning |
|---|---|---|
| `realtime` | `true` | real-time file watcher on |
| `quick_interval` | `5` | seconds between process and network checks |
| `full_interval` | `21600` | seconds between full sweeps |

### Response

| Key | Default | Meaning |
|---|---|---|
| `action` | `quarantine` | what the guard does with a CRITICAL file: `quarantine`, `ask`, `delete` or `report` |
| `auto_kill` | `true` | kill processes that match a kill-list indicator |
| `auto_clean` | `true` | with `action=ask`, quarantine when nobody answers the dialog |
| `prompt` | `true` | show native dialogs |
| `prompt_timeout` | `180` | seconds a dialog waits before the default applies |

`action` values:

| Value | Behaviour |
|---|---|
| `quarantine` | move the file to quarantine first (reversible), then show a dialog: remove for good, or restore and allow |
| `ask` | show the dialog first; on timeout quarantine if `auto_clean` is on |
| `delete` | remove without asking. Stripped files keep a backup in quarantine; deleted files do not |
| `report` | alert only, never touch files. Processes are still killed if `auto_kill` is on |

### Notifications

| Key | Default | Meaning |
|---|---|---|
| `notify_desktop` | `true` | desktop notifications |
| `notify_min_severity` | `HIGH` | lowest severity that notifies |
| `notify_sweeps` | `true` | notification when a background full sweep starts and finishes |
| `webhook_url` | `""` | receives a JSON POST per alert |
| `webhook_min_severity` | `HIGH` | lowest severity that posts |

### Network block

| Key | Default | Meaning |
|---|---|---|
| `block_c2` | `true` | keep the system-wide C2 block installed; the guard reminds you daily while it is missing |

### Indicators and updates

| Key | Default | Meaning |
|---|---|---|
| `ioc_update` | `true` | download indicators |
| `ioc_update_interval` | `86400` | seconds between indicator downloads |
| `ioc_update_url` | `""` | alternative indicator URL, for mirrors and forks |
| `auto_update` | `true` | update the program automatically |
| `update_channel` | `stable` | `stable` or `beta` |
| `update_interval` | `21600` | seconds between update checks |
| `update_api_url` | `""` | alternative release API, for mirrors |

### Records and disk limits

| Key | Default | Meaning |
|---|---|---|
| `report_keep` | `60` | number of reports kept |
| `journal` | `true` | record every finding, action, decision, sweep and error in `journal.jsonl` |
| `journal_min_severity` | `WARNING` | lowest finding severity recorded in the journal |
| `journal_keep_mb` | `100` | journal archives kept, in total. `0` = no limit |
| `journal_keep_days` | `365` | oldest journal archive kept. `0` = no limit |
| `quarantine_keep_days` | `90` | quarantined originals are deleted after this many days. `0` = keep until removed by hand |
| `quarantine_keep_mb` | `500` | size of the quarantine folder. `0` = no limit |
| `clone_keep_days` | `3` | how long `github-clean` keeps a repository copy waiting for `--apply` |
| `clone_keep_mb` | `2048` | those copies in total; a larger repository is not kept |

### Team reporting (all opt-in)

| Key | Default | Meaning |
|---|---|---|
| `feedback_url` | `""` | the guard posts a daily digest of counts here |
| `feedback_identify` | `false` | include the host name in the digest |
| `upload_url` | `""` | the guard uploads redacted journal events to this table endpoint |
| `upload_key` | `""` | the insert-only API key sent with each upload |

## Files and directories

The data directory is `~/.threatscan`. Override it with `THREATSCAN_HOME`.

| Path | Content |
|---|---|
| `config.json` | settings |
| `iocs.json` | downloaded indicators; the program carries an embedded copy as fallback |
| `journal.jsonl`, `journal-DATE.jsonl.gz` | the activity record and its rotated archives |
| `journal-DATE.pruned` | a tiny marker for a deleted archive, holding its event count |
| `guard.log`, `guard-DATE.log.gz` | the guard's text log and its archives |
| `alerts.log`, `alerts-DATE.log.gz` | one JSON line per alert, and its archives |
| `reports/` | timestamped JSON reports plus `latest.json` |
| `quarantine/` | copies of every stripped or deleted file, and `index.jsonl`, the protection history |
| `decisions.json` | files you chose to allow, with their content hash |
| `guard/` | heartbeat and state of the running guard |
| `machine-id` | a random identifier used only in the optional digest and central upload |
| `upload-state.json` | central upload: how many events are uploaded, last attempt, last success, last error |
| `github-clean-state.json` | what `github-clean` already verified, per repository and branch. No token |
| `github-clean-clones/` | repository copies kept so `--apply` does not download them again |

Outside the data directory:

| Path | Content |
|---|---|
| per-user install directory, on Linux `~/.local/share/threatscan` with a link in `~/.local/bin` | the program. Override with `THREATSCAN_INSTALL_DIR` |
| `ThreatScan Notifier.app` in the install directory | macOS only: the helper that posts notifications |
| `/etc/threatscan`, `/Library/Application Support/ThreatScan` or `%ProgramData%\ThreatScan` | root-owned state and indicators of the C2 block |
| `/usr/local/lib/threatscan`, `/usr/local/libexec/threatscan` or `%ProgramFiles%\ThreatScan` | root-owned copy of the program for the C2 block |
| `settings.json.threatscan-<timestamp>.bak` beside each editor's settings | backup made by hardening |

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `THREATSCAN_HOME` | every command | data directory instead of `~/.threatscan` |
| `THREATSCAN_INSTALL_DIR` | `install`, `update` | where the program is installed |
| `GITHUB_TOKEN`, `GH_TOKEN` | `github-clean` | token when `--token` is not given |
| `NO_COLOR` | every command | disable coloured output |
| `PAGER`, `THREATSCAN_NO_PAGER` | `help` | pager for long pages; set the second to disable paging |
| `THREATSCAN_NO_BLOCK` | `install`, `protect`, `uninstall` | never ask for administrator rights |
| `THREATSCAN_ROOTS` | install script | space-separated project directories to watch |
| `THREATSCAN_WEBHOOK` | install script | webhook URL |
| `THREATSCAN_FEEDBACK_URL` | install script | opt in to the daily digest |
| `THREATSCAN_UPLOAD_URL`, `THREATSCAN_UPLOAD_KEY` | install script | opt in to the central event upload |
| `THREATSCAN_VERSION` | install script | install this release instead of the latest |
| `THREATSCAN_NO_INSTALL` | install script | download the program only, do not register the guard |
| `THREATSCAN_BASE_URL` | install script | download from a mirror |

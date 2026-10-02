---
title: Disk use and cleanup
description: "Every store ThreatScan keeps on disk, the size or age limit of each, and how threatscan cleanup and the daily housekeeping enforce them."
---
# Disk use and cleanup

ThreatScan is meant to run for months without attention, so nothing it stores may grow without bound. Every store in the data directory has a limit. The guard enforces the limits once a day, and `threatscan cleanup` does the same on demand.

```sh
threatscan cleanup [--dry-run]
```

The command prints each store with its size and limit, then removes what is past its limit. `--dry-run` shows what would be removed and removes nothing.

`threatscan status` shows the total in its `Disk use` line.

## Limits

| Store | Limit | Setting |
|---|---|---|
| Journal archives (`journal-*.jsonl.gz`) | 100 MB in total and 365 days; oldest deleted first. The active `journal.jsonl` rotates at 10 MB | `journal_keep_mb`, `journal_keep_days` |
| Quarantined originals | 90 days and 500 MB; oldest deleted first | `quarantine_keep_days`, `quarantine_keep_mb` |
| Repository copies kept by `github-clean` | 3 days without use and 2 GB in total; a repository larger than the limit is not kept | `clone_keep_days`, `clone_keep_mb` |
| `github-clean` progress | repositories not seen for 90 days are forgotten | |
| Guard log | rotates at 5 MB; newest 5 archives kept | |
| Alerts log | rotates at 5 MB; newest 3 archives kept | |
| Reports | newest 60 | `report_keep` |
| Allow decisions | removed when they expire after 30 days | |
| Editor settings backups (`settings.json.threatscan-*.bak`) | newest 2 per file | |
| Leftovers in the system temp folder from an interrupted `github-clean` | removed after a day | |

Set a limit to `0` to turn it off:

```sh
threatscan config --set quarantine_keep_days=0    # keep quarantined files until removed by hand
threatscan config --set journal_keep_mb=500       # keep more history
```

## What expiry means for each store

**Journal.** The oldest archives are deleted. History before that point is no longer available with `history --archive`.

**Quarantine.** An expired copy can no longer be restored. The history keeps the entry and shows it as expired with the reason.

**Repository copies.** `github-clean --apply` downloads the repository again. Nothing else is lost.

## Journal pruning and the central upload

When the [central event upload](team-reporting.md) is on:

- A journal archive whose events are not all uploaded yet is kept until twice the journal limits, so a long offline period does not lose events.
- Past that, the disk limit wins. `guard.log` says how many events were dropped unsent.
- Deleting an archive does not disturb the upload. A small marker file (`journal-DATE.pruned`) keeps the event count, so no event is sent twice and the uploaded or waiting state of the remaining events stays correct.

## What is never deleted automatically

- the active journal, guard log and alerts log
- `config.json`, `iocs.json`, the machine id and state files
- any file ThreatScan does not recognise by name. The cleanup only removes files it created, identified by their name pattern, inside the data directory and its own leftovers in the temp folder

## Example output

```
  store              size   limit
  journal           12 MB   100 MB of archives, 365 days
  quarantine       5.7 MB   500 MB, 90 days
  logs             1.5 MB   5 MB each, 5 + 3 archives
  reports          120 KB   60 reports
  clones           3.8 MB   2048 MB, 3 days
  other             40 KB   settings, indicators, state
  total             23 MB

  Would remove 3 old guard logs (585 KB)
  Would remove 1 quarantined copies (5.7 MB): past the quarantine limit; they can no longer be restored
```

## Memory

The guard is idle between events. The real-time layer reacts to file-system notifications, the quick layer does a few milliseconds of work every 5 seconds, and a full sweep runs every 6 hours. A long upload backlog is read and sent in slices of 2000 events, so memory use does not grow with the backlog.

## Removing everything

```sh
threatscan uninstall --unblock --purge
```

`--purge` deletes the whole data directory. Then delete the install directory shown by `threatscan status`.

---
title: Activity history
description: "The journal that records every finding, action, decision, sweep and error, and how to read and filter it with threatscan history and threatscan alerts."
---
# Activity history

ThreatScan keeps a complete record of what it saw and did on the machine. The record is the journal; `threatscan history` reads it.

## The journal

`journal.jsonl` in the data directory holds one JSON object per line. It is append-only and written by the guard, by `scan` and by `github-clean`.

| Kind | What is recorded |
|---|---|
| `finding` | every sighting of every finding at WARNING or above, with no deduplication |
| `action` | kill, quarantine, strip, delete, restore, purge, allow |
| `decision` | an answer you gave in a dialog or terminal question |
| `sweep` | the start and end of a full pass, with duration and counts; each `github-clean` branch result |
| `guard` | guard starts and stops |
| `update` | indicator and program updates |
| `error` | failed actions, recovered crashes, refused or rolled-back updates |
| `feedback` | a finding you marked as a false positive |

Each event carries the time, the ThreatScan and indicator versions, the context that produced it (`guard-full`, `guard-quick`, `realtime`, `scan`, `github-clean`, `cli`), and for findings the severity, category, threat name, title, path, process id and command line, the matched text, the evidence, the reason and the response.

Settings:

| Setting | Default | Effect |
|---|---|---|
| `journal` | `true` | keep the journal. When off, history shows only the actions in the quarantine index |
| `journal_min_severity` | `WARNING` | lowest finding severity recorded |
| `journal_keep_mb` | `100` | rotated archives kept in total |
| `journal_keep_days` | `365` | oldest archive kept |

At 10 MB the file is rolled into a compressed archive (`journal-DATE.jsonl.gz`) and a new file starts. The oldest archives are deleted once the archives pass the size or age limit. See [Disk use and cleanup](disk-and-cleanup.md).

## Reading it: `threatscan history`

```sh
threatscan history [filters] [--all] [--details] [--json]
```

### The default view

Two parts.

**Detections** lists each distinct finding once, with when it was last seen, how many times (`14x`), and where it stands:

| State | Meaning |
|---|---|
| `handled` | a response was taken |
| `open` | reported, nothing done |
| `allowed` | you chose to keep it |
| `dry-run` | a dry run showed what would be done |
| `FAILED` | the response failed |

Each detection shows a `why:` line and a `response:` line.

**Actions and decisions** lists what was done, in order: kills, quarantines, strips, your dialog answers, errors and false-positive reports.

### Options

| Option | Effect |
|---|---|
| `--all` | every recorded event in time order, nothing collapsed: each sighting, sweep, update and error |
| `--details` | also the exact matched text, the evidence, the command line and which version recorded it |
| `--severity LEVEL` | only findings at `warning`, `high` or `critical` and above |
| `--kind KIND` | only this kind of event. Repeatable |
| `--since WHEN` | only newer events: `30m`, `24h`, `7d`, `2w`, or a date such as `2026-10-01` |
| `--path TEXT` | only events whose path, title or command line contains the text |
| `--archive` | also read the rotated journal archives |
| `--not-uploaded` | only events still waiting for the central upload. Implies `--all --archive` |
| `--limit N` | number of rows per part (default 50) |
| `--json` | the raw events as JSON |
| `--restore PATH` | put a quarantined original back |
| `--allow PATH` | restore and stop flagging this exact content for 30 days. With `--note` the reason is recorded |
| `--remove PATH` | delete the quarantined copies permanently |

### Examples

```sh
threatscan history                                    # the summary
threatscan history --severity critical --since 7d     # what was serious this week
threatscan history --all --kind sweep                 # every sweep with duration and counts
threatscan history --kind error                       # anything ThreatScan itself got wrong
threatscan history --all --path my-project --details  # everything about one project, with evidence
threatscan history --all --since 2026-10-01 --json    # machine-readable
```

## Upload state per event

When the [central event upload](team-reporting.md) is on, each event is either `uploaded` or `waiting`:

- `history --all` shows an `upload` column
- `history --details` shows a `central upload:` line
- `history --json` carries `"uploaded": true` or `false`
- `history --not-uploaded` lists what is still waiting

## Alerts

```sh
threatscan alerts [--last N] [--gui] [--json]
```

| Option | Effect |
|---|---|
| `--last N` | number of alerts to show (default 10) |
| `--gui` | show them in a native dialog |
| `--json` | print the raw records from `alerts.log` |

An alert is written for every batch of findings that contains something HIGH or CRITICAL. Each alert shows when it happened, the severity and threat name, the file or process, a `why:` line and a `response:` line. Clicking a desktop notification opens this view.

The difference from history: alerts are what you were notified about; history is everything.

## Other records

| File | Content |
|---|---|
| `guard.log` | the guard's text log, one line per event |
| `reports/` | one JSON report per full scan, plus `latest.json` |
| `quarantine/index.jsonl` | the protection history: every action on a file |

## Sending the record to someone

`threatscan feedback` packages the journal, the log tail, the latest report, the settings and a status summary into one redacted zip file. See [Team reporting](team-reporting.md).

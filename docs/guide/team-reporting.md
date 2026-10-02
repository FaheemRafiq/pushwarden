---
title: Team reporting
description: "The four ways information can leave a machine, all opt-in: webhook alerts, the feedback bundle, the daily digest and the central event upload to Supabase, with exactly what each contains."
---
# Team reporting

ThreatScan keeps everything on the machine by default. A team lead or maintainer who wants to see what is happening across machines has four tools. Three send data and are off until their URL is set; the fourth writes a file that a person sends by hand.

| Tool | What leaves the machine | How | Default |
|---|---|---|---|
| Webhook alerts | each alert: host name, platform, findings with paths, reasons | JSON POST per alert | off |
| Feedback bundle | the journal, log tail, latest report, settings and status, redacted | a zip file the person sends | nothing is sent |
| Daily digest | counts only; no paths, command lines or file contents | JSON POST once a day | off |
| Central event upload | every journal event, redacted | batches to a database table | off |

`threatscan status` shows whether the webhook and the central upload are on.

## Redaction

The bundle and the central upload pass every text through the same redactor:

- the home folder is written as `~`
- the user name and the host name are removed
- anything shaped like a secret is masked: GitHub, AWS, Slack and API tokens, private keys, Supabase keys and other JSON Web Tokens, credentials inside URLs, and the values of `token`, `password`, `api_key`, `webhook_url`, `upload_key` and similar keys

## Webhook alerts

```sh
threatscan config --set webhook_url=https://hooks.slack.com/services/T000/B000/XXXX
```

Or at install time with `THREATSCAN_WEBHOOK=URL`.

Each alert at or above `webhook_min_severity` (default `HIGH`) is posted as JSON:

| Field | Content |
|---|---|
| `text` | a formatted message for Slack |
| `content` | the same for Discord |
| `host`, `platform` | the machine |
| `context` | what produced the alert: guard, real-time, scan |
| `findings` | the findings with severity, category, title, path, details, action |
| `reasons` | for each finding: the `why` and the `response` |

One URL therefore works for Slack, Discord, Teams and your own endpoint. Webhook alerts are not redacted: they are meant for your own channel and include the host name and paths.

## Feedback bundle

```sh
threatscan feedback [--days N] [--out FILE] [--no-redact]
```

Writes `threatscan-feedback-DATE.zip` in the current folder. Nothing is uploaded; the command tells you what is in the file so you can look before you send it.

| File in the zip | Content |
|---|---|
| `README.txt` | the period, the number of events, whether it is redacted |
| `summary.txt` | version, system, guard, service, firewall and policy status |
| `journal.jsonl` | every event in the period (default: the last 14 days) |
| `guard.log` | the last 2000 lines of the guard log |
| `latest-report.json` | the most recent full scan report |
| `config.json` | the settings in effect, with URLs and keys masked |

| Option | Effect |
|---|---|
| `--days N` | how many days of activity to include (default 14) |
| `--out FILE` | where to write the bundle |
| `--no-redact` | keep paths, user and host names. Token-shaped strings are masked regardless |

## Reporting a false positive

```sh
threatscan feedback --false-positive PATH --note "what it really is"
```

Records that the finding on `PATH` was wrong, with an optional note. It does not change the file; `threatscan history --allow PATH` does that. The note travels with the bundle, the digest and the central upload.

## Daily digest

Off unless `feedback_url` is set.

```sh
threatscan config --set feedback_url=https://hooks.slack.com/services/T000/B000/XXXX
```

Or at install time with `THREATSCAN_FEEDBACK_URL=URL`.

Once a day the guard posts a summary to that URL. A Slack or Discord webhook works. It contains:

- a random machine id, the version, the operating system and the indicator version
- findings per severity and per category
- actions taken and failed
- dialog answers
- sweep count and durations
- errors
- the notes written with false-positive reports

It never contains file contents, command lines or paths. A false-positive report carries the file's base name only. The host name is included only with `feedback_identify=true`.

```sh
threatscan feedback --digest     # print exactly what would be sent
```

## Central event upload

Off unless `upload_url` is set. No URL is built into the program.

It gives whoever maintains ThreatScan for a team the full record from every machine in one database table, so a false positive or a failed action on a colleague's machine can be diagnosed without asking for a bundle.

### What is sent

Every journal event: findings, actions, dialog answers, sweeps, guard starts, updates, errors and false-positive reports. Each row has the severity, category, threat name, title, path, command line, matched text, evidence, the reason and response texts, the action and whether it worked, plus the ThreatScan version, the operating system and the random machine id.

Redaction is always applied on this path and cannot be turned off. File contents are never sent, apart from the matched text and evidence lines of a finding.

```sh
threatscan feedback --preview    # the next rows exactly as they would be stored; sends nothing
threatscan feedback --upload     # send every waiting event now
```

### Delivery

- Batches of 200 over HTTPS. A plain `http://` URL is refused unless it points at this machine. Redirects are not followed.
- The guard checks every minute whether an upload is due, and uploads every 10 minutes when there are new events.
- A long backlog is sent in slices of 2000 events, up to 20000 per run.

### Uploaded or waiting

Every event is either `uploaded` or `waiting`. An event counts as uploaded only after the server accepted the batch it was in.

- `threatscan status` shows the totals and the time of the last upload, or since when the server has been unreachable and why.
- `threatscan history --all` shows the state of each event. `--not-uploaded` lists what is waiting.
- The state belongs to the URL that is set. After `upload_url` changes, every event is waiting again and the new destination receives the full record.
- The state is counted by an event's position in the journal, not by its timestamp, so a clock change cannot make an event look uploaded.

### Offline behaviour

Protection does not need the network, and every event is written to the local journal first.

- While the server cannot be reached, events stay `waiting`.
- The guard tries again after 1, 2, 4 and 8 minutes, then every 10 minutes. A machine that is back online delivers its backlog within minutes.
- `guard.log` gets one line when uploads start failing and one when they work again.
- If a batch was stored but the answer was lost, it is sent again. Each event has a fixed id and the table skips ids it already holds, so nothing is stored twice.
- Journal archives that still hold unsent events are kept until twice the journal limits.

### Setting it up with Supabase

[Supabase](https://supabase.com) is hosted Postgres with a REST API; there is no server to run.

1. Create a project. Open the SQL editor, paste [`docs/supabase.sql`](https://github.com/FaheemRafiq/threatscan/blob/main/docs/supabase.sql) and run it. It creates the table `threatscan_events`, four views and the access rules.
2. In the project's API settings copy the project URL and the public key, named `anon` or `publishable`. Never put the `service_role` or `secret` key on a machine.
3. On each machine, at install time:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.sh | \
     THREATSCAN_UPLOAD_URL=https://PROJECT.supabase.co/rest/v1/threatscan_events THREATSCAN_UPLOAD_KEY=KEY sh
   ```

   Or on a machine that already runs ThreatScan:

   ```sh
   threatscan config --set upload_url=https://PROJECT.supabase.co/rest/v1/threatscan_events upload_key=KEY
   threatscan feedback --preview
   threatscan feedback --upload
   ```

   Restart the guard after `config --set`.
4. Read the data in the Supabase dashboard.

| View | Shows |
|---|---|
| `threatscan_false_positive_signals` | what users said was wrong: dialog answers "keep" and false-positive reports, with their notes |
| `threatscan_findings_summary` | each distinct finding with sightings and how many machines see it. One machine only is a hint of a false positive |
| `threatscan_tool_errors` | failed actions, recovered crashes, refused updates |
| `threatscan_machines` | per machine: last event, last upload, version, operating system, indicator version, average sweep time |

### Why the key on the machines is safe to distribute

The SQL turns row level security on with a single insert policy for the public key. That key can add rows and nothing else: it cannot read, change or delete anything, and the views are closed to it as well. Someone who extracts the key from a machine can add junk rows, nothing more.

### Other servers

Any server works if it accepts a JSON array by POST, with the key in the `apikey` and `Authorization: Bearer` headers, and answers with a 2xx status. A `409` answer means "already stored".

## Telling users

If you enable the digest or the central upload for a team, tell the people whose machines report. `threatscan status` shows the upload state, `threatscan feedback --preview` and `--digest` show exactly what is sent, and `threatscan install` prints a line when the upload is on.

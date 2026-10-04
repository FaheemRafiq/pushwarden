<!-- pushwarden:allow-signatures -->
# PushWarden command-line reference

PushWarden is a single binary. Every feature is a subcommand:

```
pushwarden <command> [options]
```

This page documents each command, its options, exit codes, the configuration keys,
the files PushWarden keeps, and the environment variables it reads. For the install
one-liner and a description of the threat, see the [README](https://github.com/FaheemRafiq/pushwarden#readme) and the
[documentation site](https://faheemrafiq.github.io/pushwarden/guide/overview.html).

## Contents

- [Conventions](#conventions)
- [Quick start](#quick-start)
- [Commands](#commands)
  - [scan](#scan) · [status](#status) · [history and restore](#history-and-restore) · [alerts](#alerts) · [feedback](#feedback) · [cleanup](#cleanup)
  - [github-clean](#github-clean) · [ui](#ui)
  - [guard](#guard) · [install](#install) · [uninstall](#uninstall)
  - [update](#update) · [update-iocs](#update-iocs)
  - [harden](#harden) · [protect](#protect) · [config](#config)
  - [check-staged](#check-staged) · [version](#version) · [help](#help)
- [Configuration keys](#configuration-keys)
- [Files and directories](#files-and-directories)
- [Environment variables](#environment-variables)
- [Severities, actions and threat names](#severities-actions-and-threat-names)
- [Recipes](#recipes)
- [Troubleshooting](#troubleshooting)

---

## Conventions

- **Flags** accept one or two dashes: `-fix` and `--fix` are the same. Flags may come before or
  after positional arguments.
- **`pushwarden [dirs]`** with no command is short for `pushwarden scan [dirs]`.
- **`pushwarden <command> -h`** prints that command's options. **`pushwarden help <command>`**
  prints this documentation for it, in the terminal, offline.
- **Exit codes** follow one rule everywhere: `0` clean or done, `1` threats found or not fully
  fixed, `2` usage error, nothing scanned, or an internal failure. Commands that only display
  information return `0`.
- **Nothing needs root** except `protect`, which edits the firewall and the hosts file.
- **Every destructive step is reversible.** Files are copied to the quarantine before they are
  stripped or deleted, and `pushwarden history` puts them back.

## Quick start

```sh
pushwarden install              # background guard + editor hardening + first scan
pushwarden status               # is everything running?
pushwarden scan --home          # audit every project under your home folder now
pushwarden github-clean         # dry run: which of my GitHub repos and branches are infected?
pushwarden github-clean --apply # fix and push them
pushwarden ui                   # clean your GitHub repositories the easy way, on guided screens
```

---

## Commands

### scan

One-off scan of repositories and of this computer.

```
pushwarden scan [options] [directories]
```

With no directories it scans the current working directory. In a terminal a progress bar shows
which repository is being scanned; in CI or a pipe, numbered progress lines are printed instead. Each directory is walked for git
repositories and for projects with a `package.json`, `go.mod` or `composer.json`. Every script,
config, font, image and `.vscode/*.json` file in them is checked. Then the host is checked:
running processes, network connections to known command-and-control (C2) addresses, persistence
(systemd units, LaunchAgents, scheduled tasks, cron, shell rc files), remote access tool
footprints, editor injection and exposed credentials.

| Option | Effect |
|---|---|
| `--home` | also scan the common project directories under your home folder (or `scan_roots` from the config) |
| `--deep` | also descend into `node_modules` and `vendor` (slow) |
| `--configs-only` | only check the known config and entry-file names, the old v4 scope |
| `--no-system` | skip the host checks |
| `--no-repos` | skip the repository checks |
| `--verbose` | list every repository, including clean ones |
| `--fix` | act on CRITICAL findings without asking: strip the payload or quarantine the file, remove PolinRider entries from `.gitignore`, kill malicious processes, remove persistence. Reversible |
| `--dry-run` | show what `--fix` would do and change nothing |
| `--gui` | ask about each malicious file with a native dialog instead of in the terminal |
| `--no-prompt` | report only. Never ask, never change a file |
| `--notify` | send a desktop notification and, if configured, a webhook when anything HIGH or above is found |
| `--json FILE` | also write the report as JSON to `FILE` |
| `--no-report` | do not save the report under the data directory |
| `--ci` | CI mode: no colour, compact output, never prompt |
| `--js-all` | accepted for compatibility; scanning every script is already the default |

**What happens when something is found.** In an interactive terminal, a CRITICAL finding with
strong evidence triggers a question per file: remove, or keep and allow. With `--gui` the question
is a native dialog. With `--fix` the reversible action is taken without asking. With `--no-prompt`
or `--ci` nothing is touched. Findings that PushWarden cannot fix on its own (for example a
compromised package version in a lockfile) are printed with a remediation hint.

**Exit codes:** `0` clean, `1` HIGH or CRITICAL findings, `2` error or nothing scanned.

Examples:

```sh
pushwarden scan                          # this directory
pushwarden scan ~/code ~/work            # specific directories
pushwarden scan --home --no-system       # repositories only
pushwarden scan --home --fix             # clean up without questions
pushwarden scan --ci --json report.json  # in a pipeline; exit 1 fails the job
pushwarden --deep ~/proj                 # same as `pushwarden scan --deep ~/proj`
```

### status

Protection status: a score, what each layer of protection is doing, and the details.

```
pushwarden status
```

The output has three parts.

**The verdict.** A score out of 100 with a bar, one word for it and a sentence on what it means:
`PROTECTED` (90 or more), `PARTLY PROTECTED` (65 to 89) or `AT RISK` (below 65). When the latest
sweep found something critical or high the word is `THREATS FOUND`, whatever the score. On a
terminal the PushWarden shield is drawn beside it in the colour of the verdict; piped or in CI
the same information is plain text.

**Protection.** One line per layer, marked `OK`, ` !` (partly) or `!!` (missing), with the command
that fixes it:

| Layer | Points | Full marks when |
|---|---|---|
| Background guard | 25 | the guard is alive |
| Real-time file protection | 15 | a native watcher is in use (8 for polling) |
| Starts when you sign in | 10 | the user service is registered |
| Malware servers blocked | 10 | the firewall block is active and persistent (5 if it is lost on restart) |
| Editors cannot auto-run tasks | 10 | every VS Code-family editor found is hardened |
| Indicators up to date | 5 | the indicator file is at most 30 days old |
| Recent full sweep | 5 | a full sweep finished in the last 24 hours |
| Nothing critical or high found | 20 | the latest sweep found none |

The score measures how much of the protection is switched on. It is not a guarantee that the
machine is clean; `scan --home` and `history` show what was actually found.

**Details.** Whether the guard is alive and which real-time backend it uses (inotify, kqueue,
ReadDirectoryChangesW, or polling); during a sweep the Guard line reads `scanning 7/17 repositories
(name)` and updates as it goes. Then the service state, the installed binary, the time of the
last full sweep, how many repositories are tracked, the indicator version, the configured
action policy, webhook and firewall state, the data directory, the summary of the latest sweep,
and each VS Code-family editor with its `task.allowAutomaticTasks` setting. Always exits `0`.

### history and restore

Everything PushWarden has seen and done on this machine: every detection, every kill, quarantine and
strip, every answer you gave in a dialog, every error.

```
pushwarden history [filters] [--all] [--details] [--json]
pushwarden history --restore PATH
pushwarden history --allow PATH [--note "what it really is"]
pushwarden history --remove PATH
pushwarden restore PATH            # same as history --restore PATH
```

**The default view** has two parts. *Detections* lists each distinct finding once, with when it
was last seen, how many times (`14x`), and where it stands: `handled`, `open`, `allowed`, `dry-run`
or `FAILED`. *Actions and decisions* lists what was done, in order, with the reason.

| Option | Effect |
|---|---|
| `--all` | every recorded event in time order, nothing collapsed: each sighting, sweep, update and error |
| `--details` | also the exact matched text, the evidence, the command line and which version recorded it |
| `--severity LEVEL` | only findings at `warning`, `high` or `critical` and above |
| `--kind KIND` | only this kind of event: `finding`, `action`, `decision`, `sweep`, `guard`, `update`, `error`, `feedback`. Repeatable |
| `--since WHEN` | only newer events: `30m`, `24h`, `7d`, `2w`, or a date such as `2026-10-01` |
| `--path TEXT` | only events whose path, title or command line contains the text |
| `--archive` | also read the rotated journal archives |
| `--not-uploaded` | only the events still waiting to be uploaded to `upload_url`, see [feedback](#feedback). Implies `--all --archive` |
| `--limit N` | number of rows per part (default 50) |
| `--json` | the raw events as JSON |
| `--restore PATH` | put the original file back at `PATH`. It is still malicious and will be flagged again |
| `--allow PATH` | restore and stop flagging this exact file content, remembered for 30 days. With `--note` the reason is recorded as feedback |
| `--remove PATH` | delete the quarantined copies permanently |

`PATH` is the original location as shown in the list.

**Where it comes from.** The journal, `journal.jsonl` in the data directory, records every sighting
of every finding at WARNING or above, with no deduplication, plus every action, decision, sweep,
update and error. At 10 MB it is rolled into a gzip archive beside it and a new file starts. The
oldest archives are deleted once the archives pass 100 MB in total or are older than a year
(`journal_keep_mb`, `journal_keep_days`; see [cleanup](#cleanup)). Turn it off with `pushwarden config --set journal=false`; history then shows only the
actions kept in the quarantine index.

Examples:

```sh
pushwarden history --severity critical --since 7d     # what was serious this week
pushwarden history --all --kind sweep                 # every sweep with duration and counts
pushwarden history --kind error                       # anything PushWarden itself got wrong
pushwarden history --all --path A-Bot-Ledger --details
```

### alerts

Recent alerts with the reason for each one. This is what a click on a desktop notification opens.

```
pushwarden alerts [--last N] [--gui] [--json]
```

| Option | Effect |
|---|---|
| `--last N` | number of alerts to show (default 10) |
| `--gui` | show them in a native dialog instead of the terminal |
| `--json` | print the raw records from `alerts.log` |

Each alert shows when it happened, the severity and threat name, the file or process, a `why:` line
explaining what the evidence means and why it has that severity, and a `response:` line saying
what was done and why (killed, stripped, quarantined, or left for you to decide).

### github-clean

Remove PolinRider from every branch of every GitHub repository you can push to.

```
pushwarden github-clean [options]
```

PolinRider steals a token, rewrites your repositories and force-pushes the backdoor to every
branch it can reach. `github-clean` undoes that at the same scale. For every repository:

1. bare-clone it once;
2. check out each branch in its own worktree;
3. run the repository scanner;
4. strip trailing payloads from config files, delete whole-file threats (fake fonts, malicious
   `.vscode/tasks.json`, propagation scripts) and remove the entries PolinRider adds to
   `.gitignore` to hide them, with the same reversible protector as `scan --fix`;
5. commit once per infected branch and push with an explicit refspec.

History is never rewritten and nothing is force-pushed. A push the remote refuses (protected
branch, archived repository, permission) is reported, not forced.

**Dry run is the default.** Without `--apply` nothing is committed or pushed; the output says what
would change on each branch.

**Progress is remembered.** Every branch that is finished (clean, fixed and pushed, or flagged for
manual review) is recorded right away, together with the commit it was verified at. If a run is
interrupted with Ctrl-C, hangs, or the machine goes to sleep, run the same command again: branches
whose tip is still that commit are skipped, and a repository where nothing moved is not even
cloned. The summary counts what this run did and what earlier runs did. A branch is checked again
when its tip changes, because the attacker can push again, and when PushWarden or its indicators
are updated, because a newer version may find more. Dry-run findings, refused pushes and errors
are never recorded as done. `--progress` shows what is remembered; `--fresh` forgets it and checks
everything.

**From dry run to fix without doing the work twice.** A dry run in a terminal that finds
infected branches ends with a question: `Fix and push these 12 branches in 4 repositories now?`
Answer `y` and the fixes are committed and pushed in the same run. Answer no, and a later
`--apply` picks up from there:

| After a dry run, `--apply` … | |
|---|---|
| branches found clean | are skipped, as long as their tip has not moved |
| repositories where every branch was clean | are not cloned |
| repositories with infected branches | are **not cloned again**: the dry run's copy is kept in the data directory and only new commits are fetched |
| the infected branches | are scanned once more, then fixed, committed and pushed |

The second scan of an infected branch is deliberate. The fix is made from the files as they are
on the branch at that moment, so nothing stale is ever pushed, and it takes a moment per branch.
A kept copy is a bare repository with no checked-out files and no token. It is deleted as soon
as its repository has nothing left to fix, after 3 days without use (`clone_keep_days`), when the
copies together pass 2 GB (`clone_keep_mb`, least recently used first), or by `--fresh`. A
repository larger than that limit is not kept at all.

| Option | Effect |
|---|---|
| `--apply` | commit and push the fixes |
| `--token PAT` | the GitHub token. Also read from `GITHUB_TOKEN`, then `GH_TOKEN`, then the `gh` CLI login |
| `--token-stdin` | read the token from standard input, for secret managers and CI |
| `--select` | list the reachable repositories with numbers and pick which to clean and in which order |
| `--repo owner/name` | only this repository. Repeatable; run in the order given |
| `--owner NAME` | only repositories under this user or organisation. Repeatable |
| `--branch GLOB` | only branches matching this glob, for example `release/*`. Repeatable. Default: all |
| `--list` | print the repositories the token can push to and exit |
| `--include-forks` | also clean forks (skipped by default) |
| `--include-archived` | also clean archived repositories. GitHub rejects pushes to them until they are unarchived |
| `--author "Name <email>"` | identity for the fix commits. Default: your git config, then `PushWarden <pushwarden@users.noreply.github.com>` |
| `--keep-clones DIR` | keep the clones under `DIR` for inspection instead of deleting them |
| `--json FILE` | write the full result to `FILE` |
| `--api URL` | GitHub Enterprise API base, default `https://api.github.com` |
| `--ci` | no colour, no interactive prompts |
| `--progress` | show what earlier runs already verified, per repository, and exit. Needs no token and no network |
| `--fresh` | forget the progress of earlier runs, delete the kept copies and check every branch again |
| `--no-ask` | after a dry run, do not offer to fix what was found. `--ci` implies it |

**The token.** Create a fine-grained personal access token with *Repository permissions,
Contents: Read and write* on the repositories you want cleaned (a classic token needs the
`repo` scope). The token is handed to git through an askpass helper built into the binary and
an environment variable; it is never written to disk, into a remote URL, or into the report.
Stored git credential helpers, hooks and `core.fsmonitor` are disabled while git runs.

**Selecting repositories.** `--select` prints a numbered list; type `3`, `1,4,2`, `5-9` or
`all`. The order you type is the order the repositories are processed, so put the important one
first. `--repo` does the same non-interactively.

**Per-branch status** in the output and in the JSON:

| Status | Meaning |
|---|---|
| `clean` | nothing to do |
| `clean, unchanged since verified …` / `fixed earlier …` | taken from an earlier run: the branch is still at the commit that was verified. In the JSON: `"resumed": true` |
| `infected` | dry run: this branch needs fixes |
| `pushed` | fixed and pushed; the short commit hash is shown |
| `push-failed` | fixed locally, the remote refused the push. The error is shown |
| `manual` | HIGH or CRITICAL findings PushWarden does not fix automatically. Review them |
| `error` | clone, worktree, commit or scan failure |

Repository-wide findings about commits in history that touch payload code are listed under
`history`. They are informational; removing them would need a force-push.

**Exit codes:** `0` everything clean or fixed and pushed, `1` infected branches remain (dry run,
refused pushes, errors), `2` no token, bad token, or an API failure.

**Afterwards.** Rotate the token you used and every secret those repositories or their CI could
read. Check *Settings, Applications* and *Deploy keys* on GitHub for anything you did not add.
Tell collaborators to `git pull`. Quarantined originals are in `pushwarden history`.

Examples:

```sh
pushwarden github-clean --list
pushwarden github-clean                                     # dry run over everything
pushwarden github-clean --select --apply                    # pick from a list
pushwarden github-clean --apply                             # interrupted? the same command continues
pushwarden github-clean --progress                          # what is already verified
pushwarden github-clean --repo me/api --repo me/web --apply
pushwarden github-clean --owner my-org --branch main --branch 'release/*' --apply
GITHUB_TOKEN=... pushwarden github-clean --ci --apply --json clean.json
op read op://Vault/GitHub/token | pushwarden github-clean --token-stdin --apply
```

### ui

The easy way to clean your GitHub repositories: guided screens walk you through what
[github-clean](#github-clean) does.

```
pushwarden ui [options]
```

There are no commands to remember. The Windows installer adds a **PushWarden**
entry to the Start menu and `pushwarden install` on macOS builds `~/Applications/PushWarden.app`;
both open a terminal window on these screens. On Linux, run `pushwarden ui`.

1. **Sign in.** Accounts already on the machine are found: tokens from `GITHUB_TOKEN`, `GH_TOKEN`
   and each `gh` login, and the logins git has over SSH (hosts in `~/.ssh/config` that lead to
   github.com). With several you choose from a list. With none, the screen explains how to
   create a token and takes it in a masked field; it is used for this run only and never
   written to disk. `s` on the repository list or the final report switches to another account.
2. **Choose repositories.** A list with checkboxes, nothing ticked to begin with. Each row shows
   what earlier runs verified and whether the repository is cloned on this computer. Forks and
   archived repositories are hidden until you show them. A token account lists every
   repository it can push to. An SSH account cannot ask GitHub for that list: it shows the
   local clones that use its SSH host, the account's public repositories, and names you add
   with `+`.
3. **Check.** A dry run over what you chose. Nothing is changed.
4. **Review.** Every infected branch and the files that would be fixed.
5. **Fix and push,** only after you answer `y`. One normal commit per infected branch, never a
   force-push, exactly as `github-clean --apply`.

Stopping with `q` or `Ctrl+C` keeps what is finished: the next run continues where this one
stopped, and shares that progress with `github-clean`.

| Option | Effect |
|---|---|
| `--api URL` | GitHub API base URL (GitHub Enterprise). |
| `--fresh` | Forget the progress of earlier runs and check every branch again. |
| `--pause` | If it cannot start, wait for Enter before closing. The shortcuts use this. |

**Exit codes:** as [github-clean](#github-clean); `2` also when there is no interactive terminal.
For scripts and CI use `github-clean`.

### feedback

Package this machine's activity so whoever maintains PushWarden for your team can analyse it, or
report that a finding was wrong.

```
pushwarden feedback [--days N] [--out FILE] [--no-redact]
pushwarden feedback --false-positive PATH [--note "what it really is"]
pushwarden feedback --digest
pushwarden feedback --preview
pushwarden feedback --upload
```

| Option | Effect |
|---|---|
| (none) | write `pushwarden-feedback-DATE.zip` in the current folder: the journal for the last 14 days, the tail of the guard log, the latest report, the configuration and a status summary |
| `--days N` | how many days of activity to include |
| `--out FILE` | where to write the bundle |
| `--no-redact` | keep paths, user and host names. Token-shaped strings are masked regardless |
| `--false-positive PATH` | record that the finding on `PATH` was wrong, with an optional `--note`. Does not change the file; `history --allow` does that |
| `--digest` | print the daily digest that `feedback_url` would receive |
| `--preview` | print the next events that `upload_url` would receive, exactly as they would be stored, and how many are waiting. Sends nothing |
| `--upload` | send every waiting event to `upload_url` now instead of waiting for the guard |

**Nothing is uploaded unless you opted in.** Without options this command writes a file and tells
you what is in it, so you can look before you send it. The digest and the central event upload
below are both off until their URL is set, and `pushwarden status` shows whether the upload is on.

**Redaction, on by default.** The home folder is written as `~`, the user name and host name are
removed, and anything shaped like a secret is masked: GitHub, AWS, Slack and API tokens, private
keys, Supabase keys and other JSON Web Tokens, credentials inside URLs, and the values of `token`,
`password`, `api_key`, `webhook_url`, `upload_key` and similar keys.

**The optional daily digest.** Off unless `feedback_url` is set, for example by the team lead at
install time with `PUSHWARDEN_FEEDBACK_URL`. Once a day the guard then posts a summary to that
URL (a Slack or Discord webhook works). It contains a random machine id, the version, the OS and
counts: findings per severity and category, actions taken and failed, dialog answers, sweep
durations, errors, and the notes written with false-positive reports. It never contains file
contents, command lines or paths; a false-positive report carries the file's base name only. The
host name is included only with `feedback_identify=true`. `pushwarden feedback --digest` shows
exactly what would be sent.

**The optional central event upload.** Off unless `upload_url` is set. It gives whoever maintains
PushWarden for a team the full record from every machine in one database table, so a false
positive or a failed action on a colleague's machine can be diagnosed without asking for a
bundle. Every 10 minutes the guard sends the journal events it has not sent yet: findings,
actions, dialog answers, sweeps, guard starts, updates, errors and false-positive reports.
No URL is built into the program: nothing is uploaded until `upload_url` is set on the machine.

What is sent: each event with its severity, category, threat name, title, path, command line,
matched text, evidence, the reason and response texts, the action and whether it worked, plus the
PushWarden version, the OS and the random machine id. What is removed first, always: the home
folder becomes `~`, the user name and host name are taken out, and secrets are masked as
described under redaction above. This path has no switch to turn redaction off. File contents
are never sent, apart from the matched text and evidence lines of a finding.
`pushwarden feedback --preview` prints the rows before anything leaves the machine.

Delivery: batches of 200 over HTTPS. A plain `http://` URL is refused unless it points at this
machine, and redirects are not followed.

**Every event is either `uploaded` or `waiting`.** An event counts as uploaded only after the
server accepted the batch it was in. `pushwarden status` shows the totals and the time of the
last upload, `pushwarden history --all` shows the state of each event in an `upload` column,
`history --not-uploaded` lists what is still waiting, and `history --json` carries
`"uploaded": true|false`. The state belongs to the URL that is set: after `upload_url` changes,
every event is waiting again and the new destination receives the full record. The state is
counted by an event's position in the journal, not by its timestamp, so a clock change cannot
make an event look uploaded.

**Offline.** Protection does not need the network, and every event is written to the local
journal first. While the server cannot be reached the events stay `waiting`; `status` shows since
when and why. The guard tries again after 1, 2, 4 and 8 minutes and then every 10 minutes, so a
machine that is back online delivers its backlog within minutes, all of it in one run (up to
20000 events). `guard.log` gets one line when uploads start failing and one when they work again.
If a batch was stored but the answer was lost, it is sent again; each event has a fixed id and
the table skips ids it already holds, so nothing is stored twice. Journal archives that still
hold unsent events are kept until twice the journal limits, so an offline period has to be very
long before events are dropped unsent; if that happens `guard.log` says how many.

Setting it up with [Supabase](https://supabase.com) (hosted Postgres, no server to run):

1. Create a project. Open the SQL editor, paste
   [`docs/supabase.sql`](https://github.com/FaheemRafiq/pushwarden/blob/main/docs/supabase.sql)
   and run it. It creates the table `pushwarden_events`, four views and the access rules.
2. In the project's API settings copy the project URL and the public key, named `anon` or
   `publishable`. Never use the `service_role` or `secret` key on a machine.
3. On each machine, at install time:

   ```
   curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/pushwarden/main/installers/install.sh | \
     PUSHWARDEN_UPLOAD_URL=https://PROJECT.supabase.co/rest/v1/pushwarden_events PUSHWARDEN_UPLOAD_KEY=KEY sh
   ```

   or on a machine that already runs PushWarden:

   ```
   pushwarden config --set upload_url=https://PROJECT.supabase.co/rest/v1/pushwarden_events upload_key=KEY
   pushwarden feedback --preview
   pushwarden feedback --upload
   ```

   The guard reads its settings when it starts, so restart it after `config --set`
   (`systemctl --user restart pushwarden-guard.service` on Linux, or sign out and in).
4. Read the data in the Supabase dashboard:

| View | Shows |
|---|---|
| `pushwarden_false_positive_signals` | what users said was wrong: dialog answers "keep" and `--false-positive` reports, with their notes |
| `pushwarden_findings_summary` | each distinct finding with sightings and how many machines see it. One machine only is a hint of a false positive |
| `pushwarden_tool_errors` | failed actions, recovered panics, refused updates |
| `pushwarden_machines` | per machine: last event, last upload, version, OS, indicator version, average sweep time |

The key on the machines can only add rows. The SQL turns row level security on with a single
insert policy for that key, so it cannot read, change or delete anything, and the views are closed
to it as well. Someone who extracts the key from a machine can add junk rows, nothing more. Any
other server works too if it accepts a JSON array by POST with the key in the `apikey` and
`Authorization: Bearer` headers and answers 2xx.

### cleanup

Show what PushWarden occupies on disk and remove what is past its limits.

```
pushwarden cleanup [--dry-run]
```

PushWarden is meant to run for months without attention, so nothing it stores may grow without
bound. Every store in the data directory has a limit. The guard enforces them once a day;
this command does the same on demand and prints the sizes. `--dry-run` shows what would be
removed and removes nothing. `pushwarden status` shows the total in its `Disk use` line.

| Store | Limit | Setting |
|---|---|---|
| journal archives (`journal-*.jsonl.gz`) | 100 MB in total and 365 days; oldest deleted first. The active `journal.jsonl` rotates at 10 MB | `journal_keep_mb`, `journal_keep_days` |
| quarantined originals | 90 days and 500 MB; oldest deleted first. `history` then shows the entry as expired, and it can no longer be restored | `quarantine_keep_days`, `quarantine_keep_mb` |
| repository copies kept by `github-clean` | 3 days without use and 2 GB in total | `clone_keep_days`, `clone_keep_mb` |
| `github-clean` progress | repositories not seen for 90 days are forgotten | |
| guard log | rotates at 5 MB, 5 archives kept | |
| alerts log | rotates at 5 MB, 3 archives kept | |
| reports | newest 60 | `report_keep` |
| allow decisions | removed when they expire after 30 days | |
| editor settings backups (`settings.json.pushwarden-*.bak`) | newest 2 per file | |
| leftovers in the system temp folder from an interrupted `github-clean` | removed after a day | |

Set a limit to `0` to turn it off, for example `pushwarden config --set quarantine_keep_days=0`
to keep quarantined files until you remove them yourself.

When the central upload is on, a journal archive whose events are not all uploaded yet is kept
until twice the journal limits. Deleting an archive does not disturb the upload: a small marker
(`journal-DATE.pruned`) keeps the count, so no event is sent twice and the uploaded/waiting state
of the remaining events stays correct.

### guard

Run the background protection loop in this terminal. `install` registers this as a user
service; run it by hand to debug or on a machine without a service manager.

```
pushwarden guard [--once] [--dry-run] [--verbose]
```

| Option | Effect |
|---|---|
| `--once` | one full pass, then exit |
| `--dry-run` | detect and alert but never kill or quarantine |
| `--verbose` | print the log to the terminal as well as to `guard.log` |

The loop runs four layers, each timed by a configuration key:

| Layer | Work | Key |
|---|---|---|
| real-time | native file-system watcher over the project roots, `~/Downloads` and `~/Desktop`; each written file is scanned as it lands | `realtime` |
| quick | processes and network connections to C2 addresses | `quick_interval` (5 s) |
| full | every repository plus host persistence, RATs, editor injection, credentials | `full_interval` (6 h) |
| definitions | download and validate `iocs.json` | `ioc_update_interval` (24 h) |

Findings go through the `action` policy (see [Configuration keys](#configuration-keys)), then
through desktop notification and webhook. Configuration is read at start: restart the guard after
`pushwarden config --set`.

### install

Install the background guard so it starts at sign-in, harden editors, run a first scan.

```
pushwarden install [options]
```

Everything is per user: the binary is copied to a per-user install directory and linked from
`~/.local/bin`. When that folder is not on your PATH (the macOS default), one line is appended to
your shell start-up file (`~/.zshrc` on macOS, `~/.bashrc` or `~/.profile` on Linux), marked
`# added by pushwarden install`; open a new terminal afterwards. The guard is registered as a
systemd `--user` service, a LaunchAgent or a Scheduled Task,
and every VS Code-family editor found gets `task.allowAutomaticTasks = off` and workspace trust
turned on.

| Option | Effect |
|---|---|
| `--roots DIR` | project directory to watch. Repeatable. Default: auto-discover the usual places under your home folder |
| `--webhook URL` | URL that receives JSON alerts (Slack, Discord, Teams or your own endpoint) |
| `--feedback-url URL` | opt in to the daily digest of counts, see [feedback](#feedback) |
| `--upload-url URL` | opt in to the central event upload: the table endpoint that receives redacted events, see [feedback](#feedback) |
| `--upload-key KEY` | the insert-only key for `--upload-url` |
| `--no-block-c2` | do not ask for administrator rights to block the C2 servers (default is to ask once; see [protect](#protect)) |
| `--deep` | the guard also scans `node_modules` and `vendor` (slow) |
| `--full-interval SECONDS` | seconds between full sweeps (default 21600) |
| `--no-harden` | skip editor hardening |
| `--npm-ignore-scripts` | also set `ignore-scripts=true` in `~/.npmrc` |
| `--no-kill` | never kill processes automatically |
| `--no-prompt` | never show dialogs; quarantine automatically |
| `--no-clean` | when no dialog can be shown, leave files in place instead of quarantining |
| `--unattended` | for installers: no questions, first scan in the background |
| `--dry-run` | show what would be done and change nothing |

On macOS it also builds `~/Applications/PushWarden.app`, a shortcut that opens [ui](#ui) in Terminal;
the Windows installer adds the same shortcut to the Start menu.

The one-line installer from the README calls this for you; its environment variables
`PUSHWARDEN_ROOTS`, `PUSHWARDEN_WEBHOOK`, `PUSHWARDEN_FEEDBACK_URL`, `PUSHWARDEN_UPLOAD_URL`,
`PUSHWARDEN_UPLOAD_KEY`, `PUSHWARDEN_VERSION` and `PUSHWARDEN_NO_INSTALL` map onto these options.

### uninstall

Remove the background guard.

```
pushwarden uninstall [--unblock] [--purge]
```

| Option | Effect |
|---|---|
| `--unblock` | also remove the C2 block: the boot-time job, the firewall rules and the hosts entries (asks for administrator rights) |
| `--purge` | also delete the data directory: config, reports, quarantine |

Editor hardening is left in place because it is a safe default.

### update

Update PushWarden to the latest release.

```
pushwarden update [--check]
```

`--check` only reports whether a newer release exists. Releases are verified before they replace
the binary: the checksums file is signed with the project's ed25519 key and the download's
SHA-256 must match. The previous binary is kept; if the new one fails to start the guard rolls
back. The guard does this on its own every `update_interval` seconds when `auto_update` is on.
`update_channel` `beta` also considers pre-releases.

### update-iocs

Download the latest indicator file.

```
pushwarden update-iocs [--url URL]
```

The default source is the file on the project's `main` branch. The download is parsed and
validated (every regex must compile, every IP and hash must be well formed) before it replaces
the previous copy, and a file whose version is not newer is ignored. A running guard picks a new
file up at its next definitions check; restart the service to use it immediately.

### harden

Apply preventive settings without installing the guard.

```
pushwarden harden [options]
```

| Option | Effect |
|---|---|
| (none) | harden every VS Code-family editor found: `task.allowAutomaticTasks = off`, workspace trust on |
| `--npm-ignore-scripts` | set `ignore-scripts=true` in `~/.npmrc`, so installs never run lifecycle scripts |
| `--undo-npm` | remove that setting again |
| `--pre-commit REPO` | install a pre-commit hook in `REPO` that runs `pushwarden check-staged`. Repeatable. An existing hook is kept as `pre-commit.pre-pushwarden` |
| `--dry-run` | show what would change |

### protect

Block the PolinRider command-and-control (C2) servers system-wide and keep them blocked.

```
pushwarden protect [--install | --refresh | --uninstall | --status | --block-c2 | --unblock] [--dry-run]
```

`pushwarden install` does this for you: it asks once for administrator rights (native password
dialog on macOS, polkit or sudo on Linux, UAC on Windows) and registers a small privileged job
that re-applies the block at every boot and refreshes the address list once a day. You only need
`protect` directly to check on it, to add it later, or to remove it.

| Option | Effect |
|---|---|
| `--install` (default) | block now and register the boot-time job. Needs administrator rights; asks for them when run as a normal user |
| `--status` | is the block active, and will it survive a reboot? No rights needed |
| `--refresh` | what the job runs: re-apply the rules from the root-owned indicators, then fetch newer ones and re-apply |
| `--uninstall` | remove the job, the firewall rules and the hosts entries |
| `--block-c2` | one-shot block for this boot only, no job (the pre-0.3 behaviour) |
| `--unblock` | remove the rules and hosts entries but keep the job, if any |
| `--dry-run` | show what `--install` would do |

**What gets installed.** Outgoing traffic to every IP on the C2 list is dropped: an `iptables`
chain or `nftables` table named `pushwarden` on Linux, a `pf` anchor on macOS, a Windows Firewall
rule named "PushWarden C2 block". The C2 hostnames are sinkholed in the hosts file between
`# BEGIN PUSHWARDEN C2 SINKHOLE` and `# END` markers. The job that keeps this current is a systemd
timer (`pushwarden-netblock.timer`, at boot and daily), a LaunchDaemon (`com.pushwarden.netblock`)
or a Scheduled Task ("PushWarden NetBlock", runs as SYSTEM at boot and daily).

**Why it uses its own copy of the indicators.** The job runs as root, and the `iocs.json` under
your home folder is writable by anything running as you. A privileged job must not let a
user-writable file decide what goes into the hosts file, so it keeps a root-owned copy under
`/etc/pushwarden`, `/Library/Application Support/PushWarden` or `%ProgramData%\PushWarden`,
refreshed from the project repository only, and runs a root-owned copy of the program.

**Status values** shown by `pushwarden status` and `protect --status`:

| Firewall | Meaning |
|---|---|
| `active (persistent; 25 IPs, 15 hosts; applied 3h ago; indicators …)` | all good |
| `active until reboot (…)` | a one-shot block from `--block-c2`; run `protect --install` to keep it |
| `not active (rules from a previous boot were lost)` | same, after a reboot |
| `not active` | never installed, or removed |

Opt out with `pushwarden install --no-block-c2` or `pushwarden config --set block_c2=false`; the
guard then stops reminding you. Setting `PUSHWARDEN_NO_BLOCK=1` skips the administrator prompt for
one run, which the package installers use because they already did the work as root.

### config

Show or change settings.

```
pushwarden config
pushwarden config --set key=value [--set key=value ...]
```

Without options it prints the current configuration. Keys are the JSON names listed under
[Configuration keys](#configuration-keys). Booleans take `true`/`false`, lists are
comma-separated. The guard reads the file when it starts, so restart the service after a change
(`systemctl --user restart pushwarden-guard.service` on Linux).

```sh
pushwarden config --set action=ask
pushwarden config --set scan_roots=~/code,~/work
pushwarden config --set webhook_url=https://hooks.slack.com/services/...
pushwarden config --set auto_update=false
```

### check-staged

Pre-commit hook helper: scan the files staged for commit and refuse the commit if any carries a
PolinRider indicator at HIGH or above.

```
pushwarden check-staged
```

Run it from inside the repository. Exit `1` blocks the commit, `0` allows it. Install it with
`pushwarden harden --pre-commit .`, or add this to `.git/hooks/pre-commit` yourself:

```sh
#!/bin/sh
pushwarden check-staged || exit 1
```

### version

```
pushwarden version
pushwarden --version
```

Prints the version. Release builds print the release number; development builds end in `-dev`.

### help

Show this documentation in the terminal.

```
pushwarden help                  # command list
pushwarden help <command>        # one command, for example: pushwarden help install
pushwarden help <topic>          # config-keys, files, environment, severities, recipes, troubleshooting
pushwarden help all              # the whole reference
```

The text is embedded in the binary, so it always matches the installed version and works
offline. Long pages go through `$PAGER` (default `less`); set `PUSHWARDEN_NO_PAGER=1` to print
straight to the terminal.

---

## Configuration keys

Stored in `config.json` in the data directory. Change them with `pushwarden config --set`.

| Key | Default | Meaning |
|---|---|---|
| `scan_roots` | `[]` | directories the guard watches and `scan --home` covers. Empty means auto-discover |
| `exclude` | `[]` | directories never scanned |
| `js_all` | `true` | scan every script file, not only known config names |
| `deep` | `false` | also scan `node_modules` and `vendor` |
| `realtime` | `true` | real-time file watcher on |
| `quick_interval` | `5` | seconds between process and network checks |
| `full_interval` | `21600` | seconds between full sweeps |
| `ioc_update_interval` | `86400` | seconds between indicator downloads |
| `ioc_update` | `true` | download indicators at all |
| `ioc_update_url` | `""` | alternative indicator URL, for mirrors |
| `action` | `quarantine` | what the guard does with a CRITICAL file, see below |
| `auto_kill` | `true` | kill processes that match a kill-list indicator |
| `auto_clean` | `true` | with `action=ask`, quarantine when nobody answers the dialog |
| `prompt` | `true` | show native dialogs |
| `prompt_timeout` | `180` | seconds a dialog waits before the default applies |
| `notify_desktop` | `true` | desktop notifications |
| `notify_min_severity` | `HIGH` | lowest severity that notifies |
| `notify_sweeps` | `true` | desktop notification when a background full sweep starts and when it finishes, with the result |
| `webhook_url` | `""` | receives a JSON POST per alert |
| `webhook_min_severity` | `HIGH` | lowest severity that posts |
| `block_c2` | `true` | keep the system-wide C2 block installed; `install` asks for administrator rights once and the guard reminds you daily while it is missing |
| `report_keep` | `60` | number of reports kept |
| `journal` | `true` | record every finding, action, decision, sweep and error in `journal.jsonl` |
| `journal_min_severity` | `WARNING` | lowest finding severity recorded in the journal |
| `journal_keep_mb` | `100` | journal archives kept, in total; the oldest are deleted first. `0` = no limit |
| `journal_keep_days` | `365` | oldest journal archive kept. `0` = no limit |
| `quarantine_keep_days` | `90` | quarantined originals are deleted after this many days. `0` = keep until removed by hand |
| `quarantine_keep_mb` | `500` | size of the quarantine folder; the oldest copies are deleted first. `0` = no limit |
| `clone_keep_days` | `3` | how long `github-clean` keeps a repository copy waiting for `--apply` |
| `clone_keep_mb` | `2048` | those copies in total; a larger repository is not kept |
| `feedback_url` | `""` | opt-in: the guard posts a daily digest of counts here (no paths, no command lines) |
| `feedback_identify` | `false` | include the host name in the digest instead of only a random machine id |
| `upload_url` | `""` | opt-in: the guard uploads redacted journal events to this table endpoint every 10 minutes and catches up after being offline, see [feedback](#feedback) |
| `upload_key` | `""` | the insert-only API key sent with each upload |
| `auto_update` | `true` | update the binary automatically |
| `update_channel` | `stable` | `stable` or `beta` |
| `update_interval` | `21600` | seconds between update checks |
| `update_api_url` | `""` | alternative release API, for mirrors |

**`action` values:**

| Value | Behaviour |
|---|---|
| `quarantine` | move the file to quarantine first (reversible), then show a dialog: remove for good, or restore and allow |
| `ask` | show the dialog first; on timeout quarantine if `auto_clean` is on |
| `delete` | remove without asking. Stripped files keep a backup in quarantine; deleted files do not |
| `report` | alert only, never touch files. Processes are still killed if `auto_kill` is on |

## Files and directories

The data directory is `~/.pushwarden` (override with `PUSHWARDEN_HOME`). If only `~/.threatscan`
exists, from when the program was called ThreatScan, that folder is used instead.

| Path | Content |
|---|---|
| `config.json` | settings |
| `iocs.json` | downloaded indicators; the binary carries an embedded copy as fallback |
| `journal.jsonl` | the complete activity record: every finding at every sighting, every action, decision, sweep, update and error. Rotated at 10 MB into `journal-DATE.jsonl.gz`; the oldest archives are deleted past 100 MB or one year, leaving a tiny `journal-DATE.pruned` marker with their event count |
| `guard.log` | the guard's text log, rotated at 5 MB into `guard-DATE.log.gz`; the newest 5 archives are kept |
| `machine-id` | a random identifier used only in the optional feedback digest and event upload |
| `github-clean-state.json` | what `github-clean` already verified: per repository and branch the commit, the result and the time. No token. Deleted by `github-clean --fresh` |
| `github-clean-clones/` | bare copies of repositories in which a `github-clean` dry run found infected branches, kept so `--apply` does not download them again. Removed when fixed, after 3 days without use, past 2 GB in total, or by `github-clean --fresh` |
| `upload-state.json` | when `upload_url` is set: how many events are uploaded to that URL, the time of the last attempt and success, and the last error. Deleting it sends everything again; the table stores nothing twice |
| `alerts.log` | one JSON line per alert, including the `why` and `response` texts as worded at the time. Rotated at 5 MB; the newest 3 archives are kept |
| `reports/` | timestamped JSON reports plus `latest.json` |
| `quarantine/` | copies of every stripped or deleted file, and `index.jsonl`, the protection history. Copies are deleted after 90 days or past 500 MB |
| `decisions.json` | files you chose to allow, with their content hash; entries are removed when they expire after 30 days |
| `PushWarden Notifier.app` | macOS only, in the install directory: the helper that posts notifications so a click opens `pushwarden alerts --gui` |
| `guard/` | heartbeat and state of the running guard |

The privileged C2 block keeps its own root-owned files: `netblock-state.json` and a copy of
`iocs.json` under `/etc/pushwarden` (Linux), `/Library/Application Support/PushWarden` (macOS) or
`%ProgramData%\PushWarden` (Windows), plus a copy of the program under `/usr/local/lib/pushwarden`,
`/usr/local/libexec/pushwarden` or `%ProgramFiles%\PushWarden`.

The binary itself lives in a per-user install directory, on Linux `~/.local/share/pushwarden`
with a link in `~/.local/bin` (override with `PUSHWARDEN_INSTALL_DIR`).

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `PUSHWARDEN_HOME` | every command | data directory instead of `~/.pushwarden` |
| `PUSHWARDEN_INSTALL_DIR` | `install`, `update` | where the binary is installed |
| `GITHUB_TOKEN`, `GH_TOKEN` | `github-clean` | token when `--token` is not given |
| `NO_COLOR` | every command | disable coloured output |
| `PAGER`, `PUSHWARDEN_NO_PAGER` | `help` | pager for long pages; set the second to disable paging |
| `PUSHWARDEN_NO_BLOCK` | `install`, `protect`, `uninstall` | never ask for administrator rights (package installers, CI) |
| `PUSHWARDEN_ROOTS` | install script | space-separated project directories to watch |
| `PUSHWARDEN_WEBHOOK` | install script | webhook URL |
| `PUSHWARDEN_FEEDBACK_URL` | install script | opt in to the daily digest, see [feedback](#feedback) |
| `PUSHWARDEN_UPLOAD_URL` | install script | opt in to the central event upload, see [feedback](#feedback) |
| `PUSHWARDEN_UPLOAD_KEY` | install script | the insert-only key for `PUSHWARDEN_UPLOAD_URL` |
| `PUSHWARDEN_VERSION` | install script | install this release instead of the latest |
| `PUSHWARDEN_NO_INSTALL` | install script | download the binary only, do not register the guard |
| `PUSHWARDEN_BASE_URL` | install script | download from a mirror |

## Severities, actions and threat names

| Severity | Meaning | Automatic action |
|---|---|---|
| CRITICAL | confirmed PolinRider artifact or activity | yes, per `action` policy |
| HIGH | strong indicator that needs a human: compromised package version, exposed keys on an infected host | no, listed for review |
| WARNING | context worth checking: suspicious git reflog, secrets file in an infected repo, files that arrived in the same commit as a loader (camouflage fonts, decoy README, `.vscode` set) | no |
| INFO | informational | no |

**Why-lines.** Every finding has a one-sentence reason for its severity, and every response
(kill, strip, quarantine, or nothing) has a one-sentence reason too. They appear in scan output,
in the dialogs, in `pushwarden alerts`, in `pushwarden history`, in desktop notifications, in the
webhook JSON (`reasons` array) and in `guard.log`. A process is killed only when its command line
holds a strict PolinRider marker that legitimate tools never use; a broad indicator alone is
reported but not killed, and the reason says so.

Dialogs, notifications and reports name threats Defender-style, for example
`Trojan:JS/PolinRider.FakeFont` for a script disguised as a font, `Trojan:Script/PolinRider` for an
injected loader and `Backdoor:Script/PolinRider.Persist` for a persistence entry.

## Recipes

**CI gate.** Fail the pipeline when a PolinRider indicator lands in the repository:

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/pushwarden/main/installers/install.sh | PUSHWARDEN_NO_INSTALL=1 sh
- run: ~/.local/bin/pushwarden scan --ci --no-system --json pushwarden.json .
```

**Pre-commit hook for every repository you work on:**

```sh
for r in ~/code/*/; do pushwarden harden --pre-commit "$r"; done
```

**Slack, Discord or Teams alerts** from every machine:

```sh
pushwarden config --set webhook_url=https://hooks.slack.com/services/T000/B000/XXXX
```

The POST body contains `text` (Slack), `content` (Discord), `host`, `platform`, `context` and
the `findings` array, so one URL works for all three and for your own endpoint.

**Organisation-wide clean-up after a compromise**, from a machine with a fine-grained token that
has Contents write on the organisation's repositories:

```sh
pushwarden github-clean --owner my-org --list
pushwarden github-clean --owner my-org --json dryrun.json     # review dryrun.json
pushwarden github-clean --owner my-org --apply --json applied.json
```

**Machine audit without touching anything:**

```sh
pushwarden scan --home --no-prompt --verbose --json audit.json
```

## Troubleshooting

**Clicking a macOS notification opens Script Editor.** Builds before 0.3 posted notifications
through osascript. Run `pushwarden install` again: it builds the notification helper app, and
macOS will ask once whether PushWarden may send notifications. Allow it.

**A legitimate file was quarantined.** `pushwarden history` shows it; `pushwarden history --allow
PATH` restores it and stops flagging that exact content. Please also open an issue with the file so
the indicator can be tightened.

**A process is flagged repeatedly.** The alert in `alerts.log` shows the indicator and the command
line. Update indicators first, since false positives are fixed there without a new release:
`pushwarden update-iocs` and then restart the service (`systemctl --user restart
pushwarden-guard.service` on Linux). If it persists, open an issue with the alert line.

**Firewall says `not active` or `until reboot`.** The one-time administrator prompt was declined
or could not be shown (for example a headless server without polkit). Run `sudo pushwarden protect
--install` on Linux and macOS, or `pushwarden protect --install` from an elevated terminal on
Windows. `pushwarden protect --status` confirms it afterwards.

**`status` says the guard is not alive.** Check the service: `systemctl --user status
pushwarden-guard.service` on Linux, `launchctl list | grep pushwarden` on macOS, Task Scheduler
on Windows. Run `pushwarden guard --verbose --once` in a terminal to see errors directly.

**Real-time shows `off` or `polling`.** On Linux the inotify watch limit may be exhausted with many
large repositories; raise `fs.inotify.max_user_watches`. The guard falls back to polling and to the
5-second and 6-hour layers, so protection continues.

**`github-clean` says `push-failed`.** The branch is protected, the repository is archived, or the
token lacks write access. Temporarily allow the push (or add yourself to the bypass list), or
unarchive the repository, then run again for that repository with `--repo owner/name --apply`. A
non-fast-forward error means someone pushed between clone and push; simply run again.

**`github-clean` cannot find a token.** Pass `--token`, export `GITHUB_TOKEN`, or run `gh auth
login`. A fine-grained token must list the repositories and grant *Contents: Read and write*.

**Uninstall completely:** `pushwarden uninstall --unblock --purge`, then delete the install
directory shown by `pushwarden status`.

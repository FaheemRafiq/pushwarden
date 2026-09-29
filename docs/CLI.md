<!-- threatscan:allow-signatures -->
# ThreatScan command-line reference

ThreatScan is a single binary. Every feature is a subcommand:

```
threatscan <command> [options]
```

This page documents each command, its options, exit codes, the configuration keys,
the files ThreatScan keeps, and the environment variables it reads. For the install
one-liner and a description of the threat, see the [README](../README.md).

## Contents

- [Conventions](#conventions)
- [Quick start](#quick-start)
- [Commands](#commands)
  - [scan](#scan) · [status](#status) · [history and restore](#history-and-restore) · [alerts](#alerts)
  - [github-clean](#github-clean)
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
- **`threatscan [dirs]`** with no command is short for `threatscan scan [dirs]`.
- **`threatscan <command> -h`** prints that command's options. **`threatscan help <command>`**
  prints this documentation for it, in the terminal, offline.
- **Exit codes** follow one rule everywhere: `0` clean or done, `1` threats found or not fully
  fixed, `2` usage error, nothing scanned, or an internal failure. Commands that only display
  information return `0`.
- **Nothing needs root** except `protect`, which edits the firewall and the hosts file.
- **Every destructive step is reversible.** Files are copied to the quarantine before they are
  stripped or deleted, and `threatscan history` puts them back.

## Quick start

```sh
threatscan install              # background guard + editor hardening + first scan
threatscan status               # is everything running?
threatscan scan --home          # audit every project under your home folder now
threatscan github-clean         # dry run: which of my GitHub repos and branches are infected?
threatscan github-clean --apply # fix and push them
```

---

## Commands

### scan

One-off scan of repositories and of this computer.

```
threatscan scan [options] [directories]
```

With no directories it scans the current working directory. Each directory is walked for git
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
or `--ci` nothing is touched. Findings that ThreatScan cannot fix on its own (for example a
compromised package version in a lockfile) are printed with a remediation hint.

**Exit codes:** `0` clean, `1` HIGH or CRITICAL findings, `2` error or nothing scanned.

Examples:

```sh
threatscan scan                          # this directory
threatscan scan ~/code ~/work            # specific directories
threatscan scan --home --no-system       # repositories only
threatscan scan --home --fix             # clean up without questions
threatscan scan --ci --json report.json  # in a pipeline; exit 1 fails the job
threatscan --deep ~/proj                 # same as `threatscan scan --deep ~/proj`
```

### status

Protection status, editor hardening state and the latest report.

```
threatscan status
```

Shows whether the guard is alive and which real-time backend it uses (inotify, kqueue,
ReadDirectoryChangesW, or polling), the service state, the installed binary, the time of the
last full sweep, how many repositories are tracked, the indicator version, the configured
action policy, webhook and firewall state, the data directory, the summary of the latest report,
and each VS Code-family editor with its `task.allowAutomaticTasks` setting. Always exits `0`.

### history and restore

Protection history: everything the guard or `scan --fix` ever quarantined, stripped, killed or
removed, newest last.

```
threatscan history [--limit N]
threatscan history --restore PATH
threatscan history --allow PATH
threatscan history --remove PATH
threatscan restore PATH            # same as history --restore PATH
```

| Option | Effect |
|---|---|
| `--limit N` | number of entries to show (default 50) |
| `--details` | also print the evidence behind each entry and, for kills, the command line |
| `--json` | print the raw entries as JSON |
| `--restore PATH` | put the original file back at `PATH`. It is still malicious and will be flagged again |
| `--allow PATH` | restore and stop flagging this exact file content. The decision is remembered for 30 days and only for this content hash. Use it for a false positive |
| `--remove PATH` | delete the quarantined copies permanently |

`PATH` is the original location as shown by `threatscan history`.

Every entry carries a `why:` line: the reason for the response, for example that a process was
killed because its command line held a strict PolinRider marker, or that a file was quarantined
whole because the payload was woven into it rather than appended.

### alerts

Recent alerts with the reason for each one. This is what a click on a desktop notification opens.

```
threatscan alerts [--last N] [--gui] [--json]
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
threatscan github-clean [options]
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
| `--author "Name <email>"` | identity for the fix commits. Default: your git config, then `ThreatScan <threatscan@users.noreply.github.com>` |
| `--keep-clones DIR` | keep the clones under `DIR` for inspection instead of deleting them |
| `--json FILE` | write the full result to `FILE` |
| `--api URL` | GitHub Enterprise API base, default `https://api.github.com` |
| `--ci` | no colour, no interactive prompts |

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
| `infected` | dry run: this branch needs fixes |
| `pushed` | fixed and pushed; the short commit hash is shown |
| `push-failed` | fixed locally, the remote refused the push. The error is shown |
| `manual` | HIGH or CRITICAL findings ThreatScan does not fix automatically. Review them |
| `error` | clone, worktree, commit or scan failure |

Repository-wide findings about commits in history that touch payload code are listed under
`history`. They are informational; removing them would need a force-push.

**Exit codes:** `0` everything clean or fixed and pushed, `1` infected branches remain (dry run,
refused pushes, errors), `2` no token, bad token, or an API failure.

**Afterwards.** Rotate the token you used and every secret those repositories or their CI could
read. Check *Settings, Applications* and *Deploy keys* on GitHub for anything you did not add.
Tell collaborators to `git pull`. Quarantined originals are in `threatscan history`.

Examples:

```sh
threatscan github-clean --list
threatscan github-clean                                     # dry run over everything
threatscan github-clean --select --apply                    # pick from a list
threatscan github-clean --repo me/api --repo me/web --apply
threatscan github-clean --owner my-org --branch main --branch 'release/*' --apply
GITHUB_TOKEN=... threatscan github-clean --ci --apply --json clean.json
op read op://Vault/GitHub/token | threatscan github-clean --token-stdin --apply
```

### guard

Run the background protection loop in this terminal. `install` registers this as a user
service; run it by hand to debug or on a machine without a service manager.

```
threatscan guard [--once] [--dry-run] [--verbose]
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
`threatscan config --set`.

### install

Install the background guard so it starts at sign-in, harden editors, run a first scan.

```
threatscan install [options]
```

Everything is per user: the binary is copied to a per-user install directory and put on your
PATH, the guard is registered as a systemd `--user` service, a LaunchAgent or a Scheduled Task,
and every VS Code-family editor found gets `task.allowAutomaticTasks = off` and workspace trust
turned on.

| Option | Effect |
|---|---|
| `--roots DIR` | project directory to watch. Repeatable. Default: auto-discover the usual places under your home folder |
| `--webhook URL` | URL that receives JSON alerts (Slack, Discord, Teams or your own endpoint) |
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

The one-line installer from the README calls this for you; its environment variables
`THREATSCAN_ROOTS`, `THREATSCAN_WEBHOOK`, `THREATSCAN_VERSION` and `THREATSCAN_NO_INSTALL` map
onto these options.

### uninstall

Remove the background guard.

```
threatscan uninstall [--unblock] [--purge]
```

| Option | Effect |
|---|---|
| `--unblock` | also remove the C2 block: the boot-time job, the firewall rules and the hosts entries (asks for administrator rights) |
| `--purge` | also delete the data directory: config, reports, quarantine |

Editor hardening is left in place because it is a safe default.

### update

Update ThreatScan to the latest release.

```
threatscan update [--check]
```

`--check` only reports whether a newer release exists. Releases are verified before they replace
the binary: the checksums file is signed with the project's ed25519 key and the download's
SHA-256 must match. The previous binary is kept; if the new one fails to start the guard rolls
back. The guard does this on its own every `update_interval` seconds when `auto_update` is on.
`update_channel` `beta` also considers pre-releases.

### update-iocs

Download the latest indicator file.

```
threatscan update-iocs [--url URL]
```

The default source is the file on the project's `main` branch. The download is parsed and
validated (every regex must compile, every IP and hash must be well formed) before it replaces
the previous copy, and a file whose version is not newer is ignored. A running guard picks a new
file up at its next definitions check; restart the service to use it immediately.

### harden

Apply preventive settings without installing the guard.

```
threatscan harden [options]
```

| Option | Effect |
|---|---|
| (none) | harden every VS Code-family editor found: `task.allowAutomaticTasks = off`, workspace trust on |
| `--npm-ignore-scripts` | set `ignore-scripts=true` in `~/.npmrc`, so installs never run lifecycle scripts |
| `--undo-npm` | remove that setting again |
| `--pre-commit REPO` | install a pre-commit hook in `REPO` that runs `threatscan check-staged`. Repeatable. An existing hook is kept as `pre-commit.pre-threatscan` |
| `--dry-run` | show what would change |

### protect

Block the PolinRider command-and-control (C2) servers system-wide and keep them blocked.

```
threatscan protect [--install | --refresh | --uninstall | --status | --block-c2 | --unblock] [--dry-run]
```

`threatscan install` does this for you: it asks once for administrator rights (native password
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
chain or `nftables` table named `threatscan` on Linux, a `pf` anchor on macOS, a Windows Firewall
rule named "ThreatScan C2 block". The C2 hostnames are sinkholed in the hosts file between
`# BEGIN THREATSCAN C2 SINKHOLE` and `# END` markers. The job that keeps this current is a systemd
timer (`threatscan-netblock.timer`, at boot and daily), a LaunchDaemon (`com.threatscan.netblock`)
or a Scheduled Task ("ThreatScan NetBlock", runs as SYSTEM at boot and daily).

**Why it uses its own copy of the indicators.** The job runs as root, and the `iocs.json` under
your home folder is writable by anything running as you. A privileged job must not let a
user-writable file decide what goes into the hosts file, so it keeps a root-owned copy under
`/etc/threatscan`, `/Library/Application Support/ThreatScan` or `%ProgramData%\ThreatScan`,
refreshed from the project repository only, and runs a root-owned copy of the program.

**Status values** shown by `threatscan status` and `protect --status`:

| Firewall | Meaning |
|---|---|
| `active (persistent; 25 IPs, 15 hosts; applied 3h ago; indicators …)` | all good |
| `active until reboot (…)` | a one-shot block from `--block-c2`; run `protect --install` to keep it |
| `not active (rules from a previous boot were lost)` | same, after a reboot |
| `not active` | never installed, or removed |

Opt out with `threatscan install --no-block-c2` or `threatscan config --set block_c2=false`; the
guard then stops reminding you. Setting `THREATSCAN_NO_BLOCK=1` skips the administrator prompt for
one run, which the package installers use because they already did the work as root.

### config

Show or change settings.

```
threatscan config
threatscan config --set key=value [--set key=value ...]
```

Without options it prints the current configuration. Keys are the JSON names listed under
[Configuration keys](#configuration-keys). Booleans take `true`/`false`, lists are
comma-separated. The guard reads the file when it starts, so restart the service after a change
(`systemctl --user restart threatscan-guard.service` on Linux).

```sh
threatscan config --set action=ask
threatscan config --set scan_roots=~/code,~/work
threatscan config --set webhook_url=https://hooks.slack.com/services/...
threatscan config --set auto_update=false
```

### check-staged

Pre-commit hook helper: scan the files staged for commit and refuse the commit if any carries a
PolinRider indicator at HIGH or above.

```
threatscan check-staged
```

Run it from inside the repository. Exit `1` blocks the commit, `0` allows it. Install it with
`threatscan harden --pre-commit .`, or add this to `.git/hooks/pre-commit` yourself:

```sh
#!/bin/sh
threatscan check-staged || exit 1
```

### version

```
threatscan version
threatscan --version
```

Prints the version. Release builds print the release number; development builds end in `-dev`.

### help

Show this documentation in the terminal.

```
threatscan help                  # command list
threatscan help <command>        # one command, for example: threatscan help install
threatscan help <topic>          # config-keys, files, environment, severities, recipes, troubleshooting
threatscan help all              # the whole reference
```

The text is embedded in the binary, so it always matches the installed version and works
offline. Long pages go through `$PAGER` (default `less`); set `THREATSCAN_NO_PAGER=1` to print
straight to the terminal.

---

## Configuration keys

Stored in `config.json` in the data directory. Change them with `threatscan config --set`.

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
| `webhook_url` | `""` | receives a JSON POST per alert |
| `webhook_min_severity` | `HIGH` | lowest severity that posts |
| `block_c2` | `true` | keep the system-wide C2 block installed; `install` asks for administrator rights once and the guard reminds you daily while it is missing |
| `report_keep` | `60` | number of reports kept |
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

The data directory is `~/.threatscan` (override with `THREATSCAN_HOME`).

| Path | Content |
|---|---|
| `config.json` | settings |
| `iocs.json` | downloaded indicators; the binary carries an embedded copy as fallback |
| `guard.log` | the guard's log |
| `alerts.log` | one JSON line per alert, including the `why` and `response` texts as worded at the time |
| `reports/` | timestamped JSON reports plus `latest.json` |
| `quarantine/` | copies of every stripped or deleted file, and `index.jsonl`, the protection history |
| `decisions.json` | files you chose to allow, with their content hash |
| `ThreatScan Notifier.app` | macOS only, in the install directory: the helper that posts notifications so a click opens `threatscan alerts --gui` |
| `guard/` | heartbeat and state of the running guard |

The privileged C2 block keeps its own root-owned files: `netblock-state.json` and a copy of
`iocs.json` under `/etc/threatscan` (Linux), `/Library/Application Support/ThreatScan` (macOS) or
`%ProgramData%\ThreatScan` (Windows), plus a copy of the program under `/usr/local/lib/threatscan`,
`/usr/local/libexec/threatscan` or `%ProgramFiles%\ThreatScan`.

The binary itself lives in a per-user install directory, on Linux `~/.local/share/threatscan`
with a link in `~/.local/bin` (override with `THREATSCAN_INSTALL_DIR`).

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `THREATSCAN_HOME` | every command | data directory instead of `~/.threatscan` |
| `THREATSCAN_INSTALL_DIR` | `install`, `update` | where the binary is installed |
| `GITHUB_TOKEN`, `GH_TOKEN` | `github-clean` | token when `--token` is not given |
| `NO_COLOR` | every command | disable coloured output |
| `PAGER`, `THREATSCAN_NO_PAGER` | `help` | pager for long pages; set the second to disable paging |
| `THREATSCAN_NO_BLOCK` | `install`, `protect`, `uninstall` | never ask for administrator rights (package installers, CI) |
| `THREATSCAN_ROOTS` | install script | space-separated project directories to watch |
| `THREATSCAN_WEBHOOK` | install script | webhook URL |
| `THREATSCAN_VERSION` | install script | install this release instead of the latest |
| `THREATSCAN_NO_INSTALL` | install script | download the binary only, do not register the guard |
| `THREATSCAN_BASE_URL` | install script | download from a mirror |

## Severities, actions and threat names

| Severity | Meaning | Automatic action |
|---|---|---|
| CRITICAL | confirmed PolinRider artifact or activity | yes, per `action` policy |
| HIGH | strong indicator that needs a human: compromised package version, exposed keys on an infected host | no, listed for review |
| WARNING | context worth checking: suspicious git reflog, secrets file in an infected repo, files that arrived in the same commit as a loader (camouflage fonts, decoy README, `.vscode` set) | no |
| INFO | informational | no |

**Why-lines.** Every finding has a one-sentence reason for its severity, and every response
(kill, strip, quarantine, or nothing) has a one-sentence reason too. They appear in scan output,
in the dialogs, in `threatscan alerts`, in `threatscan history`, in desktop notifications, in the
webhook JSON (`reasons` array) and in `guard.log`. A process is killed only when its command line
holds a strict PolinRider marker that legitimate tools never use; a broad indicator alone is
reported but not killed, and the reason says so.

Dialogs, notifications and reports name threats Defender-style, for example
`Trojan:JS/PolinRider.FakeFont` for a script disguised as a font, `Trojan:Script/PolinRider` for an
injected loader and `Backdoor:Script/PolinRider.Persist` for a persistence entry.

## Recipes

**CI gate.** Fail the pipeline when a PolinRider indicator lands in the repository:

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.sh | THREATSCAN_NO_INSTALL=1 sh
- run: ~/.local/bin/threatscan scan --ci --no-system --json threatscan.json .
```

**Pre-commit hook for every repository you work on:**

```sh
for r in ~/code/*/; do threatscan harden --pre-commit "$r"; done
```

**Slack, Discord or Teams alerts** from every machine:

```sh
threatscan config --set webhook_url=https://hooks.slack.com/services/T000/B000/XXXX
```

The POST body contains `text` (Slack), `content` (Discord), `host`, `platform`, `context` and
the `findings` array, so one URL works for all three and for your own endpoint.

**Organisation-wide clean-up after a compromise**, from a machine with a fine-grained token that
has Contents write on the organisation's repositories:

```sh
threatscan github-clean --owner my-org --list
threatscan github-clean --owner my-org --json dryrun.json     # review dryrun.json
threatscan github-clean --owner my-org --apply --json applied.json
```

**Machine audit without touching anything:**

```sh
threatscan scan --home --no-prompt --verbose --json audit.json
```

## Troubleshooting

**Clicking a macOS notification opens Script Editor.** Builds before 0.3 posted notifications
through osascript. Run `threatscan install` again: it builds the notification helper app, and
macOS will ask once whether ThreatScan may send notifications. Allow it.

**A legitimate file was quarantined.** `threatscan history` shows it; `threatscan history --allow
PATH` restores it and stops flagging that exact content. Please also open an issue with the file so
the indicator can be tightened.

**A process is flagged repeatedly.** The alert in `alerts.log` shows the indicator and the command
line. Update indicators first, since false positives are fixed there without a new release:
`threatscan update-iocs` and then restart the service (`systemctl --user restart
threatscan-guard.service` on Linux). If it persists, open an issue with the alert line.

**Firewall says `not active` or `until reboot`.** The one-time administrator prompt was declined
or could not be shown (for example a headless server without polkit). Run `sudo threatscan protect
--install` on Linux and macOS, or `threatscan protect --install` from an elevated terminal on
Windows. `threatscan protect --status` confirms it afterwards.

**`status` says the guard is not alive.** Check the service: `systemctl --user status
threatscan-guard.service` on Linux, `launchctl list | grep threatscan` on macOS, Task Scheduler
on Windows. Run `threatscan guard --verbose --once` in a terminal to see errors directly.

**Real-time shows `off` or `polling`.** On Linux the inotify watch limit may be exhausted with many
large repositories; raise `fs.inotify.max_user_watches`. The guard falls back to polling and to the
5-second and 6-hour layers, so protection continues.

**`github-clean` says `push-failed`.** The branch is protected, the repository is archived, or the
token lacks write access. Temporarily allow the push (or add yourself to the bypass list), or
unarchive the repository, then run again for that repository with `--repo owner/name --apply`. A
non-fast-forward error means someone pushed between clone and push; simply run again.

**`github-clean` cannot find a token.** Pass `--token`, export `GITHUB_TOKEN`, or run `gh auth
login`. A fine-grained token must list the repositories and grant *Contents: Read and write*.

**Uninstall completely:** `threatscan uninstall --unblock --purge`, then delete the install
directory shown by `threatscan status`.

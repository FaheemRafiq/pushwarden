<!-- threatscan:allow-signatures -->
# ThreatScan v5

**Real-time protection against the PolinRider / Contagious Interview supply-chain malware, for developer machines.**
Linux, macOS and Windows. One install command. Behaves like Windows Defender: a malicious file is caught the
moment it is written, quarantined before it can run, named, and you decide from a native dialog whether to
remove it for good or restore and allow it.

PolinRider is the DPRK (Lazarus) campaign that hides obfuscated JavaScript loaders in framework config files
(`postcss.config.mjs`, `eslint.config.mjs`, `next.config.js` ...), fake font files (`fa-solid-400/500/900.woff2`)
and `.vscode/tasks.json` autorun tasks, then steals credentials, rewrites git history and force-pushes the
backdoor to every branch you can reach. Over 2,000 GitHub owners and 4,000 repos were hit between March and
September 2026. Sources are listed at the bottom.

```
  file written ──► real-time watcher ──► scan (evidence) ──► quarantine ──► notification
  (inotify / kqueue / ReadDirectoryChangesW)                     │            "Threats found:
                                                                 │             Trojan:JS/PolinRider.FakeFont"
                                                                 ▼
                                                   native dialog: [Remove]  [Restore & allow]
                                                                 │
                                                                 ▼
                                                   threatscan history  (restore / allow / remove)

  every 5 s   processes + sockets to C2  ──► kill          every 6 h  full sweep of every repo + host
  every 24 h  indicator refresh                            always     VS Code / Cursor hardening
```

---

## Install

**Linux / macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.sh | sh
```

**Windows** (PowerShell, no admin needed)

```powershell
irm https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/installers/install.ps1 | iex
```

The installer

1. finds or installs Python 3.8+ (winget / brew / apt / dnf),
2. installs the package into its own virtualenv under `~/.threatscan/venv` and puts `threatscan` on your PATH,
3. hardens every VS Code-family editor it finds (`task.allowAutomaticTasks = off`, workspace trust on),
4. registers the background guard as a **user** service (systemd `--user`, LaunchAgent, or a Scheduled Task),
5. runs a first full scan and cleans anything CRITICAL it finds (originals go to quarantine).

Optional environment variables for the one-liners:

| Variable | Effect |
|---|---|
| `THREATSCAN_WEBHOOK=https://hooks.slack.com/...` | send alerts from this machine to a Slack/Discord/Teams/custom webhook |
| `THREATSCAN_ROOTS="~/code ~/work"` (`;`-separated on Windows) | which project directories to watch (default: auto-discover) |
| `THREATSCAN_BLOCK_C2=1` | also add firewall rules for the C2 IPs (asks for sudo / needs elevated PowerShell) |
| `THREATSCAN_NO_INSTALL=1` | install the CLI only, no guard |

No Python and no admin? Download the single-file binary for your OS from the
[Releases](https://github.com/FaheemRafiq/threatscan/releases) page and run `threatscan install`.
There is also `threatscan.pyz`, a zero-dependency file that runs with any `python3`.

---

## Day-to-day

```sh
threatscan status                 # guard alive? real-time backend? editors hardened? firewall?
threatscan scan --home            # audit now; asks in the terminal before touching a file
threatscan scan --home --gui      # same, but asks through the native dialog
threatscan scan --home --no-prompt   # report only
threatscan scan --home --fix      # act without asking (quarantine / strip, reversible)
threatscan scan --deep ~/proj     # also descend into node_modules / vendor
threatscan history                # protection history (restore / allow / remove)
threatscan update-iocs            # pull the latest indicator file
sudo threatscan protect --block-c2   # firewall + hosts sinkhole for all known C2
threatscan uninstall [--unblock] [--purge]
```

Legacy invocation still works: `python3 threat_scanner.py --ci .` behaves like v4 (`--configs-only` restores
the v4 "known config names only" scope; v5 scans every script file by default).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | HIGH or CRITICAL findings |
| 2 | error / nothing scanned |

---

## What the guard does (Defender-style)

| Layer | Work | Latency / cost |
|---|---|---|
| **real-time** | native file-system watcher (inotify on Linux, kqueue on macOS, ReadDirectoryChangesW on Windows, polling fallback) over your project dirs, `~/Downloads` and `~/Desktop`; every written script, config, font, image or `.vscode/*.json` file is scanned as it lands | under 1 s, idle otherwise |
| **behaviour** | every 5 s: process command lines and sockets to C2 IPs | a few ms |
| **scheduled** | every 6 h: full sweep of every repo (all script files, not only known config names) plus host persistence, RAT footprint, editor injection, credentials | seconds to a minute |
| **definitions** | every 24 h: `iocs.json` downloaded from this repo and validated before use | one HTTPS request |

What happens when a file has strong evidence (`threatscan config --set action=...`):

| `action` | Behaviour |
|---|---|
| `quarantine` (default) | file is quarantined **immediately**, a notification names the threat, then a native dialog shows the evidence with **Remove** (permanent) or **Restore & allow** (restores the exact file and stops flagging it). No answer within 3 minutes: it stays in quarantine. |
| `ask` | dialog first, nothing is touched until you answer; no answer: quarantine |
| `delete` | remove permanently without asking |
| `report` | notify only |

Strong evidence means a literal campaign signature or marker, a payload XOR key, a dead-drop wallet, a known
loader hash, a font/image file whose bytes are code, `runOn: folderOpen` with a loader, or a propagation script.
The dialog always lists the exact indicators found (string, offset, whitespace padding, C2 host ...).

Other responses:

| Finding | Response |
|---|---|
| process whose command line carries a **strict** campaign marker, or a socket to a C2 IP | killed at once (`auto_kill`, no dialog: a running payload cannot wait) |
| config or entry file with an appended payload | payload **stripped by byte offset**, legitimate export kept; prepended or mid-file injections quarantine the whole file instead of guessing |
| RAT systemd unit / LaunchAgent / scheduled task / crontab line / RAT directory | disabled and quarantined (crontab backed up first) |
| HIGH and WARNING findings (heuristics: `node -e`, oversized configs, backdated commits) | alert only, never auto-acted |

Threat names follow the Defender convention so alerts are recognisable at a glance: `Trojan:JS/PolinRider.FakeFont`,
`Trojan:JS/PolinRider.ConfigInject`, `Trojan:Script/PolinRider.TaskJacker`, `Trojan:BAT/PolinRider.AutoPush`,
`Behavior:Node/PolinRider.Payload`, `Backdoor:JS/RuntimeDevLink` ...

Alerts go to the desktop (notify-send / Notification Center / Windows toast), `~/.threatscan/alerts.log`, and
the webhook if configured. Every action is in the protection history:

```sh
threatscan history                       # what was quarantined / stripped / removed, with threat names
threatscan history --restore <path>      # put the original back (still malicious)
threatscan history --allow <path>        # restore and allow this exact content (30 days)
threatscan history --remove <path>       # delete the quarantined copies for good
```

---

## What it detects

**Repositories**

| Indicator | Severity |
|---|---|
| `global['_V']=`, `global['!']=`, `global.i='A10-*NNN'`, `8-stNN` build tags, `_$_1e42`, `MDy(`, `Cot%3t=shtP`, `rmcej%otb%` | CRITICAL |
| XOR keys (4 known), TRON / Aptos / Ethereum dead-drop wallets, RPC hosts co-located with a marker | CRITICAL |
| C2 IPs (17), Vercel stage-1 hosts (7), C2 paths (`/$/boot`, `/verify-human/`, `/0x/cls`, `/api/telemetry/*` ...), `X-Payload-B64` | CRITICAL |
| Font / image / `.dict` files whose bytes are code (with or without whitespace padding), 6 known loader hashes | CRITICAL |
| Any `.js/.ts/.json/.py/.sh/.bat/.ps1/...` file in the repo carrying a signature (not only known config names) | CRITICAL |
| `.vscode/tasks.json` with `runOn: folderOpen` (+ loader / C2 host), `task.allowAutomaticTasks` forced on | CRITICAL / HIGH |
| `temp_auto_push.bat`, `config.bat`, `.gitignore` hiding them or itself, `branch_structure.json`, `nul` | CRITICAL / HIGH |
| Malicious git hooks, `core.fsmonitor` running node | CRITICAL |
| Compromised packages: 12 npm (incl. the `tailwind*` typosquats), 16 Go modules, 1 Packagist; suspicious lifecycle scripts | CRITICAL / HIGH |
| Backdated commits, force-push reflog, commits touching payload code on any branch | HIGH / WARNING |

**Host**

| Check | Severity |
|---|---|
| Live processes with campaign markers, `SvcHostUpdate.py`, `VSCodeUpdater`, `runtimedev-link`, `MicrosoftCLROptimization` | CRITICAL |
| Sockets to known C2 IPs | CRITICAL |
| RAT dirs/files, `agent.env`, `SSTAR_*` env vars, portable Node/Python runtimes | CRITICAL / HIGH |
| cron, systemd `--user`, XDG autostart, LaunchAgents, schtasks, Startup folder, HKCU Run | CRITICAL / HIGH |
| Shell rc / PowerShell profile injection | HIGH |
| VS Code / Cursor / VSCodium / Windsurf / Discord / GitHub Desktop injection, backdoored or oversized global `npm/lib/cli.js` | CRITICAL / HIGH |
| Hosts-file redirects of registries | HIGH |
| Plain-text tokens (`.npmrc`, `.git-credentials`, gh, aws, docker) and SSH keys on an infected host | HIGH |

All indicators live in [`threatscan/iocs.json`](threatscan/iocs.json). Add new ones there; no code change needed.
Files that legitimately contain signature strings (rule sets, tests, indicator databases) opt out with the token
`threatscan:allow-signatures` in their first 512 bytes; the token is never honoured for config, entry, asset or JavaScript/TypeScript files.

---

## Hardening (what actually stops stage 1)

`threatscan harden` (run automatically by `install`) writes into each editor's user `settings.json`:

```json
"task.allowAutomaticTasks": "off",
"security.workspace.trust.enabled": true,
"security.workspace.trust.startupPrompt": "always",
"security.workspace.trust.untrustedFiles": "prompt"
```

A backup of the previous file is left next to it. Opt-ins:

```sh
threatscan harden --npm-ignore-scripts        # ignore-scripts=true in ~/.npmrc (pnpm v10 does this by default)
threatscan harden --pre-commit ~/code/repo1   # pre-commit hook that refuses PolinRider indicators
```

---

## Team setup

1. Fork or use this repo. Colleagues run the one-liner above with `THREATSCAN_WEBHOOK` set to a channel you watch.
2. Every alert arrives as JSON with hostname, platform, findings and the action taken.
3. When a new variant appears, edit `threatscan/iocs.json`, bump `"version"`, push. Every guard picks it up within 24 h
   (`threatscan update-iocs` forces it).
4. Add the reusable GitHub Actions workflow to your repos:

```yaml
# .github/workflows/malware-scan.yml
name: Malware Scan
on: [push, pull_request]
jobs:
  scan:
    uses: FaheemRafiq/threatscan/.github/workflows/malware-scan.yml@main
```

---

## Falco add-on (Linux, optional)

For kernel-level blocking on Linux workstations and CI runners, `falco/` ships the rule set that runs on the
author's machines: Tier-1 rules (tagged `kill`) terminate `node -e` payloads with campaign markers, node reading
`fa-solid-*.woff2`, `temp_auto_push.bat`, curl to the Vercel stage-1 hosts; Tier-2 rules alert on
`folderOpen` task writes, automated `git commit --amend` / `push --force`, node spawning shells, download pipes.

```sh
sudo bash falco/install-falco.sh     # needs Falco + jq installed
```

---

## If something is found

1. Do not `git pull`; the remote may re-infect you. Clean via the GitHub web editor first.
2. Kill processes and remove persistence (the guard has already done the CRITICAL ones; check `threatscan status`).
3. Rotate **everything**: GitHub password, PATs, SSH keys, OAuth apps, npm token, Vercel/Netlify/AWS tokens, every value in `.env`, browser sessions, password-manager vault if it was unlocked.
4. Audit every repo you can push to for force-pushes ("X force pushed the branch") and unverified commits.
5. Reinstall Node/npm from nodejs.org if `npm/lib/cli.js` was touched.
6. Report at https://opensourcemalware.com. Windows Defender names the family `Trojan:JS/PolinRider.DB!MTB`.

The full checklist is in [`analysis/remediation-checklist.md`](analysis/remediation-checklist.md).

---

## Development

```sh
git clone https://github.com/FaheemRafiq/threatscan && cd threatscan
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" && pytest -q
sh installers/build-pyz.sh                 # dist/threatscan.pyz
THREATSCAN_HOME=/tmp/ts threatscan guard --once --dry-run --verbose
```

Layout:

```
threatscan/
  iocs.json          all indicators (data only, hot-updatable)
  iocs.py            loader + validation
  scanner/repo.py    repository checks          scanner/system.py   host checks
  protect.py         kill / quarantine / strip / persistence removal / firewall
  guard.py           background loop + policy   realtime.py         inotify / kqueue / RDCW watcher
  prompt.py          native dialogs, threat names service.py         systemd / launchd / schtasks
  hardening.py       editor + npm settings      notify.py           desktop + webhook
  cli.py             commands                   report.py, config.py, updater.py
installers/          install.sh, install.ps1, build-pyz.sh
falco/               Linux runtime rules + response handler
analysis/            sandbox, deobfuscator, YARA, sample notes (do not run samples)
tests/               inert fixtures that mimic the artefacts' shape
```

Tests never touch `~/.threatscan`; they run under a temporary `THREATSCAN_HOME`.

---

## Sources

- https://github.com/OpenSourceMalware/PolinRider
- https://opensourcemalware.com/blog/polinrider-is-a-b-testing-its-way-past-your-detections
- https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider
- https://opensourcemalware.com/blog/malware-abuses-vscode-lifecycle-scripts
- https://github.com/orgs/community/discussions/188732
- https://socprime.com/active-threats/dprk-polinrider-campaign-shows-hands-on-keyboard-supply-chain-activity/
- https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
- https://socket.dev/blog/joyfill-npm-beta-releases-compromised
- https://thehackernews.com/2026/07/north-korean-hackers-publish-108.html

## License

MIT

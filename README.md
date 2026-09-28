# ThreatScan v5

**Detect, remove and block the PolinRider / Contagious Interview supply-chain malware on developer machines.**
Linux, macOS and Windows. One install command. Keeps watching in the background.

PolinRider is the DPRK (Lazarus) campaign that hides obfuscated JavaScript loaders in framework config files
(`postcss.config.mjs`, `eslint.config.mjs`, `next.config.js` ...), fake font files (`fa-solid-400/500/900.woff2`)
and `.vscode/tasks.json` autorun tasks, then steals credentials, rewrites git history and force-pushes the
backdoor to every branch you can reach. Over 2,000 GitHub owners and 4,000 repos were hit between March and
September 2026. Sources are listed at the bottom.

```
                  ┌────────────────────────────────────────────────────────┐
  threatscan      │  scan     one-off audit of repos + host (read-only)     │
                  │  guard    background service: 60 s / 6 h / 24 h passes  │
                  │  protect  kill, quarantine, strip payloads, block C2    │
                  │  harden   VS Code / Cursor / npm settings that stop     │
                  │           stage 1 from ever running                     │
                  └────────────────────────────────────────────────────────┘
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
threatscan status                 # guard alive? last sweep? editors hardened? firewall?
threatscan scan --home            # audit now (read-only)
threatscan scan --home --fix      # audit and remove CRITICAL findings (originals kept)
threatscan scan --dry-run ~/proj  # show what --fix would do
threatscan restore --list         # everything the guard quarantined or stripped
threatscan restore /path/to/file  # put an original back (it is still malicious!)
threatscan update-iocs            # pull the latest indicator file
sudo threatscan protect --block-c2   # firewall + hosts sinkhole for all known C2
threatscan uninstall [--unblock] [--purge]
```

Legacy invocation still works: `python3 threat_scanner.py --ci .` behaves like v4.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | HIGH or CRITICAL findings |
| 2 | error / nothing scanned |

---

## What the guard does

| Cadence | Work | Cost |
|---|---|---|
| every 60 s | process command lines, established sockets to C2 IPs, and any tracked file (config files, `.vscode/tasks.json`, propagation scripts, known loader names) whose mtime changed | a few ms |
| every 6 h | full sweep: every repo under the watched roots plus host persistence, RAT footprint, editor injection, credentials | seconds to a minute |
| every 24 h | download `iocs.json` from this repo; validated (schema, regex compile, size) before use | one HTTPS request |

Response policy (both switchable with `threatscan config --set auto_kill=false auto_clean=false`):

| Finding | Response |
|---|---|
| process whose command line carries a **strict** campaign marker, or a socket to a C2 IP | `kill -9` / `taskkill /F` |
| config or entry file with a signature / marker / XOR key | payload **stripped by byte offset**, legitimate export kept, original quarantined |
| font/image/dict file that is really code, hash-matched loader, `temp_auto_push.bat`, `tasks.json` with a loader | quarantined |
| RAT systemd unit / LaunchAgent / scheduled task / crontab line / RAT directory | disabled and quarantined |
| HIGH and WARNING findings | alert only |

Everything is written to `~/.threatscan/quarantine/index.jsonl` and reversible with `threatscan restore`.
Alerts go to the desktop (notify-send / Notification Center / Windows toast), `~/.threatscan/alerts.log`,
and the webhook if configured. Reports land in `~/.threatscan/reports/`.

Broad heuristics (`node -e`, `python -c`, oversized configs) are **never** auto-killed or auto-cleaned.

---

## What it detects

**Repositories**

| Indicator | Severity |
|---|---|
| `global['_V']=`, `global['!']=`, `global.i='A10-*NNN'`, `8-stNN` build tags, `_$_1e42`, `MDy(`, `Cot%3t=shtP`, `rmcej%otb%` | CRITICAL |
| XOR keys (4 known), TRON / Aptos / Ethereum dead-drop wallets, RPC hosts co-located with a marker | CRITICAL |
| C2 IPs (17), Vercel stage-1 hosts (7), C2 paths (`/$/boot`, `/verify-human/`, `/0x/cls`, `/api/telemetry/*` ...), `X-Payload-B64` | CRITICAL |
| Font / image / `.dict` files whose bytes are code (with or without whitespace padding), 6 known loader hashes | CRITICAL |
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
  guard.py           background loop            service.py          systemd / launchd / schtasks
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

# Go port (v6) handoff: finishing P4 to P8

This guide is for whoever picks up the Go rewrite, human or AI agent. It says
what is done, what remains, which existing functions to plug into, and how to
prove each piece works. Read `~/.claude/plans/` is not available to you; this
file is the plan.

## Ground rules

1. **Do not invent behaviour.** Every remaining piece already exists in the
   Python v5 package under `threatscan/`. Port it; keep names, paths, file
   formats and timings identical so a machine can move from v5 to v6 with its
   history intact.
2. **Go 1.24 only.** `go.mod` says `go 1.24.0` on purpose: binaries must run on
   macOS 11+, Windows 10+, Linux kernel 3.2+. Do not let `go get` or
   `go mod tidy` raise it. Run tooling as `GOTOOLCHAIN=go1.24.13 go ...`. If a
   dependency needs a newer Go, pin an older version of that dependency
   (already done for `tailscale/hujson` and `ncruces/zenity`).
3. **Vet on all three OSes after every change:**
   `for os in linux windows darwin; do GOOS=$os go vet ./...; done`
4. **No admin rights anywhere.** Everything installs per user.
5. **Use inert fixtures only.** `internal/testfixtures` builds files that have
   the *shape* of the malware (marker strings, padding, fake magic bytes) and
   nothing executable. Never add real samples to the repo.
6. Files that legitimately contain signature strings (tests, rule sets) start
   with the comment `threatscan:allow-signatures`. See `internal/helpers.IsAllowlisted`
   for where it is and is not honoured.

## What exists (pushed to `main`)

| Package | Ported from | Notes |
|---|---|---|
| `internal/iocs` | `threatscan/iocs.py` | embeds `threatscan/iocs.json` via `threatscan/iocsdata.go`; loads a newer user copy from `<data_dir>/iocs.json` |
| `internal/findings` | `findings.py` | `Finding`, `Meta`, `Stats`, `Severity` (JSON as names) |
| `internal/platform` | `platform_info.py` | paths (`DataDir`, `InstallDir`, `ExeName`), gopsutil processes/sockets, `RunRC`, `Kill`, `Exe()`, `IsAdmin()`, `Detach()` |
| `internal/helpers` | `helpers.py` | `AssetVerdict`, `Evidence`, `PayloadCut`, `IsAllowlisted`, `IsUnder`, `SHA256` |
| `internal/scan` | `scanner/repo.py`, `scanner/system.py` | `Repo.ScanAll/ScanRepo/ScanFile/Discover`, `System.ScanAll/Quick` |
| `internal/protect` | `protect.py` | `Respond`, `Quarantine`, `Clean`, `Delete`, `Purge`, `Restore`, `Remember`, `Entries`; `NetBlocker` |
| `internal/prompt` | `prompt.py` | `Ask`, `AskQuarantined`, `AskTerminal`, `ThreatName`, `SetDialogForTest` |
| `internal/notify` | `notify.py` | desktop (zenity.Notify), alerts.log, webhook |
| `internal/harden` | `hardening.py` | hujson keeps user comments; `Editor`, `NPM`, `PreCommit` |
| `internal/config`, `report`, `ui` | same names in Python | config already has `auto_update`, `update_channel`, `update_interval`, `update_api_url` |
| `internal/guard` | `guard.py` | loop, policy, dialog worker, heartbeat; `Hooks` for later phases |
| `internal/realtime` | `realtime.py` | fsnotify + polling fallback |
| `internal/service` | `service.py` | P4: `Manager` with `Preview`, `PlaceBinary`, `Install`, `Uninstall`, `Status`, `LinkCLI`/`UnlinkCLI`; Windows PATH edits in `path_windows.go` |
| `cmd/threatscan` | `cli.py` | scan, guard, status, history, restore, harden, protect, config, check-staged, version, install, uninstall |

Tests: `GOTOOLCHAIN=go1.24.13 go test -race ./...` passes. Python tests
(`pytest -q`, 24 cases) still pass and must keep passing.

## Extension points you plug into (do not restructure them)

- `cmd/threatscan/cmd_guard.go`: `var guardHooks guard.Hooks`. Set fields in an
  `init()` of a new file in `cmd/threatscan/`, exactly as `hooks_realtime.go`
  does for `StartRealtime`.
- `guard.Hooks.UpdateIOCs func(dataDir, current string, cfg *config.Config) (bool, string)`
  is called on the 24 h cadence; the guard reloads indicators when it returns true.
- `guard.Hooks.Periodic []guard.PeriodicTask{Name, Interval(cfg), Run(g)}` runs
  extra work on its own cadence from the main loop. Program self-update goes here.
- `cmd/threatscan/cmd_manage.go`: `var statusServiceRows func(c *ctx) [][2]string`.
  Wrap it (see `cmd_guard.go`) to add rows to `threatscan status`.
- `main.go`: `register(name, help, func([]string) int)` adds a subcommand. Add
  `install`, `uninstall`, `update`, `update-iocs`. Give them a position in the
  `order` map in `usage()`.
- `platform.Info.InstallDir()` is the per-user, user-writable location the
  binary must run from: `%LOCALAPPDATA%\Programs\ThreatScan`,
  `~/Library/Application Support/ThreatScan`, `~/.local/share/threatscan`.
  `THREATSCAN_INSTALL_DIR` overrides it (use this in tests).
- `platform.Info.DataDir()` is `~/.threatscan` (`THREATSCAN_HOME` overrides it).
  Tests must set `THREATSCAN_HOME` to a temp dir.

## P4. Start the guard at sign-in: `internal/service` (done)

Implemented as specified below. Choices worth knowing:
- Linux runs `enable` then `restart` (not `enable --now`) so a reinstall picks up
  the new binary. `Status()` reports "not installed" when the unit file is absent.
- On Windows a successful task registration deletes a leftover Startup-folder
  launcher so two guards never start. The stop before copying ends the task and
  kills any `threatscan ... guard` process (gopsutil, not PowerShell).
- `PlaceBinary` is a no-op when the target is the same file or has the same SHA-256.
- `uninstall` also removes the `~/.local/bin` symlink (only if it points at the
  installed binary) or the Windows PATH entry. It leaves the binary itself; P7's
  installers own removing program files.
- Not yet verified: a real `install` on Linux/macOS/Windows (`Guard: alive`).
  That is the CI smoke job in P5/P7.

Port `threatscan/service.py` (class `ServiceManager`, function `_guard_cmd`).
Keep these names so v6 replaces a v5 install cleanly:

| OS | Mechanism | Name / file |
|---|---|---|
| Linux | systemd user unit | `~/.config/systemd/user/threatscan-guard.service` |
| macOS | LaunchAgent | `~/Library/LaunchAgents/com.threatscan.guard.plist` |
| Windows | Scheduled Task at logon, limited rights | task `ThreatScan Guard`; fall back to a Startup-folder launcher if task creation is refused |

Behaviour to reproduce from `service.py`:
- The registered command is `<InstallDir>/<ExeName> guard`.
- `install` first copies the running executable into `InstallDir()` (skip if
  already running from there), then registers and starts the service, then
  makes `threatscan` callable from a terminal (symlink in `~/.local/bin`, or
  the install dir on the user's PATH on Windows). Do not replace a v5 shim that
  is a real file; the v5.2 migration removes it.
- Linux unit: `Restart=always`, `Nice=10`, `IOSchedulingClass=idle`, log to
  `<data_dir>/guard.log`, `WantedBy=default.target`, and **no `After=default.target`**
  (that created an ordering cycle in v5.0; the v5 review caught it). Pass
  `THREATSCAN_HOME` through as `Environment=` when set. Enable lingering when
  `loginctl` exists so the guard survives logout.
- macOS plist: `RunAtLoad`, `KeepAlive`, `ThrottleInterval` 10, `ProcessType`
  Background, log paths, a `PATH` that includes `/opt/homebrew/bin`. Use
  `launchctl bootout` then `bootstrap gui/<uid>`, falling back to `load -w`.
- Windows: stop the running task before overwriting the exe (the running file
  is locked), then re-register. Uninstall must also stop a guard started by the
  Startup-folder fallback.
- Provide `Preview()` for `--dry-run`, `Install()`, `Uninstall()`, `Status()`.
- Windows-only code goes in `_windows.go` files; use `golang.org/x/sys/windows/registry`
  for PATH edits under `HKCU\Environment`.

CLI (`cmd/threatscan/cmd_install.go`), mirroring `cli.py` `cmd_install`/`cmd_uninstall`:
- `install [--roots ...] [--webhook URL] [--no-kill] [--no-prompt] [--deep] [--no-harden] [--npm-ignore-scripts] [--block-c2] [--full-interval N] [--dry-run] [--unattended]`
- `--dry-run` writes nothing at all (config, editor settings, service).
- `--unattended` is what the installers call: no terminal prompts, run
  hardening, install the service, start it, and run the first scan **in the
  background** (start `<exe> scan --home --fix --notify` detached with
  `platform.Detach`), then send one notification "ThreatScan is protecting this computer".
- `uninstall [--unblock] [--purge]`.
- Add `Service` and `Binary` rows to `status` through `statusServiceRows`.

Tests (`internal/service/service_test.go`, use `THREATSCAN_INSTALL_DIR` and
`THREATSCAN_HOME` temp dirs):
- `Preview()` on the current OS contains the binary path and `guard`.
- Linux unit text has no `After=default.target` and has `Restart=always`.
- `PlaceBinary` copies the test binary and is a no-op on a second call.
- Do **not** call `Install()` in unit tests; CI does that in a smoke job.

Done when `install --dry-run` prints the definition for the current OS, and a
real `install` on a Linux box shows `Guard: alive` in `threatscan status`.

## P5. Remaining tests, parity, CI

Port every case in `tests/test_scanner.py` that has no Go twin yet. Missing:
- `internal/scan/repo_test.go`: infected fixture yields config_injection,
  fake_font_loader, vscode_autorun (CRITICAL, `Meta.Quarantine`, evidence),
  propagation_script, gitignore_tampering, compromised_package; clean fixture
  has nothing >= HIGH; default scope scans `lib/helper.js` but not
  `node_modules`; `Deep` includes it; `JSAll=false` restores v4 scope;
  allow token ignored for config files; `Exclude` of `vendor` keeps `vendor-tools`.
- `internal/protect/protect_test.go`: `Respond` with a `decide` callback:
  Delete removes permanently and records `type: delete` with evidence; Keep
  leaves the file, sets `Action` "kept by user", and is remembered until the
  file's hash changes; Timeout falls back to reversible quarantine with
  `Action` prefixed "no decision (timeout)"; dry run changes nothing;
  mid-file injection quarantines the whole file (`Meta.MidFileInjection`)
  and `Restore` brings back the exact bytes.
- `internal/prompt/prompt_test.go`: `BuildMessage` includes "Evidence:" and
  "permanently"; `Dialog` returns Timeout when Delete arrives at the timeout
  boundary (use `SetDialogForTest` with a sleeping fake).

Parity: `scripts/parity.sh` runs
`python3 threat_scanner.py scan --ci --no-system --no-report --no-prompt --json py.json DIR`
and `go run ./cmd/threatscan scan --ci --no-system --no-report --no-prompt --json go.json DIR`
on `internal/testfixtures` output and on `~/Coding`, then compares the sorted
sets of `(category, severity, path)`. Any difference must be fixed or written
down in this file.

CI: add a `go` job to `.github/workflows/ci.yml` on ubuntu, macos-latest,
macos-13, windows-latest and the Fedora containers: `go vet ./...`,
`go test -race ./...`, `go build` with Go 1.24, plus the parity script on Linux.

## P6. Updates: `internal/update`

**Indicators** (do first, it is a straight port of `threatscan/updater.py`):
`UpdateIOCs(dataDir, current, cfg)`: GET `cfg.IOCUpdateURL` or the default
`https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/threatscan/iocs.json`
with User-Agent `threatscan/<version>`, cap at 2 MB, validate with
`iocs.Parse`, install to `iocs.UserPath(dataDir)` via temp file + rename only
if `version` is newer, always write `<data_dir>/ioc-last-check` (Unix seconds).
Set `guardHooks.UpdateIOCs` to it and add the `update-iocs [--url]` command.

**Program** (`update.go`, wired as a `guard.PeriodicTask` named "self-update"
with interval `cfg.UpdateInterval` when `cfg.AutoUpdate`, plus an `update
[--check]` command):
1. GET `cfg.UpdateAPIURL` or `https://api.github.com/repos/FaheemRafiq/threatscan/releases/latest`
   (`.../releases` and pick the newest when `update_channel` is `beta`).
   Skip drafts. Compare tags as semver against the running version; nothing to
   do unless newer. Skip a version recorded as failed (see step 6).
2. Download `threatscan-<goos>-<goarch>[.exe]`, `checksums.txt`,
   `checksums.txt.sig` to `<InstallDir>/update/`.
3. Verify `checksums.txt.sig` with ed25519 against the public keys in
   `internal/update/pubkeys.go` (a slice, so keys can rotate), then verify the
   binary's SHA-256 against the matching line. Any mismatch: delete the
   downloads, log, return.
4. Run the downloaded file with `version` and require exit 0 and output
   containing the new version.
5. Rename the current binary to `<name>.old`, rename the new one into place
   (on Windows the running exe can be renamed but not deleted; that is why the
   order is rename-old, rename-new). Record `{version, time}` in
   `<data_dir>/update-state.json`. Ask the service manager to restart the guard
   (systemd/launchd restart the unit; on Windows start the new exe detached and
   exit).
6. Rollback: on guard start, if `update-state.json` says an update happened
   less than 2 minutes ago and the previous run never wrote a heartbeat with the
   new version, and a `.old` exists, swap `.old` back, mark that version as
   failed, and restart. `guard.ReadHeartbeat` gives you the last heartbeat.
7. After a successful start on a new version, notify "ThreatScan updated to vX.Y.Z"
   and delete `.old`.

Tests: an `httptest.Server` serving a fake releases API and assets; build two
tiny test binaries with `go build -ldflags -X main.version=...`; assert a valid
update is installed, a tampered checksum is refused, a binary that fails step 4
is refused, and a simulated missing heartbeat rolls back.

One-time setup: generate an ed25519 key pair (`go run ./scripts/keygen`),
commit only the public key, put the private key in the GitHub secret
`THREATSCAN_SIGNING_KEY` and an offline backup.

## P7. Installers, download page, release pipeline

- `scripts/release.sh`: `CGO_ENABLED=0 GOTOOLCHAIN=go1.24.13 go build -trimpath -ldflags "-s -w -X main.version=$TAG"`
  for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64,
  windows/arm64; write `checksums.txt`; sign it with the secret; `nfpm` for
  `.rpm`/`.deb` (payload in `/usr/lib/threatscan`, postinstall runs
  `install --unattended` as the invoking user).
- Windows: Inno Setup `installers/windows/threatscan.iss`,
  `PrivilegesRequired=lowest`, installs to `{localappdata}\Programs\ThreatScan`,
  `[Run]` `threatscan.exe install --unattended`, `[UninstallRun]`
  `threatscan.exe uninstall`. Build with `iscc` on the Windows runner.
- macOS: `lipo` the two darwin binaries, `pkgbuild` + `productbuild` into
  `ThreatScan.pkg` targeting the user home; `postinstall` runs
  `install --unattended` as the console user (`stat -f %Su /dev/console`).
- Linux `installers/install.sh`: detect arch, download binary + checksums +
  sig from `releases/latest/download/`, verify SHA-256 (signature verification
  is optional in shell; the binary re-verifies on its first self-update),
  `chmod +x`, run `install --unattended`.
- `docs/index.html` on GitHub Pages: detect OS from `navigator.userAgent`,
  one button linking to `https://github.com/FaheemRafiq/threatscan/releases/latest/download/<asset>`,
  and the Linux one-liner.
- Replace `.github/workflows/release.yml` (currently PyInstaller) with the Go
  pipeline above. Tag `v6.0.0-rc1` as a pre-release first.

Smoke tests in CI: `ThreatScan-Setup.exe /VERYSILENT` on windows-latest,
`installer -pkg ThreatScan.pkg -target CurrentUserHomeDirectory` on macOS,
`install.sh` in the Fedora container; each must end with `threatscan status`
showing `Guard: alive`.

## P8. v5.2 migration (Python)

In `threatscan/guard.py`, extend `maybe_update_iocs` (daily) to also check the
releases API for a stable `v6.*`; download the Go binary for this OS/arch,
verify SHA-256 against `checksums.txt` (and the ed25519 signature: use the
same public key, `cryptography` is not a dependency, so ship a tiny pure-Python
ed25519 verify or skip signature and rely on HTTPS + hash for this one-time
step, documented), run it with `install --unattended`, then call
`ServiceManager.uninstall()` and exit. Release as v5.2. Wait for the rc to be
confirmed, then tag `v6.0.0`.

## Pitfalls already met

- The process monitor and Falco see dialog **command lines**. Never put
  evidence text in a subprocess argument list; `internal/prompt` uses the
  zenity library and `internal/scan/system.go` ignores the dialog tools by name.
- `zenity --text-info` and `--question` both exit 5 on timeout; the Go code
  also treats a "Delete" that arrives at the timeout boundary as a timeout.
- fsnotify watches single directories: add every subdirectory, and add new
  trees recursively (the v5.1 macOS/Windows bug).
- `install --dry-run` must not save config or touch editor settings.
- `crontab` edits: abort if `crontab -l` fails, back up first.

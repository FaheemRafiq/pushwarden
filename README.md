# ThreatScan v4.0

**PolinRider / Contagious Interview Malware Detector**

Cross-platform (Linux / macOS / Windows) scanner for the **Lazarus Group (DPRK)** supply-chain campaign tracked as **PolinRider** and **Contagious Interview**. Detects obfuscated JavaScript payloads injected into framework config files, blockchain dead-drop loaders, git history rewriting, RAT persistence, compromised dependencies, and active C2 connections.

**Current as of: September 2026** — includes rotated signatures (March → July), live samples from production infections, and all indicators documented by OpenSourceMalware.com, JFrog, Socket, Nextron, and Checkmarx.

---

## What It Detects

### Repository Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| `global['_V']='A#-####'` | Campaign obfuscation marker | **CRITICAL** |
| `global['!']='#-####'` | Alternate marker family | **CRITICAL** |
| `_$_1e42` / `MDy(` | Decoder function names (March + July rotations) | **CRITICAL** |
| `Cot%3t=shtP` | Rotated code signature (July 2026+) | **CRITICAL** |
| Hidden payloads | Malicious code after ~280 spaces on export lines | **HIGH** |
| `temp_auto_push.bat` | Git history rewriter + force-pusher | **CRITICAL** |
| `.gitignore` hiding `.bat` | Config tampering evidence | **HIGH** |
| `.vscode/tasks.json` `folderOpen` | VS Code stage-1 autorun (bypasses npm v12 lifecycle script protections) | **CRITICAL** |
| `fa-solid-400.woff2` | Fake font loader (SHA-256 verified against 18 confirmed cases) | **CRITICAL** |
| Forged committer dates | Git commits with `%ct < %at - 7 days` (timestamp forgery detection) | **HIGH** |
| XOR keys | `2[gWfGj;<:-93Z^C`, `ThZG+0jfXE6VAGOJ`, `q4FZkxX{!h,Sr3=@` | **CRITICAL** |
| Blockchain RPC refs | `api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`, `bsc-dataseed.binance.org` **+ campaign marker** | **CRITICAL** |
| TRON wallets | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`, `TA48dct6rFW8...` | **CRITICAL** |
| C2 IPs & paths | 14 C2 servers, 15 URL paths including `/$/boot`, `/verify-human/`, `/api/telemetry/*` | **CRITICAL** |
| Telegram exfil | Bot token `7870147428:AAGbYG...`, chat ID `7699029999` | **CRITICAL** |

### Package Indicators

| Type | Details | Severity |
|------|---------|----------|
| npm compromised | `html-to-gutenberg@4.2.11`, `fetch-page-assets@1.2.9`, `@joyfill/*` | **CRITICAL** |
| Go modules | 16 poisoned modules (bm-197/chill, lambda-platform/*, etc.) | **CRITICAL** |
| Packagist | `roberts/leads` (shares C2 23.27.202.27) | **CRITICAL** |
| Lifecycle scripts | `preinstall`/`postinstall`/`prepare` with `node -e`, `curl\|bash`, `.woff2` refs | **HIGH** |

### System Indicators

| Check | What It Looks For | Severity |
|-------|-------------------|----------|
| **Live processes** | `global['_V']`, `/verify-human/`, `/0x/clb`, `Sec-V`, runtimedev-link markers in cmdlines | **CRITICAL** |
| **Network C2** | Connections to 14 known malicious IPs (193.247.144.38, 194.11.226.41, etc.) | **CRITICAL** |
| **RAT footprint** | Directories: `VSCodeUpdater`, `runtimedev-link`; files: `agent.env`, `tg14xq.js`, `*.log` | **CRITICAL** |
| **Cron/Scheduling** | PolinRider keywords in crontab, `/etc/cron.d`, Windows schtasks | **CRITICAL** / **HIGH** |
| **Systemd (Linux)** | `~/.config/systemd/user/*.service` with `runtimedev-link`, `VSCodeUpdater`, `node -e` | **CRITICAL** |
| **XDG Autostart (Linux)** | `~/.config/autostart/*.desktop` with malware indicators | **CRITICAL** |
| **Launchd (macOS)** | `~/Library/LaunchAgents/*.plist` with rat names or env vars | **CRITICAL** |
| **Shell startup** | `.bashrc`, `.zshrc`, `.profile` with `curl\|bash`, `eval(atob)`, malware markers | **HIGH** |
| **Credentials exposed** | `.npmrc`, `.git-credentials`, `.netrc`, `~/.ssh/`, `gh/hosts.yml` present on infected host | **WARNING** (HIGH if infected) |
| **SSH keys** | Multiple private keys indicate widespread compromise | **WARNING** |
| **Editor injection** | Payloads in VS Code, Cursor, Discord, GitHub Desktop extension dirs or global npm | **CRITICAL** |
| **/etc/hosts tampering** | Redirects to npm, GitHub, PyPI registries | **HIGH** |
| **Portable Python (Windows)** | `%LOCALAPPDATA%\Programs\Python\Python3127\` (stage-4 OmniStealer runtime) | **HIGH** |

---

## Installation

```bash
# Download the scanner
curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/threat_scanner.py -o threat_scanner.py
chmod +x threat_scanner.py

# Python 3.8+ required
python3 --version
```

---

## Local Usage

### Basic Scan (Current Directory)
```bash
python3 threat_scanner.py
```

### Scan Specific Directory
```bash
python3 threat_scanner.py /path/to/projects
python3 threat_scanner.py ~/Documents ~/code
```

### Common Scenarios

**Scan home directory + auto-discover project folders:**
```bash
python3 threat_scanner.py --home
# Automatically scans: ~/projects, ~/dev, ~/code, ~/work, ~/Developer, etc.
```

**Verbose output (see every repo scanned, including clean ones):**
```bash
python3 threat_scanner.py --verbose ~/projects
```

**Scan every .js/.ts/.mjs file (not just known config names):**
```bash
python3 threat_scanner.py --js-all ~/projects
# Warning: slower; produces more false positives on unrelated code
```

**Skip system checks (repos only):**
```bash
python3 threat_scanner.py --no-repos --ci ~/projects
# Fast repo-focused scan; no network/process/persistence checks
```

**Skip repository checks (system-only):**
```bash
python3 threat_scanner.py --no-repos
# Check for active infections, C2 connections, RAT persistence, cron jobs, etc.
```

**CI / non-interactive mode (no colour, compact output):**
```bash
python3 threat_scanner.py --ci ~/projects
```

**Write JSON report (for parsing/alerting systems):**
```bash
python3 threat_scanner.py --json report.json ~/projects
# Creates: {"version":"4.0", "stats":{...}, "findings":[...]}
```

### Full Example (Post-Incident Recovery)
```bash
# Scan everything on a potentially-infected host
python3 threat_scanner.py --home --verbose --json incident-report.json

# Exit codes:
#   0 = clean
#   1 = HIGH or CRITICAL findings detected
#   2 = error (bad path, permission denied, etc.)

if [ $? -eq 1 ]; then
  echo "Infections detected. See incident-report.json for details."
fi
```

---

## Output Example

### Infected Repo

```
  SCAN SUMMARY
══════════════════════════════════════════════════════════════════════
  Platform:                      Linux 6.18.44-fc-v37
  Duration:                      0.5s
  Repos scanned:                 1
  Repos infected:                1
  Files checked:                 5

  CRITICAL:                      8
  HIGH:                          3
  WARNING:                       1
  INFO:                          0

  Status:                        INFECTIONS DETECTED
══════════════════════════════════════════════════════════════════════

  ✖ [CRITICAL] PolinRider signature in postcss.config.mjs
      Path: /home/faheem/projects/web-app/postcss.config.mjs
      Literal: global['_V']='A8-4032-1';
      Remove everything after the legitimate config in:
        /home/faheem/projects/web-app/postcss.config.mjs

  ✖ [CRITICAL] VS Code folderOpen autorun task
      Path: /home/faheem/projects/web-app/.vscode/tasks.json
      Delete .vscode/tasks.json unless you wrote it.

  ✖ [CRITICAL] Propagation script: temp_auto_push.bat
      Path: /home/faheem/projects/web-app/temp_auto_push.bat
      Delete immediately and audit every branch this repo pushed to.
```

### Clean Repo

```
✔ Clean: /home/faheem/projects/documentation
✔ Clean: /home/faheem/projects/landing-page

  SCAN SUMMARY
══════════════════════════════════════════════════════════════════════
  Status:                        CLEAN
══════════════════════════════════════════════════════════════════════
```

---

## What's New in v4.0

### Signatures & IOCs
- ✅ Rotated signatures: `Cot%3t=shtP`, `MDy(`, `global['_t_s']`, `global['_t_u']`
- ✅ All 3 XOR keys (March original + July rotation + live Sept 2026 sample)
- ✅ 14 C2 IPs including your host's attackers (193.247.144.38, 194.11.226.41)
- ✅ 3 TRON wallets, 3 Aptos addresses, 15 C2 URL paths
- ✅ Telegram exfiltration bot indicators

### New Detection Modules
- ✅ **runtimedev-link RAT**: dirs, `agent.env`, systemd `--user`, XDG autostart, launchd, schtasks
- ✅ **VS Code folderOpen autorun** (`.vscode/tasks.json` stage 1)
- ✅ **Fake font SHA-256 validation** (OmniStealer loader)
- ✅ **Git history tampering** (forged committer dates, `%ct < %at`)
- ✅ **Compromised packages**: 4 npm, 16 Go modules, 1 Packagist package
- ✅ **Lifecycle script inspection** (`package.json` preinstall/postinstall)
- ✅ **Credential exposure**: `.npmrc`, `.git-credentials`, `.netrc`, `.ssh/`, gh, docker, aws
- ✅ **Editor/app injection**: VS Code, Cursor, Discord, GitHub Desktop, global npm CLI
- ✅ **Linux systemd `--user` units** & XDG autostart
- ✅ **Windows portable Python** stage-4 detector
- ✅ **Non-git projects**: scans `package.json`, `go.mod`, `composer.json` even without `.git`

### Usability
- ✅ `--json` report output (for CI/alerting systems)
- ✅ `--ci` mode (no colour, compact output)
- ✅ `--no-repos` / `--no-system` (skip respective scans)
- ✅ `--home` auto-discovery of project directories
- ✅ `--js-all` for comprehensive file scanning
- ✅ Exit codes `0/1/2` compatible with `polinrider-scanner.sh`
- ✅ Multiple directory arguments
- ✅ CI-evasion hostname detection (warns if payload would stay dormant)

---

## Known False Positives

### Browser Extensions (FIXED in v4.0)

**TronLink, MetaMask, Uniswap, and other legitimate crypto wallet extensions** reference blockchain RPCs (`api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`). The scanner now:

- ✅ Skips browser profile directories entirely during walks
- ✅ Only flags blockchain refs if co-located with campaign markers, XOR keys, or wallet addresses
- ✅ Never flags bare `eval()` + RPC hostname without additional indicators

If you see findings in `~/.config/google-chrome/Profile 1/Extensions/`, verify:
```bash
# Check if it's from Chrome Web Store
chrome://extensions → Click the extension → "Offered by Chrome Web Store"

# If yes, it's safe (Google vets these)
# If no or it's a fork/clone, delete it
```

---

## Incident Response Workflow

### If Infections Are Found

**1. Kill live processes:**
```bash
# Find and kill malware
ps aux | grep -E "global\['_V'\]|/verify-human|runtimedev-link|VSCodeUpdater"
kill -9 <PID>
```

**2. Block C2 IPs:**
```bash
# Linux
sudo iptables -A OUTPUT -d 193.247.144.38 -j DROP
sudo iptables -A OUTPUT -d 194.11.226.41 -j DROP
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# macOS
echo "block drop out to 193.247.144.38" | sudo pfctl -f -

# Windows
netsh advfirewall firewall add rule name="Block PolinRider" dir=out action=block remoteip=193.247.144.38
```

**3. Remove persistence:**
```bash
# Cron
crontab -e  # Remove entries

# Systemd --user (Linux)
systemctl --user disable --now runtimedev-link.service
rm ~/.config/systemd/user/runtimedev-link.service

# XDG Autostart (Linux)
rm ~/.config/autostart/runtimedev-link.desktop

# Launchd (macOS)
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.runtimedev.link.plist

# Scheduled tasks (Windows)
schtasks /Delete /TN "runtimedev-link" /F
```

**4. Clean repositories:**
```bash
# For each infected repo
cd /path/to/repo
git log --all --oneline | head -20  # Find last good commit

# Reset all branches to the good commit (before Sept 8, 2026)
git reset --hard <good-commit-sha>
git push origin --all -f  # Force-push clean history
git push origin --tags -f
```

**5. Rotate credentials:**
```
- GitHub: Settings → Developer Settings → Personal access tokens (revoke all)
- npm: npm profile set password (or revoke tokens at npmjs.com)
- SSH: Delete ~/.ssh/id_* and generate new keys
- Git: Update ~/.git-credentials or use ssh-agent
- Cloud: Rotate API keys for Vercel, Netlify, AWS, etc.
- 2FA: Enable hardware-backed 2FA on GitHub and npm
```

**6. Report:**
```
https://opensourcemalware.com/report
Subject: PolinRider infection
Include: exit code 1 scan results, any custom IOCs, timelines
```

---

## Exit Codes

| Code | Meaning | Use In CI |
|------|---------|----------|
| `0` | No findings, system clean | Success ✓ |
| `1` | HIGH or CRITICAL findings detected | Fail (block PR/merge) ✗ |
| `2` | Error (invalid path, permission denied) | Retry/investigate |

---

## CI/CD Integration (GitHub Actions)

### Minimal Setup

Add to any repo:

**.github/workflows/malware-scan.yml:**
```yaml
name: Malware Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
      - run: |
          curl -fsSL https://raw.githubusercontent.com/FaheemRafiq/threatscan/main/threat_scanner.py -o threat_scanner.py
          chmod +x threat_scanner.py
          python3 threat_scanner.py --no-system --ci --json report.json .
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: threat-scan-report
          path: report.json
```

### With Branch Protection

Repo Settings → Branches → Branch Protection Rules:
```
☑ Require status checks to pass
  → Select "Malware Scan"
☑ Require branches to be up to date
☑ Require code reviews
☑ Block automatic merges if malware scan fails
```

---

## Comparison: Local Scanner vs Falco Runtime Monitor

| Feature | `threat_scanner.py` | Falco |
|---------|:-------------------:|:-----:|
| Repository scanning | ✅ | ❌ |
| Point-in-time audit | ✅ | ❌ |
| Post-incident forensics | ✅ | ❌ |
| Live process detection | ✅ | ✅ |
| C2 connection blocking | ⚠️ (reports only) | ✅ (auto-kills) |
| Continuous monitoring | ❌ | ✅ |
| Zero-day detection | ❌ | ✅ (heuristic) |
| CI/CD integration | ✅ | ❌ |

**Use both:** Falco catches active infections; ThreatScan catches dormant code before it runs.

---

## Attribution

**Campaign:** Lazarus Group (DPRK) — "Contagious Interview" / "PolinRider"  
**Active:** March 2026 – September 2026+ (ongoing)  
**Victims:** Developers across npm, Go, PHP, PyPI ecosystems  
**Entry vectors:** Fake job interviews, lure repos, typosquatted packages  
**Goals:** Credential theft, source code exfiltration, cryptocurrency wallet compromise, lateral movement

**Sources:**
- https://opensourcemalware.com/blog/polinrider-caused-dozens-of-npm-and-go-compromises (July 2026)
- https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/ (June 2026)
- https://socket.dev/blog/joyfill-npm-beta-releases-compromised (June 2026)
- https://github.com/OpenSourceMalware/PolinRider (March–September 2026)

---

## License

MIT

## Contributing

Report false positives, new IOCs, or missing detection categories via GitHub Issues.

---

## Support

```bash
# Get help
python3 threat_scanner.py --help

# Report a finding
https://opensourcemalware.com

# Check your host
python3 threat_scanner.py --home --verbose
```

**Stay safe.** 🛡️

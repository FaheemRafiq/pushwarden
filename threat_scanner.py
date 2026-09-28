#!/usr/bin/env python3
"""
ThreatScan v4.1 — Cross-Platform PolinRider / Contagious Interview Detector

Detects the DPRK (Lazarus Group) supply-chain campaign tracked as PolinRider,
including every signature rotation documented through September 2026:

  * Config-file payload injection (postcss/next/vue/tailwind/eslint/...)
  * Rotated obfuscation signatures  (rmcej%otb% -> Cot%3t=shtP, _$_1e42 -> MDy)
  * Blockchain dead-drop loaders     (TRON / Aptos / BSC RPC + XOR keys)
  * Fake font-file loader            (fa-solid-400/500.woff2, SHA-256 + magic-byte verified)
  * Disguised payloads               (JS hidden in font/image files behind whitespace padding)
  * VS Code folderOpen autorun       (.vscode/tasks.json stage-1 entry point)
  * VS Code autorun enablers         (.vscode/settings.json task.allowAutomaticTasks)
  * Payloads buried in git history   (commits re-adding the loader under decoy messages)
  * Git history rewriting            (temp_auto_push.bat, forged committer dates)
  * runtimedev-link RAT              (VSCodeUpdater disguise, systemd/cron/launchd)
  * Known compromised packages       (npm / Go / Packagist)
  * Credential exposure              (.npmrc, .git-credentials, .netrc, gh hosts.yml)
  * Live process + network C2 checks (Sec-V markers, C2 IPs, blockchain RPCs)
  * Persistence                      (cron, systemd --user, XDG, launchd, schtasks)

This script is READ-ONLY. It never deletes, modifies, or uploads anything.

Usage:
    python3 threat_scanner.py [OPTIONS] [DIRECTORY]

Options:
    --verbose        Show every repo scanned, including clean ones
    --js-all         Scan every .js/.mjs/.ts/.tsx file, not just known configs
    --no-system      Skip host checks (processes, network, persistence, creds)
    --no-repos       Skip repository checks
    --json FILE      Write machine-readable results to FILE
    --ci             CI mode: no colour, compact output, exit 1 on any HIGH+
    --home           Also scan common project dirs under $HOME automatically

Exit codes (compatible with polinrider-scanner.sh):
    0 - clean
    1 - infections / high-severity findings
    2 - error

Platforms: Linux, macOS, Windows (Python 3.8+)

Sources:
    https://opensourcemalware.com/blog/polinrider-caused-dozens-of-npm-and-go-compromises
    https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
    https://socket.dev/blog/joyfill-npm-beta-releases-compromised
    https://github.com/OpenSourceMalware/PolinRider
"""

import os
import sys
import re
import json
import time
import hashlib
import platform
import subprocess
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Tuple
from enum import IntEnum
from datetime import datetime, timezone

VERSION = "4.1"

# ═══════════════════════════════════════════════════════════════════════════════
# INDICATORS OF COMPROMISE
# All values sourced from OpenSourceMalware, JFrog, Socket, Nextron, Checkmarx,
# and live samples recovered from infected Fedora hosts (Sept 2026).
# ═══════════════════════════════════════════════════════════════════════════════


class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    HIGH = 2
    CRITICAL = 3


# ─── Code signatures: original (March 2026) and rotated (July 2026+) ──────────
LITERAL_SIGNATURES = [
    # March 2026 originals
    '("rmcej%otb%",2857687)',
    "global['!']='8-270-2';var $_1e42=",
    "global['!']='4-1928'",
    "global['_V']='A4-1928'",
    "global['!']='10-83-10'",
    "global['!']='A10-010'",
    "global['!']='A10-2340'",
    # July 2026 rotation
    "Cot%3t=shtP",
    # Live sample from erstech host, Sept 2026
    "global['_V']='A8-4032-1'",
    "global['_t_s']=",
    "global['_t_u']=",
    "/verify-human/",
    "/0x/clb",
    "/0x/cb",
    "/$/boot",
    "'Sec-V'",
    '"Sec-V"',
    "/*RS260605*/",
]

# ─── XOR keys (both rotations) ────────────────────────────────────────────────
XOR_KEYS = [
    "2[gWfGj;<:-93Z^C",
    "ThZG+0jfXE6VAGOJ",
    "q4FZkxX{!h,Sr3=@",   # live sample Sept 2026
]

# ─── Blockchain dead-drop infrastructure ──────────────────────────────────────
BLOCKCHAIN_RPC_HOSTS = [
    "api.trongrid.io",
    "fullnode.mainnet.aptoslabs.com",
    "bsc-dataseed.binance.org",
    "bsc-rpc.publicnode.com",
]

TRON_WALLETS = [
    "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP",
    "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG",
    "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v",
]

APTOS_ADDRESSES = [
    "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e",
    "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3",
    "0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1",
]

# ─── C2 infrastructure ────────────────────────────────────────────────────────
MALICIOUS_IPS = [
    # PolinRider (OpenSourceMalware, July 2026)
    "166.88.134.62", "23.27.13.43", "198.105.127.210", "23.27.202.27",
    # Live on erstech host, Sept 2026
    "193.247.144.38", "194.11.226.41",
    # Earlier campaign infrastructure
    "166.88.54.158", "154.91.0.103", "136.0.9.8", "166.88.4.2",
    "23.27.120.142", "202.155.8.173", "166.88.134.82", "188.43.33.249",
]

C2_URL_PATHS = [
    "/$/boot", "/verify-human/", "/snv", "/u/e", "/u/f",
    "/d/python.zip", "/d/python.7z", "/d/7zr.exe",
    "/0x/clb", "/0x/cb", "/0x/js",
    "/api/telemetry/poll-command",
    "/api/telemetry/report",
    "/api/telemetry/command-result",
    "/api/telemetry/upload-download",
]

# ─── Telegram exfiltration ────────────────────────────────────────────────────
TELEGRAM_INDICATORS = [
    "7870147428:AAGbYG",
    "7699029999",
]

# ─── Fake font loader hashes (Nextron / JFrog) ────────────────────────────────
FAKE_FONT_SHA256 = {
    "53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8",
    "13e9a3c41e038bf9d8fcb0831305819819e4f7f4452bc20a04b9bf2756ee22e8",
    # Live samples recovered from an infected monorepo's git history, Sept 2026
    "3287f2de563bd76465d353bd22b4d07c2af1cda9dd45efcb0da49e3ca49f7639",  # fa-solid-400.woff2, A10-*010
    "c98f2703db7e8b73b296e686cc8dee89d1b1643a90c3e89ef90b6a75805421aa",  # fa-solid-400.woff2, A10-*020
    "9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba",  # fa-solid-500.woff2, A10-*050
}
FAKE_FONT_NAMES = ["fa-solid-400.woff2", "fa-solid-400.woff", "fa-regular-400.woff2",
                   "fa-solid-500.woff2"]

# ─── Magic bytes for binary assets that loaders masquerade as ─────────────────
# (offset, signature) pairs; any match means the header is genuine.
FONT_EXTENSIONS = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
ASSET_MAGIC = {
    ".woff2": [(0, b"wOF2")],
    ".woff": [(0, b"wOFF")],
    ".ttf": [(0, b"\x00\x01\x00\x00"), (0, b"true"), (0, b"OTTO"), (0, b"ttcf")],
    ".otf": [(0, b"OTTO"), (0, b"\x00\x01\x00\x00")],
    ".eot": [(34, b"LP")],
    ".png": [(0, b"\x89PNG")],
    ".jpg": [(0, b"\xff\xd8\xff")],
    ".jpeg": [(0, b"\xff\xd8\xff")],
    ".gif": [(0, b"GIF87a"), (0, b"GIF89a")],
    ".ico": [(0, b"\x00\x00\x01\x00"), (0, b"\x00\x00\x02\x00")],
    ".webp": [(0, b"RIFF")],
}

# ─── Marker regex (generalised across all A#- versions) ───────────────────────
MARKER_REGEX = re.compile(
    r"""global\[['"]![ '"]\]\s*=\s*['"][A0-9*-]{4,}['"]"""
    r"""|global\[['"]_V['"]\]\s*=\s*['"][A0-9*-]{4,}['"]"""
    r"""|global(?:\.i|\[['"]i['"]\])\s*=\s*['"]A\d+-\*?\d+['"]"""
    r"""|global\.r\s*=\s*require\b"""
    r"""|_\$_1e42"""
    r"""|\bMDy\s*\("""
    r"""|global\[['"]r['"]\]\s*=\s*require"""
    r"""|global\[['"]_t_[su]['"]\]"""
    r"""|atob\s*\(\s*process\.env"""
    r"""|eval\s*\(\s*atob"""
    r"""|['"]Sec-V['"]\s*:"""
    r"""|Sec-V['"]\s*,"""
    r"""|await\s+eval\s*\("""
    r"""|Function\s*\(\s*['"]retur['"]\s*\+"""
    r"""|require\s*\(\s*['"]child['"]\s*\+\s*['"]_proc['"]""",
    re.IGNORECASE,
)

# ─── Config files targeted by PolinRider ──────────────────────────────────────
CONFIG_FILES = [
    "postcss.config.mjs", "postcss.config.js", "postcss.config.cjs",
    "tailwind.config.js", "tailwind.config.mjs", "tailwind.config.ts",
    "eslint.config.mjs", "eslint.config.js", "eslint.config.cjs",
    "next.config.mjs", "next.config.js", "next.config.ts",
    "vue.config.js", "vue.config.mjs",
    "astro.config.mjs", "astro.config.js", "astro.config.ts",
    "babel.config.js", "babel.config.mjs", "babel.config.cjs",
    "jest.config.js", "jest.config.mjs", "jest.config.ts",
    "vite.config.js", "vite.config.mjs", "vite.config.ts",
    "vitest.config.ts", "vitest.config.js",
    "webpack.config.js", "webpack.config.mjs",
    "svelte.config.js",
    "nuxt.config.js", "nuxt.config.ts",
    "prettier.config.js", "prettier.config.mjs",
    "rollup.config.js", "rollup.config.mjs",
    "tsup.config.ts", "drizzle.config.ts",
]

# ─── Propagation / orchestration scripts ─────────────────────────────────────
PROPAGATION_SCRIPTS = [
    "temp_auto_push.bat", "temp_interactive_push.bat",
    "config.bat", "auto_push.bat", "temp_auto_push.sh", "auto_push.sh",
]

# ─── .gitignore entries the propagator adds to hide its own artefacts ─────────
# ".gitignore" ignoring itself keeps the tampering out of `git status`;
# "nul" is left behind when the Windows orchestrator's >nul redirect runs under bash.
GITIGNORE_IOCS = [".gitignore", "branch_structure.json", "nul"]

# ─── git log -G pattern (POSIX ERE) for payloads committed anywhere in history ─
HISTORY_PAYLOAD_REGEX = (
    r"global(\.i|\[.i.\]) ?= ?.A[0-9]+-\*?[0-9]+"
    r"|global\[.(!|_V).\] ?= ?.A?[0-9]+-"
    r"|_\$_1e42|Cot%3t=shtP|rmcej%otb%"
    r"|node \./[^ )]+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico)"
)

# ─── Known compromised packages ───────────────────────────────────────────────
COMPROMISED_NPM = {
    "html-to-gutenberg": ["4.2.11"],
    "fetch-page-assets": ["1.2.9"],
    "@joyfill/components": ["4.0.0-rc24-2773-beta.4"],
    "@joyfill/layouts": ["0.1.2-2773.beta.0"],
    "runtimedev-link": ["*"],
}

COMPROMISED_GO = [
    "github.com/Barsu5489/commerce",
    "github.com/Setsu548/Logistic",
    "github.com/amantsehay/a2sv-go-course",
    "github.com/anatoli-derese/a2sv-excercise",
    "github.com/bm-197/chill",
    "github.com/dexbotsdev/uniswap-v2-v3-arbitrage",
    "github.com/glacialspring/go-winsparkle",
    "github.com/glacialspring/static",
    "github.com/hngi/Team-Fierce-Backend-Golang",
    "github.com/lambda-platform/dan",
    "github.com/lambda-platform/ebarimt-rest-api",
    "github.com/lambda-platform/lambda",
    "github.com/naol7/dist-task-scheduler",
    "github.com/reauheau/goaubio",
    "github.com/rickt/slack-weather-bot",
    "github.com/zainirfan13/graphql-client",
]

COMPROMISED_PACKAGIST = ["roberts/leads"]

# ─── runtimedev-link RAT (VSCodeUpdater disguise) ─────────────────────────────
RAT_DIR_NAMES = [
    "VSCodeUpdater", "vscode-updater", "VSCode-Updater",
    "runtimedev-link", "runtimedev",
]
RAT_SERVICE_NAMES = ["runtimedev-link", "com.runtimedev.link"]
RAT_ENV_KEYS = ["SSTAR_API_BASE", "SSTAR_DEPLOYMENT_HASH", "NODE_LINK_API_BASE", "NODE_LINK_HASH"]

# ─── Process indicators ───────────────────────────────────────────────────────
MALICIOUS_PROCESS_PATTERNS = [
    re.compile(r"global\[['\"]_V['\"]\]", re.I),
    re.compile(r"global\[['\"]!['\"]\]", re.I),
    re.compile(r"global\[['\"]_t_[su]['\"]\]", re.I),
    re.compile(r"_\$_1e42", re.I),
    re.compile(r"\bMDy\s*\(", re.I),
    re.compile(r"Cot%3t=shtP", re.I),
    re.compile(r"rmcej%otb%", re.I),
    re.compile(r"Sec-V", re.I),
    re.compile(r"/verify-human/", re.I),
    re.compile(r"/0x/c(l)?b", re.I),
    re.compile(r"/\$/boot", re.I),
    re.compile(r"node\s+-e\s+.*eval\(atob", re.I),
    re.compile(r"node\s+-e\s+.*await\s+eval", re.I),
    re.compile(r"python[3]?\s+-c\s+.*(exec|eval)\(", re.I),
    re.compile(r"python[3]?\s+-c\s+.*base64", re.I),
    re.compile(r"VSCodeUpdater", re.I),
    re.compile(r"runtimedev-link", re.I),
    re.compile(r"--token\s+https?://[^\s]+\|", re.I),
    re.compile(r"font[-_]?updater", re.I),
    re.compile(r"\.cache/font", re.I),
    re.compile(r"fa-solid-[45]00\.woff2", re.I),
    re.compile(r"global\.i\s*=\s*['\"]A\d+-\*", re.I),
    re.compile(r"\bnode\s+\S+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico)\b", re.I),
    re.compile(r"/tmp/\.[a-z]", re.I),
]

# ─── Shell rc / startup file patterns ─────────────────────────────────────────
SHELL_SUSPICIOUS_PATTERNS = [
    re.compile(r"curl\s+[^|\n]*\|\s*(bash|sh|python[3]?)", re.I),
    re.compile(r"wget\s+[^|\n]*\|\s*(bash|sh|python[3]?)", re.I),
    re.compile(r"eval\s*\(\s*base64", re.I),
    re.compile(r"eval\s*\(\s*atob", re.I),
    re.compile(r"python[3]?\s+-c\s+.*import\s+socket", re.I),
    re.compile(r"node\s+-e\s+.*child_process", re.I),
    re.compile(r"global\[['\"]!['\"]\]", re.I),
    re.compile(r"global\[['\"]_V['\"]\]", re.I),
    re.compile(r"VSCodeUpdater|runtimedev-link", re.I),
]

# ─── Suspicious cron / task keywords ──────────────────────────────────────────
SCHEDULED_TASK_KEYWORDS = [
    "runtimedev", "vscodeupdater", "font", "cache", "updater", "temp", ".tmp",
    "node -e", "python -c", "wscript", "//B", "curl", "wget",
]

# ─── Hostnames the malware refuses to run on (CI evasion) ─────────────────────
CI_EVASION_HOSTNAMES = ["github-runner", "buildbot", "buildkitsandbox", "microsoft-standard-WSL2"]


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    path: Optional[str] = None
    details: str = ""
    remediation: str = ""

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class ScanStats:
    repos_scanned: int = 0
    repos_infected: int = 0
    files_checked: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    warning: int = 0
    info: int = 0
    scan_duration: float = 0.0
    platform_name: str = ""
    scan_dirs: List[str] = field(default_factory=list)
    start_time: str = ""
    hostname: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# PLATFORM
# ═══════════════════════════════════════════════════════════════════════════════

class PlatformInfo:
    def __init__(self):
        system = platform.system().lower()
        self.is_windows = system == "windows"
        self.is_macos = system == "darwin"
        self.is_linux = system == "linux"
        self.os_name = system
        self.hostname = platform.node()
        self.python_version = platform.python_version()
        self.arch = platform.machine()
        self.kernel = platform.release()
        self.home = Path.home()
        self._no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    @property
    def display_name(self):
        if self.is_macos:
            return f"macOS {platform.mac_ver()[0]}"
        if self.is_windows:
            return f"Windows {platform.version()}"
        return f"Linux {self.kernel}"

    def run(self, cmd, timeout=15):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=self._no_window if self.is_windows else 0,
            )
            return r.stdout
        except Exception:
            return ""

    # ── Locations ────────────────────────────────────────────────────────────
    def shell_rc_files(self):
        names = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv",
                 ".config/fish/config.fish"]
        return [self.home / n for n in names if (self.home / n).is_file()]

    def local_share(self):
        if self.is_windows:
            return Path(os.environ.get("LOCALAPPDATA", self.home / "AppData/Local"))
        if self.is_macos:
            return self.home / "Library/Application Support"
        return self.home / ".local/share"

    def config_dir(self):
        if self.is_windows:
            return Path(os.environ.get("APPDATA", self.home / "AppData/Roaming"))
        return self.home / ".config"

    def persistence_dirs(self):
        d = []
        if self.is_linux:
            d += [self.home / ".config/systemd/user",
                  self.home / ".config/autostart",
                  Path("/etc/systemd/system"),
                  Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly")]
        elif self.is_macos:
            d += [self.home / "Library/LaunchAgents",
                  Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
        elif self.is_windows:
            appdata = Path(os.environ.get("APPDATA", ""))
            d += [appdata / "Microsoft/Windows/Start Menu/Programs/Startup"]
        return [p for p in d if p.is_dir()]

    def credential_files(self):
        c = self.home
        files = [
            c / ".npmrc", c / ".git-credentials", c / ".netrc",
            c / ".config/gh/hosts.yml", c / ".config/hub",
            c / ".docker/config.json", c / ".aws/credentials",
            c / ".yarnrc", c / ".yarnrc.yml", c / ".pypirc",
            c / ".config/runtimedev-link/agent.env",
        ]
        if self.is_windows:
            files += [self.home / "_netrc"]
        return [f for f in files if f.is_file()]

    def editor_dirs(self):
        """Editor / app install dirs the Joyfill variant injects into."""
        dirs = []
        if self.is_linux:
            dirs += [self.home / ".vscode/extensions", self.home / ".cursor/extensions",
                     self.home / ".config/discord", self.home / ".config/GitHub Desktop"]
        elif self.is_macos:
            dirs += [self.home / ".vscode/extensions", self.home / ".cursor/extensions",
                     self.home / "Library/Application Support/discord",
                     self.home / "Library/Application Support/GitHub Desktop"]
        elif self.is_windows:
            appdata = Path(os.environ.get("APPDATA", ""))
            local = Path(os.environ.get("LOCALAPPDATA", ""))
            dirs += [self.home / ".vscode/extensions", self.home / ".cursor/extensions",
                     appdata / "discord", local / "GitHubDesktop"]
        return [d for d in dirs if d.is_dir()]

    def npm_global_root(self):
        out = self.run(["npm", "root", "-g"]).strip()
        return Path(out) if out else None

    def hosts_file(self):
        if self.is_windows:
            return Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/drivers/etc/hosts"
        return Path("/etc/hosts")

    # ── Live system ──────────────────────────────────────────────────────────
    def list_processes(self) -> List[Tuple[int, str, str]]:
        procs = []
        if self.is_windows:
            out = self.run([
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | "
                "ConvertTo-Json -Compress"
            ])
            try:
                data = json.loads(out) if out.strip() else []
                if isinstance(data, dict):
                    data = [data]
                for p in data:
                    procs.append((int(p.get("ProcessId", 0)), p.get("Name") or "",
                                  p.get("CommandLine") or ""))
                return procs
            except Exception:
                pass
            out = self.run(["wmic", "process", "get", "ProcessId,Name,CommandLine", "/format:csv"])
            for line in out.strip().split("\n"):
                parts = line.strip().split(",", 3)
                if len(parts) >= 4 and parts[-1].isdigit():
                    procs.append((int(parts[-1]), parts[2], parts[1]))
            return procs

        if self.is_linux:
            proc = Path("/proc")
            for p in proc.iterdir():
                if not p.name.isdigit():
                    continue
                try:
                    cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf8", "ignore").strip()
                    name = (p / "comm").read_text(errors="ignore").strip()
                    if cmd:
                        procs.append((int(p.name), name, cmd))
                except Exception:
                    continue
            if procs:
                return procs

        out = self.run(["ps", "-eo", "pid=,comm=,args="])
        for line in out.split("\n"):
            parts = line.strip().split(None, 2)
            if len(parts) >= 3 and parts[0].isdigit():
                procs.append((int(parts[0]), parts[1], parts[2]))
        return procs

    def network_connections(self) -> List[Tuple[str, str, str]]:
        conns = []
        ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)")
        if self.is_windows:
            out = self.run(["netstat", "-ano"])
            for line in out.split("\n"):
                if "ESTABLISHED" in line or "SYN_SENT" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        m = ip_re.match(parts[2])
                        if m:
                            conns.append((m.group(1), m.group(2), parts[-1]))
        elif self.is_macos:
            out = self.run(["lsof", "-i", "-P", "-n"])
            for line in out.split("\n"):
                if "ESTABLISHED" in line or "SYN_SENT" in line:
                    parts = line.split()
                    for tok in parts:
                        if "->" in tok:
                            m = ip_re.search(tok.split("->")[-1])
                            if m:
                                conns.append((m.group(1), m.group(2), parts[1] if len(parts) > 1 else ""))
        else:
            for cmd in (["ss", "-tnp"], ["netstat", "-tnp"]):
                out = self.run(cmd)
                if not out:
                    continue
                for line in out.split("\n"):
                    if "ESTAB" in line or "SYN-SENT" in line:
                        parts = line.split()
                        pid = ""
                        pm = re.search(r"pid=(\d+)", line)
                        if pm:
                            pid = pm.group(1)
                        for tok in parts:
                            m = ip_re.match(tok)
                            if m and not m.group(1).startswith("127."):
                                conns.append((m.group(1), m.group(2), pid))
                if conns:
                    break
        return conns

    def crontab_lines(self):
        lines = []
        if self.is_windows:
            return lines
        out = self.run(["crontab", "-l"])
        lines += [l for l in out.split("\n") if l.strip() and not l.strip().startswith("#")]
        return lines

    def scheduled_tasks_windows(self):
        return self.run(["schtasks", "/query", "/fo", "CSV", "/v"])

    def systemd_user_units(self):
        if not self.is_linux:
            return ""
        return self.run(["systemctl", "--user", "list-units", "--all", "--no-pager", "--plain"])


# ═══════════════════════════════════════════════════════════════════════════════
# TERMINAL UI
# ═══════════════════════════════════════════════════════════════════════════════

class TerminalUI:
    COLORS = {
        "RESET": "\033[0m", "BOLD": "\033[1m", "DIM": "\033[2m",
        "RED": "\033[0;31m", "BOLD_RED": "\033[1;31m",
        "GREEN": "\033[0;32m", "BOLD_GREEN": "\033[1;32m",
        "YELLOW": "\033[0;33m", "BOLD_YELLOW": "\033[1;33m",
        "CYAN": "\033[0;36m", "BOLD_CYAN": "\033[1;36m",
        "WHITE": "\033[0;37m", "BOLD_WHITE": "\033[1;37m",
        "MAGENTA": "\033[0;35m",
    }
    BADGE = {
        Severity.CRITICAL: ("CRITICAL", "BOLD_RED"),
        Severity.HIGH: ("HIGH", "RED"),
        Severity.WARNING: ("WARNING", "BOLD_YELLOW"),
        Severity.INFO: ("INFO", "CYAN"),
    }

    def __init__(self, ci=False):
        self.ci = ci
        self.use_color = self._detect_color() and not ci

    def _detect_color(self):
        if os.environ.get("NO_COLOR"):
            return False
        if not sys.stdout.isatty():
            return False
        if platform.system().lower() == "windows":
            try:
                import ctypes
                k = ctypes.windll.kernel32
                k.SetConsoleMode(k.GetStdHandle(-11), 7)
            except Exception:
                pass
        return True

    def c(self, color, text):
        if not self.use_color:
            return str(text)
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['RESET']}"

    def banner(self):
        w = 70
        print()
        print(self.c("BOLD_CYAN", "=" * w))
        print(self.c("BOLD_CYAN", f"  ThreatScan v{VERSION} — PolinRider / Contagious Interview Detector"))
        print(self.c("BOLD_CYAN", "  Cross-platform | Read-only | Signatures current to Sept 2026"))
        print(self.c("BOLD_CYAN", "=" * w))
        print()

    def section(self, title):
        print()
        print(self.c("BOLD", "─" * 70))
        print(self.c("BOLD", f"  {title}"))
        print(self.c("BOLD", "─" * 70))

    def finding(self, f: Finding):
        label, color = self.BADGE[f.severity]
        print(f"  [{self.c(color, label)}] {self.c('BOLD', f.title)}")
        if f.path:
            print(f"      Path: {f.path}")
        for line in f.details.strip().split("\n"):
            if line.strip():
                print(f"      {self.c('DIM', line)}")

    def progress(self, msg):
        if not self.ci:
            print(f"  ▸ {self.c('DIM', msg)}")

    def ok(self, msg):
        print(f"  ✔ {self.c('BOLD_GREEN', msg)}")

    def info(self, msg):
        print(f"  ℹ {self.c('CYAN', msg)}")

    def warn(self, msg):
        print(f"  ⚠ {self.c('YELLOW', msg)}")

    def err(self, msg):
        print(f"  ✖ {self.c('BOLD_RED', msg)}")

    def system_info(self, plat: PlatformInfo, dirs, start):
        print(self.c("BOLD", "  System"))
        rows = [("Platform", plat.display_name), ("Hostname", plat.hostname),
                ("Python", plat.python_version), ("Arch", plat.arch),
                ("Scan dirs", ", ".join(str(d) for d in dirs) or "(none)"),
                ("Started", start)]
        for k, v in rows:
            print(f"    {self.c('BOLD_CYAN', k + ':'):<22} {v}")
        if plat.hostname in CI_EVASION_HOSTNAMES:
            print(f"    {self.c('YELLOW', 'Note: this hostname is on the malware CI-evasion list; the payload may stay dormant here.')}")

    def summary(self, stats: ScanStats):
        print()
        print(self.c("BOLD", "═" * 70))
        print(self.c("BOLD", "  SCAN SUMMARY"))
        print(self.c("BOLD", "═" * 70))
        def row(k, v, color="WHITE"):
            print(f"  {self.c('BOLD_CYAN', k + ':'):<30} {self.c(color, v)}")
        row("Platform", stats.platform_name)
        row("Duration", f"{stats.scan_duration:.1f}s")
        row("Repos scanned", stats.repos_scanned)
        row("Repos infected", stats.repos_infected, "BOLD_RED" if stats.repos_infected else "GREEN")
        row("Files checked", stats.files_checked)
        print()
        row("CRITICAL", stats.critical, "BOLD_RED" if stats.critical else "DIM")
        row("HIGH", stats.high, "RED" if stats.high else "DIM")
        row("WARNING", stats.warning, "BOLD_YELLOW" if stats.warning else "DIM")
        row("INFO", stats.info, "CYAN" if stats.info else "DIM")
        print()
        bad = stats.critical + stats.high
        status = "INFECTIONS DETECTED" if bad else ("REVIEW WARNINGS" if stats.warning else "CLEAN")
        color = "BOLD_RED" if bad else ("BOLD_YELLOW" if stats.warning else "BOLD_GREEN")
        row("Status", status, color)
        print(self.c("BOLD", "═" * 70))

    def remediation(self, findings: List[Finding]):
        by_sev = {s: [] for s in Severity}
        for f in findings:
            by_sev[f.severity].append(f)
        if not (by_sev[Severity.CRITICAL] or by_sev[Severity.HIGH] or by_sev[Severity.WARNING]):
            return
        print()
        print(self.c("BOLD", "  REMEDIATION (by priority)"))
        print(self.c("BOLD", "  " + "─" * 66))
        for sev, title, color in [(Severity.CRITICAL, "CRITICAL — act now", "BOLD_RED"),
                                  (Severity.HIGH, "HIGH — rotate credentials & audit", "RED"),
                                  (Severity.WARNING, "WARNING — review", "YELLOW")]:
            items = by_sev[sev]
            if not items:
                continue
            print(f"\n  {self.c(color, title)}")
            seen = set()
            for f in items:
                if f.remediation and f.remediation not in seen:
                    seen.add(f.remediation)
                    for line in f.remediation.strip().split("\n"):
                        print(f"    {line}")
        print()
        print(self.c("BOLD", "  After ANY critical/high finding, regardless of what else you do:"))
        for line in [
            "1. Rotate: GitHub PATs, SSH keys, npm tokens, cloud/deploy tokens (Vercel/Netlify/AWS).",
            "2. Revoke OAuth apps & GitHub App installs you don't recognise.",
            "3. Enable hardware-backed 2FA on GitHub and npm.",
            "4. Set VS Code: Task > Allow Automatic Tasks in Folder = off.",
            "5. Report: https://opensourcemalware.com",
        ]:
            print(f"    {line}")
        print()


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def sha256_of(path: Path, limit_bytes=50 * 1024 * 1024) -> str:
    try:
        if path.stat().st_size > limit_bytes:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def read_text(path: Path, limit_bytes=20 * 1024 * 1024) -> str:
    try:
        if path.stat().st_size > limit_bytes:
            return ""
        return path.read_text(errors="ignore")
    except Exception:
        return ""


CODE_MARKERS = (b"<html", b"<!doc", b"<script", b"require(", b"global[", b"global.", b"function",
                b"eval(", b"const ", b"var ", b"let ", b"#!/", b"process.env", b"=>")


def asset_verdict(path: Path) -> Tuple[str, str]:
    """Classify a font/image file by content.

    Returns (verdict, detail) where verdict is:
      "real"    - header matches the extension's magic bytes
      "code"    - file is script/markup (loader payload)
      "text"    - plain text where a binary is expected
      "unknown" - unreadable or an unrecognised binary
    Leading whitespace is skipped before looking for code: PolinRider pads its
    loader with hundreds of spaces so the first bytes look blank.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except Exception:
        return "unknown", ""
    if not head:
        return "text", "file is empty"
    for offset, sig in ASSET_MAGIC.get(path.suffix.lower(), []):
        if head[offset:offset + len(sig)] == sig:
            return "real", ""
    if head.startswith(b"version https://git-lfs"):
        return "real", ""
    body = head.lstrip()
    pad = len(head) - len(body)
    pad_note = f" after {pad} bytes of whitespace padding" if pad >= 32 else ""
    low = body[:2048].lower()
    if any(m in low for m in CODE_MARKERS):
        marker = MARKER_REGEX.search(body.decode("latin-1"))
        return "code", (f"JavaScript/HTML{pad_note}" +
                        (f"; campaign marker: {marker.group(0)[:60]}" if marker else ""))
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text", f"plain text{pad_note}"
        except UnicodeDecodeError:
            pass
    return "unknown", ""


def skip_dir(name: str) -> bool:
    return name in {"node_modules", ".git", ".hg", ".svn", "vendor", "__pycache__",
                    ".venv", "venv", "dist", "build", ".next", ".nuxt", ".cache",
                    "target", ".gradle", ".idea",
                    # Browser profiles: extension bundles are multi-MB minified
                    # vendor code (TronLink, MetaMask, etc.) that legitimately
                    # reference blockchain RPCs. Browser extensions are checked
                    # separately by SystemScanner.check_editor_injection with
                    # strict wallet/signature-only matching.
                    "google-chrome", "chromium", "BraveSoftware", "microsoft-edge",
                    "Google", "Mozilla", "firefox", "Extensions", "Service Worker",
                    "Cache", "Code Cache", "GPUCache", "IndexedDB", "Local Storage"}


# ═══════════════════════════════════════════════════════════════════════════════
# REPOSITORY SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class RepoScanner:
    def __init__(self, scan_dir: Path, ui: TerminalUI, js_all=False, verbose=False):
        self.scan_dir = scan_dir.resolve()
        self.ui = ui
        self.js_all = js_all
        self.verbose = verbose
        self.files_checked = 0

    # ── Discovery ────────────────────────────────────────────────────────────
    def find_repos(self) -> List[Path]:
        repos = []
        for root, dirs, files in os.walk(self.scan_dir):
            dirs[:] = [d for d in dirs if not skip_dir(d) or d == ".git"]
            # .git is a file (not a dir) in worktrees and submodules
            if ".git" in dirs or ".git" in files:
                repos.append(Path(root))
                dirs[:] = [d for d in dirs if d != ".git"]
        return repos

    def find_non_git_projects(self) -> List[Path]:
        """Projects with package.json / go.mod but no .git — still worth checking."""
        projects = []
        for root, dirs, files in os.walk(self.scan_dir):
            dirs[:] = [d for d in dirs if not skip_dir(d)]
            if ".git" in os.listdir(root) if os.path.isdir(root) else False:
                dirs[:] = []
                continue
            if "package.json" in files or "go.mod" in files or "composer.json" in files:
                projects.append(Path(root))
                dirs[:] = []
        return projects

    # ── File-level checks ────────────────────────────────────────────────────
    def check_signatures(self, fp: Path) -> List[Finding]:
        out = []
        content = read_text(fp)
        if not content:
            return out
        self.files_checked += 1

        for sig in LITERAL_SIGNATURES:
            if sig in content:
                out.append(Finding(Severity.CRITICAL, "config_injection",
                    f"PolinRider signature in {fp.name}", str(fp),
                    f"Literal: {sig[:70]}",
                    f"Remove everything after the legitimate config in:\n  {fp}\n"
                    f"  Look for global['!'], global['_V'], _$_1e42, MDy(, or Cot%3t=shtP."))
                break

        if not out and MARKER_REGEX.search(content):
            out.append(Finding(Severity.CRITICAL, "config_injection",
                f"PolinRider marker regex in {fp.name}", str(fp),
                "Generalised campaign marker matched (covers all A#- rotations).",
                f"Inspect and strip the obfuscated block from:\n  {fp}"))

        for key in XOR_KEYS:
            if key in content:
                out.append(Finding(Severity.CRITICAL, "xor_key",
                    f"PolinRider XOR key in {fp.name}", str(fp),
                    f"Key: {key}",
                    f"This file contains the payload decryption key. Delete or clean:\n  {fp}"))
                break

        # RPC hostnames alone are NOT an indicator — TronLink, MetaMask, tronweb,
        # aptos SDKs and every dApp legitimately reference them. Only fire on a
        # known dead-drop wallet, or an RPC host co-located with a real campaign
        # marker / XOR key / literal signature in the same file.
        hosts = [h for h in BLOCKCHAIN_RPC_HOSTS if h in content]
        wallets = [w for w in TRON_WALLETS + APTOS_ADDRESSES if w in content]
        has_marker = bool(MARKER_REGEX.search(content)) or any(k in content for k in XOR_KEYS) \
            or any(s in content for s in LITERAL_SIGNATURES)
        if wallets or (hosts and has_marker):
            out.append(Finding(Severity.CRITICAL, "blockchain_c2",
                f"Blockchain dead-drop indicators in {fp.name}", str(fp),
                f"RPC hosts: {', '.join(hosts) or '-'}\nWallets: {', '.join(wallets) or '-'}",
                f"File references PolinRider dead-drop wallets/RPCs. Clean or delete:\n  {fp}"))

        c2paths = [p for p in C2_URL_PATHS if p in content]
        ips = [ip for ip in MALICIOUS_IPS if ip in content]
        if ips or (c2paths and ("http" in content)):
            out.append(Finding(Severity.CRITICAL, "c2_reference",
                f"C2 reference in {fp.name}", str(fp),
                f"IPs: {', '.join(ips) or '-'}\nPaths: {', '.join(c2paths) or '-'}",
                f"Hard-coded C2 infrastructure. Clean or delete:\n  {fp}"))

        tg = [t for t in TELEGRAM_INDICATORS if t in content]
        if tg:
            out.append(Finding(Severity.CRITICAL, "telegram_exfil",
                f"Telegram exfiltration bot in {fp.name}", str(fp),
                f"Indicator: {tg[0]}", f"OmniStealer exfil channel. Delete:\n  {fp}"))
        return out

    def check_size_and_lines(self, fp: Path) -> List[Finding]:
        out = []
        try:
            size = fp.stat().st_size
        except Exception:
            return out
        if size > 4096:
            out.append(Finding(Severity.WARNING, "file_anomaly",
                f"{fp.name} is large ({size} bytes)", str(fp),
                "Framework config files are normally <1 KB. PolinRider appends 5–80 KB payloads.",
                f"Inspect {fp}; strip anything after the real export."))
        content = read_text(fp)
        for i, line in enumerate(content.split("\n"), 1):
            if len(line) > 400:
                trailing = re.search(r"\s{40,}\S", line)
                out.append(Finding(Severity.HIGH if trailing else Severity.WARNING, "file_anomaly",
                    f"{fp.name} line {i} is {len(line)} chars" + (" with hidden payload after whitespace" if trailing else ""),
                    str(fp), "PolinRider hides its payload after ~280 spaces on the export line.",
                    f"Open {fp}, go to line {i}, scroll right, delete the trailing code."))
                break
        return out

    def check_entry_hook(self, fp: Path) -> List[Finding]:
        content = read_text(fp)
        if re.search(r"atob\s*\(\s*process\.env", content) or re.search(r"eval\s*\(\s*atob", content):
            return [Finding(Severity.CRITICAL, "entry_hook",
                f"Malicious entry hook in {fp.name}", str(fp),
                "atob(process.env…)/eval(atob…) — decodes a base64 URL from env and evals the response.",
                f"Remove the injected async IIFE from:\n  {fp}")]
        return []

    # ── Repo-level checks ────────────────────────────────────────────────────
    def check_propagation_scripts(self, repo: Path) -> List[Finding]:
        out = []
        for name in PROPAGATION_SCRIPTS:
            p = repo / name
            if p.exists():
                out.append(Finding(Severity.CRITICAL, "propagation_script",
                    f"Propagation script: {name}", str(p),
                    "Rewrites git history with forged GIT_COMMITTER_DATE and force-pushes.",
                    f"Delete {p}. Then audit every branch this repo pushed to."))
        gi = repo / ".gitignore"
        if gi.is_file():
            content = read_text(gi)
            for name in PROPAGATION_SCRIPTS:
                if re.search(rf"^\s*{re.escape(name)}\s*$", content, re.M):
                    out.append(Finding(Severity.HIGH, "gitignore_tampering",
                        f".gitignore hides {name}", str(gi),
                        "PolinRider adds its orchestrator to .gitignore so it never shows in git status.",
                        f"Remove '{name}' from {gi}."))
            # Only meaningful in a git repo; tool-generated dirs (e.g. .opencode/) self-ignore legitimately
            for name in GITIGNORE_IOCS if (repo / ".git").exists() else []:
                if re.search(rf"^\s*/?{re.escape(name)}\s*$", content, re.M):
                    out.append(Finding(Severity.HIGH, "gitignore_tampering",
                        f".gitignore hides {name}", str(gi),
                        "PolinRider ignores its own artefacts (and .gitignore itself) to hide the tampering.",
                        f"Remove '{name}' from {gi}, then run: git status --ignored"))
        return out

    def check_vscode_tasks(self, repo: Path) -> List[Finding]:
        out = []
        tasks = repo / ".vscode" / "tasks.json"
        if not tasks.is_file():
            return out
        content = read_text(tasks)
        if "folderOpen" in content:
            sev = Severity.CRITICAL
            details = "runOptions.runOn=folderOpen executes the moment the folder opens in VS Code/Cursor/GitHub Desktop.\n"
            loader = re.search(r"\bnode\s+\S+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico)\b", content, re.I)
            if loader or any(k in content for k in ("woff2", "node -e", "curl", "wget", "powershell", "cmd /c", ".bat")):
                details += "Task body references a loader/font/shell — this is the PolinRider stage-1 entry point."
            else:
                details += "No obvious loader in the task body, but folderOpen autorun is itself the PolinRider signature."
                sev = Severity.HIGH
            out.append(Finding(sev, "vscode_autorun",
                "VS Code folderOpen autorun task", str(tasks), details,
                f"Delete {tasks} unless you wrote it.\n  In VS Code: Task > Allow Automatic Tasks in Folder = off."))
        return out

    def check_vscode_settings(self, repo: Path) -> List[Finding]:
        settings = repo / ".vscode" / "settings.json"
        if not settings.is_file():
            return []
        content = read_text(settings)
        if not re.search(r'"task\.allowAutomaticTasks"\s*:\s*(true|"on")', content):
            return []
        extras = [k for k in ('"terminal.integrated.hideOnStartup"', '"runOn": "folderOpen"', '"debug.openDebug"')
                  if k in content]
        return [Finding(Severity.HIGH, "vscode_autorun",
            "VS Code settings force automatic tasks on", str(settings),
            "task.allowAutomaticTasks suppresses the 'allow automatic tasks?' prompt, so a folderOpen "
            "task runs silently." + (f"\nAlso sets: {', '.join(extras)}" if extras else ""),
            f"Remove task.allowAutomaticTasks from {settings} unless you added it.")]

    def check_disguised_assets(self, repo: Path) -> List[Finding]:
        """Font/image files whose content is not what the extension claims."""
        out = []
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if not skip_dir(d)]
            for fn in files:
                p = Path(root) / fn
                ext = p.suffix.lower()
                if ext not in ASSET_MAGIC:
                    continue
                self.files_checked += 1
                is_font = ext in FONT_EXTENSIONS
                category = "fake_font_loader" if is_font else "disguised_payload"
                kind = "Font" if is_font else "Image"
                digest = sha256_of(p)
                if digest in FAKE_FONT_SHA256:
                    out.append(Finding(Severity.CRITICAL, category,
                        f"PolinRider loader (hash match): {fn}", str(p),
                        f"SHA-256 {digest} matches a confirmed PolinRider font-disguised loader.",
                        f"Delete {p}. Search the repo for what references it (tasks.json, package.json scripts)."))
                    continue
                verdict, detail = asset_verdict(p)
                if verdict == "code":
                    out.append(Finding(Severity.CRITICAL, category,
                        f"{kind} file contains code: {fn}", str(p),
                        f"Has a {ext} extension but the content is {detail}, not {ext[1:]} magic bytes.",
                        f"Delete {p} and find what loads it (grep -r '{fn}' .vscode package.json)."))
                elif verdict == "text":
                    out.append(Finding(Severity.HIGH if fn in FAKE_FONT_NAMES else Severity.WARNING, category,
                        f"{kind} file is not binary: {fn}", str(p),
                        f"Has a {ext} extension but the content is {detail}.",
                        f"Run: file {p}  — then open it in a text editor and check what it contains."))
                elif verdict == "unknown" and fn in FAKE_FONT_NAMES:
                    out.append(Finding(Severity.WARNING, category,
                        f"Unverifiable font with PolinRider filename: {fn}", str(p),
                        "Name matches the campaign loader but header is inconclusive.",
                        f"Run: file {p}  — it should say 'Web Open Font Format'."))
        return out

    def check_git_history(self, repo: Path) -> List[Finding]:
        out = []
        git = ["git", "-C", str(repo)]
        try:
            reflog = subprocess.run(git + ["reflog", "--all", "-40"],
                                    capture_output=True, text=True, timeout=15).stdout.lower()
        except Exception:
            return out
        amend = reflog.count("amend")
        force = reflog.count("forced-update") + reflog.count("force")
        if amend > 2 or force > 0:
            out.append(Finding(Severity.WARNING, "git_tampering",
                f"Suspicious reflog in {repo.name} ({amend} amends, {force} force refs)",
                str(repo / ".git"), "PolinRider amends commits in place and force-pushes.",
                f"git -C {repo} reflog --all -40   # look for commits you didn't make"))

        # Forged committer dates: committer date far older than author date, or
        # committer date more than 30 days before the reflog entry that created it.
        try:
            log = subprocess.run(git + ["log", "-30", "--format=%H|%at|%ct|%an|%cn|%s"],
                                 capture_output=True, text=True, timeout=15).stdout
        except Exception:
            log = ""
        suspicious = []
        for line in log.strip().split("\n"):
            parts = line.split("|", 5)
            if len(parts) < 6:
                continue
            h, at, ct, an, cn, subj = parts
            try:
                at, ct = int(at), int(ct)
            except ValueError:
                continue
            if ct < at - 86400 * 7:
                suspicious.append(f"{h[:10]} committer date {datetime.fromtimestamp(ct, timezone.utc):%Y-%m-%d} is before author date {datetime.fromtimestamp(at, timezone.utc):%Y-%m-%d}")
        if suspicious:
            out.append(Finding(Severity.HIGH, "forged_timestamp",
                f"Backdated commits in {repo.name}", str(repo / ".git"),
                "\n".join(suspicious[:5]) + ("\n…" if len(suspicious) > 5 else "") +
                "\nPolinRider sets GIT_COMMITTER_DATE to hide when the backdoor was really pushed.",
                f"git -C {repo} log --format='%h %ad %cd %s' --date=iso   # compare author vs committer dates"))
        return out

    def check_history_payloads(self, repo: Path) -> List[Finding]:
        """Commits that added or removed payload code, on any branch.

        Reported as WARNING: the working tree may be clean, but the payload is
        still one checkout away, and the commits show when it was injected.
        PolinRider re-adds its loader under decoy messages like 'rm malware'.
        """
        try:
            log = subprocess.run(
                ["git", "-C", str(repo), "log", "--all", "-n", "1000", "--text", "-E",
                 "-G", HISTORY_PAYLOAD_REGEX, "--format=%h|%ad|%s", "--date=short"],
                capture_output=True, text=True, timeout=60).stdout
        except Exception:
            return []
        commits = [line.split("|", 2) for line in log.strip().split("\n") if line.count("|") >= 2]
        if not commits:
            return []
        listing = "\n".join(f"{h} {d} {s[:60]}" for h, d, s in commits[:10])
        return [Finding(Severity.WARNING, "history_payload",
            f"{len(commits)} commit(s) in {repo.name} history touch PolinRider payload code", str(repo / ".git"),
            listing + ("\n…" if len(commits) > 10 else "") +
            "\nCheck each one: commit messages are often decoys that add the loader rather than remove it.",
            f"git -C {repo} show --stat <commit>   # then audit every branch that contains it")]

    def check_package_json(self, repo: Path) -> List[Finding]:
        out = []
        pj = repo / "package.json"
        if not pj.is_file():
            return out
        self.files_checked += 1
        try:
            data = json.loads(read_text(pj) or "{}")
        except Exception:
            return out

        deps = {}
        for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps.update(data.get(k, {}) or {})
        for name, bad_versions in COMPROMISED_NPM.items():
            if name in deps:
                ver = str(deps[name])
                hit = "*" in bad_versions or any(v in ver for v in bad_versions)
                out.append(Finding(Severity.CRITICAL if hit else Severity.HIGH, "compromised_package",
                    f"Compromised npm package: {name}@{ver}", str(pj),
                    f"Known-bad versions: {', '.join(bad_versions)}",
                    f"Remove {name} or pin to a clean version; rm -rf node_modules; check lockfile."))

        scripts = data.get("scripts", {}) or {}
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
            body = str(scripts.get(hook, ""))
            if not body:
                continue
            if re.search(r"node\s+-e|curl|wget|\.woff2|bash\s+-c|powershell|\.bat|atob\(|eval\(", body, re.I):
                out.append(Finding(Severity.HIGH, "lifecycle_script",
                    f"Suspicious {hook} script", str(pj), f"{hook}: {body[:120]}",
                    f"Review scripts.{hook} in {pj}; install with --ignore-scripts until verified."))
        return out

    def check_lockfiles(self, repo: Path) -> List[Finding]:
        out = []
        for lock in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            p = repo / lock
            if not p.is_file():
                continue
            content = read_text(p)
            for name, bad_versions in COMPROMISED_NPM.items():
                if name not in content:
                    continue
                for v in bad_versions:
                    if v == "*" or f"{name}@{v}" in content or f'"{name}": "{v}"' in content or f"/{name}/{v}" in content or f"{name}/-/{name.split('/')[-1]}-{v}.tgz" in content:
                        out.append(Finding(Severity.CRITICAL, "compromised_package",
                            f"Compromised package pinned in {lock}: {name}@{v if v != '*' else 'any'}",
                            str(p), "Lockfile resolves a known-poisoned release.",
                            f"Delete node_modules and {lock}; remove {name} or pin clean; reinstall with --ignore-scripts."))
                        break
        return out

    def check_go_mod(self, repo: Path) -> List[Finding]:
        out = []
        for name in ("go.mod", "go.sum"):
            p = repo / name
            if not p.is_file():
                continue
            content = read_text(p)
            for mod in COMPROMISED_GO:
                if mod in content:
                    out.append(Finding(Severity.CRITICAL, "compromised_package",
                        f"Compromised Go module in {name}: {mod}", str(p),
                        "proxy.golang.org caches these permanently; the poisoned tag is still served.",
                        f"Drop {mod}; go clean -modcache; audit the vendored fa-solid-400.woff2."))
        return out

    def check_composer(self, repo: Path) -> List[Finding]:
        out = []
        for name in ("composer.json", "composer.lock"):
            p = repo / name
            if not p.is_file():
                continue
            content = read_text(p)
            for pkg in COMPROMISED_PACKAGIST:
                if pkg in content:
                    out.append(Finding(Severity.CRITICAL, "compromised_package",
                        f"Compromised Packagist package in {name}: {pkg}", str(p),
                        "Shares C2 23.27.202.27 with PolinRider infrastructure.",
                        f"Remove {pkg}; composer clear-cache; rotate any secrets the project holds."))
        return out

    def check_env_files(self, repo: Path) -> List[Finding]:
        out = []
        for name in (".env", ".env.local", ".env.production", ".env.development", ".env.staging"):
            p = repo / name
            if p.is_file():
                out.append(Finding(Severity.WARNING, "credential_exposure",
                    f"Secrets file present in infected repo: {name}", str(p),
                    "The payload reads process.env; every value here should be treated as leaked.",
                    f"Rotate every secret in {p}."))
        return out

    # ── Orchestration ────────────────────────────────────────────────────────
    def scan_repo(self, repo: Path, is_git=True) -> List[Finding]:
        f: List[Finding] = []
        self.ui.progress(f"Scanning {repo}")

        for name in CONFIG_FILES:
            fp = repo / name
            if fp.is_file():
                f += self.check_signatures(fp)
                f += self.check_size_and_lines(fp)

        entry = ["main.ts", "main.js", "index.ts", "index.js", "app.ts", "app.js",
                 "server.ts", "server.js", "src/main.ts", "src/main.js", "src/index.ts",
                 "src/index.js", "src/app.ts", "src/app.js", "src/server.ts", "src/server.js",
                 "src/main.tsx", "src/index.tsx", "src/App.tsx", "app/layout.tsx"]
        for name in entry:
            fp = repo / name
            if fp.is_file():
                f += self.check_entry_hook(fp)
                f += self.check_signatures(fp)

        if self.js_all:
            for root, dirs, files in os.walk(repo):
                dirs[:] = [d for d in dirs if not skip_dir(d)]
                for fn in files:
                    if fn.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
                        f += self.check_signatures(Path(root) / fn)

        f += self.check_propagation_scripts(repo)
        f += self.check_vscode_tasks(repo)
        f += self.check_vscode_settings(repo)
        f += self.check_disguised_assets(repo)
        f += self.check_package_json(repo)
        f += self.check_lockfiles(repo)
        f += self.check_go_mod(repo)
        f += self.check_composer(repo)
        if is_git:
            f += self.check_git_history(repo)
            f += self.check_history_payloads(repo)
        if any(x.severity >= Severity.HIGH for x in f):
            f += self.check_env_files(repo)
        return f

    def scan_all(self) -> Tuple[List[Finding], int, int]:
        findings: List[Finding] = []
        repos = self.find_repos()
        projects = [p for p in self.find_non_git_projects() if p not in repos]
        total = len(repos) + len(projects)
        if not total:
            self.ui.info(f"No repositories or projects under {self.scan_dir}")
            return findings, 0, 0
        self.ui.progress(f"Found {len(repos)} git repos + {len(projects)} non-git projects")
        infected = 0
        for repo in repos:
            rf = self.scan_repo(repo, is_git=True)
            if any(x.severity >= Severity.HIGH for x in rf):
                infected += 1
                self.ui.err(f"[INFECTED] {repo}")
                for x in rf:
                    self.ui.finding(x)
            elif rf and self.verbose:
                self.ui.warn(f"[REVIEW] {repo}")
                for x in rf:
                    self.ui.finding(x)
            elif self.verbose:
                self.ui.ok(f"Clean: {repo}")
            findings += rf
        for proj in projects:
            rf = self.scan_repo(proj, is_git=False)
            if any(x.severity >= Severity.HIGH for x in rf):
                infected += 1
                self.ui.err(f"[INFECTED] {proj}")
                for x in rf:
                    self.ui.finding(x)
            findings += rf
        return findings, total, infected


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class SystemScanner:
    def __init__(self, plat: PlatformInfo, ui: TerminalUI, verbose=False):
        self.plat = plat
        self.ui = ui
        self.verbose = verbose

    # ── Live processes ───────────────────────────────────────────────────────
    def check_processes(self) -> List[Finding]:
        out = []
        self.ui.progress("Checking running processes")
        for pid, name, cmd in self.plat.list_processes():
            for pat in MALICIOUS_PROCESS_PATTERNS:
                if pat.search(cmd):
                    kill = f"taskkill /PID {pid} /F" if self.plat.is_windows else f"kill -9 {pid}"
                    out.append(Finding(Severity.CRITICAL, "malicious_process",
                        f"Malicious process running: PID {pid} ({name})", None,
                        f"Pattern: {pat.pattern[:50]}\nCmd: {cmd[:200]}{'…' if len(cmd) > 200 else ''}",
                        f"{kill}\n  Then find its parent and persistence: this scanner's persistence section."))
                    break
        return out

    # ── Network ──────────────────────────────────────────────────────────────
    def check_network(self) -> List[Finding]:
        out = []
        self.ui.progress("Checking network connections")
        bad = set(MALICIOUS_IPS)
        seen = set()
        for ip, port, pid in self.plat.network_connections():
            if ip in bad and (ip, port) not in seen:
                seen.add((ip, port))
                if self.plat.is_windows:
                    block = f"netsh advfirewall firewall add rule name=\"PolinRider C2\" dir=out action=block remoteip={ip}"
                elif self.plat.is_macos:
                    block = f"echo 'block drop out to {ip}' | sudo pfctl -ef -"
                else:
                    block = f"sudo iptables -A OUTPUT -d {ip} -j DROP"
                out.append(Finding(Severity.CRITICAL, "c2_connection",
                    f"Live connection to PolinRider C2 {ip}:{port}", None,
                    f"PID: {pid or 'unknown'}",
                    f"{block}\n  Then kill PID {pid or '<pid>'}."))
        return out

    # ── Persistence ──────────────────────────────────────────────────────────
    def check_cron(self) -> List[Finding]:
        out = []
        for line in self.plat.crontab_lines():
            low = line.lower()
            if any(k in low for k in SCHEDULED_TASK_KEYWORDS) or "@reboot" in low:
                sev = Severity.CRITICAL if any(r in low for r in ("runtimedev", "vscodeupdater", "node -e", "python -c")) else Severity.WARNING
                out.append(Finding(sev, "persistence_cron", "Suspicious crontab entry", None,
                    line[:160], "crontab -e   # remove the line you didn't add"))
        for d in [Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly")]:
            if not d.is_dir():
                continue
            for p in d.iterdir():
                if p.is_file():
                    c = read_text(p).lower()
                    if any(k in c for k in ("runtimedev", "vscodeupdater", "node -e", "curl", "wget")):
                        out.append(Finding(Severity.HIGH, "persistence_cron",
                            f"Suspicious system cron file: {p.name}", str(p), "", f"sudo rm {p}"))
        return out

    def check_systemd_user(self) -> List[Finding]:
        out = []
        if not self.plat.is_linux:
            return out
        unit_dir = self.plat.home / ".config/systemd/user"
        if unit_dir.is_dir():
            for p in unit_dir.rglob("*.service"):
                if p.is_symlink() and not p.exists():
                    continue
                content = read_text(p)
                name_hit = any(s in p.name for s in RAT_SERVICE_NAMES)
                body_hit = any(k in content for k in ("VSCodeUpdater", "runtimedev", "node -e", "start.sh", "SSTAR_"))
                if name_hit or body_hit:
                    out.append(Finding(Severity.CRITICAL, "persistence_systemd",
                        f"RAT systemd --user unit: {p.name}", str(p),
                        content[:300],
                        f"systemctl --user disable --now {p.name}\n  rm {p}\n  systemctl --user daemon-reload"))
        units = self.plat.systemd_user_units()
        for line in units.split("\n"):
            if any(s in line for s in RAT_SERVICE_NAMES):
                out.append(Finding(Severity.CRITICAL, "persistence_systemd",
                    "RAT unit loaded in systemd --user", None, line.strip(),
                    "systemctl --user disable --now runtimedev-link.service"))
        return out

    def check_xdg_autostart(self) -> List[Finding]:
        out = []
        d = self.plat.home / ".config/autostart"
        if not d.is_dir():
            return out
        for p in d.glob("*.desktop"):
            content = read_text(p)
            if any(k in content for k in ("runtimedev", "VSCodeUpdater", "node -e", "RuntimeDev", "start.sh")):
                out.append(Finding(Severity.CRITICAL, "persistence_autostart",
                    f"RAT XDG autostart: {p.name}", str(p), content[:200], f"rm {p}"))
        return out

    def check_launchd(self) -> List[Finding]:
        out = []
        if not self.plat.is_macos:
            return out
        for d in [self.plat.home / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]:
            if not d.is_dir():
                continue
            for p in d.glob("*.plist"):
                content = read_text(p)
                if any(s in p.name for s in RAT_SERVICE_NAMES) or any(k in content for k in ("runtimedev", "VSCodeUpdater", "SSTAR_", "node -e")):
                    out.append(Finding(Severity.CRITICAL, "persistence_launchd",
                        f"RAT LaunchAgent: {p.name}", str(p), content[:200],
                        f"launchctl bootout gui/$(id -u) {p}\n  rm {p}"))
        return out

    def check_windows_tasks(self) -> List[Finding]:
        out = []
        if not self.plat.is_windows:
            return out
        csv = self.plat.scheduled_tasks_windows()
        for line in csv.split("\n"):
            low = line.lower()
            if any(k in low for k in ("runtimedev", "vscodeupdater", "wscript.exe //b", "node -e", "python -c")):
                out.append(Finding(Severity.CRITICAL, "persistence_schtasks",
                    "RAT scheduled task", None, line[:200],
                    'schtasks /Delete /TN "runtimedev-link" /F'))
        startup = self.plat.persistence_dirs()
        for d in startup:
            for p in d.iterdir():
                if p.is_file() and any(k in p.name.lower() for k in ("runtimedev", "vscode", "updater")):
                    out.append(Finding(Severity.HIGH, "persistence_startup",
                        f"Suspicious Startup item: {p.name}", str(p), "", f"del \"{p}\""))
        return out

    # ── RAT footprint ────────────────────────────────────────────────────────
    def check_rat_directories(self) -> List[Finding]:
        out = []
        self.ui.progress("Checking for runtimedev-link RAT footprint")
        roots = [self.plat.local_share(), self.plat.config_dir(), self.plat.home]
        for root in roots:
            for name in RAT_DIR_NAMES:
                p = root / name
                if p.is_dir():
                    js = list(p.glob("*.js"))[:3]
                    out.append(Finding(Severity.CRITICAL, "rat_footprint",
                        f"RAT directory: {p}", str(p),
                        f"Contains: {', '.join(x.name for x in js) or '(no .js at top level)'}\n"
                        "Disguised as a VSCode updater; polls C2 for shell commands and exfiltrates files.",
                        f"rm -rf \"{p}\""))
        env = self.plat.config_dir() / "runtimedev-link" / "agent.env"
        if env.is_file():
            content = read_text(env)
            out.append(Finding(Severity.CRITICAL, "rat_footprint",
                "RAT config with C2 URL", str(env), content[:200],
                f"rm -rf \"{env.parent}\""))
        log = self.plat.home / "runtimedev-link.log"
        if log.is_file():
            out.append(Finding(Severity.HIGH, "rat_footprint",
                "RAT log file (proves it ran)", str(log),
                read_text(log)[-400:], f"Review then rm \"{log}\""))
        for k in RAT_ENV_KEYS:
            if os.environ.get(k):
                out.append(Finding(Severity.CRITICAL, "rat_footprint",
                    f"RAT environment variable set: {k}", None, os.environ[k][:120],
                    "Find where it is exported (shell rc, systemd unit, agent.env) and remove it."))
        return out

    # ── Shell startup ────────────────────────────────────────────────────────
    def check_shell_rc(self) -> List[Finding]:
        out = []
        for rc in self.plat.shell_rc_files():
            content = read_text(rc)
            for pat in SHELL_SUSPICIOUS_PATTERNS:
                m = pat.search(content)
                if m:
                    out.append(Finding(Severity.HIGH, "shell_injection",
                        f"Suspicious code in {rc.name}", str(rc), m.group(0)[:120],
                        f"Edit {rc}; remove anything you didn't add."))
                    break
        return out

    # ── Credentials ──────────────────────────────────────────────────────────
    def check_credentials(self, infected: bool) -> List[Finding]:
        out = []
        self.ui.progress("Checking credential files")
        sev = Severity.HIGH if infected else Severity.INFO
        for f in self.plat.credential_files():
            content = read_text(f)
            has_token = bool(re.search(r"(_authToken|password|token|ghp_|gho_|npm_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})", content))
            if has_token:
                out.append(Finding(sev, "credential_exposure",
                    f"Stored credential: {f.name}", str(f),
                    "OmniStealer harvests this file. " + ("Treat as leaked." if infected else "Prefer keyring/ssh-agent."),
                    "Revoke the token at its provider, then delete/rewrite the file." if infected else
                    f"Consider removing plaintext tokens from {f}."))
        ssh = self.plat.home / ".ssh"
        if ssh.is_dir():
            keys = [p for p in ssh.iterdir() if p.is_file() and p.suffix != ".pub" and p.name.startswith("id_")]
            if keys and infected:
                out.append(Finding(Severity.HIGH, "credential_exposure",
                    f"{len(keys)} SSH private key(s) present on infected host", str(ssh),
                    ", ".join(k.name for k in keys),
                    "Generate new keys; remove the old public keys from GitHub/servers."))
            ak = ssh / "authorized_keys"
            if ak.is_file():
                lines = [l for l in read_text(ak).split("\n") if l.strip() and not l.startswith("#")]
                if lines:
                    out.append(Finding(Severity.WARNING if infected else Severity.INFO, "credential_exposure",
                        f"authorized_keys has {len(lines)} key(s)", str(ak),
                        "Verify each one is yours.", f"cat {ak}"))
        return out

    # ── Editors / global npm ─────────────────────────────────────────────────
    def check_editor_injection(self) -> List[Finding]:
        out = []
        self.ui.progress("Checking editor and app injection points")
        for d in self.plat.editor_dirs():
            for root, dirs, files in os.walk(d):
                dirs[:] = [x for x in dirs if x != "node_modules"]
                for fn in files:
                    if not fn.endswith((".js", ".mjs", ".cjs")):
                        continue
                    p = Path(root) / fn
                    content = read_text(p, limit_bytes=5 * 1024 * 1024)
                    if content and (MARKER_REGEX.search(content) or any(k in content for k in XOR_KEYS) or any(w in content for w in TRON_WALLETS)):
                        out.append(Finding(Severity.CRITICAL, "editor_injection",
                            f"Injected payload in editor/app file: {fn}", str(p),
                            "Joyfill variant injects into VS Code, Cursor, Discord, GitHub Desktop.",
                            f"Reinstall the affected app; delete {p}."))
        root = self.plat.npm_global_root()
        if root and root.is_dir():
            for name in COMPROMISED_NPM:
                if (root / name).is_dir():
                    out.append(Finding(Severity.CRITICAL, "compromised_package",
                        f"Compromised package installed globally: {name}", str(root / name), "",
                        f"npm uninstall -g {name}"))
            npm_cli = root / "npm" / "lib" / "cli.js"
            if npm_cli.is_file():
                c = read_text(npm_cli, limit_bytes=5 * 1024 * 1024)
                if MARKER_REGEX.search(c) or any(k in c for k in XOR_KEYS):
                    out.append(Finding(Severity.CRITICAL, "editor_injection",
                        "Global npm CLI is backdoored", str(npm_cli), "",
                        "Reinstall Node/npm from nodejs.org; do not use the current npm to do it."))
        return out

    # ── Hosts file ───────────────────────────────────────────────────────────
    def check_hosts(self) -> List[Finding]:
        out = []
        hf = self.plat.hosts_file()
        if hf.is_file():
            content = read_text(hf)
            for line in content.split("\n"):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if any(h in s for h in ("registry.npmjs.org", "github.com", "nodejs.org", "pypi.org")):
                    out.append(Finding(Severity.HIGH, "hosts_tampering",
                        "Hosts file redirects a package registry", str(hf), s,
                        f"Edit {hf} and remove the line."))
        return out

    # ── Windows portable Python (stage 4) ────────────────────────────────────
    def check_portable_python(self) -> List[Finding]:
        out = []
        if self.plat.is_windows:
            local = Path(os.environ.get("LOCALAPPDATA", ""))
            for p in [local / "Programs/Python/Python3127", local / "Programs/Python/Python312"]:
                if p.is_dir() and not (p / "Lib" / "site-packages" / "pip").is_dir():
                    out.append(Finding(Severity.HIGH, "stage4_python",
                        f"Suspicious portable Python: {p}", str(p),
                        "PolinRider stage 4 drops a portable interpreter here for OmniStealer.",
                        f"rmdir /s /q \"{p}\" if you did not install it."))
        else:
            rt = self.plat.local_share() / "runtimedev-link" / "runtime"
            if rt.is_dir():
                out.append(Finding(Severity.CRITICAL, "stage4_runtime",
                    "RAT portable Node runtime", str(rt), "", f"rm -rf \"{rt.parent}\""))
        return out

    # ── Orchestration ────────────────────────────────────────────────────────
    def scan_all(self, repo_infected: bool) -> List[Finding]:
        f: List[Finding] = []
        f += self.check_processes()
        f += self.check_network()
        f += self.check_rat_directories()
        f += self.check_cron()
        f += self.check_systemd_user()
        f += self.check_xdg_autostart()
        f += self.check_launchd()
        f += self.check_windows_tasks()
        f += self.check_shell_rc()
        f += self.check_editor_injection()
        f += self.check_hosts()
        f += self.check_portable_python()
        host_infected = repo_infected or any(x.severity >= Severity.HIGH for x in f)
        f += self.check_credentials(host_infected)
        return f


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def common_project_dirs(home: Path) -> List[Path]:
    names = ["projects", "Projects", "dev", "Dev", "code", "Code", "work", "src", "repos",
             "Documents/projects", "Documents/dev", "Documents/code", "Documents/GitHub",
             "Desktop/projects", "Desktop/dev", "Developer", "Coding", "workspace", "www", "sites"]
    return [home / n for n in names if (home / n).is_dir()]


def main() -> int:
    ap = argparse.ArgumentParser(description="ThreatScan — PolinRider / Contagious Interview detector")
    ap.add_argument("directories", nargs="*", help="directories to scan (default: cwd)")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--js-all", action="store_true", help="scan every JS/TS file, not just configs")
    ap.add_argument("--no-system", action="store_true", help="skip host checks")
    ap.add_argument("--no-repos", action="store_true", help="skip repository checks")
    ap.add_argument("--json", metavar="FILE", help="write JSON report")
    ap.add_argument("--ci", action="store_true", help="CI mode (no colour, compact)")
    ap.add_argument("--home", action="store_true", help="also scan common project dirs under $HOME")
    ap.add_argument("--version", action="version", version=f"ThreatScan {VERSION}")
    args = ap.parse_args()

    plat = PlatformInfo()
    ui = TerminalUI(ci=args.ci)
    start = time.time()
    start_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    dirs: List[Path] = []
    for d in args.directories:
        p = Path(d).expanduser()
        if not p.is_dir():
            ui.err(f"Not a directory: {d}")
            return 2
        dirs.append(p.resolve())
    if args.home:
        dirs += [d for d in common_project_dirs(plat.home) if d not in dirs]
    if not dirs and not args.no_repos:
        dirs = [Path.cwd()]

    if not args.ci:
        ui.banner()
        ui.system_info(plat, dirs, start_str)

    all_findings: List[Finding] = []
    repos_total = repos_infected = files_checked = 0

    if not args.no_repos:
        ui.section("REPOSITORY SCAN")
        seen = set()
        for d in dirs:
            rs = RepoScanner(d, ui, js_all=args.js_all, verbose=args.verbose)
            fs, total, infected = rs.scan_all()
            all_findings += fs
            repos_total += total
            repos_infected += infected
            files_checked += rs.files_checked
        if repos_total and not repos_infected:
            ui.ok(f"{repos_total} repositories scanned, none infected")

    if not args.no_system:
        ui.section("SYSTEM SCAN")
        ss = SystemScanner(plat, ui, verbose=args.verbose)
        sysf = ss.scan_all(repo_infected=repos_infected > 0)
        for x in sysf:
            if x.severity >= Severity.WARNING or args.verbose:
                ui.finding(x)
        if not any(x.severity >= Severity.HIGH for x in sysf):
            ui.ok("No malicious processes, C2 connections, or RAT persistence found")
        all_findings += sysf

    stats = ScanStats(
        repos_scanned=repos_total, repos_infected=repos_infected, files_checked=files_checked,
        total_findings=len(all_findings),
        critical=sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
        high=sum(1 for f in all_findings if f.severity == Severity.HIGH),
        warning=sum(1 for f in all_findings if f.severity == Severity.WARNING),
        info=sum(1 for f in all_findings if f.severity == Severity.INFO),
        scan_duration=time.time() - start, platform_name=plat.display_name,
        scan_dirs=[str(d) for d in dirs], start_time=start_str, hostname=plat.hostname,
    )

    ui.summary(stats)
    if not args.ci:
        ui.remediation(all_findings)

    if args.json:
        try:
            with open(args.json, "w") as fh:
                json.dump({"version": VERSION, "stats": asdict(stats),
                           "findings": [f.to_dict() for f in all_findings]}, fh, indent=2)
            ui.info(f"JSON report written to {args.json}")
        except Exception as e:
            ui.err(f"Could not write JSON: {e}")
            return 2

    if stats.critical or stats.high:
        return 1
    if args.no_system and not repos_total:
        ui.err("Nothing was scanned: no git repositories or projects found.")
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(2)

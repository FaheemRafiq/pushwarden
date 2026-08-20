#!/usr/bin/env python3
"""
ThreatScan v3.0 — Cross-Platform
Blockchain C2 Config-Injection Detection Tool

Detects the malware family that injects obfuscated payloads into JS/TS config
files, spreads via stolen Git/CI-CD credentials, and drops propagation scripts,
fake font files, and process.env-reading entry-file hooks.

Attributed to the Lazarus Group (DPRK) "Contagious Interview" campaign.

This script is READ-ONLY. It never deletes, modifies, or uploads anything.

Usage:
    python3 threat_scanner.py [OPTIONS] [DIRECTORY]
    python3 threat_scanner.py --ci /path/to/repo    # CI mode for GitHub Actions

Platforms: Linux, macOS, Windows
"""

import os
import sys
import re
import subprocess
import time
import platform
import shutil
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum
from datetime import datetime

# ─── Version ────────────────────────────────────────────────────────────────────
VERSION = "3.0"

# ─── Severity Levels ────────────────────────────────────────────────────────────
class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    HIGH = 2
    CRITICAL = 3

# ─── Known Malware Signatures ───────────────────────────────────────────────────
LITERAL_SIGNATURES = [
    '("rmcej%otb%",2857687)',
    "global['!']='8-270-2';var $_1e42=",
    "global['!']='4-1928'",
    "global['_V']='A4-1928'",
    "global['!']='10-83-10'",
    "global['!']='A10-010'",
    "global['!']='A10-2340'",
    'global["!"]',
]

MARKER_REGEX = re.compile(
    r"""global\[['"]![ '"]\]=['"][A0-9-]{4,}['"]"""
    r"""|global\[['"]_V['"]\]=['"][A0-9-]{4,}['"]"""
    r"""|_\$_1e42"""
    r"""|global\[['"]r['"]\]=require"""
    r"""|atob\(process\.env"""
    r"""|eval\(atob""",
    re.IGNORECASE,
)

# ─── Target Config Files ────────────────────────────────────────────────────────
CONFIG_FILES = [
    "postcss.config.mjs", "postcss.config.js",
    "tailwind.config.js", "tailwind.config.mjs",
    "eslint.config.mjs", "eslint.config.js",
    "next.config.mjs", "next.config.js", "next.config.ts",
    "vue.config.js", "vue.config.mjs",
    "astro.config.mjs", "astro.config.js",
    "babel.config.js", "babel.config.mjs",
    "jest.config.js", "jest.config.mjs",
    "vite.config.js", "vite.config.mjs", "vite.config.ts",
    "webpack.config.js",
    "svelte.config.js",
    "nuxt.config.js", "nuxt.config.ts",
]

# ─── Propagation Scripts ────────────────────────────────────────────────────────
PROPAGATION_SCRIPTS = [
    "temp_auto_push.bat",
    "temp_interactive_push.bat",
    "config.bat",
    "auto_push.bat",
]

# ─── Known Malicious IPs ────────────────────────────────────────────────────────
MALICIOUS_IPS = [
    "166.88.54.158",
    "198.105.127.210",
    "23.27.202.27",
    "154.91.0.103",
    "136.0.9.8",
    "166.88.4.2",
    "23.27.120.142",
    "202.155.8.173",
    "166.88.134.82",
    "188.43.33.249",
]

# ─── Malware Process Indicators ────────────────────────────────────────────────
MALICIOUS_PROCESS_PATTERNS = [
    re.compile(r"global\[['\"]_V['\"]\]", re.IGNORECASE),
    re.compile(r"A10-010", re.IGNORECASE),
    re.compile(r"A10-2340", re.IGNORECASE),
    re.compile(r"_t_t", re.IGNORECASE),
    re.compile(r"node\s+-e\s+.*global\['!", re.IGNORECASE),
    re.compile(r"node\s+-e\s+.*_\$_1e42", re.IGNORECASE),
    re.compile(r"node\s+-e\s+.*eval\(atob", re.IGNORECASE),
    re.compile(r"python[3]?\s+-c\s+.*eval\(", re.IGNORECASE),
    re.compile(r"python[3]?\s+-c\s+.*base64", re.IGNORECASE),
    re.compile(r"python[3]?\s+-c\s+.*exec\(", re.IGNORECASE),
    re.compile(r"font[-_]?updater", re.IGNORECASE),
    re.compile(r"\.cache/font", re.IGNORECASE),
    re.compile(r"/tmp/\.[a-z]", re.IGNORECASE),
]

# ─── Suspicious Shell Patterns ─────────────────────────────────────────────────
SHELL_SUSPICIOUS_PATTERNS = [
    re.compile(r"curl\s+.*\|\s*(bash|sh|python)", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*(bash|sh|python)", re.IGNORECASE),
    re.compile(r"eval\s*\(\s*base64", re.IGNORECASE),
    re.compile(r"eval\s*\(\s*atob", re.IGNORECASE),
    re.compile(r"python\s+-c\s+.*import\s+socket", re.IGNORECASE),
    re.compile(r"node\s+-e\s+.*require\(['\"]child_process['\"]\)", re.IGNORECASE),
    re.compile(r"global\[['\"]!", re.IGNORECASE),
]

# ─── Suspicious Git Commit Messages ────────────────────────────────────────────
SUSPICIOUS_COMMIT_MESSAGES = [
    "add copy code button",
    "update config",
    "fix build",
    "update postcss",
    "add postcss config",
    "update tailwind config",
    "update dependencies",
    "update package.json",
    "update next.config",
    "update eslint config",
    "chore: update",
    "style: update",
    "fix: update",
]

# ─── Common Project Directories per OS ─────────────────────────────────────────
def get_common_project_dirs():
    """Return common project directory names to scan under home."""
    home = Path.home()
    candidates = [
        "projects", "dev", "code", "work", "src", "repos",
        "Documents/projects", "Documents/dev", "Documents/code",
        "Desktop/projects", "Desktop/dev",
        "Developer",  # macOS
    ]
    dirs = []
    for name in candidates:
        p = home / name
        if p.is_dir():
            dirs.append(p)
    return dirs


# ═══════════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    path: Optional[str] = None
    details: str = ""
    remediation: str = ""

    def __str__(self):
        return f"[{self.severity.name}] {self.title}"


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
    scan_dir: str = ""
    start_time: str = ""


# ═══════════════════════════════════════════════════════════════════════════════════
# Platform Detection
# ═══════════════════════════════════════════════════════════════════════════════════

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

    @property
    def display_name(self):
        if self.is_macos:
            return f"macOS {platform.mac_ver()[0]}"
        elif self.is_windows:
            return f"Windows {platform.version()}"
        else:
            return f"Linux {self.kernel}"

    def get_shell_rc_files(self):
        home = Path.home()
        if self.is_windows:
            return [home / f for f in [".bashrc", ".bash_profile", ".profile"] if (home / f).exists()]
        else:
            files = [".bashrc", ".zshrc", ".profile", ".bash_profile"]
            return [home / f for f in files if (home / f).exists()]

    def get_launch_dirs(self):
        if self.is_macos:
            home = Path.home()
            dirs = [home / "Library/LaunchAgents"]
            for d in [Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]:
                if d.is_dir():
                    dirs.append(d)
            return dirs
        elif self.is_windows:
            startup = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"
            return [startup] if startup.is_dir() else []
        return []

    def get_ssh_dir(self):
        return Path.home() / ".ssh"

    def list_running_processes(self):
        """Return list of (pid, name, cmdline) tuples."""
        procs = []
        try:
            if self.is_windows:
                r = subprocess.run(
                    ["wmic", "process", "get", "ProcessId,Name,CommandLine", "/format:csv"],
                    capture_output=True, text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                for line in r.stdout.strip().split("\n"):
                    parts = line.strip().split(",")
                    if len(parts) >= 4 and parts[0].isdigit():
                        pid = int(parts[0])
                        name = parts[1] if len(parts) > 1 else ""
                        cmd = parts[2] if len(parts) > 2 else ""
                        procs.append((pid, name, cmd))
            else:
                r = subprocess.run(
                    ["ps", "aux"], capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.strip().split("\n")[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        try:
                            pid = int(parts[1])
                        except ValueError:
                            continue
                        name = parts[10]
                        procs.append((pid, parts[10], line))
        except Exception:
            pass
        return procs

    def get_network_connections(self):
        """Return list of (local, remote_ip, remote_port, pid_or_name) tuples."""
        conns = []
        try:
            if self.is_windows:
                r = subprocess.run(
                    ["netstat", "-ano"], capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                for line in r.stdout.split("\n"):
                    if "ESTABLISHED" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            remote = parts[2]
                            pid = parts[-1]
                            if ":" in remote:
                                ip, port = remote.rsplit(":", 1)
                                conns.append(("", ip, port, pid))
            elif self.is_macos:
                r = subprocess.run(
                    ["lsof", "-i", "-P", "-n"], capture_output=True, text=True, timeout=10,
                )
                for line in r.stdout.split("\n"):
                    if "ESTABLISHED" in line or "TCP" in line:
                        parts = line.split()
                        for p in parts:
                            if re.match(r"\d+\.\d+\.\d+\.\d+:\d+$", p):
                                ip, port = p.rsplit(":", 1)
                                conns.append(("", ip, port, ""))
                                break
            else:
                for cmd in [["ss", "-tnp"], ["netstat", "-tnp"]]:
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                        if r.returncode == 0:
                            for line in r.stdout.split("\n"):
                                if "ESTAB" in line:
                                    parts = line.split()
                                    for p in parts:
                                        m = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+)", p)
                                        if m and m.group(1) != "127.0.0.1":
                                            conns.append(("", m.group(1), m.group(2), ""))
                            break
                    except FileNotFoundError:
                        continue
        except Exception:
            pass
        return conns


# ═══════════════════════════════════════════════════════════════════════════════════
# Terminal UI
# ═══════════════════════════════════════════════════════════════════════════════════

class TerminalUI:
    # ANSI colors
    COLORS = {
        "RESET":     "\033[0m",
        "BOLD":      "\033[1m",
        "DIM":       "\033[2m",
        "RED":       "\033[0;31m",
        "BOLD_RED":  "\033[1;31m",
        "GREEN":     "\033[0;32m",
        "BOLD_GREEN":"\033[1;32m",
        "YELLOW":    "\033[0;33m",
        "BOLD_YELLOW":"\033[1;33m",
        "BLUE":      "\033[0;34m",
        "BOLD_BLUE": "\033[1;34m",
        "CYAN":      "\033[0;36m",
        "BOLD_CYAN": "\033[1;36m",
        "MAGENTA":   "\033[0;35m",
        "WHITE":     "\033[0;37m",
        "BG_RED":    "\033[41m",
        "BG_GREEN":  "\033[42m",
        "BG_YELLOW": "\033[43m",
    }

    SEVERITY_BADGE = {
        Severity.CRITICAL: (" CRITICAL ", "BG_RED",    "BOLD_WHITE"),
        Severity.HIGH:     (" HIGH     ", "RED",       "BOLD"),
        Severity.WARNING:  (" WARNING  ", "YELLOW",    "BOLD"),
        Severity.INFO:     (" INFO     ", "CYAN",      "DIM"),
    }

    SEVERITY_ICON = {
        Severity.CRITICAL: "\u274c",   # ❌
        Severity.HIGH:     "\u26a0\ufe0f",  # ⚠️
        Severity.WARNING:  "\u26a0\ufe0f",  # ⚠️
        Severity.INFO:     "\u2139\ufe0f",  # ℹ️
    }

    def __init__(self):
        self._use_color = self._detect_color_support()

    def _detect_color_support(self):
        if os.environ.get("NO_COLOR"):
            return False
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        if platform.system().lower() == "windows":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass
        return True

    def c(self, color_name, text):
        if not self._use_color or color_name not in self.COLORS:
            return str(text)
        return f"{self.COLORS[color_name]}{text}{self.COLORS['RESET']}"

    def banner(self):
        w = 64
        lines = [
            f"{'=' * w}",
            f"  Polinrider Malware Scanner v{VERSION}  --  Cross-Platform",
            f"  Blockchain C2 Config-Injection Detection Tool",
            f"  Attributed to: Lazarus Group (DPRK) Contagious Interview",
            f"{'=' * w}",
        ]
        print()
        for line in lines:
            print(self.c("BOLD_CYAN", line))
        print()

    def section_header(self, title, icon="\u2550"):
        w = 64
        print()
        print(self.c("BOLD", f"{icon * w}"))
        print(self.c("BOLD", f"  {title}"))
        print(self.c("BOLD", f"{icon * w}"))
        print()

    def finding(self, f):
        badge_text, badge_bg, badge_fg = self.SEVERITY_BADGE[f.severity]
        icon = self.SEVERITY_ICON[f.severity]
        severity_str = self.c(badge_fg, f"[{badge_text.strip()}]")
        print(f"  {icon} {severity_str}  {self.c('BOLD', f.title)}")
        if f.path:
            print(f"           Path: {self.c('WHITE', f.path)}")
        if f.details:
            for line in f.details.strip().split("\n"):
                print(f"           {self.c('DIM', line)}")

    def progress(self, msg):
        print(f"  \u25b8 {self.c('DIM', msg)}")

    def success(self, msg):
        print(f"  \u2714 {self.c('BOLD_GREEN', msg)}")

    def info(self, msg):
        print(f"  \u2139  {self.c('CYAN', msg)}")

    def warning(self, msg):
        print(f"  \u26a0  {self.c('YELLOW', msg)}")

    def error(self, msg):
        print(f"  \u2716 {self.c('BOLD_RED', msg)}")

    def _visible_len(self, s):
        """Length of string excluding ANSI escape codes."""
        return len(re.sub(r"\033\[[0-9;]*m", "", s))

    def _pad(self, s, width, align="left"):
        """Pad a string to width accounting for ANSI codes."""
        vis = self._visible_len(s)
        pad = max(0, width - vis)
        if align == "right":
            return " " * pad + s
        return s + " " * pad

    def system_info_table(self, plat: PlatformInfo, scan_dir: str, start_time: str):
        print(self.c("BOLD", "  System Information"))
        print(self.c("BOLD", "  " + "-" * 50))
        rows = [
            ("Platform",   plat.display_name),
            ("Hostname",   plat.hostname),
            ("Python",     plat.python_version),
            ("Arch",       plat.arch),
            ("Scan dir",   scan_dir),
            ("Started at", start_time),
        ]
        for label, val in rows:
            label_colored = self.c("BOLD_CYAN", label + ":")
            val_colored = self.c("WHITE", val)
            print(f"  {self._pad(label_colored, 22, 'right')}  {val_colored}")
        print()

    def summary_table(self, stats: ScanStats, findings: list):
        w = 66
        inner = w - 4  # inside content area

        print()
        print(self.c("BOLD", f"\u2554{'=' * w}\u2557"))
        title = "SCAN RESULTS SUMMARY"
        title_pad = w - len(title)
        left_pad = title_pad // 2
        right_pad = title_pad - left_pad
        print(self.c("BOLD", f"\u2551{' ' * left_pad}{title}{' ' * right_pad}\u2551"))
        print(self.c("BOLD", f"\u2560{'=' * w}\u2563"))

        def row(label, val, color="WHITE"):
            lbl = self.c("BOLD_CYAN", label + ":")
            val_s = self.c(color, str(val))
            lbl_vis = label + ":"
            # inner = label(28) + gap(2) + value(rest) + border
            # total visible inner = inner = 28 + 2 + val_area
            val_area = inner - 28 - 2
            print(
                self.c("BOLD", "\u2551")
                + "  "
                + self._pad(lbl, 28)
                + "  "
                + self._pad(val_s, val_area, "right")
                + "  "
                + self.c("BOLD", "\u2551")
            )

        def divider():
            print(self.c("BOLD", "\u2551  ") + self.c("DIM", "\u2500" * inner) + self.c("BOLD", "  \u2551"))

        row("Platform", stats.platform_name)
        row("Scan directory", stats.scan_dir[:50] if len(stats.scan_dir) > 50 else stats.scan_dir)
        row("Scan started", stats.start_time)
        row("Scan duration", f"{stats.scan_duration:.1f}s")
        divider()
        row("Repos scanned", stats.repos_scanned)
        row("Repos infected", stats.repos_infected, "BOLD_RED" if stats.repos_infected > 0 else "GREEN")
        row("Files checked", stats.files_checked)
        divider()

        sev_colors = {
            "critical": "BOLD_RED",
            "high": "RED",
            "warning": "BOLD_YELLOW",
            "info": "CYAN",
        }
        sev_icons = {
            "critical": "\u274c ",
            "high":     "\u26a0\ufe0f ",
            "warning":  "\u26a0\ufe0f ",
            "info":     "\u2139\ufe0f ",
        }
        for sev_name, count in [("critical", stats.critical), ("high", stats.high),
                                 ("warning", stats.warning), ("info", stats.info)]:
            row(f"{sev_icons[sev_name]}{sev_name.upper()}", count, sev_colors[sev_name])

        divider()
        total_color = "BOLD_RED" if stats.total_findings > 0 else "BOLD_GREEN"
        status = "INFECTIONS DETECTED" if stats.total_findings > 0 else "SYSTEM CLEAN"
        row("TOTAL FINDINGS", stats.total_findings, total_color)
        row("Status", status, total_color)
        print(self.c("BOLD", f"\u255a{'=' * w}\u255d"))
        print()

    def remediation_table(self, findings: list):
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        warning = [f for f in findings if f.severity == Severity.WARNING]
        info = [f for f in findings if f.severity == Severity.INFO]

        if not any([critical, high, warning]):
            return

        w = 66
        print(self.c("BOLD", f"\u2554{'=' * w}\u2557"))
        print(self.c("BOLD", f"\u2551{'REMEDIATION STEPS (by priority)':^{w}}\u2551"))
        print(self.c("BOLD", f"\u2560{'=' * w}\u2563"))

        def section(title, items, color):
            if not items:
                return
            print(self.c("BOLD", f"\u2551"))
            print(self.c("BOLD", f"\u2551  {self.c(color, title)}"))
            print(self.c("BOLD", f"\u2551  {self.c('DIM', '\u2500' * 58)}"))
            seen_remediations = set()
            for f in items:
                if f.remediation and f.remediation not in seen_remediations:
                    seen_remediations.add(f.remediation)
                    for line in f.remediation.strip().split("\n"):
                        print(self.c("BOLD", f"\u2551    ") + self.c("WHITE", line))
                    print(self.c("BOLD", f"\u2551"))

        section("[CRITICAL] Immediate action required:", critical, "BOLD_RED")
        section("[HIGH] Rotate credentials & audit:", high, "RED")
        section("[WARNING] Recommended cleanup:", warning, "YELLOW")
        section("[INFO] Best practices:", info, "CYAN")

        print(self.c("BOLD", f"\u255a{'=' * w}\u255d"))
        print()


# ═══════════════════════════════════════════════════════════════════════════════════
# Repo Scanner
# ═══════════════════════════════════════════════════════════════════════════════════

class RepoScanner:
    def __init__(self, scan_dir: str, scan_all_js: bool = False, verbose: bool = False):
        self.scan_dir = Path(scan_dir).resolve()
        self.scan_all_js = scan_all_js
        self.verbose = verbose
        self.files_checked = 0
        self.ui = TerminalUI()

    def find_git_repos(self):
        """Find all directories containing .git under scan_dir."""
        repos = []
        seen_parents = set()
        for git_dir in self.scan_dir.rglob(".git"):
            if git_dir.is_dir():
                repo = git_dir.parent
                # skip if a parent is already in the list
                skip = False
                for existing in repos:
                    try:
                        repo.relative_to(existing)
                        skip = True
                        break
                    except ValueError:
                        pass
                if not skip:
                    repos.append(repo)
        return repos

    def check_file_signatures(self, filepath):
        """Check a file for malware signatures. Returns list of findings."""
        findings = []
        try:
            content = filepath.read_text(errors="ignore")
        except Exception:
            return findings

        # Check literal signatures
        for sig in LITERAL_SIGNATURES:
            if sig in content:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="config_injection",
                    title=f"Malware signature match in {filepath.name}",
                    path=str(filepath),
                    details=f"Literal signature found: {sig[:60]}{'...' if len(sig) > 60 else ''}",
                    remediation=f"Remove everything after the legitimate config content in:\n  {filepath}\n  Look for 'global[!' or '_$_1e42' markers.",
                ))
                break  # one literal match per file is enough

        # Check regex markers
        if MARKER_REGEX.search(content):
            # only add if not already added by literal match
            if not any(f.path == str(filepath) for f in findings):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="config_injection",
                    title=f"Campaign marker in {filepath.name}",
                    path=str(filepath),
                    details="Matches known malware campaign regex pattern (global['!'], _$_1e42, etc.)",
                    remediation=f"Remove the obfuscated payload from:\n  {filepath}\n  Everything after the legitimate export statement is malware.",
                ))

        return findings

    def check_file_size(self, filepath):
        """Check if a config file is abnormally large."""
        findings = []
        try:
            size = filepath.stat().st_size
            if size > 1024:
                findings.append(Finding(
                    severity=Severity.WARNING,
                    category="file_anomaly",
                    title=f"{filepath.name} is abnormally large ({size} bytes)",
                    path=str(filepath),
                    details=f"Normal config files are ~80-300 bytes. This file is {size} bytes.\nThe malware appends ~5000+ bytes of hidden payload.",
                    remediation=f"Inspect {filepath} and remove hidden content.\n  Normal postcss/tailwind config should be under 300 bytes.",
                ))
        except Exception:
            pass
        return findings

    def check_long_lines(self, filepath):
        """Check for suspiciously long lines (hidden payload after spaces)."""
        findings = []
        try:
            content = filepath.read_text(errors="ignore")
            for i, line in enumerate(content.split("\n"), 1):
                if len(line) > 300:
                    findings.append(Finding(
                        severity=Severity.WARNING,
                        category="file_anomaly",
                        title=f"{filepath.name} has hidden payload (line {i}: {len(line)} chars)",
                        path=str(filepath),
                        details=f"Line {i} is {len(line)} characters long.\n"
                                f"Malware hides payload after ~280 spaces on the export line.",
                        remediation=f"Open {filepath} and scroll to the right on line {i}.\n  Remove everything after the legitimate config code.",
                    ))
                    break  # one finding per file
        except Exception:
            pass
        return findings

    def check_atob_pattern(self, filepath):
        """Check for atob(process.env...) + eval pattern in entry files."""
        findings = []
        try:
            content = filepath.read_text(errors="ignore")
            if re.search(r"atob\s*\(\s*process\.env", content):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="entry_hook",
                    title=f"Malicious entry hook in {filepath.name}",
                    path=str(filepath),
                    details="Found atob(process.env...) pattern — the malware decodes a base64 URL\n"
                            "from process.env and eval()s the fetched content.",
                    remediation=f"Remove the malicious (async () => {{ ... }}) block from:\n  {filepath}",
                ))
        except Exception:
            pass
        return findings

    def check_propagation_scripts(self, repo_path):
        """Check for .bat propagation scripts."""
        findings = []
        for script in PROPAGATION_SCRIPTS:
            p = repo_path / script
            if p.exists():
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="propagation_script",
                    title=f"Propagation script found: {script}",
                    path=str(p),
                    details="This is a malware propagation/orchestrator script used to\n"
                            "push infected commits to your GitHub repos.",
                    remediation=f"Delete {p} immediately.",
                ))
        return findings

    def check_gitignore(self, repo_path):
        """Check if .gitignore hides propagation scripts."""
        findings = []
        gi = repo_path / ".gitignore"
        if gi.exists():
            try:
                content = gi.read_text(errors="ignore")
                for script in PROPAGATION_SCRIPTS:
                    if script in content:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category="gitignore_tampering",
                            title=f".gitignore hides {script}",
                            path=str(gi),
                            details=f"The .gitignore contains an entry to hide '{script}',\n"
                                    "which is a known malware propagation script.",
                            remediation=f"Remove '{script}' from {gi} and delete the script itself.",
                        ))
            except Exception:
                pass
        return findings

    def check_fake_fonts(self, repo_path):
        """Check for fake font files under public/."""
        findings = []
        public_dirs = [repo_path / "public", repo_path / "static", repo_path / "assets"]
        font_exts = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
        for public_dir in public_dirs:
            if not public_dir.is_dir():
                continue
            for f in public_dir.rglob("*"):
                if f.suffix.lower() in font_exts and f.is_file():
                    try:
                        # Check if it's actually a font by reading the header
                        with open(f, "rb") as fh:
                            header = fh.read(64)
                        is_font = False
                        if header[:4] == b"wOFF":
                            is_font = True
                        elif header[:4] == b"\x00\x01\x00\x00":
                            is_font = True  # TrueType
                        elif b"OTTO" in header[:4]:
                            is_font = True
                        elif b"<html" in header.lower() or b"<!doc" in header.lower():
                            is_font = False
                        elif b"node" in header.lower() or b"eval" in header.lower():
                            is_font = False
                        else:
                            is_font = True  # unknown but probably ok

                        if not is_font:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category="fake_font",
                                title=f"Suspicious font file: {f.name}",
                                path=str(f),
                                details="File has a font extension but does not contain valid font data.\n"
                                        "The malware uses fake font files as payload drop points.",
                                remediation=f"Delete {f} and check its contents.",
                            ))
                    except Exception:
                        pass
        return findings

    def check_git_reflog(self, repo_path):
        """Check git reflog for amend/force-push evidence."""
        findings = []
        try:
            r = subprocess.run(
                ["git", "-C", str(repo_path), "reflog", "--all", "-20"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                amend_count = r.stdout.lower().count("amend")
                rebase_count = r.stdout.lower().count("rebase")
                force_count = r.stdout.lower().count("force")
                if amend_count > 2 or force_count > 0:
                    findings.append(Finding(
                        severity=Severity.WARNING,
                        category="git_tampering",
                        title=f"Suspicious git activity in {repo_path.name}",
                        path=str(repo_path / ".git"),
                        details=f"Found {amend_count} amend(s), {rebase_count} rebase(s), "
                                f"{force_count} force-push(es) in recent reflog.\n"
                                "The malware rewrites commit history to inject payloads.",
                        remediation=f"Audit commit history for {repo_path.name}:\n"
                                    f"  git -C {repo_path} reflog --all -30\n"
                                    "  Look for commits you didn't make.",
                    ))
        except Exception:
            pass
        return findings

    def check_env_files(self, repo_path):
        """Check for .env files in infected repos (secrets may be compromised)."""
        findings = []
        for name in [".env", ".env.local", ".env.production", ".env.development"]:
            p = repo_path / name
            if p.exists():
                findings.append(Finding(
                    severity=Severity.WARNING,
                    category="credential_exposure",
                    title=f"Secrets file found: {name}",
                    path=str(p),
                    details=f"If this repo was infected, the malware had access to all secrets\n"
                            f"in process.env including values from {name}.",
                    remediation=f"Rotate ALL secrets in {p} immediately.\n  Change API keys, database URLs, and any tokens.",
                ))
        return findings

    def scan_repo(self, repo_path):
        """Full scan of one repository."""
        findings = []
        self.ui.progress(f"Scanning {repo_path}...")

        # 1. Known config files — signature, size, long lines
        for config_name in CONFIG_FILES:
            fp = repo_path / config_name
            if fp.exists():
                self.files_checked += 1
                findings.extend(self.check_file_signatures(fp))
                findings.extend(self.check_file_size(fp))
                findings.extend(self.check_long_lines(fp))

        # 2. Optional: scan ALL js/ts files
        if self.scan_all_js:
            for ext in ["*.js", "*.mjs", "*.ts", "*.tsx"]:
                for fp in repo_path.rglob(ext):
                    rel = fp.relative_to(repo_path)
                    if any(part == "node_modules" or part == ".git" for part in rel.parts):
                        continue
                    findings.extend(self.check_file_signatures(fp))

        # 3. Entry file hooks (atob + process.env)
        entry_files = ["main.ts", "main.js", "index.ts", "index.js", "app.ts", "app.js",
                        "server.ts", "server.js", "src/main.ts", "src/main.js",
                        "src/index.ts", "src/index.js", "src/app.ts", "src/app.js",
                        "src/server.ts", "src/server.js"]
        for name in entry_files:
            fp = repo_path / name
            if fp.exists():
                findings.extend(self.check_atob_pattern(fp))

        # 4. Propagation scripts
        findings.extend(self.check_propagation_scripts(repo_path))

        # 5. .gitignore tampering
        findings.extend(self.check_gitignore(repo_path))

        # 6. Fake fonts
        findings.extend(self.check_fake_fonts(repo_path))

        # 7. Git reflog evidence
        findings.extend(self.check_git_reflog(repo_path))

        # 8. .env files in potentially infected repos
        has_infections = any(f.severity >= Severity.HIGH for f in findings)
        if has_infections:
            findings.extend(self.check_env_files(repo_path))

        return findings

    def scan_all(self):
        """Find all repos and scan each."""
        all_findings = []
        self.files_checked = 0

        repos = self.find_git_repos()
        if not repos:
            self.ui.info(f"No git repositories found under {self.scan_dir}")
            return all_findings, 0, 0

        self.ui.progress(f"Found {len(repos)} git repositories")
        infected = 0

        for repo in repos:
            repo_findings = self.scan_repo(repo)
            if repo_findings:
                all_findings.extend(repo_findings)
                infected += 1
                self.ui.error(f"[INFECTED] {repo}")
                for f in repo_findings:
                    if f.severity >= Severity.HIGH:
                        self.ui.finding(f)
            else:
                if self.verbose:
                    self.ui.success(f"Clean: {repo}")

        return all_findings, len(repos), infected


# ═══════════════════════════════════════════════════════════════════════════════════
# System Scanner
# ═══════════════════════════════════════════════════════════════════════════════════

class SystemScanner:
    def __init__(self, plat: PlatformInfo, verbose: bool = False):
        self.plat = plat
        self.verbose = verbose
        self.ui = TerminalUI()

    def check_shell_startup_files(self):
        findings = []
        rc_files = self.plat.get_shell_rc_files()
        for rc in rc_files:
            try:
                content = rc.read_text(errors="ignore")
                for pattern in SHELL_SUSPICIOUS_PATTERNS:
                    matches = pattern.findall(content)
                    if matches:
                        for match in matches[:3]:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category="shell_injection",
                                title=f"Suspicious code in {rc.name}",
                                path=str(rc),
                                details=f"Pattern: {match[:80]}{'...' if len(match) > 80 else ''}",
                                remediation=f"Review {rc} and remove any code you didn't add.\n"
                                           f"  Look for curl|bash, eval(base64...), or global['!'] patterns.",
                            ))
                        break  # one finding per file
            except Exception:
                pass
        return findings

    def check_suspicious_processes(self):
        findings = []
        procs = self.plat.list_running_processes()
        for pid, name, cmdline in procs:
            for pattern in MALICIOUS_PROCESS_PATTERNS:
                if pattern.search(cmdline):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        category="malicious_process",
                        title=f"Suspicious process running (PID {pid})",
                        details=f"Process: {cmdline[:120]}{'...' if len(cmdline) > 120 else ''}",
                        remediation=f"Kill the process:\n"
                                   f"  kill -9 {pid}  (Linux/macOS)\n"
                                   f"  taskkill /PID {pid} /F  (Windows)\n"
                                   "  Then investigate how it was started.",
                    ))
                    break  # one match per process
        return findings

    def check_network_connections(self):
        findings = []
        conns = self.plat.get_network_connections()
        malicious_set = set(MALICIOUS_IPS)
        for _, remote_ip, remote_port, proc_info in conns:
            if remote_ip in malicious_set:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="c2_connection",
                    title=f"Active connection to known C2: {remote_ip}:{remote_port}",
                    details=f"Remote: {remote_ip}:{remote_port}\n"
                            f"Process: {proc_info}" if proc_info else "",
                    remediation=f"Block this IP in your firewall immediately:\n"
                               f"  sudo iptables -A OUTPUT -d {remote_ip} -j DROP  (Linux)\n"
                               f"  sudo pfctl -a 'block' -d {remote_ip}  (macOS)\n"
                               f"  netsh advfirewall firewall add rule name='Block C2' dir=out action=block remoteip={remote_ip}  (Windows)\n"
                               "Then kill the process using this connection.",
                ))
        return findings

    def check_cron_jobs(self):
        findings = []
        try:
            if self.plat.is_windows:
                r = subprocess.run(
                    ["schtasks", "/query", "/fo", "CSV"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                for line in r.stdout.split("\n"):
                    lower = line.lower()
                    if any(kw in lower for kw in ["font", "cache", "update", "temp", ".tmp"]):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            category="scheduled_task",
                            title=f"Suspicious scheduled task found",
                            details=line.strip()[:120],
                            remediation="Review Windows Task Scheduler for tasks you didn't create.\n"
                                       "  Run: schtasks /query /fo LIST /v  to see full details.",
                        ))
            else:
                r = subprocess.run(
                    ["crontab", "-l"], capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0 and r.stdout.strip():
                    for line in r.stdout.strip().split("\n"):
                        if line.startswith("#"):
                            continue
                        lower = line.lower()
                        if any(kw in lower for kw in ["font", "cache", "temp", "/tmp", "curl", "wget", "eval", "base64", "node"]):
                            findings.append(Finding(
                                severity=Severity.WARNING,
                                category="cron_job",
                                title=f"Suspicious cron job found",
                                details=line.strip()[:120],
                                remediation="Review your crontab:\n  crontab -l\n"
                                           "  Remove any entries you didn't add.",
                            ))
        except Exception:
            pass
        return findings

    def check_launch_agents(self):
        findings = []
        for d in self.plat.get_launch_dirs():
            if not d.is_dir():
                continue
            try:
                for f in d.iterdir():
                    if f.suffix == ".plist" or f.suffix == ".job":
                        try:
                            content = f.read_text(errors="ignore")
                            lower = content.lower()
                            if any(kw in lower for kw in ["curl", "wget", "eval", "base64", "node -e", "font-updater"]):
                                findings.append(Finding(
                                    severity=Severity.HIGH,
                                    category="launch_agent",
                                    title=f"Suspicious launch agent: {f.name}",
                                    path=str(f),
                                    details=f"File contains suspicious patterns:\n{content[:200]}",
                                    remediation=f"Remove {f} and unload it:\n"
                                               f"  launchctl unload {f}  (macOS)\n"
                                               f"  Or on Windows, check Startup folder.",
                                ))
                        except Exception:
                            pass
            except Exception:
                pass
        return findings

    def check_python_scripts(self):
        findings = []
        home = Path.home()
        search_dirs = [home / ".npm", home / ".cache", home / "tmp"]
        if self.plat.is_windows:
            search_dirs = [Path(os.environ.get("LOCALAPPDATA", "")) / "Temp"]

        for d in search_dirs:
            if not d.is_dir():
                continue
            try:
                for py in d.rglob("*.py"):
                    if py.stat().st_size > 100000:  # skip large files
                        continue
                    try:
                        content = py.read_text(errors="ignore")
                        has_eval = bool(re.search(r"eval\s*\(|exec\s*\(", content))
                        has_net = bool(re.search(r"requests\.|urllib|socket\.|http[^\w]|fetch\(", content))
                        if has_eval and has_net:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category="malicious_script",
                                title=f"Suspicious Python script: {py.name}",
                                path=str(py),
                                details="Contains eval/exec + network calls — possible second-stage loader.",
                                remediation=f"Investigate {py}:\n  Read its contents, check if it's legitimate.\n  Delete if unknown.",
                            ))
                    except Exception:
                        pass
            except Exception:
                pass
        return findings

    def scan_all(self):
        all_findings = []
        self.ui.progress("Checking shell startup files...")
        all_findings.extend(self.check_shell_startup_files())

        self.ui.progress("Checking running processes...")
        all_findings.extend(self.check_suspicious_processes())

        self.ui.progress("Checking network connections...")
        all_findings.extend(self.check_network_connections())

        self.ui.progress("Checking cron/scheduled tasks...")
        all_findings.extend(self.check_cron_jobs())

        self.ui.progress("Checking launch agents/daemons...")
        all_findings.extend(self.check_launch_agents())

        self.ui.progress("Checking for suspicious Python scripts...")
        all_findings.extend(self.check_python_scripts())

        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════════
# Credential Scanner
# ═══════════════════════════════════════════════════════════════════════════════════

class CredentialScanner:
    def __init__(self, scan_dir: str, verbose: bool = False):
        self.scan_dir = Path(scan_dir).resolve()
        self.verbose = verbose
        self.ui = TerminalUI()

    def check_ssh_keys(self):
        findings = []
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.is_dir():
            return findings

        for f in ssh_dir.iterdir():
            if f.name in ["authorized_keys", "known_hosts", "config", "."]:
                continue
            if not f.is_file():
                continue
            # Skip public keys — they don't need restrictive permissions
            if f.suffix == ".pub" or f.name.endswith(".pub"):
                continue

            # Check permissions on Unix
            if not sys.platform.startswith("win"):
                try:
                    mode = oct(f.stat().st_mode)[-3:]
                    if mode not in ("600", "400"):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            category="ssh_key_permissions",
                            title=f"SSH key has weak permissions: {f.name} ({mode})",
                            path=str(f),
                            details="SSH private keys should have mode 600 (owner read/write only).",
                            remediation=f"  chmod 600 {f}",
                        ))
                except Exception:
                    pass

            # Check if key is in a non-standard location
            try:
                content = f.read_text(errors="ignore")
                if "OPENSSH PRIVATE KEY" in content or "RSA PRIVATE KEY" in content:
                    config = ssh_dir / "config"
                    if config.exists():
                        config_content = config.read_text(errors="ignore")
                        if f.name not in config_content and str(f) not in config_content:
                            if self.verbose:
                                findings.append(Finding(
                                    severity=Severity.INFO,
                                    category="ssh_key",
                                    title=f"SSH key not referenced in config: {f.name}",
                                    path=str(f),
                                    details="This key exists but isn't referenced in ~/.ssh/config.",
                                    remediation="Review if this key is still needed.",
                                ))
            except Exception:
                pass
        return findings

    def check_env_file_leaks(self):
        findings = []
        env_pattern = re.compile(r"\.env($|\.)")
        infected_indicators = ["global['!']", "global['_V']", "_$_1e42", "atob(process.env"]

        for env_file in self.scan_dir.rglob(".env*"):
            if any(part == "node_modules" or part == ".git" for part in env_file.parts):
                continue
            if env_file.is_file() and env_pattern.search(env_file.name):
                # Check if the parent project is infected
                parent = env_file.parent
                for indicator in infected_indicators:
                    # Check config files in same dir
                    for cfg in CONFIG_FILES:
                        fp = parent / cfg
                        if fp.exists():
                            try:
                                content = fp.read_text(errors="ignore")
                                if indicator in content:
                                    findings.append(Finding(
                                        severity=Severity.HIGH,
                                        category="credential_exposure",
                                        title=f"Secrets in infected project: {env_file.name}",
                                        path=str(env_file),
                                        details=f"The config file {cfg} in the same directory contains malware.\n"
                                                "The malware had full access to process.env and all secrets.",
                                        remediation=f"Rotate ALL secrets in {env_file}:\n"
                                                   "  - API keys\n  - Database URLs\n  - Auth tokens\n"
                                                   "  - Any other credentials",
                                    ))
                                    break
                            except Exception:
                                pass
                    else:
                        continue
                    break
        return findings

    def check_git_credential_cache(self):
        findings = []
        try:
            # Check for cached HTTPS credentials
            if self.ui._use_color:
                r = subprocess.run(
                    ["git", "config", "--global", "--get-regexp", "credential"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0 and r.stdout.strip():
                    findings.append(Finding(
                        severity=Severity.INFO,
                        category="git_credentials",
                        title="Git credential helper configured",
                        details=r.stdout.strip()[:200],
                        remediation="After cleaning up, consider switching to SSH keys:\n"
                                   "  gh auth setup-git\n"
                                   "  Or use: git config --global credential.helper store\n"
                                   "  And rotate your GitHub PAT.",
                    ))
        except Exception:
            pass
        return findings

    def scan_all(self):
        all_findings = []
        self.ui.progress("Checking SSH key permissions...")
        all_findings.extend(self.check_ssh_keys())

        self.ui.progress("Checking for exposed .env files in infected repos...")
        all_findings.extend(self.check_env_file_leaks())

        self.ui.progress("Checking git credential configuration...")
        all_findings.extend(self.check_git_credential_cache())

        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════════
# GitHub Scanner
# ═══════════════════════════════════════════════════════════════════════════════════

class GitHubScanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.ui = TerminalUI()
        self.gh_available = shutil.which("gh") is not None

    def check_gh_cli(self):
        findings = []
        if not self.gh_available:
            findings.append(Finding(
                severity=Severity.INFO,
                category="github_audit",
                title="gh CLI not found — skipping GitHub audit",
                details="Install gh CLI for GitHub repo auditing:\n"
                        "  https://cli.github.com/",
                remediation="Install gh CLI and authenticate:\n"
                           "  brew install gh  (macOS)\n"
                           "  sudo apt install gh  (Linux)\n"
                           "  winget install gh  (Windows)\n"
                           "  gh auth login",
            ))
            return findings

        # Check if authenticated
        try:
            r = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True, text=True, timeout=10,
            )
            output = r.stdout + r.stderr
            if "Logged in" in output:
                # Extract username
                for line in output.split("\n"):
                    if "account" in line.lower():
                        findings.append(Finding(
                            severity=Severity.INFO,
                            category="github_audit",
                            title=f"gh CLI authenticated",
                            details=line.strip(),
                        ))
                        break
            else:
                findings.append(Finding(
                    severity=Severity.INFO,
                    category="github_audit",
                    title="gh CLI not authenticated",
                    details="Run 'gh auth login' to authenticate.",
                    remediation="gh auth login",
                ))
        except Exception:
            pass
        return findings

    def audit_repos(self):
        findings = []
        if not self.gh_available:
            return findings

        try:
            # Get list of repos
            r = subprocess.run(
                ["gh", "repo", "list", "--limit", "30", "--json", "name,owner,updatedAt,pushedAt"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                return findings

            repos = json.loads(r.stdout)
            if not repos:
                return findings

            self.ui.progress(f"Checking {len(repos)} GitHub repositories...")

            for repo_info in repos:
                repo_name = f"{repo_info['owner']['login']}/{repo_info['name']}"
                pushed_at = repo_info.get("pushedAt", "")

                # Check for recent suspicious pushes
                if pushed_at:
                    try:
                        pushed_dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                        hours_ago = (datetime.now().astimezone() - pushed_dt).total_seconds() / 3600
                        if hours_ago < 24:
                            findings.append(Finding(
                                severity=Severity.INFO,
                                category="github_recent_push",
                                title=f"Recent push to {repo_info['name']} ({hours_ago:.1f}h ago)",
                                details=f"Repository: {repo_name}\n"
                                        f"Last pushed: {pushed_at}\n"
                                        "If you didn't push recently, this could be the malware.",
                                remediation=f"Check recent commits:\n  gh api repos/{repo_name}/commits?per_page=10\n"
                                           "  Look for commits you didn't make.",
                            ))
                    except Exception:
                        pass

                # Check for suspicious commit messages
                try:
                    r2 = subprocess.run(
                        ["gh", "api", f"repos/{repo_name}/commits",
                         "--paginate", "-q", ".[].commit.message"],
                        capture_output=True, text=True, timeout=15,
                    )
                    if r2.returncode == 0:
                        for msg in r2.stdout.strip().split("\n"):
                            msg_lower = msg.lower().strip()
                            for suspicious in SUSPICIOUS_COMMIT_MESSAGES:
                                if suspicious in msg_lower:
                                    findings.append(Finding(
                                        severity=Severity.HIGH,
                                        category="github_suspicious_commit",
                                        title=f"Suspicious commit in {repo_info['name']}",
                                        details=f'Commit message: "{msg.strip()[:80]}"\n'
                                                f"Repository: {repo_name}",
                                        remediation=f"Audit this repo on GitHub web UI:\n"
                                                   f"  https://github.com/{repo_name}/commits\n"
                                                   "  Revert any commits you didn't make.",
                                    ))
                                    break
                except Exception:
                    pass

        except Exception as e:
            if self.verbose:
                self.ui.warning(f"GitHub audit error: {e}")

        return findings

    def scan_all(self):
        all_findings = []
        self.ui.progress("Checking gh CLI...")
        all_findings.extend(self.check_gh_cli())
        all_findings.extend(self.audit_repos())
        return all_findings


# ═══════════════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════════════

class Report:
    def __init__(self):
        self.findings: list = []
        self.stats = ScanStats()
        self.ui = TerminalUI()

    def add(self, findings: list):
        self.findings.extend(findings)
        for f in findings:
            self.stats.total_findings += 1
            if f.severity == Severity.CRITICAL:
                self.stats.critical += 1
            elif f.severity == Severity.HIGH:
                self.stats.high += 1
            elif f.severity == Severity.WARNING:
                self.stats.warning += 1
            elif f.severity == Severity.INFO:
                self.stats.info += 1

    def print_remediation(self):
        self.ui.remediation_table(self.findings)


# ═══════════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        prog="threat_scanner",
        description=f"ThreatScan v{VERSION} — Blockchain C2 Config-Injection Detection",
    )
    parser.add_argument(
        "directory", nargs="?", default=None,
        help="Directory to scan (default: common project dirs under home)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed output during scanning",
    )
    parser.add_argument(
        "--js-all", action="store_true",
        help="Also scan every .js/.ts file (not just known config names)",
    )
    parser.add_argument(
        "--no-github", action="store_true",
        help="Skip GitHub repository audit",
    )
    parser.add_argument(
        "--ci", action="store_true",
        help="CI mode: repo scan only, GitHub Actions annotations, machine-readable output",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}",
    )
    return parser.parse_args()


def print_github_annotations(findings):
    """Print GitHub Actions annotations for each finding."""
    for f in findings:
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.WARNING: "warning",
            Severity.INFO: "notice",
        }
        level = severity_map.get(f.severity, "notice")
        msg = f.title
        if f.path:
            msg = f"{f.title} — {f.path}"
        # Escape newlines and colons for GHA annotation format
        msg = msg.replace("\n", "%0A").replace("::", ":::")
        if f.path:
            print(f"::{level} file={f.path}::{msg}")
        else:
            print(f"::{level}::{msg}")


def main():
    args = parse_args()
    start_time = time.time()
    start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # CI mode: suppress colors
    if args.ci:
        os.environ["NO_COLOR"] = "1"

    plat = PlatformInfo()
    ui = TerminalUI()
    report = Report()
    report.stats.platform_name = plat.display_name
    report.stats.start_time = start_time_str

    # Determine scan directory
    if args.directory:
        scan_dir = str(Path(args.directory).resolve())
    else:
        # Scan common project directories under home
        common_dirs = get_common_project_dirs()
        if common_dirs:
            scan_dir = str(common_dirs[0].parent)  # scan the parent
        else:
            scan_dir = str(Path.home())

    report.stats.scan_dir = scan_dir

    if args.ci:
        # CI mode: minimal output, repo scan only
        print(f"ThreatScan v{VERSION} — CI Mode")
        print(f"Scanning: {scan_dir}")
        print()
    else:
        # Banner and system info
        ui.banner()
        ui.system_info_table(plat, scan_dir, start_time_str)

    # ─── Module 1: Repository Scanning ─────────────────────────────────────
    if not args.ci:
        ui.section_header("MODULE 1: Repository Scanning", "\u2550")

    repo_scanner = RepoScanner(scan_dir, args.js_all, args.verbose)
    repo_findings, repos_scanned, repos_infected = repo_scanner.scan_all()
    report.stats.repos_scanned = repos_scanned
    report.stats.repos_infected = repos_infected
    report.stats.files_checked += repo_scanner.files_checked
    report.add(repo_findings)

    if args.ci:
        # CI: print findings concisely
        for f in repo_findings:
            prefix = {Severity.CRITICAL: "CRITICAL", Severity.HIGH: "HIGH",
                      Severity.WARNING: "WARNING", Severity.INFO: "INFO"}
            print(f"[{prefix.get(f.severity, '?')}] {f.title}")
            if f.path:
                print(f"  Path: {f.path}")
    else:
        if not repo_findings:
            ui.success(f"All {repos_scanned} repositories scanned clean")

    # ─── Module 2-4: Skip in CI mode ──────────────────────────────────────
    if not args.ci:
        # Module 2: System-Wide Checks
        ui.section_header("MODULE 2: System-Wide Checks", "\u2550")
        sys_scanner = SystemScanner(plat, args.verbose)
        sys_findings = sys_scanner.scan_all()
        report.add(sys_findings)
        if not sys_findings:
            ui.success("No suspicious system activity detected")

        # Module 3: Credential Checks
        ui.section_header("MODULE 3: Credential & Secret Checks", "\u2550")
        cred_scanner = CredentialScanner(scan_dir, args.verbose)
        cred_findings = cred_scanner.scan_all()
        report.add(cred_findings)
        if not cred_findings:
            ui.success("No credential exposure issues found")

        # Module 4: GitHub Audit
        if not args.no_github:
            ui.section_header("MODULE 4: GitHub Repository Audit", "\u2550")
            gh_scanner = GitHubScanner(args.verbose)
            gh_findings = gh_scanner.scan_all()
            report.add(gh_findings)
            if not gh_findings:
                ui.success("GitHub audit completed — no issues found")
        else:
            ui.section_header("MODULE 4: GitHub Audit (SKIPPED)", "\u2550")
            ui.info("Skipped per --no-github flag")

    # ─── Final Summary ─────────────────────────────────────────────────────
    report.stats.scan_duration = time.time() - start_time

    if args.ci:
        # CI mode: machine-readable output
        print()
        print(f"Repos scanned: {report.stats.repos_scanned}")
        print(f"Repos infected: {report.stats.repos_infected}")
        print(f"Files checked: {report.stats.files_checked}")
        print(f"Critical: {report.stats.critical}")
        print(f"High: {report.stats.high}")
        print(f"Warning: {report.stats.warning}")
        print(f"Duration: {report.stats.scan_duration:.1f}s")
        print()
        # GitHub Actions annotations
        print_github_annotations(report.findings)
        print()
        # Machine-readable flag
        if report.stats.total_findings > 0:
            print("MALWARE_DETECTED=true")
        else:
            print("MALWARE_DETECTED=false")
    else:
        ui.summary_table(report.stats, report.findings)
        if report.stats.total_findings > 0:
            report.print_remediation()
        # Known malicious IPs reference
        ui.section_header("KNOWN MALICIOUS IPs (block in firewall)", "\u2550")
        for ip in MALICIOUS_IPS:
            print(f"  {ui.c('RED', ip)}")
        print()

    # Exit code
    if report.stats.critical > 0 or report.stats.high > 0:
        sys.exit(1)
    elif report.stats.warning > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

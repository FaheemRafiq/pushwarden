"""Terminal output."""

import os
import platform
import sys
from typing import List

from . import VERSION
from .findings import Finding, ScanStats, Severity


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

    def __init__(self, ci=False, quiet=False):
        self.ci = ci
        self.quiet = quiet
        self.use_color = self._detect_color() and not ci

    def _detect_color(self):
        if os.environ.get("NO_COLOR"):
            return False
        if not sys.stdout or not sys.stdout.isatty():
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

    def _p(self, *a):
        if not self.quiet:
            try:
                print(*a)
            except UnicodeEncodeError:
                print(*(str(x).encode("ascii", "replace").decode() for x in a))

    def banner(self, ioc_version=""):
        w = 70
        self._p()
        self._p(self.c("BOLD_CYAN", "=" * w))
        self._p(self.c("BOLD_CYAN", f"  ThreatScan v{VERSION} - PolinRider / Contagious Interview Detector"))
        self._p(self.c("BOLD_CYAN", f"  Cross-platform | Indicators {ioc_version}"))
        self._p(self.c("BOLD_CYAN", "=" * w))
        self._p()

    def section(self, title):
        self._p()
        self._p(self.c("BOLD", "-" * 70))
        self._p(self.c("BOLD", f"  {title}"))
        self._p(self.c("BOLD", "-" * 70))

    def finding(self, f: Finding):
        label, color = self.BADGE[f.severity]
        self._p(f"  [{self.c(color, label)}] {self.c('BOLD', f.title)}")
        if f.path:
            self._p(f"      Path: {f.path}")
        for line in f.details.strip().split("\n"):
            if line.strip():
                self._p(f"      {self.c('DIM', line)}")
        if f.action:
            self._p(f"      {self.c('BOLD_GREEN', 'Action: ' + f.action)}")

    def progress(self, msg):
        if not self.ci:
            self._p(f"  > {self.c('DIM', msg)}")

    def ok(self, msg):
        self._p(f"  + {self.c('BOLD_GREEN', msg)}")

    def info(self, msg):
        self._p(f"  i {self.c('CYAN', msg)}")

    def warn(self, msg):
        self._p(f"  ! {self.c('YELLOW', msg)}")

    def err(self, msg):
        self._p(f"  x {self.c('BOLD_RED', msg)}")

    def system_info(self, plat, dirs, start, ci_hostnames):
        self._p(self.c("BOLD", "  System"))
        rows = [("Platform", plat.display_name), ("Hostname", plat.hostname),
                ("Python", plat.python_version), ("Arch", plat.arch),
                ("Scan dirs", ", ".join(str(d) for d in dirs) or "(none)"),
                ("Started", start)]
        for k, v in rows:
            self._p(f"    {self.c('BOLD_CYAN', k + ':'):<22} {v}")
        if plat.hostname in ci_hostnames:
            self._p(f"    {self.c('YELLOW', 'Note: this hostname is on the malware CI-evasion list; the payload may stay dormant here.')}")

    def summary(self, stats: ScanStats):
        self._p()
        self._p(self.c("BOLD", "=" * 70))
        self._p(self.c("BOLD", "  SCAN SUMMARY"))
        self._p(self.c("BOLD", "=" * 70))

        def row(k, v, color="WHITE"):
            self._p(f"  {self.c('BOLD_CYAN', k + ':'):<30} {self.c(color, v)}")
        row("Platform", stats.platform_name)
        row("Duration", f"{stats.scan_duration:.1f}s")
        row("Repos scanned", stats.repos_scanned)
        row("Repos infected", stats.repos_infected, "BOLD_RED" if stats.repos_infected else "GREEN")
        row("Files checked", stats.files_checked)
        self._p()
        row("CRITICAL", stats.critical, "BOLD_RED" if stats.critical else "DIM")
        row("HIGH", stats.high, "RED" if stats.high else "DIM")
        row("WARNING", stats.warning, "BOLD_YELLOW" if stats.warning else "DIM")
        row("INFO", stats.info, "CYAN" if stats.info else "DIM")
        self._p()
        bad = stats.critical + stats.high
        status = "INFECTIONS DETECTED" if bad else ("REVIEW WARNINGS" if stats.warning else "CLEAN")
        color = "BOLD_RED" if bad else ("BOLD_YELLOW" if stats.warning else "BOLD_GREEN")
        row("Status", status, color)
        self._p(self.c("BOLD", "=" * 70))

    def remediation(self, findings: List[Finding]):
        by_sev = {s: [] for s in Severity}
        for f in findings:
            by_sev[f.severity].append(f)
        if not (by_sev[Severity.CRITICAL] or by_sev[Severity.HIGH] or by_sev[Severity.WARNING]):
            return
        self._p()
        self._p(self.c("BOLD", "  REMEDIATION (by priority)"))
        self._p(self.c("BOLD", "  " + "-" * 66))
        for sev, title, color in [(Severity.CRITICAL, "CRITICAL - act now", "BOLD_RED"),
                                  (Severity.HIGH, "HIGH - rotate credentials & audit", "RED"),
                                  (Severity.WARNING, "WARNING - review", "YELLOW")]:
            items = by_sev[sev]
            if not items:
                continue
            self._p(f"\n  {self.c(color, title)}")
            seen = set()
            for f in items:
                if f.remediation and f.remediation not in seen:
                    seen.add(f.remediation)
                    for line in f.remediation.strip().split("\n"):
                        self._p(f"    {line}")
        self._p()
        self._p(self.c("BOLD", "  After ANY critical/high finding, regardless of what else you do:"))
        for line in [
            "1. Rotate: GitHub PATs, SSH keys, npm tokens, cloud/deploy tokens (Vercel/Netlify/AWS).",
            "2. Revoke OAuth apps & GitHub App installs you don't recognise.",
            "3. Enable hardware-backed 2FA on GitHub and npm.",
            "4. Run: threatscan harden   (turns off VS Code automatic tasks).",
            "5. Report: https://opensourcemalware.com",
        ]:
            self._p(f"    {line}")
        self._p()

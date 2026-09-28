"""Background guard: continuous detection + response.

Three cadences (all configurable in config.json):
  quick  (60 s)   processes + C2 sockets + tracked files whose mtime changed
  full   (6 h)    complete repository sweep + host persistence checks
  iocs   (24 h)   refresh indicators from the project repository

State lives in <data_dir>/guard/ : heartbeat.json, seen.json (alert dedup).
"""

import json
import os
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, List

from . import VERSION, iocs as iocmod
from .config import Config
from .findings import Finding, ScanStats, Severity
from .notify import Notifier
from .protect import Protector
from .report import write_report
from .scanner import RepoScanner, SystemScanner
from .ui import TerminalUI
from .updater import last_check, update_iocs


class Guard:
    def __init__(self, plat, data_dir: Path, once=False, dry_run=False, verbose=False):
        self.plat = plat
        self.data_dir = data_dir
        self.once = once
        self.dry_run = dry_run
        self.cfg = Config.load(data_dir)
        self.ui = TerminalUI(ci=True, quiet=not verbose)
        self.iocs = iocmod.load(data_dir)
        self.notifier = Notifier(plat, self.cfg, data_dir)
        self.protector = Protector(plat, self.iocs, data_dir, ui=self.ui, dry_run=dry_run)
        self.state_dir = data_dir / "guard"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.seen: Dict[str, float] = self._load_json(self.state_dir / "seen.json", {})
        self.mtimes: Dict[str, float] = {}
        self.repos: List[Path] = []
        self.tracked: List[Path] = []
        self.last_full = 0.0
        self.running = True
        self.log_path = data_dir / "guard.log"

    # ── utils ────────────────────────────────────────────────────────────────
    def _load_json(self, p: Path, default):
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return default

    def _save_json(self, p: Path, data):
        try:
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(p)
        except Exception:
            pass

    def log(self, msg):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass
        if not self.ui.quiet:
            print(line, flush=True)

    def heartbeat(self, phase: str, extra=None):
        hb = {"ts": time.time(), "pid": os.getpid(), "phase": phase, "version": VERSION,
              "iocs": self.iocs.version, "last_full": self.last_full, "repos": len(self.repos)}
        if extra:
            hb.update(extra)
        self._save_json(self.state_dir / "heartbeat.json", hb)

    def _stop(self, *_):
        self.running = False

    # ── discovery ────────────────────────────────────────────────────────────
    def refresh_targets(self):
        roots = self.cfg.roots(self.plat)
        repos = []
        for r in roots:
            rs = RepoScanner(r, self.ui, self.iocs, exclude=self.cfg.exclude)
            repos += rs.find_repos()
            repos += [p for p in rs.find_non_git_projects() if p not in repos]
        self.repos = repos
        rs = RepoScanner(Path.home(), self.ui, self.iocs, exclude=self.cfg.exclude)
        self.tracked = rs.tracked_files(repos)
        # Prime mtimes so the first quick pass does not re-scan everything the
        # full pass just covered.
        for p in self.tracked:
            try:
                self.mtimes[str(p)] = p.stat().st_mtime
            except OSError:
                self.mtimes.pop(str(p), None)

    # ── response + alerting ──────────────────────────────────────────────────
    def handle(self, findings: List[Finding], context: str):
        if not findings:
            return
        acted = self.protector.respond(findings, auto_kill=self.cfg.auto_kill, auto_clean=self.cfg.auto_clean)
        now = time.time()
        fresh = []
        for f in findings:
            # Re-alert on the same finding at most once per 6 hours, always alert actions.
            if f.action or now - self.seen.get(f.key, 0) > 6 * 3600:
                fresh.append(f)
            self.seen[f.key] = now
        # prune
        for k in [k for k, t in self.seen.items() if now - t > 7 * 86400]:
            del self.seen[k]
        self._save_json(self.state_dir / "seen.json", self.seen)
        for f in findings:
            self.log(f"[{f.severity.name}] {f.title} {f.path or ''} {('-> ' + f.action) if f.action else ''}")
        if any(f.severity >= Severity.HIGH for f in fresh):
            self.notifier.alert([f for f in fresh if f.severity >= Severity.WARNING], context=context)
        if acted:
            self.log(f"responded to {len(acted)} finding(s)")

    # ── passes ───────────────────────────────────────────────────────────────
    def quick_pass(self):
        self.heartbeat("quick")
        ss = SystemScanner(self.plat, self.ui, self.iocs)
        findings = ss.quick()
        # Tracked files whose mtime changed (or that newly appeared)
        rs = RepoScanner(Path.home(), self.ui, self.iocs, exclude=self.cfg.exclude)
        changed = []
        for p in self.tracked:
            try:
                m = p.stat().st_mtime
            except OSError:
                if str(p) in self.mtimes:
                    del self.mtimes[str(p)]
                continue
            if self.mtimes.get(str(p)) != m:
                self.mtimes[str(p)] = m
                changed.append(p)
        for p in changed:
            findings += rs.scan_file(p)
        if changed:
            self.log(f"quick pass: {len(changed)} changed file(s) rescanned")
        self.handle(findings, "guard-quick")

    def full_pass(self):
        self.heartbeat("full")
        start = time.time()
        self.refresh_targets()
        findings: List[Finding] = []
        repos_total = infected = files = 0
        for root in self.cfg.roots(self.plat):
            rs = RepoScanner(root, self.ui, self.iocs, js_all=self.cfg.js_all, exclude=self.cfg.exclude)
            fs, total, inf = rs.scan_all()
            findings += fs
            repos_total += total
            infected += inf
            files += rs.files_checked
        ss = SystemScanner(self.plat, self.ui, self.iocs)
        findings += ss.scan_all(repo_infected=infected > 0)
        self.handle(findings, "guard-full")
        stats = ScanStats.from_findings(findings, repos_scanned=repos_total, repos_infected=infected,
                                        files_checked=files, scan_duration=time.time() - start,
                                        platform_name=self.plat.display_name, hostname=self.plat.hostname,
                                        scan_dirs=[str(r) for r in self.cfg.roots(self.plat)],
                                        start_time=time.strftime("%Y-%m-%d %H:%M:%S"))
        write_report(self.data_dir, stats, findings, self.iocs.version, keep=self.cfg.report_keep, tag="guard")
        self.last_full = time.time()
        self.log(f"full pass: {repos_total} repos, {infected} infected, {stats.critical} critical, "
                 f"{stats.high} high in {stats.scan_duration:.1f}s")
        self.heartbeat("idle", {"last_full_stats": {"repos": repos_total, "infected": infected,
                                                    "critical": stats.critical, "high": stats.high}})

    def maybe_update_iocs(self):
        if not self.cfg.ioc_update:
            return
        if time.time() - last_check(self.data_dir) < self.cfg.ioc_update_interval:
            return
        updated, msg = update_iocs(self.data_dir, self.iocs.version, self.cfg.ioc_update_url)
        self.log(f"ioc update: {msg}")
        if updated:
            self.iocs = iocmod.load(self.data_dir)
            self.protector.iocs = self.iocs

    # ── main loop ────────────────────────────────────────────────────────────
    def run(self) -> int:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._stop)
            except Exception:
                pass
        self.log(f"guard v{VERSION} starting (iocs {self.iocs.version}, auto_kill={self.cfg.auto_kill}, "
                 f"auto_clean={self.cfg.auto_clean}, dry_run={self.dry_run})")
        try:
            self.maybe_update_iocs()
            self.full_pass()
        except Exception:
            self.log("full pass error:\n" + traceback.format_exc())
        if self.once:
            return 0
        next_quick = time.time() + self.cfg.quick_interval
        while self.running:
            time.sleep(1)
            now = time.time()
            if now < next_quick:
                continue
            next_quick = now + self.cfg.quick_interval
            try:
                if now - self.last_full >= self.cfg.full_interval:
                    self.maybe_update_iocs()
                    self.full_pass()
                else:
                    self.quick_pass()
            except Exception:
                self.log("pass error:\n" + traceback.format_exc())
        self.log("guard stopped")
        return 0


def heartbeat_status(data_dir: Path) -> dict:
    p = data_dir / "guard" / "heartbeat.json"
    try:
        hb = json.loads(p.read_text(encoding="utf-8"))
        hb["age_seconds"] = int(time.time() - hb.get("ts", 0))
        hb["alive"] = hb["age_seconds"] < 600
        return hb
    except Exception:
        return {"alive": False}

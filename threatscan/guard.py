"""Background guard: continuous detection + response.

Three cadences (all configurable in config.json):
  quick  (60 s)   processes + C2 sockets + tracked files whose mtime changed
  full   (6 h)    complete repository sweep + host persistence checks
  iocs   (24 h)   refresh indicators from the project repository

State lives in <data_dir>/guard/ : heartbeat.json, seen.json (alert dedup).
"""

import json
import os
import queue
import signal
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Dict, List

from . import VERSION, iocs as iocmod
from .config import Config
from .findings import Finding, ScanStats, Severity
from .notify import Notifier
from .protect import Protector
from . import prompt
from .helpers import ASSET_MAGIC, SCRIPT_EXTENSIONS, TEXT_ASSET_EXTENSIONS, is_under, skip_dir
from .realtime import Watcher
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
        self.watcher = None
        self._dialogs: "queue.Queue" = queue.Queue()
        self._dialog_thread = None

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
              "iocs": self.iocs.version, "last_full": self.last_full, "repos": len(self.repos),
              "realtime": self.watcher.backend if self.watcher else "off", "action": self.cfg.action}
        if extra:
            hb.update(extra)
        self._save_json(self.state_dir / "heartbeat.json", hb)

    def _stop(self, *_):
        self.running = False

    # ── discovery ────────────────────────────────────────────────────────────
    def refresh_targets(self, discovered=None):
        """discovered: {root: (repos, projects)} from a full pass, to avoid a second walk."""
        repos = []
        if discovered is None:
            discovered = {}
            for r in self.cfg.roots(self.plat):
                rs = RepoScanner(r, self.ui, self.iocs, exclude=self.cfg.exclude, deep=self.cfg.deep)
                discovered[r] = rs.discover()
        for r, (rp, pj) in discovered.items():
            repos += rp + [p for p in pj if p not in rp]
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
    def decide(self, f: Finding, action_word: str) -> str:
        """Before-action dialog (policy "ask")."""
        if not self.cfg.prompt:
            return prompt.UNAVAILABLE
        self.log(f"asking user about {f.path} ({action_word})")
        verdict = prompt.ask(self.plat, f, action_word, timeout=self.cfg.prompt_timeout)
        self.log(f"user decision for {f.path}: {verdict}")
        return verdict

    def _after_quarantine(self, f: Finding):
        """Defender-style follow-up: file is already quarantined; Remove or Restore & allow."""
        verdict = prompt.ask_quarantined(self.plat, f, timeout=self.cfg.prompt_timeout)
        self.log(f"post-quarantine decision for {f.path}: {verdict}")
        if verdict == prompt.DELETE:
            n = self.protector.purge(f.path)
            self.log(f"removed {n} quarantined cop(ies) of {f.path}")
        elif verdict == prompt.KEEP:
            if self.protector.restore(f.path):
                self.protector.remember(f, prompt.KEEP)
                self.log(f"restored and allowed {f.path}")
        # timeout / unavailable: stays in quarantine (threatscan history to review)

    def _dialog_worker(self):
        while self.running:
            try:
                f = self._dialogs.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._after_quarantine(f)
            except Exception:
                self.log("dialog error:\n" + traceback.format_exc())

    def _queue_dialog(self, f: Finding):
        if not self.cfg.prompt:
            return
        if self._dialog_thread is None or not self._dialog_thread.is_alive():
            self._dialog_thread = threading.Thread(target=self._dialog_worker, name="threatscan-dialogs", daemon=True)
            self._dialog_thread.start()
        self._dialogs.put(f)

    def handle(self, findings: List[Finding], context: str):
        """Apply the configured policy, alert, and record."""
        if not findings:
            return
        policy = (self.cfg.action or "quarantine").lower()
        if policy == "ask":
            acted = self.protector.respond(findings, auto_kill=self.cfg.auto_kill, auto_clean=self.cfg.auto_clean,
                                           decide=self.decide)
        elif policy == "delete":
            acted = self.protector.respond(findings, auto_kill=self.cfg.auto_kill, auto_clean=True,
                                           decide=lambda f, w: prompt.DELETE)
        elif policy == "report":
            acted = self.protector.respond(findings, auto_kill=self.cfg.auto_kill, auto_clean=False)
        else:  # quarantine: act first (reversible), then let the user decide
            acted = self.protector.respond(findings, auto_kill=self.cfg.auto_kill, auto_clean=True)
        now = time.time()
        fresh = []
        for f in findings:
            if f.action.startswith("kept"):
                self.seen[f.key] = now      # user saw it; do not nag
                continue
            # Re-alert on the same finding at most once per 6 hours, always alert actions.
            if f.action or now - self.seen.get(f.key, 0) > 6 * 3600:
                fresh.append(f)
                self.seen[f.key] = now
        for k in [k for k, t in self.seen.items() if now - t > 7 * 86400]:
            del self.seen[k]
        self._save_json(self.state_dir / "seen.json", self.seen)
        for f in findings:
            self.log(f"[{f.severity.name}] {f.title} {f.path or ''} {('-> ' + f.action) if f.action else ''}")
        if any(f.severity >= Severity.HIGH for f in fresh):
            self.notifier.alert([f for f in fresh if f.severity >= Severity.WARNING], context=context)
        if acted:
            self.log(f"responded to {len(acted)} finding(s)")
        if policy == "quarantine":
            for f in acted:
                if f.path and f.category not in ("malicious_process", "c2_connection") \
                        and (f.meta.get("quarantine") or f.meta.get("cleanable") or f.meta.get("mid_file_injection")):
                    self._queue_dialog(f)

    # ── real-time ────────────────────────────────────────────────────────────
    def _watch_skip(self, name: str) -> bool:
        if self.cfg.deep and name in ("node_modules", "vendor"):
            return False
        return skip_dir(name)

    def _interesting(self, p: Path) -> bool:
        if is_under(p, [self.data_dir]) or is_under(p, self.cfg.exclude):
            return False
        name = p.name
        if name in ("tasks.json", "settings.json") and p.parent.name == ".vscode":
            return True
        if name in self.iocs.propagation_scripts or name in self.iocs.fake_font_names:
            return True
        ext = p.suffix.lower()
        return ext in SCRIPT_EXTENSIONS or ext in ASSET_MAGIC or ext in TEXT_ASSET_EXTENSIONS

    def on_fs_events(self, paths):
        rs = RepoScanner(Path.home(), self.ui, self.iocs, exclude=self.cfg.exclude, deep=self.cfg.deep)
        findings: List[Finding] = []
        n = 0
        for p in paths:
            try:
                if not p.is_file() or not self._interesting(p):
                    continue
                if p.stat().st_size > 8 * 1024 * 1024:
                    continue
            except OSError:
                continue
            n += 1
            findings += rs.scan_file(p)
            self.mtimes[str(p)] = p.stat().st_mtime if p.exists() else 0
        if findings:
            self.log(f"realtime: {n} file(s) scanned, {len(findings)} finding(s)")
        self.handle(findings, "realtime")

    def start_realtime(self):
        if not self.cfg.realtime or self.watcher is not None:
            return
        roots = self.cfg.roots(self.plat)
        if not roots:
            return
        self.watcher = Watcher(roots, skip=self._watch_skip, on_events=self.on_fs_events, log=self.log)
        self.watcher.start()

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
        findings: List[Finding] = []
        repos_total = infected = files = 0
        discovered = {}
        for root in self.cfg.roots(self.plat):
            rs = RepoScanner(root, self.ui, self.iocs, js_all=self.cfg.js_all, exclude=self.cfg.exclude,
                             deep=self.cfg.deep)
            discovered[root] = rs.discover()
            fs, total, inf = rs.scan_all(*discovered[root])
            findings += fs
            repos_total += total
            infected += inf
            files += rs.files_checked
        self.refresh_targets(discovered)
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
                 f"auto_clean={self.cfg.auto_clean}, prompt={self.cfg.prompt}, deep={self.cfg.deep}, dry_run={self.dry_run})")
        try:
            self.maybe_update_iocs()
            self.full_pass()
        except Exception:
            self.log("full pass error:\n" + traceback.format_exc())
        if self.once:
            return 0
        try:
            self.start_realtime()
        except Exception:
            self.log("realtime start error:\n" + traceback.format_exc())
        quick = max(self.cfg.quick_interval, 15 if self.plat.is_windows else 2)
        next_quick = time.time() + quick
        while self.running:
            time.sleep(1)
            now = time.time()
            if now < next_quick:
                continue
            next_quick = now + quick
            try:
                if now - self.last_full >= self.cfg.full_interval:
                    self.maybe_update_iocs()
                    self.full_pass()
                else:
                    self.quick_pass()
            except Exception:
                self.log("pass error:\n" + traceback.format_exc())
        if self.watcher:
            self.watcher.stop()
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

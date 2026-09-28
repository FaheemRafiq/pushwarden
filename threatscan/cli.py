"""Command-line interface."""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import List

from . import IOC_UPDATE_URL, REPO_URL, VERSION, iocs as iocmod
from .config import Config
from .findings import Finding, ScanStats, Severity
from .hardening import EDITOR_SETTINGS, editor_status, harden_editor, harden_npm, install_pre_commit, unharden_npm
from .helpers import read_text
from .notify import Notifier
from . import prompt
from .platform_info import PlatformInfo
from .protect import NetBlocker, Protector
from .report import report_dict, write_report
from .scanner import RepoScanner, SystemScanner
from .service import ServiceManager
from .ui import TerminalUI
from .updater import update_iocs


def _ctx(args):
    plat = PlatformInfo()
    data_dir = plat.data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    return plat, data_dir, Config.load(data_dir), iocmod.load(data_dir)


# ═══════════════════════════════════════════════════════════════════════════════
# scan
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_scan(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI(ci=args.ci)
    start = time.time()
    start_str = time.strftime("%Y-%m-%d %H:%M:%S")

    dirs: List[Path] = []
    for d in args.directories:
        p = Path(d).expanduser()
        if not p.is_dir():
            ui.err(f"Not a directory: {d}")
            return 2
        dirs.append(p.resolve())
    if args.home:
        dirs += [d for d in cfg.roots(plat) if d not in dirs]
    if not dirs and not args.no_repos:
        dirs = [Path.cwd()]

    if not args.ci:
        ui.banner(iocs.version)
        ui.system_info(plat, dirs, start_str, iocs.ci_evasion_hostnames)

    all_findings: List[Finding] = []
    repos_total = repos_infected = files_checked = 0
    if not args.no_repos:
        ui.section("REPOSITORY SCAN")
        for d in dirs:
            rs = RepoScanner(d, ui, iocs, js_all=not args.configs_only, verbose=args.verbose,
                             exclude=cfg.exclude, deep=args.deep)
            fs, total, infected = rs.scan_all()
            all_findings += fs
            repos_total += total
            repos_infected += infected
            files_checked += rs.files_checked
        if repos_total and not repos_infected:
            ui.ok(f"{repos_total} repositories scanned, none infected")

    if not args.no_system:
        ui.section("SYSTEM SCAN")
        ss = SystemScanner(plat, ui, iocs, verbose=args.verbose)
        sysf = ss.scan_all(repo_infected=repos_infected > 0)
        for x in sysf:
            if x.severity >= Severity.WARNING or args.verbose:
                ui.finding(x)
        if not any(x.severity >= Severity.HIGH for x in sysf):
            ui.ok("No malicious processes, C2 connections, or RAT persistence found")
        all_findings += sysf

    strong = [f for f in all_findings if Protector.needs_decision(f)]
    interactive = (not args.ci and not args.no_prompt and not args.fix
                   and (args.gui or (sys.stdin and sys.stdin.isatty())))
    if args.fix or args.dry_run or (interactive and strong):
        ui.section("RESPONSE" + (" (dry run)" if args.dry_run else ""))
        prot = Protector(plat, iocs, data_dir, ui=ui, dry_run=args.dry_run)
        if args.fix or args.dry_run:
            decide = None                       # --fix: act without asking (reversible: quarantine/strip)
        elif args.gui:
            decide = lambda f, w: prompt.ask(plat, f, w, timeout=cfg.prompt_timeout)
        else:
            decide = lambda f, w: prompt.ask_terminal(f, w)
        acted = prot.respond(all_findings, auto_kill=cfg.auto_kill, auto_clean=args.fix or args.dry_run, decide=decide)
        for f in all_findings:
            if f.action:
                ui.finding(f)
        if not acted:
            ui.info("Nothing was changed.")
        else:
            ui.info(f"Quarantine index: {prot.index}   (undo: threatscan restore <path>)")

    stats = ScanStats.from_findings(
        all_findings, repos_scanned=repos_total, repos_infected=repos_infected, files_checked=files_checked,
        scan_duration=time.time() - start, platform_name=plat.display_name,
        scan_dirs=[str(d) for d in dirs], start_time=start_str, hostname=plat.hostname)

    ui.summary(stats)
    if not args.ci:
        ui.remediation(all_findings)

    if args.json:
        try:
            Path(args.json).write_text(json.dumps(report_dict(stats, all_findings, iocs.version), indent=2))
            ui.info(f"JSON report written to {args.json}")
        except Exception as e:
            ui.err(f"Could not write JSON: {e}")
            return 2
    if not args.no_report:
        write_report(data_dir, stats, all_findings, iocs.version, keep=cfg.report_keep)
    if args.notify and any(f.severity >= Severity.HIGH for f in all_findings):
        Notifier(plat, cfg, data_dir).alert([f for f in all_findings if f.severity >= Severity.WARNING], "scan")

    if stats.critical or stats.high:
        return 1
    if args.no_system and not repos_total:
        ui.err("Nothing was scanned: no git repositories or projects found.")
        return 2
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# guard / service
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_guard(args) -> int:
    from .guard import Guard
    plat, data_dir, cfg, iocs = _ctx(args)
    g = Guard(plat, data_dir, once=args.once, dry_run=args.dry_run, verbose=args.verbose)
    return g.run()


def cmd_install(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    ui.banner(iocs.version)
    changed = False
    if args.roots:
        cfg.scan_roots = [str(Path(r).expanduser()) for r in args.roots]
        changed = True
    if args.webhook is not None:
        cfg.webhook_url = args.webhook
        changed = True
    if args.no_kill:
        cfg.auto_kill = False
        changed = True
    if args.no_clean:
        cfg.auto_clean = False
        changed = True
    if args.no_prompt:
        cfg.prompt = False
        changed = True
    if args.deep:
        cfg.deep = True
        changed = True
    if args.full_interval:
        cfg.full_interval = args.full_interval
        changed = True
    if args.dry_run:
        ui.info(f"[dry-run] config would be saved to {data_dir / 'config.json'}")
    else:
        p = cfg.save(data_dir)
        ui.info(f"Config: {p}" + (" (updated)" if changed else ""))
    roots = cfg.roots(plat)
    ui.info("Guard will sweep: " + (", ".join(str(r) for r in roots) or "(no project dirs found; set with --roots)"))

    if not args.no_harden:
        ui.section("HARDENING")
        _do_harden(plat, ui, npm=args.npm_ignore_scripts, dry_run=args.dry_run)

    ui.section("BACKGROUND GUARD")
    sm = ServiceManager(plat, data_dir, ui)
    ok, msg = sm.install(dry_run=args.dry_run)
    (ui.ok if ok else ui.err)(msg)
    if not ok:
        ui.warn("You can still run the guard in a terminal:  threatscan guard")

    if args.block_c2:
        ui.section("NETWORK BLOCKING")
        if plat.is_admin():
            nb = NetBlocker(plat, iocs, ui)
            nb.block_ips()
            nb.sinkhole_hosts()
        else:
            ui.warn("Not running as root/Administrator; skip. Later:  sudo threatscan protect --block-c2")

    ui.section("FIRST SCAN")
    ui.info("Running the first full scan now (this may take a minute)...")
    ns = argparse.Namespace(directories=[], home=True, no_repos=False, no_system=False, configs_only=False,
                            deep=cfg.deep, verbose=False, ci=False, json=None, gui=not sys.stdin.isatty(),
                            no_prompt=args.dry_run, fix=False, dry_run=args.dry_run,
                            no_report=args.dry_run, notify=not args.dry_run)
    rc = cmd_scan(ns)
    ui.info(f"Status any time:  threatscan status      Logs: {data_dir / 'guard.log'}")
    return 0 if ok else 1


def cmd_uninstall(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    ok, msg = ServiceManager(plat, data_dir, ui).uninstall()
    (ui.ok if ok else ui.err)(msg)
    if args.unblock:
        nb = NetBlocker(plat, iocs, ui)
        nb.unblock_ips()
        nb.unsinkhole_hosts()
    if args.purge:
        import shutil
        shutil.rmtree(data_dir, ignore_errors=True)
        ui.ok(f"Removed {data_dir} (config, reports, quarantine)")
    else:
        ui.info(f"Kept {data_dir} (quarantine, reports). Remove with --purge.")
    return 0 if ok else 1


def cmd_status(args) -> int:
    from .guard import heartbeat_status
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    ui.banner(iocs.version)
    sm = ServiceManager(plat, data_dir, ui)
    hb = heartbeat_status(data_dir)
    rows = [
        ("Service", sm.status()),
        ("Guard heartbeat", ("alive, " + hb.get("phase", "") + f", {hb.get('age_seconds', '?')}s ago") if hb.get("alive") else "not running"),
        ("Last full sweep", time.strftime("%Y-%m-%d %H:%M", time.localtime(hb["last_full"])) if hb.get("last_full") else "never"),
        ("Repos tracked", str(hb.get("repos", "?"))),
        ("Indicators", f"{iocs.version} ({iocs.source})"),
        ("Auto-kill / prompt / fallback-clean", f"{cfg.auto_kill} / {cfg.prompt} / {cfg.auto_clean}"),
        ("Webhook", "configured" if cfg.webhook_url else "none"),
        ("Firewall", NetBlocker(plat, iocs).status()),
        ("Data dir", str(data_dir)),
    ]
    for k, v in rows:
        print(f"  {ui.c('BOLD_CYAN', k + ':'):<32} {v}")
    latest = data_dir / "reports" / "latest.json"
    if latest.is_file():
        try:
            r = json.loads(latest.read_text(encoding="utf-8"))
            s = r["stats"]
            print(f"\n  Latest report ({r.get('generated')}): {s['repos_scanned']} repos, "
                  f"{s['critical']} critical, {s['high']} high, {s['warning']} warning")
            for f in r["findings"]:
                if f["severity"] in ("CRITICAL", "HIGH"):
                    print(f"    [{f['severity']}] {f['title']}  {f.get('path') or ''}  {f.get('action') or ''}")
        except Exception:
            pass
    print("\n  Editor hardening:")
    for label, sp in plat.editor_settings_files().items():
        st = editor_status(sp)
        val = st.get("task.allowAutomaticTasks", "<unset>") if st else "<no settings.json>"
        mark = "OK " if val == "off" else "!! "
        print(f"    {mark}{label:<18} task.allowAutomaticTasks = {val}")
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# harden / protect / restore / update
# ═══════════════════════════════════════════════════════════════════════════════

def _do_harden(plat, ui, npm=False, dry_run=False):
    editors = plat.editor_settings_files()
    if not editors:
        ui.info("No VS Code-family editor found (VS Code, Cursor, VSCodium, Windsurf).")
    for label, sp in editors.items():
        changed, notes = harden_editor(sp, dry_run=dry_run)
        if changed:
            ui.ok(f"{label}: {'would update' if dry_run else 'updated'} {sp}")
            for n in notes:
                ui.info("   " + n)
        elif notes:
            ui.warn(f"{label}: {notes[0]}")
        else:
            ui.ok(f"{label}: already hardened")
    if npm:
        changed, msg = harden_npm(plat.home, dry_run=dry_run)
        (ui.ok if changed else ui.info)(f"npm: {msg}")
    else:
        ui.info("npm: ignore-scripts not changed (opt in with --npm-ignore-scripts)")


def cmd_harden(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    if args.undo_npm:
        ui.ok("npm ignore-scripts removed" if unharden_npm(plat.home) else "npm ignore-scripts was not set")
        return 0
    _do_harden(plat, ui, npm=args.npm_ignore_scripts, dry_run=args.dry_run)
    if args.pre_commit:
        for r in args.pre_commit:
            ok, msg = install_pre_commit(Path(r).expanduser(), dry_run=args.dry_run)
            (ui.ok if ok else ui.warn)(f"{r}: {msg}")
    return 0


def cmd_protect(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    nb = NetBlocker(plat, iocs, ui)
    if args.status:
        ui.info(f"Firewall: {nb.status()}")
        return 0
    if args.unblock:
        nb.unblock_ips()
        nb.unsinkhole_hosts()
        return 0
    if not plat.is_admin():
        ui.err("Network blocking needs root/Administrator.  Linux/macOS: sudo threatscan protect --block-c2   Windows: run an elevated PowerShell.")
        return 2
    ok = nb.block_ips()
    ok2 = nb.sinkhole_hosts()
    return 0 if (ok or ok2) else 1


def cmd_restore(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    prot = Protector(plat, iocs, data_dir, ui=ui)
    if args.list or not args.path:
        entries = prot.entries()
        if not entries:
            ui.info("Quarantine is empty.")
            return 0
        for e in entries[-50:]:
            print(f"  {e.get('ts')}  {e.get('type'):<10} {e.get('original') or e.get('pid') or e.get('name') or ''}"
                  f"{'  (' + str(e.get('removed_bytes')) + ' bytes removed)' if e.get('removed_bytes') else ''}")
        return 0
    if prot.restore(args.path):
        ui.ok(f"Restored {args.path}. It is malicious as far as the scanner knows: re-scan before use.")
        return 0
    ui.err(f"No quarantine entry for {args.path}")
    return 1


def cmd_history(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    prot = Protector(plat, iocs, data_dir, ui=ui)
    if args.restore:
        ok = prot.restore(args.restore)
        (ui.ok if ok else ui.err)(("Restored " if ok else "No quarantine entry for ") + args.restore)
        return 0 if ok else 1
    if args.allow:
        ok = prot.restore(args.allow)
        if not ok:
            ui.err(f"No quarantine entry for {args.allow}")
            return 1
        from .findings import Finding
        prot.remember(Finding(Severity.CRITICAL, "user_allow", "allowed by user", args.allow), prompt.KEEP)
        ui.ok(f"Restored and allowed {args.allow} (this exact content will not be flagged again for 30 days)")
        return 0
    if args.remove:
        n = prot.purge(args.remove)
        (ui.ok if n else ui.err)(f"Removed {n} quarantined cop{'y' if n == 1 else 'ies'} of {args.remove}")
        return 0 if n else 1
    entries = prot.entries()
    if not entries:
        ui.info("Protection history is empty.")
        return 0
    print(f"  {'when':<19} {'action':<11} {'threat':<38} path")
    for e in entries[-int(args.limit):]:
        label = e.get("threat") or e.get("title") or ""
        target = e.get("original") or (f"pid {e.get('pid')}" if e.get("pid") else e.get("name") or e.get("line") or "")
        extra = f"  ({e['removed_bytes']} bytes stripped)" if e.get("removed_bytes") else ""
        extra += "  [dry-run]" if e.get("dry_run") else ""
        print(f"  {e.get('ts', ''):<19} {e.get('type', ''):<11} {label[:38]:<38} {target}{extra}")
    print("\n  threatscan history --restore <path> | --allow <path> | --remove <path>")
    return 0


def cmd_update_iocs(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    updated, msg = update_iocs(data_dir, iocs.version, args.url or cfg.ioc_update_url)
    (ui.ok if updated else ui.info)(msg)
    return 0


def cmd_config(args) -> int:
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI()
    if args.set:
        for kv in args.set:
            if "=" not in kv:
                ui.err(f"expected key=value, got {kv}")
                return 2
            k, v = kv.split("=", 1)
            if not hasattr(cfg, k):
                ui.err(f"unknown key {k}")
                return 2
            cur = getattr(cfg, k)
            if isinstance(cur, bool):
                v = v.lower() in ("1", "true", "yes", "on")
            elif isinstance(cur, int):
                v = int(v)
            elif isinstance(cur, list):
                v = [x for x in v.split(",") if x]
            setattr(cfg, k, v)
        cfg.save(data_dir)
        ui.ok("config saved")
    print(json.dumps(cfg.__dict__, indent=2))
    return 0


def cmd_check_staged(args) -> int:
    """Pre-commit helper: scan files staged in the current repo."""
    plat, data_dir, cfg, iocs = _ctx(args)
    ui = TerminalUI(ci=True)
    try:
        out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception as e:
        ui.err(f"git failed: {e}")
        return 0
    rs = RepoScanner(Path.cwd(), ui, iocs)
    bad = []
    for name in out.split("\n"):
        if not name.strip():
            continue
        p = Path(name)
        fs = rs.scan_file(p) if p.is_file() else []
        bad += [f for f in fs if f.severity >= Severity.HIGH]
    for f in bad:
        ui.finding(f)
    if bad:
        ui.err("Commit blocked: PolinRider indicators in staged files.")
        return 1
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# parser
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="threatscan",
        description="ThreatScan: detect, remove and block the PolinRider / Contagious Interview supply-chain malware.",
        epilog=f"Docs: {REPO_URL}")
    ap.add_argument("--version", action="version", version=f"ThreatScan {VERSION}")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="one-off scan (default command)")
    s.add_argument("directories", nargs="*", help="directories to scan (default: cwd)")
    s.add_argument("--home", action="store_true", help="also scan common project dirs under $HOME")
    s.add_argument("--verbose", action="store_true")
    s.add_argument("--configs-only", action="store_true", help="only check known config/entry files (faster, v4 behaviour)")
    s.add_argument("--js-all", action="store_true", help=argparse.SUPPRESS)  # v4 compat, now the default
    s.add_argument("--deep", action="store_true", help="also descend into node_modules / vendor")
    s.add_argument("--no-system", action="store_true", help="skip host checks")
    s.add_argument("--no-repos", action="store_true", help="skip repository checks")
    s.add_argument("--json", metavar="FILE", help="write JSON report")
    s.add_argument("--ci", action="store_true", help="CI mode (no colour, compact)")
    s.add_argument("--fix", action="store_true", help="act on CRITICAL findings without asking (reversible: quarantine/strip)")
    s.add_argument("--dry-run", action="store_true", help="show what --fix would do")
    s.add_argument("--gui", action="store_true", help="ask about each malicious file with a native dialog instead of the terminal")
    s.add_argument("--no-prompt", action="store_true", help="report only; never ask, never change files")
    s.add_argument("--notify", action="store_true", help="send desktop/webhook alert on HIGH+")
    s.add_argument("--no-report", action="store_true", help="do not save a report under ~/.threatscan/reports")
    s.set_defaults(func=cmd_scan)

    g = sub.add_parser("guard", help="run the continuous guard in the foreground")
    g.add_argument("--once", action="store_true", help="one full pass then exit")
    g.add_argument("--dry-run", action="store_true", help="detect and alert but never kill/quarantine")
    g.add_argument("--verbose", action="store_true")
    g.set_defaults(func=cmd_guard)

    i = sub.add_parser("install", help="harden editors, install the background guard, run first scan")
    i.add_argument("--roots", nargs="*", help="project directories to watch (default: auto-discover)")
    i.add_argument("--webhook", help="URL that receives JSON alerts (Slack/Discord/Teams/custom)")
    i.add_argument("--no-kill", action="store_true", help="never kill processes automatically")
    i.add_argument("--no-clean", action="store_true", help="when no dialog can be shown, leave files in place instead of quarantining")
    i.add_argument("--no-prompt", action="store_true", help="never show dialogs; rely on auto-clean (quarantine) only")
    i.add_argument("--deep", action="store_true", help="guard also scans node_modules / vendor (slow)")
    i.add_argument("--no-harden", action="store_true", help="skip editor hardening")
    i.add_argument("--npm-ignore-scripts", action="store_true", help="also set ignore-scripts=true in ~/.npmrc")
    i.add_argument("--block-c2", action="store_true", help="also add firewall + hosts blocks (needs admin)")
    i.add_argument("--full-interval", type=int, help="seconds between full sweeps (default 21600)")
    i.add_argument("--dry-run", action="store_true")
    i.set_defaults(func=cmd_install)

    u = sub.add_parser("uninstall", help="remove the background guard")
    u.add_argument("--unblock", action="store_true", help="also remove firewall/hosts blocks")
    u.add_argument("--purge", action="store_true", help="also delete ~/.threatscan")
    u.set_defaults(func=cmd_uninstall)

    st = sub.add_parser("status", help="guard, hardening and last report status")
    st.set_defaults(func=cmd_status)

    h = sub.add_parser("harden", help="apply preventive settings")
    h.add_argument("--npm-ignore-scripts", action="store_true")
    h.add_argument("--undo-npm", action="store_true")
    h.add_argument("--pre-commit", nargs="*", metavar="REPO", help="install a pre-commit hook in these repos")
    h.add_argument("--dry-run", action="store_true")
    h.set_defaults(func=cmd_harden)

    p = sub.add_parser("protect", help="block C2 IPs at the firewall and sinkhole C2 hosts (admin)")
    p.add_argument("--block-c2", action="store_true", default=True)
    p.add_argument("--unblock", action="store_true")
    p.add_argument("--status", action="store_true")
    p.set_defaults(func=cmd_protect)

    hi = sub.add_parser("history", help="protection history: what was quarantined/removed; restore, allow or purge")
    hi.add_argument("--restore", metavar="PATH", help="put the original back (it is still malicious)")
    hi.add_argument("--allow", metavar="PATH", help="restore and stop flagging this exact file content")
    hi.add_argument("--remove", metavar="PATH", help="delete the quarantined copies permanently")
    hi.add_argument("--limit", default=50)
    hi.set_defaults(func=cmd_history)

    r = sub.add_parser("restore", help="alias for history --restore")
    r.add_argument("path", nargs="?")
    r.add_argument("--list", action="store_true")
    r.set_defaults(func=cmd_restore)

    up = sub.add_parser("update-iocs", help="download the latest indicator file")
    up.add_argument("--url", default="")
    up.set_defaults(func=cmd_update_iocs)

    c = sub.add_parser("config", help="show or set guard configuration")
    c.add_argument("--set", nargs="*", metavar="KEY=VALUE")
    c.set_defaults(func=cmd_config)

    cs = sub.add_parser("check-staged", help="pre-commit hook helper")
    cs.set_defaults(func=cmd_check_staged)
    return ap


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = build_parser()
    known = {"scan", "guard", "install", "uninstall", "status", "harden", "protect", "restore", "history",
             "update-iocs", "config", "check-staged", "-h", "--help", "--version"}
    # Backwards compatible: `threatscan [opts] [dirs]` means `threatscan scan ...`
    if not argv or argv[0] not in known:
        argv = ["scan"] + argv
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 2

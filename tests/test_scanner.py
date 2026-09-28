# threatscan:allow-signatures
import json
import time
from pathlib import Path

from threatscan import iocs as iocmod
from threatscan.findings import Severity
from threatscan.helpers import asset_verdict, find_payload_cut
from threatscan.platform_info import PlatformInfo
from threatscan.protect import Protector
from threatscan.scanner import RepoScanner
from threatscan.ui import TerminalUI

from conftest import CLEAN_POSTCSS, INFECTED_POSTCSS, FAKE_WOFF2


def _iocs():
    return iocmod.load()


def _ui():
    return TerminalUI(ci=True, quiet=True)


def test_iocs_load_and_validate():
    I = _iocs()
    assert I.version >= "2026.09.28"
    assert "fa-solid-900.woff2" in I.fake_font_names
    assert "default-configuration.vercel.app" in I.malicious_hosts
    assert I.marker_regex.search("global['_V']='8-st17'")
    assert I.marker_regex.search("global['!']='A10-010'")
    assert I.marker_regex.search('global["_V"] = "9-10094"')
    assert not I.marker_regex.search("const globalThis = {}; module.exports = {}")


def test_asset_verdict_padding_and_magic(tmp_path):
    I = _iocs()
    real = tmp_path / "a.woff2"
    real.write_bytes(b"wOF2" + b"\x00" * 50)
    assert asset_verdict(real, I.marker_regex)[0] == "real"
    fake = tmp_path / "fa-solid-900.woff2"
    fake.write_bytes(b" " * 300 + b"var x = require('y');")
    v, d = asset_verdict(fake, I.marker_regex)
    assert v == "code" and "padding" in d
    nopad = tmp_path / "b.woff2"
    nopad.write_bytes(b"const a = () => 1;")
    assert asset_verdict(nopad, I.marker_regex)[0] == "code"


def test_payload_cut_keeps_legit_config():
    I = _iocs()
    cut = find_payload_cut(INFECTED_POSTCSS, I)
    assert cut > 0
    assert INFECTED_POSTCSS[:cut].rstrip() == CLEAN_POSTCSS.rstrip()
    assert find_payload_cut(CLEAN_POSTCSS, I) == -1


def test_infected_repo_findings(infected_repo):
    rs = RepoScanner(infected_repo.parent, _ui(), _iocs())
    findings, total, infected = rs.scan_all()
    assert total == 1 and infected == 1
    cats = {f.category for f in findings}
    assert {"config_injection", "fake_font_loader", "vscode_autorun", "propagation_script",
            "gitignore_tampering", "compromised_package"} <= cats
    tasks = [f for f in findings if f.category == "vscode_autorun"][0]
    assert tasks.severity == Severity.CRITICAL and tasks.meta.get("quarantine")
    assert all(f.severity == Severity.CRITICAL for f in findings if f.category == "compromised_package")


def test_clean_repo_no_high(clean_repo):
    rs = RepoScanner(clean_repo.parent, _ui(), _iocs())
    findings, total, infected = rs.scan_all()
    assert total == 1 and infected == 0
    assert not [f for f in findings if f.severity >= Severity.HIGH]


def test_scan_file_quick_path(infected_repo):
    rs = RepoScanner(infected_repo, _ui(), _iocs())
    f = rs.scan_file(infected_repo / "postcss.config.mjs")
    assert any(x.category == "config_injection" for x in f)
    f = rs.scan_file(infected_repo / "public" / "fonts" / "fa-solid-900.woff2")
    assert f and f[0].severity == Severity.CRITICAL
    f = rs.scan_file(infected_repo / ".vscode" / "tasks.json")
    assert f and f[0].category == "vscode_autorun"


def test_protector_clean_quarantine_restore(infected_repo, home):
    plat = PlatformInfo()
    I = _iocs()
    rs = RepoScanner(infected_repo.parent, _ui(), I)
    findings, _, _ = rs.scan_all()
    prot = Protector(plat, I, home, dry_run=False)
    acted = prot.respond(findings, auto_kill=False, auto_clean=True)
    assert acted
    # config stripped, legit content intact
    cfg = (infected_repo / "postcss.config.mjs").read_text()
    assert "global['_V']" not in cfg and "@tailwindcss/postcss" in cfg
    # loader, tasks.json and .bat gone
    assert not (infected_repo / "public" / "fonts" / "fa-solid-900.woff2").exists()
    assert not (infected_repo / ".vscode" / "tasks.json").exists()
    assert not (infected_repo / "temp_auto_push.bat").exists()
    # rescanned: no more CRITICAL in files
    again, _, inf = RepoScanner(infected_repo.parent, _ui(), I).scan_all()
    assert not [f for f in again if f.category in ("config_injection", "fake_font_loader", "propagation_script")]
    # index + restore
    entries = prot.entries()
    assert any(e["type"] == "clean" for e in entries) and any(e["type"] == "quarantine" for e in entries)
    assert prot.restore(str(infected_repo / "postcss.config.mjs"))
    assert "global['_V']" in (infected_repo / "postcss.config.mjs").read_text()


def test_protector_dry_run_changes_nothing(infected_repo, home):
    plat = PlatformInfo()
    I = _iocs()
    findings, _, _ = RepoScanner(infected_repo.parent, _ui(), I).scan_all()
    prot = Protector(plat, I, home, dry_run=True)
    acted = prot.respond(findings, auto_kill=False, auto_clean=True)
    assert acted and all("would" in f.action or "quarantined" in f.action or "removed" in f.action for f in acted)
    assert (infected_repo / "temp_auto_push.bat").exists()
    assert "global['_V']" in (infected_repo / "postcss.config.mjs").read_text()


def test_hardening_settings(tmp_path):
    from threatscan.hardening import harden_editor, editor_status
    sp = tmp_path / "User" / "settings.json"
    sp.parent.mkdir()
    sp.write_text('{\n  // comment\n  "editor.fontSize": 14,\n  "task.allowAutomaticTasks": "on",\n}\n')
    changed, notes = harden_editor(sp)
    assert changed
    data = json.loads(sp.read_text())
    assert data["task.allowAutomaticTasks"] == "off" and data["editor.fontSize"] == 14
    assert editor_status(sp)["task.allowAutomaticTasks"] == "off"
    changed, notes = harden_editor(sp)
    assert not changed


def test_guard_once(infected_repo, home, monkeypatch):
    from threatscan.config import Config
    from threatscan.guard import Guard, heartbeat_status
    cfg = Config(scan_roots=[str(infected_repo.parent)], notify_desktop=False, auto_kill=False)
    cfg.save(home)
    plat = PlatformInfo()
    g = Guard(plat, home, once=True, dry_run=False)
    monkeypatch.setattr(g, "maybe_update_iocs", lambda: None)
    assert g.run() == 0
    hb = heartbeat_status(home)
    assert hb["alive"] and hb["repos"] == 1
    latest = json.loads((home / "reports" / "latest.json").read_text())
    assert latest["stats"]["repos_infected"] == 1
    assert not (infected_repo / "temp_auto_push.bat").exists()
    assert (home / "alerts.log").is_file()


def test_cli_scan_exit_codes(infected_repo, clean_repo, home, capsys):
    from threatscan.cli import main
    assert main(["scan", "--ci", "--no-system", "--no-report", str(clean_repo)]) == 0
    assert main(["scan", "--ci", "--no-system", "--no-report", str(infected_repo)]) == 1
    # legacy invocation without subcommand
    assert main(["--ci", "--no-system", "--no-report", str(infected_repo)]) == 1
    out = capsys.readouterr().out
    assert "INFECTIONS DETECTED" in out


def test_service_dry_run(home):
    from threatscan.service import ServiceManager
    plat = PlatformInfo()
    ok, msg = ServiceManager(plat, home).install(dry_run=True)
    assert ok and "guard" in msg


# ── v5.1: evidence, allowlist, decisions, dialogs ────────────────────────────

def test_evidence_and_allowlist(tmp_path):
    from threatscan.helpers import evidence, is_allowlisted, ALLOW_TOKEN
    I = _iocs()
    ev = evidence(INFECTED_POSTCSS, I)
    assert any("campaign marker" in e for e in ev) and any("whitespace" in e for e in ev)
    db = tmp_path / "rules.yaml"
    db.write_text(f"# {ALLOW_TOKEN}\nglobal['_V']='A4-1928'\n")
    assert is_allowlisted(db, I)
    cfg = tmp_path / "postcss.config.mjs"
    cfg.write_text(f"// {ALLOW_TOKEN}\n" + INFECTED_POSTCSS)
    assert not is_allowlisted(cfg, I)          # never for config files
    rs = RepoScanner(tmp_path, _ui(), I)
    assert rs.check_signatures(db) == []
    assert rs.check_signatures(cfg)


def test_all_script_files_scanned_by_default(tmp_path):
    repo = tmp_path / "r"
    (repo / ".git").mkdir(parents=True)
    (repo / "lib").mkdir()
    (repo / "lib" / "helper.js").write_text("module.exports = 1;" + " " * 300 + "global['!']='A10-2340';")
    (repo / "node_modules" / "x").mkdir(parents=True)
    (repo / "node_modules" / "x" / "index.js").write_text("global['_V']='8-st9';")
    I = _iocs()
    f, _, _ = RepoScanner(tmp_path, _ui(), I).scan_all()
    paths = {x.path for x in f}
    assert str(repo / "lib" / "helper.js") in paths
    assert str(repo / "node_modules" / "x" / "index.js") not in paths
    f, _, _ = RepoScanner(tmp_path, _ui(), I, deep=True).scan_all()
    assert str(repo / "node_modules" / "x" / "index.js") in {x.path for x in f}
    f, _, _ = RepoScanner(tmp_path, _ui(), I, js_all=False).scan_all()
    assert not [x for x in f if x.category == "config_injection"]


def test_decision_delete_keep_timeout(infected_repo, home):
    from threatscan.prompt import DELETE, KEEP, TIMEOUT
    plat = PlatformInfo()
    I = _iocs()
    findings, _, _ = RepoScanner(infected_repo.parent, _ui(), I).scan_all()
    asked = []

    def decide(f, word):
        asked.append((Path(f.path).name, word))
        if f.path.endswith("fa-solid-900.woff2"):
            return DELETE
        if f.path.endswith("postcss.config.mjs"):
            return KEEP
        return TIMEOUT

    prot = Protector(plat, I, home)
    acted = prot.respond(findings, auto_kill=False, auto_clean=True, decide=decide)
    words = dict(asked)
    assert words["fa-solid-900.woff2"] == "Delete the file"
    assert words["postcss.config.mjs"] == "Remove payload"
    # delete: gone, no quarantine copy, record kept
    assert not (infected_repo / "public" / "fonts" / "fa-solid-900.woff2").exists()
    assert any(e["type"] == "delete" and e["evidence"] for e in prot.entries())
    # keep: untouched + remembered
    assert "global['_V']" in (infected_repo / "postcss.config.mjs").read_text()
    kept = [f for f in findings if f.path.endswith("postcss.config.mjs")][0]
    assert kept.action == "kept by user"
    # timeout: reversible fallback (quarantine)
    assert not (infected_repo / "temp_auto_push.bat").exists()
    bat = [f for f in findings if f.path.endswith("temp_auto_push.bat")][0]
    assert bat.action.startswith("no decision (timeout)")
    # second run: kept file is not asked again while unchanged
    asked.clear()
    findings2, _, _ = RepoScanner(infected_repo.parent, _ui(), I).scan_all()
    Protector(plat, I, home).respond(findings2, auto_kill=False, auto_clean=True, decide=decide)
    assert "postcss.config.mjs" not in dict(asked)
    # ... but is asked again once the file changes
    (infected_repo / "postcss.config.mjs").write_text(INFECTED_POSTCSS + "// changed\n")
    findings3, _, _ = RepoScanner(infected_repo.parent, _ui(), I).scan_all()
    Protector(plat, I, home).respond(findings3, auto_kill=False, auto_clean=True, decide=decide)
    assert "postcss.config.mjs" in dict(asked)


def test_prompt_message_and_os_dispatch(monkeypatch, infected_repo):
    from threatscan import prompt
    from threatscan.findings import Finding
    f = Finding(Severity.CRITICAL, "fake_font_loader", "Font file contains code: fa-solid-900.woff2",
                str(infected_repo / "public/fonts/fa-solid-900.woff2"),
                meta={"evidence": ["woff2 extension but content is JavaScript", "campaign marker global['!']"]})
    msg = prompt.build_message(f, "Delete the file")
    assert "Evidence:" in msg and "campaign marker" in msg and "permanently" in msg

    calls = []

    class R:
        def __init__(self, rc, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[0] == "zenity":
            return R(0)
        if cmd[0] == "osascript":
            return R(0, "button returned:Delete the file")
        if cmd[0] == "powershell":
            return R(0, "7\n")
        return R(1)

    monkeypatch.setattr(prompt.subprocess, "run", fake_run)
    monkeypatch.setattr(prompt.shutil, "which", lambda n: "/usr/bin/zenity" if n == "zenity" else None)
    monkeypatch.setenv("DISPLAY", ":0")

    class P:
        is_linux, is_macos, is_windows = True, False, False
    assert prompt.ask(P(), f, "Delete the file", timeout=5) == prompt.DELETE
    assert calls[-1][0] == "zenity" and any(a.startswith("--timeout=5") for a in calls[-1])
    P.is_linux, P.is_macos = False, True
    assert prompt.ask(P(), f, "Delete the file", timeout=5) == prompt.DELETE
    assert calls[-1][0] == "osascript" and "giving up after 5" in calls[-1][2]
    P.is_macos, P.is_windows = False, True
    assert prompt.ask(P(), f, "Delete the file", timeout=5) == prompt.KEEP
    assert calls[-1][0] == "powershell" and "Popup(" in calls[-1][-1]


def test_cli_no_prompt_reports_only(infected_repo, home, capsys):
    from threatscan.cli import main
    rc = main(["scan", "--no-system", "--no-report", "--no-prompt", str(infected_repo)])
    assert rc == 1
    assert (infected_repo / "temp_auto_push.bat").exists()


# ── review fixes ─────────────────────────────────────────────────────────────

def test_jsonc_stripper_keeps_globs(tmp_path):
    from threatscan.hardening import _strip_json_comments, harden_editor
    raw = '{\n  // c\n  "files.exclude": {"**/*.pyc": true, "**/node_modules": true}, /* x */\n  "a": "http://h/*/y",\n}\n'
    d = json.loads(_strip_json_comments(raw))
    assert d["files.exclude"] == {"**/*.pyc": True, "**/node_modules": True} and d["a"] == "http://h/*/y"
    sp = tmp_path / "settings.json"
    sp.write_text(raw)
    harden_editor(sp)
    assert json.loads(sp.read_text())["files.exclude"]["**/*.pyc"] is True


def test_mid_file_injection_is_quarantined_not_truncated(tmp_path, home):
    plat = PlatformInfo()
    I = _iocs()
    repo = tmp_path / "r"
    (repo / ".git").mkdir(parents=True)
    (repo / "src").mkdir()
    body = "(async()=>{eval(atob(process.env.AUTH_API_KEY))})();\n" + "\n".join(f"export const v{i} = {i};" for i in range(50)) + "\n"
    (repo / "src" / "index.js").write_text(body)
    findings, _, _ = RepoScanner(tmp_path, _ui(), I).scan_all()
    prot = Protector(plat, I, home)
    acted = prot.respond(findings, auto_kill=False, auto_clean=True)
    assert acted and not (repo / "src" / "index.js").exists()
    f = acted[0]
    assert "not a trailing append" in f.action and f.meta.get("mid_file_injection")
    assert prot.restore(str(repo / "src" / "index.js"))
    assert (repo / "src" / "index.js").read_text() == body


def test_exclude_is_component_aware(tmp_path):
    from threatscan.helpers import is_under
    assert is_under(tmp_path / "vendor" / "x", [tmp_path / "vendor"])
    assert not is_under(tmp_path / "vendor-tools" / "x", [tmp_path / "vendor"])


def test_install_dry_run_writes_nothing(home, monkeypatch, tmp_path):
    from threatscan.cli import main
    sp = tmp_path / "Code" / "User" / "settings.json"
    sp.parent.mkdir(parents=True)
    sp.write_text('{"task.allowAutomaticTasks": "on"}')
    monkeypatch.setattr(PlatformInfo, "editor_settings_files", lambda self: {"VS Code": sp})
    monkeypatch.setattr(PlatformInfo, "common_project_dirs", lambda self: [])
    main(["install", "--dry-run"])
    assert json.loads(sp.read_text())["task.allowAutomaticTasks"] == "on"
    assert not (home / "config.json").exists()


# ── real-time (Defender-style) ───────────────────────────────────────────────

def test_watcher_detects_new_and_modified_files(tmp_path):
    import threading
    from threatscan.realtime import Watcher
    from threatscan.helpers import skip_dir
    root = tmp_path / "w"
    (root / "proj").mkdir(parents=True)
    (root / "proj" / "node_modules").mkdir()
    got, ev = [], threading.Event()

    def cb(paths):
        got.extend(paths)
        ev.set()
    w = Watcher([root], skip=skip_dir, on_events=cb, poll_interval=0.5)
    w.start()
    time.sleep(1.0)
    (root / "proj" / "postcss.config.mjs").write_text("export default {};")
    assert ev.wait(6), f"no event (backend={w.backend})"
    assert root / "proj" / "postcss.config.mjs" in got
    ev.clear(); got.clear()
    with open(root / "proj" / "postcss.config.mjs", "a") as fh:
        fh.write(" " * 300 + "global['_V']='8-st1';")
    assert ev.wait(6)
    ev.clear(); got.clear()
    (root / "proj" / "newdir" / "public" / "fonts").mkdir(parents=True)
    time.sleep(0.6)
    (root / "proj" / "newdir" / "public" / "fonts" / "fa-solid-900.woff2").write_bytes(b"var x=1;")
    assert ev.wait(6)
    assert any(p.name == "fa-solid-900.woff2" for p in got)
    w.stop()
    assert w.backend in ("inotify", "kqueue", "rdcw", "poll")


def test_guard_realtime_quarantine_then_dialog(tmp_path, home, monkeypatch):
    from threatscan import prompt
    from threatscan.config import Config
    from threatscan.guard import Guard
    root = tmp_path / "root"
    (root / "proj" / ".git").mkdir(parents=True)
    (root / "proj" / "postcss.config.mjs").write_text(CLEAN_POSTCSS)
    Config(scan_roots=[str(root)], notify_desktop=False, auto_kill=False, quick_interval=1).save(home)
    g = Guard(PlatformInfo(), home, once=True)
    monkeypatch.setattr(g, "maybe_update_iocs", lambda: None)
    g.run()
    decisions = {"n": 0}

    def fake_ask_quarantined(plat, f, timeout=180):
        decisions["n"] += 1
        return prompt.DELETE if f.path.endswith(".woff2") else prompt.KEEP
    monkeypatch.setattr(prompt, "ask_quarantined", fake_ask_quarantined)
    g.running = True
    # simulate the watcher delivering events
    (root / "proj" / "postcss.config.mjs").write_text(INFECTED_POSTCSS)
    (root / "proj" / "public" / "fonts").mkdir(parents=True)
    (root / "proj" / "public" / "fonts" / "fa-solid-900.woff2").write_bytes(FAKE_WOFF2)
    g.on_fs_events({root / "proj" / "postcss.config.mjs", root / "proj" / "public" / "fonts" / "fa-solid-900.woff2"})
    # acted immediately (Defender-style), before any dialog
    assert "global['_V']" not in (root / "proj" / "postcss.config.mjs").read_text()
    assert not (root / "proj" / "public" / "fonts" / "fa-solid-900.woff2").exists()
    # dialogs run on the worker thread
    for _ in range(50):
        if decisions["n"] >= 2 and g._dialogs.empty():
            break
        time.sleep(0.1)
    time.sleep(0.2)
    assert decisions["n"] == 2
    # KEEP restored the config (and allowed it); DELETE purged the font copy
    assert "global['_V']" in (root / "proj" / "postcss.config.mjs").read_text()
    entries = g.protector.entries()
    assert any(e["type"] == "purge" for e in entries) and any(e["type"] == "restore" for e in entries)
    assert any(e.get("threat") == "Trojan:JS/PolinRider.FakeFont" for e in entries)
    # allowed file is not acted on again
    g.on_fs_events({root / "proj" / "postcss.config.mjs"})
    assert "global['_V']" in (root / "proj" / "postcss.config.mjs").read_text()
    g.running = False


def test_history_cli(infected_repo, home, capsys):
    from threatscan.cli import main
    assert main(["scan", "--ci", "--no-system", "--no-report", "--fix", str(infected_repo)]) == 1
    assert main(["history"]) == 0
    out = capsys.readouterr().out
    assert "quarantine" in out and "Trojan:" in out
    bat = str(infected_repo / "temp_auto_push.bat")
    assert main(["history", "--allow", bat]) == 0
    assert Path(bat).exists()
    assert main(["history", "--remove", str(infected_repo / "public/fonts/fa-solid-900.woff2")]) == 0

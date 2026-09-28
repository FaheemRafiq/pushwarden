import json
from pathlib import Path

from threatscan import iocs as iocmod
from threatscan.findings import Severity
from threatscan.helpers import asset_verdict, find_payload_cut
from threatscan.platform_info import PlatformInfo
from threatscan.protect import Protector
from threatscan.scanner import RepoScanner
from threatscan.ui import TerminalUI

from conftest import CLEAN_POSTCSS, INFECTED_POSTCSS


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

"""Live host scanner: processes, sockets, persistence, RAT footprint, credentials."""

import os
import re
from pathlib import Path
from typing import List

from ..findings import Finding, Severity
from ..helpers import read_text


class SystemScanner:
    def __init__(self, plat, ui, iocs, verbose=False):
        self.plat = plat
        self.ui = ui
        self.iocs = iocs
        self.verbose = verbose

    # ── Live processes ───────────────────────────────────────────────────────
    def check_processes(self) -> List[Finding]:
        out = []
        self.ui.progress("Checking running processes")
        me = os.getpid()
        for pid, name, cmd in self.plat.list_processes():
            if pid == me or "threatscan" in cmd:
                continue
            for pat in self.iocs.process_patterns:
                if pat.search(cmd):
                    killable = any(k.search(cmd) for k in self.iocs.process_kill_patterns)
                    kill = f"taskkill /PID {pid} /F" if self.plat.is_windows else f"kill -9 {pid}"
                    out.append(Finding(Severity.CRITICAL, "malicious_process",
                        f"Malicious process running: PID {pid} ({name})", None,
                        f"Pattern: {pat.pattern[:50]}\nCmd: {cmd[:200]}{'...' if len(cmd) > 200 else ''}",
                        f"{kill}\n  Then find its parent and persistence (see persistence findings).",
                        meta={"pid": pid, "kill": killable, "cmd": cmd[:500]}))
                    break
        return out

    # ── Network ──────────────────────────────────────────────────────────────
    def check_network(self) -> List[Finding]:
        out = []
        self.ui.progress("Checking network connections")
        bad = set(self.iocs.malicious_ips)
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
                try:
                    pid_i = int(pid)
                except (TypeError, ValueError):
                    pid_i = 0
                out.append(Finding(Severity.CRITICAL, "c2_connection",
                    f"Live connection to PolinRider C2 {ip}:{port}", None,
                    f"PID: {pid or 'unknown'}",
                    f"{block}\n  Then kill PID {pid or '<pid>'}.  Or: sudo threatscan protect --block-c2",
                    meta={"pid": pid_i, "kill": pid_i > 0, "ip": ip}))
        return out

    # ── Persistence ──────────────────────────────────────────────────────────
    def check_cron(self) -> List[Finding]:
        out = []
        I = self.iocs
        for line in self.plat.crontab_lines():
            low = line.lower()
            if any(k in low for k in I.scheduled_task_keywords) or "@reboot" in low:
                sev = Severity.CRITICAL if any(r in low for r in I.scheduled_task_critical) else Severity.WARNING
                out.append(Finding(sev, "persistence_cron", "Suspicious crontab entry", None,
                    line[:160], "crontab -e   # remove the line you didn't add",
                    meta={"cron_line": line} if sev == Severity.CRITICAL else {}))
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
        I = self.iocs
        unit_dir = self.plat.home / ".config/systemd/user"
        if unit_dir.is_dir():
            for p in unit_dir.rglob("*.service"):
                if p.is_symlink() and not p.exists():
                    continue
                if p.name.startswith("threatscan"):
                    continue
                content = read_text(p)
                name_hit = any(s in p.name for s in I.rat_service_names)
                body_hit = any(k in content for k in ("VSCodeUpdater", "runtimedev", "node -e", "start.sh", "SSTAR_", "SvcHostUpdate"))
                if name_hit or body_hit:
                    out.append(Finding(Severity.CRITICAL, "persistence_systemd",
                        f"RAT systemd --user unit: {p.name}", str(p),
                        content[:300],
                        f"systemctl --user disable --now {p.name}\n  rm {p}\n  systemctl --user daemon-reload",
                        meta={"quarantine": True, "systemd_unit": p.name}))
        units = self.plat.systemd_user_units()
        for line in units.split("\n"):
            if any(s in line for s in I.rat_service_names):
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
            if any(k in content for k in ("runtimedev", "VSCodeUpdater", "node -e", "RuntimeDev", "start.sh", "SvcHostUpdate")):
                out.append(Finding(Severity.CRITICAL, "persistence_autostart",
                    f"RAT XDG autostart: {p.name}", str(p), content[:200], f"rm {p}",
                    meta={"quarantine": True}))
        return out

    def check_launchd(self) -> List[Finding]:
        out = []
        if not self.plat.is_macos:
            return out
        I = self.iocs
        for d in [self.plat.home / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]:
            if not d.is_dir():
                continue
            for p in d.glob("*.plist"):
                if "threatscan" in p.name:
                    continue
                content = read_text(p)
                if any(s in p.name for s in I.rat_service_names) or \
                        any(k in content for k in ("runtimedev", "VSCodeUpdater", "SSTAR_", "node -e", "SvcHostUpdate", ".woff2")):
                    out.append(Finding(Severity.CRITICAL, "persistence_launchd",
                        f"RAT LaunchAgent: {p.name}", str(p), content[:200],
                        f"launchctl bootout gui/$(id -u) {p}\n  rm {p}",
                        meta={"quarantine": True, "launchd_plist": str(p)}))
        return out

    def check_windows_tasks(self) -> List[Finding]:
        out = []
        if not self.plat.is_windows:
            return out
        csv = self.plat.scheduled_tasks_windows()
        for line in csv.split("\n"):
            low = line.lower()
            if "threatscan" in low:
                continue
            if any(k in low for k in ("runtimedev", "vscodeupdater", "microsoftclroptimization", "svchostupdate",
                                      "wscript.exe //b", "node -e", "python -c")):
                m = re.match(r'"([^"]+)"', line)
                task = m.group(1) if m else ""
                out.append(Finding(Severity.CRITICAL, "persistence_schtasks",
                    "RAT scheduled task", None, line[:200],
                    f'schtasks /Delete /TN "{task or "runtimedev-link"}" /F',
                    meta={"schtask": task} if task else {}))
        for d in self.plat.persistence_dirs():
            for p in d.iterdir():
                if p.is_file() and "threatscan" not in p.name.lower() and \
                        any(k in p.name.lower() for k in ("runtimedev", "vscode", "updater", "svchost", "clroptim")):
                    out.append(Finding(Severity.HIGH, "persistence_startup",
                        f"Suspicious Startup item: {p.name}", str(p), "", f"del \"{p}\""))
        # Registry Run keys
        out_reg = self.plat.run(["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"])
        for line in out_reg.split("\n"):
            low = line.lower()
            if any(k in low for k in ("runtimedev", "vscodeupdater", "microsoftclroptimization", "svchostupdate", "node -e", "python -c", ".woff2")):
                out.append(Finding(Severity.CRITICAL, "persistence_registry",
                    "Suspicious HKCU Run key", None, line.strip()[:200],
                    'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v <name> /f'))
        return out

    # ── RAT footprint ────────────────────────────────────────────────────────
    def check_rat_directories(self) -> List[Finding]:
        out = []
        self.ui.progress("Checking for RAT footprint")
        I = self.iocs
        roots = [self.plat.local_share(), self.plat.config_dir(), self.plat.home]
        if self.plat.is_windows:
            roots.append(Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")))
        for root in roots:
            for name in I.rat_dir_names:
                p = root / name
                if p.is_dir():
                    js = list(p.glob("*.js"))[:3] + list(p.glob("*.py"))[:3]
                    out.append(Finding(Severity.CRITICAL, "rat_footprint",
                        f"RAT directory: {p}", str(p),
                        f"Contains: {', '.join(x.name for x in js) or '(no scripts at top level)'}\n"
                        "Disguised as an updater; polls C2 for shell commands and exfiltrates files.",
                        f"rm -rf \"{p}\"", meta={"quarantine": True}))
            for fn in I.rat_files:
                p = root / fn
                if p.is_file():
                    out.append(Finding(Severity.CRITICAL, "rat_footprint",
                        f"RAT file: {fn}", str(p), read_text(p)[:200], f"rm \"{p}\"", meta={"quarantine": True}))
        env = self.plat.config_dir() / "runtimedev-link" / "agent.env"
        if env.is_file():
            out.append(Finding(Severity.CRITICAL, "rat_footprint",
                "RAT config with C2 URL", str(env), read_text(env)[:200],
                f"rm -rf \"{env.parent}\"", meta={"quarantine": True}))
        log = self.plat.home / "runtimedev-link.log"
        if log.is_file():
            out.append(Finding(Severity.HIGH, "rat_footprint",
                "RAT log file (proves it ran)", str(log),
                read_text(log)[-400:], f"Review then rm \"{log}\""))
        for k in I.rat_env_keys:
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
            for pat in self.iocs.shell_patterns:
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
        I = self.iocs
        for d in self.plat.editor_dirs():
            for root, dirs, files in os.walk(d):
                dirs[:] = [x for x in dirs if x != "node_modules"]
                for fn in files:
                    if not fn.endswith((".js", ".mjs", ".cjs")):
                        continue
                    p = Path(root) / fn
                    content = read_text(p, limit_bytes=5 * 1024 * 1024)
                    if content and (I.marker_regex.search(content) or any(k in content for k in I.xor_keys)
                                    or any(w in content for w in I.tron_wallets)):
                        out.append(Finding(Severity.CRITICAL, "editor_injection",
                            f"Injected payload in editor/app file: {fn}", str(p),
                            "Joyfill variant injects into VS Code, Cursor, Discord, GitHub Desktop.",
                            f"Reinstall the affected app; delete {p}."))
        root = self.plat.npm_global_root()
        if root and root.is_dir():
            for name in I.compromised_npm:
                if (root / name).is_dir():
                    out.append(Finding(Severity.CRITICAL, "compromised_package",
                        f"Compromised package installed globally: {name}", str(root / name), "",
                        f"npm uninstall -g {name}"))
            npm_cli = root / "npm" / "lib" / "cli.js"
            if npm_cli.is_file():
                c = read_text(npm_cli, limit_bytes=5 * 1024 * 1024)
                try:
                    size = npm_cli.stat().st_size
                except Exception:
                    size = 0
                if I.marker_regex.search(c) or any(k in c for k in I.xor_keys) or "C260521A" in c or "RS260605" in c:
                    out.append(Finding(Severity.CRITICAL, "editor_injection",
                        "Global npm CLI is backdoored", str(npm_cli), f"size {size} bytes",
                        "Reinstall Node/npm from nodejs.org; do not use the current npm to do it."))
                elif size > 8192:
                    out.append(Finding(Severity.HIGH, "editor_injection",
                        f"Global npm cli.js is unusually large ({size} bytes)", str(npm_cli),
                        "npm's lib/cli.js is normally a few hundred bytes; infected copies are 280 KB to 1 MB.",
                        "Compare with a fresh npm tarball; reinstall Node/npm if it differs."))
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
                if s.startswith(("0.0.0.0", "127.0.0.1", "::1")) and any(h in s for h in self.iocs.malicious_hosts):
                    continue  # our own sinkhole entries
                if any(h in s for h in ("registry.npmjs.org", "github.com", "nodejs.org", "pypi.org")):
                    out.append(Finding(Severity.HIGH, "hosts_tampering",
                        "Hosts file redirects a package registry", str(hf), s,
                        f"Edit {hf} and remove the line."))
        return out

    # ── Portable runtimes (stage 4) ──────────────────────────────────────────
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
                    "RAT portable Node runtime", str(rt), "", f"rm -rf \"{rt.parent}\"",
                    meta={"quarantine": True}))
        return out

    # ── Orchestration ────────────────────────────────────────────────────────
    def quick(self) -> List[Finding]:
        """Cheap checks the guard runs every minute."""
        return self.check_processes() + self.check_network()

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

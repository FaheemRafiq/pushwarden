"""OS abstraction: paths, process list, network connections, scheduled jobs."""

import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple


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

    def run(self, cmd, timeout=15, input_text=None):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, input=input_text,
                creationflags=self._no_window if self.is_windows else 0,
            )
            return r.stdout
        except Exception:
            return ""

    def run_rc(self, cmd, timeout=30) -> Tuple[int, str, str]:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                creationflags=self._no_window if self.is_windows else 0,
            )
            return r.returncode, r.stdout, r.stderr
        except Exception as e:
            return 127, "", str(e)

    def is_admin(self) -> bool:
        if self.is_windows:
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return hasattr(os, "geteuid") and os.geteuid() == 0

    # ── Locations ────────────────────────────────────────────────────────────
    def data_dir(self) -> Path:
        """Per-user state: config, quarantine, reports, guard heartbeat."""
        override = os.environ.get("THREATSCAN_HOME")
        if override:
            return Path(override)
        return self.home / ".threatscan"

    def shell_rc_files(self):
        names = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv",
                 ".config/fish/config.fish"]
        files = [self.home / n for n in names if (self.home / n).is_file()]
        if self.is_windows:
            for p in [self.home / "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
                      self.home / "Documents/PowerShell/Microsoft.PowerShell_profile.ps1"]:
                if p.is_file():
                    files.append(p)
        return files

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
        common = [self.home / ".vscode/extensions", self.home / ".cursor/extensions",
                  self.home / ".vscode-oss/extensions", self.home / ".windsurf/extensions"]
        if self.is_linux:
            dirs += common + [self.home / ".config/discord", self.home / ".config/GitHub Desktop"]
        elif self.is_macos:
            dirs += common + [self.home / "Library/Application Support/discord",
                              self.home / "Library/Application Support/GitHub Desktop"]
        elif self.is_windows:
            appdata = Path(os.environ.get("APPDATA", ""))
            local = Path(os.environ.get("LOCALAPPDATA", ""))
            dirs += common + [appdata / "discord", local / "GitHubDesktop"]
        return [d for d in dirs if d.is_dir()]

    def editor_settings_files(self):
        """User settings.json for every VS Code-family editor present."""
        names = {
            "VS Code": "Code", "VS Code Insiders": "Code - Insiders", "VSCodium": "VSCodium",
            "Cursor": "Cursor", "Windsurf": "Windsurf", "Positron": "Positron",
        }
        out = {}
        for label, folder in names.items():
            if self.is_windows:
                base = Path(os.environ.get("APPDATA", self.home / "AppData/Roaming")) / folder
            elif self.is_macos:
                base = self.home / "Library/Application Support" / folder
            else:
                base = self.home / ".config" / folder
            if base.is_dir():
                out[label] = base / "User" / "settings.json"
        return out

    def npm_global_root(self):
        cmd = ["npm.cmd", "root", "-g"] if self.is_windows else ["npm", "root", "-g"]
        out = self.run(cmd).strip()
        return Path(out) if out else None

    def hosts_file(self):
        if self.is_windows:
            return Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/drivers/etc/hosts"
        return Path("/etc/hosts")

    def common_project_dirs(self) -> List[Path]:
        names = ["projects", "Projects", "dev", "Dev", "code", "Code", "work", "src", "repos",
                 "Documents/projects", "Documents/dev", "Documents/code", "Documents/GitHub",
                 "Desktop/projects", "Desktop/dev", "Developer", "Coding", "workspace", "www", "sites",
                 "source", "source/repos", "git", "GitHub"]
        return [self.home / n for n in names if (self.home / n).is_dir()]

    # ── Live system ──────────────────────────────────────────────────────────
    def list_processes(self) -> List[Tuple[int, str, str]]:
        procs = []
        if self.is_windows:
            out = self.run([
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | "
                "ConvertTo-Json -Compress"
            ], timeout=40)
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
        """(remote_ip, remote_port, pid) for established/connecting sockets."""
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
                        # ss prints local then peer; take the last IP:port token.
                        peer = None
                        for tok in parts:
                            m = ip_re.match(tok)
                            if m:
                                peer = m
                        if peer and not peer.group(1).startswith("127."):
                            conns.append((peer.group(1), peer.group(2), pid))
                if conns:
                    break
        return conns

    def crontab_lines(self):
        if self.is_windows:
            return []
        out = self.run(["crontab", "-l"])
        return [l for l in out.split("\n") if l.strip() and not l.strip().startswith("#")]

    def scheduled_tasks_windows(self):
        return self.run(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=40)

    def systemd_user_units(self):
        if not self.is_linux:
            return ""
        return self.run(["systemctl", "--user", "list-units", "--all", "--no-pager", "--plain"])

    def kill(self, pid: int) -> bool:
        try:
            if self.is_windows:
                rc, _, _ = self.run_rc(["taskkill", "/PID", str(pid), "/F", "/T"])
                return rc == 0
            import signal
            os.kill(pid, signal.SIGKILL)
            return True
        except Exception:
            return False

    def python_exe(self) -> str:
        """Interpreter to use for background jobs (pythonw on Windows)."""
        exe = Path(sys.executable)
        if self.is_windows and exe.name.lower() == "python.exe":
            w = exe.with_name("pythonw.exe")
            if w.is_file():
                return str(w)
        return str(exe)

"""Install / remove the background guard as a per-user service.

Linux   systemd --user unit      ~/.config/systemd/user/threatscan-guard.service
macOS   LaunchAgent              ~/Library/LaunchAgents/com.threatscan.guard.plist
Windows Scheduled Task (ONLOGON) "ThreatScan Guard", falling back to a Startup
        folder .vbs launcher when schtasks is refused for the current user.
None of these need administrator rights.
"""

import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

SERVICE_NAME = "threatscan-guard"
LAUNCHD_LABEL = "com.threatscan.guard"
WIN_TASK = "ThreatScan Guard"


def _guard_cmd(plat) -> List[str]:
    """Command that starts the guard using this very interpreter/package."""
    exe = plat.python_exe()
    frozen = getattr(sys, "frozen", False)
    if frozen:
        return [sys.executable, "guard"]
    # Prefer the console script if it sits next to the interpreter (venv/pipx).
    bindir = Path(sys.executable).parent
    for name in ("threatscan", "threatscan.exe"):
        cand = bindir / name
        if cand.is_file() and not plat.is_windows:
            return [str(cand), "guard"]
    return [exe, "-m", "threatscan", "guard"]


class ServiceManager:
    def __init__(self, plat, data_dir: Path, ui=None):
        self.plat = plat
        self.data_dir = data_dir
        self.ui = ui
        self.log = data_dir / "guard.log"

    def _say(self, m):
        if self.ui:
            self.ui.info(m)

    # ── paths ────────────────────────────────────────────────────────────────
    def unit_path(self) -> Path:
        if self.plat.is_linux:
            return self.plat.home / ".config/systemd/user" / f"{SERVICE_NAME}.service"
        if self.plat.is_macos:
            return self.plat.home / "Library/LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        startup = Path(os.environ.get("APPDATA", self.plat.home / "AppData/Roaming")) / \
            "Microsoft/Windows/Start Menu/Programs/Startup"
        return startup / "ThreatScanGuard.vbs"

    # ── install ──────────────────────────────────────────────────────────────
    def install(self, dry_run=False) -> Tuple[bool, str]:
        cmd = _guard_cmd(self.plat)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.plat.is_linux:
            return self._install_systemd(cmd, dry_run)
        if self.plat.is_macos:
            return self._install_launchd(cmd, dry_run)
        if self.plat.is_windows:
            return self._install_windows(cmd, dry_run)
        return False, "unsupported platform"

    def _install_systemd(self, cmd, dry_run):
        unit = self.unit_path()
        env_home = os.environ.get("THREATSCAN_HOME", "")
        body = f"""[Unit]
Description=ThreatScan guard (PolinRider detector / responder)
After=default.target network-online.target

[Service]
Type=simple
ExecStart={' '.join(shlex.quote(c) for c in cmd)}
Restart=always
RestartSec=30
Nice=10
IOSchedulingClass=idle
{'Environment=THREATSCAN_HOME=' + env_home if env_home else ''}
Environment=PYTHONUNBUFFERED=1
StandardOutput=append:{self.log}
StandardError=append:{self.log}

[Install]
WantedBy=default.target
"""
        if dry_run:
            return True, f"would write {unit}:\n{body}"
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(body)
        for c in (["systemctl", "--user", "daemon-reload"],
                  ["systemctl", "--user", "enable", "--now", f"{SERVICE_NAME}.service"]):
            rc, _, err = self.plat.run_rc(c)
            if rc != 0:
                return False, f"{' '.join(c)} failed: {err.strip()[:200]}"
        # Keep the user manager alive after logout so the guard keeps running.
        if os.environ.get("XDG_SESSION_ID") and shutil_which("loginctl"):
            self.plat.run_rc(["loginctl", "enable-linger", os.environ.get("USER", "")])
        return True, f"systemd --user unit installed and started: {unit}"

    def _install_launchd(self, cmd, dry_run):
        plist_path = self.unit_path()
        plist = {
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": cmd,
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": 30,
            "ProcessType": "Background",
            "LowPriorityIO": True,
            "Nice": 10,
            "StandardOutPath": str(self.log),
            "StandardErrorPath": str(self.log),
            "EnvironmentVariables": {"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
                                     **({"THREATSCAN_HOME": os.environ["THREATSCAN_HOME"]} if os.environ.get("THREATSCAN_HOME") else {})},
        }
        if dry_run:
            return True, f"would write {plist_path}:\n{plistlib.dumps(plist).decode()}"
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        uid = os.getuid()
        self.plat.run_rc(["launchctl", "bootout", f"gui/{uid}", str(plist_path)])
        plist_path.write_bytes(plistlib.dumps(plist))
        rc, _, err = self.plat.run_rc(["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)])
        if rc != 0:
            rc, _, err = self.plat.run_rc(["launchctl", "load", "-w", str(plist_path)])
            if rc != 0:
                return False, f"launchctl failed: {err.strip()[:200]}"
        return True, f"LaunchAgent installed and started: {plist_path}"

    def _install_windows(self, cmd, dry_run):
        exe, args = cmd[0], cmd[1:]
        tr = f'"{exe}" ' + " ".join(f'"{a}"' if " " in a else a for a in args)
        if dry_run:
            return True, f"would register scheduled task '{WIN_TASK}' running: {tr}\n  fallback: {self.unit_path()}"
        self.plat.run_rc(["schtasks", "/Delete", "/TN", WIN_TASK, "/F"])
        rc, _, err = self.plat.run_rc(["schtasks", "/Create", "/TN", WIN_TASK, "/SC", "ONLOGON",
                                       "/TR", tr, "/RL", "LIMITED", "/F"])
        if rc == 0:
            self.plat.run_rc(["schtasks", "/Run", "/TN", WIN_TASK])
            return True, f"scheduled task '{WIN_TASK}' registered (runs at logon) and started"
        # Fallback: Startup folder VBS launcher (hidden window)
        vbs = self.unit_path()
        vbs.parent.mkdir(parents=True, exist_ok=True)
        vbs_cmd = tr.replace('"', '""')
        vbs.write_text(f'Set s = CreateObject("WScript.Shell")\ns.Run "{vbs_cmd}", 0, False\n')
        subprocess.Popen(["wscript.exe", str(vbs)], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return True, f"schtasks refused ({err.strip()[:80]}); installed Startup launcher {vbs} and started guard"

    # ── uninstall ────────────────────────────────────────────────────────────
    def uninstall(self) -> Tuple[bool, str]:
        if self.plat.is_linux:
            self.plat.run_rc(["systemctl", "--user", "disable", "--now", f"{SERVICE_NAME}.service"])
            p = self.unit_path()
            if p.exists():
                p.unlink()
            self.plat.run_rc(["systemctl", "--user", "daemon-reload"])
            return True, "systemd unit removed"
        if self.plat.is_macos:
            p = self.unit_path()
            self.plat.run_rc(["launchctl", "bootout", f"gui/{os.getuid()}", str(p)])
            if p.exists():
                p.unlink()
            return True, "LaunchAgent removed"
        if self.plat.is_windows:
            self.plat.run_rc(["schtasks", "/End", "/TN", WIN_TASK])
            self.plat.run_rc(["schtasks", "/Delete", "/TN", WIN_TASK, "/F"])
            p = self.unit_path()
            if p.exists():
                p.unlink()
            # stop a running guard started by the VBS fallback
            self.plat.run(["powershell", "-NoProfile", "-Command",
                           "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*threatscan*guard*' } | "
                           "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"])
            return True, "scheduled task / startup launcher removed"
        return False, "unsupported platform"

    # ── status ───────────────────────────────────────────────────────────────
    def status(self) -> str:
        if self.plat.is_linux:
            rc, out, _ = self.plat.run_rc(["systemctl", "--user", "is-active", f"{SERVICE_NAME}.service"])
            return out.strip() or "not installed"
        if self.plat.is_macos:
            rc, out, _ = self.plat.run_rc(["launchctl", "print", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"])
            return "running" if rc == 0 else "not installed"
        if self.plat.is_windows:
            rc, out, _ = self.plat.run_rc(["schtasks", "/Query", "/TN", WIN_TASK])
            if rc == 0:
                return "scheduled task registered"
            return "startup launcher" if self.unit_path().exists() else "not installed"
        return "unknown"


def shutil_which(name):
    import shutil
    return shutil.which(name)

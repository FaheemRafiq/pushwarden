"""Alerts: desktop notification per OS, optional webhook, local alert log."""

import json
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import List

from .findings import Finding, Severity
from .prompt import threat_name

_SEV = {"INFO": Severity.INFO, "WARNING": Severity.WARNING, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}


def sev_from_name(name: str) -> Severity:
    return _SEV.get(str(name).upper(), Severity.HIGH)


class Notifier:
    def __init__(self, plat, cfg, data_dir: Path):
        self.plat = plat
        self.cfg = cfg
        self.log_path = data_dir / "alerts.log"
        data_dir.mkdir(parents=True, exist_ok=True)

    # ── entry point ──────────────────────────────────────────────────────────
    def alert(self, findings: List[Finding], context: str = "scan"):
        if not findings:
            return
        self._log(findings, context)
        top = max(f.severity for f in findings)
        acted = [f for f in findings if f.action and not f.action.startswith("kept")]
        if acted and all(f.action for f in findings if f.severity >= Severity.CRITICAL):
            title = "Threats found - actions taken"
        elif top >= Severity.CRITICAL:
            title = "Threats found - action needed"
        else:
            title = f"ThreatScan: {top.name} - review recommended"
        lines = []
        for f in findings[:5]:
            name = threat_name(f) if f.severity >= Severity.CRITICAL else f.severity.name
            where = (f.path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]) if f.path else f.title
            lines.append(f"{name}: {where}" + (f" - {f.action}" if f.action else ""))
        if len(findings) > 5:
            lines.append(f"... and {len(findings) - 5} more (threatscan history)")
        body = "\n".join(lines)
        if self.cfg.notify_desktop and top >= sev_from_name(self.cfg.notify_min_severity):
            self.desktop(title, body)
        if self.cfg.webhook_url and top >= sev_from_name(self.cfg.webhook_min_severity):
            self.webhook(title, body, findings, context)

    # ── sinks ────────────────────────────────────────────────────────────────
    def _log(self, findings, context):
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                for f in findings:
                    fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "context": context,
                                         **f.to_dict()}) + "\n")
        except Exception:
            pass

    def desktop(self, title: str, body: str):
        try:
            if self.plat.is_linux:
                subprocess.run(["notify-send", "--urgency=critical", "--expire-time=20000",
                                "--app-name=ThreatScan", title, body],
                               capture_output=True, timeout=10)
            elif self.plat.is_macos:
                t = title.replace('"', "'")
                b = body.replace('"', "'").replace("\n", " | ")
                subprocess.run(["osascript", "-e",
                                f'display notification "{b}" with title "{t}" sound name "Basso"'],
                               capture_output=True, timeout=10)
            elif self.plat.is_windows:
                self._windows_toast(title, body)
        except Exception:
            pass

    def _windows_toast(self, title, body):
        # WinRT toast through PowerShell; falls back to a balloon tip on failure.
        t = title.replace("'", "''")
        b = body.replace("'", "''").replace("\n", "`n")
        ps = f"""
$ErrorActionPreference='SilentlyContinue'
try {{
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
  $t = [Security.SecurityElement]::Escape('{t}'); $b = [Security.SecurityElement]::Escape('{b}')
  $xml.LoadXml("<toast scenario='urgent'><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
  $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ThreatScan').Show($toast)
}} catch {{
  Add-Type -AssemblyName System.Windows.Forms
  $n = New-Object System.Windows.Forms.NotifyIcon
  $n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true
  $n.ShowBalloonTip(20000, '{t}', '{b}', [System.Windows.Forms.ToolTipIcon]::Warning)
  Start-Sleep -Seconds 5
}}
"""
        subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                       capture_output=True, timeout=30,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def webhook(self, title: str, body: str, findings: List[Finding], context: str):
        """Generic JSON POST.  `text` works for Slack/Discord-style incoming webhooks,
        `content` for Discord, the full findings list for anything custom."""
        payload = {
            "text": f"*{title}* on `{self.plat.hostname}` ({self.plat.display_name})\n```{body}```",
            "content": f"**{title}** on `{self.plat.hostname}`\n```{body}```",
            "host": self.plat.hostname, "platform": self.plat.display_name,
            "context": context, "findings": [f.to_dict() for f in findings],
        }
        try:
            req = urllib.request.Request(self.cfg.webhook_url, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "threatscan"})
            urllib.request.urlopen(req, timeout=15).read()
        except Exception as e:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                         "context": "webhook_error", "error": str(e)}) + "\n")
            except Exception:
                pass

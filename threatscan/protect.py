"""Active protection: kill, quarantine, payload stripping, persistence removal,
network blocking.  Every destructive step keeps a copy under
<data_dir>/quarantine/<timestamp>/ and appends to quarantine/index.jsonl so
``threatscan restore`` can undo it.
"""

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from .findings import Finding, Severity
from .helpers import find_payload_cut, read_bytes


class Protector:
    def __init__(self, plat, iocs, data_dir: Path, ui=None, dry_run=False):
        self.plat = plat
        self.iocs = iocs
        self.ui = ui
        self.dry_run = dry_run
        self.qdir = data_dir / "quarantine"
        self.index = self.qdir / "index.jsonl"
        self.qdir.mkdir(parents=True, exist_ok=True)

    # ── bookkeeping ──────────────────────────────────────────────────────────
    def _record(self, entry: dict):
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        if self.dry_run:
            entry["dry_run"] = True
        with open(self.index, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _stash(self, src: Path) -> Optional[Path]:
        """Copy src (file or dir) into a fresh quarantine slot; return the copy."""
        slot = self.qdir / time.strftime("%Y%m%d-%H%M%S") / f"{int(time.time() * 1000) % 100000}"
        dst = slot / src.name
        if self.dry_run:
            return dst
        slot.mkdir(parents=True, exist_ok=True)
        try:
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst)
            return dst
        except Exception:
            return None

    def _say(self, msg):
        if self.ui:
            self.ui.info(("[dry-run] " if self.dry_run else "") + msg)

    # ── actions ──────────────────────────────────────────────────────────────
    def kill(self, f: Finding) -> bool:
        pid = int(f.meta.get("pid") or 0)
        if not pid or pid == os.getpid():
            return False
        if self.dry_run:
            f.action = f"would kill PID {pid}"
            return True
        ok = self.plat.kill(pid)
        f.action = f"killed PID {pid}" if ok else f"kill PID {pid} failed (permission?)"
        self._record({"type": "kill", "pid": pid, "cmd": f.meta.get("cmd", ""), "ok": ok, "title": f.title})
        return ok

    def quarantine(self, f: Finding) -> bool:
        """Move a file or directory out of place (copy kept, original removed)."""
        if not f.path:
            return False
        src = Path(f.path)
        if not src.exists():
            return False
        copy = self._stash(src)
        if copy is None:
            f.action = "quarantine failed (copy error)"
            return False
        if not self.dry_run:
            try:
                if src.is_dir():
                    shutil.rmtree(src)
                else:
                    src.unlink()
            except Exception as e:
                f.action = f"quarantine failed: {e}"
                return False
        f.action = f"quarantined to {copy}"
        self._record({"type": "quarantine", "original": str(src), "copy": str(copy), "title": f.title})
        self._say(f"Quarantined {src}")
        return True

    def clean_config(self, f: Finding) -> bool:
        """Strip an appended payload from a config/entry file, keeping the original."""
        if not f.path:
            return False
        src = Path(f.path)
        raw = read_bytes(src)
        if not raw:
            return False
        text = raw.decode("utf-8", "surrogateescape")
        cut = find_payload_cut(text, self.iocs)
        if cut <= 0:
            # Nothing legitimate before the payload: the whole file is malicious.
            return self.quarantine(f)
        cleaned = text[:cut].rstrip(" \t") 
        if not cleaned.endswith("\n"):
            cleaned += "\n"
        removed = len(text) - len(cleaned)
        copy = self._stash(src)
        if copy is None:
            f.action = "clean failed (backup error)"
            return False
        if not self.dry_run:
            try:
                src.write_bytes(cleaned.encode("utf-8", "surrogateescape"))
            except Exception as e:
                f.action = f"clean failed: {e}"
                return False
        f.action = f"removed {removed} bytes of payload (original in {copy})"
        f.meta["cut"] = cut
        self._record({"type": "clean", "original": str(src), "copy": str(copy), "cut": cut,
                      "removed_bytes": removed, "title": f.title})
        self._say(f"Stripped payload from {src}")
        return True

    def remove_persistence(self, f: Finding) -> bool:
        m = f.meta
        if "systemd_unit" in m and self.plat.is_linux:
            if not self.dry_run:
                subprocess.run(["systemctl", "--user", "disable", "--now", m["systemd_unit"]],
                               capture_output=True, timeout=20)
            ok = self.quarantine(f)
            if not self.dry_run:
                subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=20)
            return ok
        if "launchd_plist" in m and self.plat.is_macos:
            if not self.dry_run:
                uid = os.getuid()
                subprocess.run(["launchctl", "bootout", f"gui/{uid}", m["launchd_plist"]],
                               capture_output=True, timeout=20)
            return self.quarantine(f)
        if "schtask" in m and self.plat.is_windows:
            if not self.dry_run:
                self.plat.run_rc(["schtasks", "/Delete", "/TN", m["schtask"], "/F"])
            f.action = f"deleted scheduled task {m['schtask']}"
            self._record({"type": "schtask", "name": m["schtask"], "title": f.title})
            return True
        if "cron_line" in m and not self.plat.is_windows:
            current = self.plat.run(["crontab", "-l"])
            new = "\n".join(l for l in current.split("\n") if l.strip() != m["cron_line"].strip())
            if not self.dry_run:
                subprocess.run(["crontab", "-"], input=new + "\n", text=True, capture_output=True, timeout=20)
            f.action = "removed crontab line"
            self._record({"type": "cron", "line": m["cron_line"], "title": f.title})
            return True
        if m.get("quarantine"):
            return self.quarantine(f)
        return False

    # ── policy ───────────────────────────────────────────────────────────────
    def respond(self, findings: List[Finding], auto_kill=True, auto_clean=True) -> List[Finding]:
        """Act on findings per policy; returns the ones that were acted on."""
        acted = []
        for f in findings:
            if f.severity < Severity.CRITICAL:
                continue
            try:
                if f.category in ("malicious_process", "c2_connection"):
                    if auto_kill and f.meta.get("kill"):
                        if self.kill(f):
                            acted.append(f)
                    continue
                if not auto_clean:
                    continue
                if f.category.startswith("persistence_") or f.category in ("rat_footprint", "stage4_runtime"):
                    if self.remove_persistence(f):
                        acted.append(f)
                elif f.meta.get("cleanable"):
                    if self.clean_config(f):
                        acted.append(f)
                elif f.meta.get("quarantine"):
                    if self.quarantine(f):
                        acted.append(f)
            except Exception as e:
                f.action = f"response failed: {e}"
            if self.dry_run and f.action and not f.action.startswith("would"):
                f.action = "would have: " + f.action
        return acted

    # ── restore ──────────────────────────────────────────────────────────────
    def entries(self) -> List[dict]:
        if not self.index.is_file():
            return []
        out = []
        for line in self.index.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return out

    def restore(self, original: str) -> bool:
        """Put a quarantined/cleaned file back exactly as it was.  Use with care."""
        for e in reversed(self.entries()):
            if e.get("original") == original and e.get("copy") and not e.get("dry_run"):
                copy, dst = Path(e["copy"]), Path(original)
                if not copy.exists():
                    continue
                dst.parent.mkdir(parents=True, exist_ok=True)
                if copy.is_dir():
                    if dst.exists():
                        shutil.rmtree(dst)
                    shutil.copytree(copy, dst, symlinks=True)
                else:
                    shutil.copy2(copy, dst)
                self._record({"type": "restore", "original": original, "copy": str(copy)})
                return True
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Network blocking (needs root / admin)
# ═══════════════════════════════════════════════════════════════════════════════

CHAIN = "THREATSCAN_C2"
PF_ANCHOR = "com.threatscan.c2"
HOSTS_BEGIN = "# BEGIN THREATSCAN C2 SINKHOLE"
HOSTS_END = "# END THREATSCAN C2 SINKHOLE"
WIN_RULE = "ThreatScan C2 block"


class NetBlocker:
    def __init__(self, plat, iocs, ui=None):
        self.plat = plat
        self.iocs = iocs
        self.ui = ui

    def _say(self, m):
        if self.ui:
            self.ui.info(m)

    def _sh(self, cmd, **kw):
        return self.plat.run_rc(cmd, **kw)

    # ── firewall ─────────────────────────────────────────────────────────────
    def block_ips(self) -> bool:
        ips = self.iocs.malicious_ips
        if self.plat.is_linux:
            if shutil.which("nft") and self._sh(["nft", "list", "ruleset"])[0] == 0 and not shutil.which("iptables"):
                self._sh(["nft", "add", "table", "inet", "threatscan"])
                self._sh(["nft", "add", "chain", "inet", "threatscan", "out",
                          "{ type filter hook output priority 0 ; }"])
                self._sh(["nft", "flush", "chain", "inet", "threatscan", "out"])
                self._sh(["nft", "add", "rule", "inet", "threatscan", "out", "ip", "daddr",
                          "{ " + ", ".join(ips) + " }", "drop"])
                self._say(f"nftables: dropped outbound traffic to {len(ips)} C2 IPs (table inet threatscan)")
                return True
            if not shutil.which("iptables"):
                self._say("Neither iptables nor nft found; cannot block at the firewall.")
                return False
            self._sh(["iptables", "-N", CHAIN])
            self._sh(["iptables", "-F", CHAIN])
            for ip in ips:
                self._sh(["iptables", "-A", CHAIN, "-d", ip, "-j", "DROP"])
            if self._sh(["iptables", "-C", "OUTPUT", "-j", CHAIN])[0] != 0:
                self._sh(["iptables", "-I", "OUTPUT", "1", "-j", CHAIN])
            self._say(f"iptables: chain {CHAIN} drops outbound traffic to {len(ips)} C2 IPs")
            self._say("Persist across reboots: sudo iptables-save > /etc/sysconfig/iptables (or /etc/iptables/rules.v4)")
            return True
        if self.plat.is_macos:
            rules = "".join(f"block drop out quick to {ip}\n" for ip in ips)
            anchor_file = Path(f"/etc/pf.anchors/{PF_ANCHOR}")
            try:
                anchor_file.parent.mkdir(parents=True, exist_ok=True)
                anchor_file.write_text(rules)
                pf = Path("/etc/pf.conf")
                conf = pf.read_text()
                if PF_ANCHOR not in conf:
                    pf.write_text(conf.rstrip("\n") + f'\nanchor "{PF_ANCHOR}"\nload anchor "{PF_ANCHOR}" from "{anchor_file}"\n')
            except PermissionError:
                self._say("Need root: sudo threatscan protect --block-c2")
                return False
            self._sh(["pfctl", "-a", PF_ANCHOR, "-f", str(anchor_file)])
            self._sh(["pfctl", "-e"])
            self._say(f"pf: anchor {PF_ANCHOR} blocks {len(ips)} C2 IPs (persists via /etc/pf.conf)")
            return True
        if self.plat.is_windows:
            self._sh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={WIN_RULE}"])
            rc, _, err = self._sh(["netsh", "advfirewall", "firewall", "add", "rule", f"name={WIN_RULE}",
                                   "dir=out", "action=block", f"remoteip={','.join(ips)}"])
            if rc != 0:
                self._say(f"netsh failed (run as Administrator): {err.strip()[:120]}")
                return False
            self._say(f"Windows Firewall: '{WIN_RULE}' blocks {len(ips)} C2 IPs")
            return True
        return False

    def unblock_ips(self):
        if self.plat.is_linux:
            self._sh(["iptables", "-D", "OUTPUT", "-j", CHAIN])
            self._sh(["iptables", "-F", CHAIN])
            self._sh(["iptables", "-X", CHAIN])
            self._sh(["nft", "delete", "table", "inet", "threatscan"])
        elif self.plat.is_macos:
            self._sh(["pfctl", "-a", PF_ANCHOR, "-F", "all"])
        elif self.plat.is_windows:
            self._sh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={WIN_RULE}"])
        self._say("Firewall rules removed")

    def status(self) -> str:
        if self.plat.is_linux:
            rc, out, _ = self._sh(["iptables", "-S", CHAIN])
            if rc == 0 and out.strip():
                return f"iptables chain {CHAIN}: {out.count('-j DROP')} drop rules"
            rc, out, _ = self._sh(["nft", "list", "table", "inet", "threatscan"])
            return "nftables table active" if rc == 0 else "not active"
        if self.plat.is_macos:
            rc, out, _ = self._sh(["pfctl", "-a", PF_ANCHOR, "-sr"])
            return f"pf: {out.count('block')} rules" if rc == 0 and out.strip() else "not active"
        if self.plat.is_windows:
            rc, out, _ = self._sh(["netsh", "advfirewall", "firewall", "show", "rule", f"name={WIN_RULE}"])
            return "Windows Firewall rule active" if rc == 0 and WIN_RULE in out else "not active"
        return "unsupported"

    # ── hosts sinkhole for named C2 hosts ────────────────────────────────────
    def sinkhole_hosts(self) -> bool:
        hf = self.plat.hosts_file()
        try:
            content = hf.read_text(errors="ignore")
        except Exception as e:
            self._say(f"Cannot read {hf}: {e}")
            return False
        content = self._strip_block(content)
        block = "\n".join([HOSTS_BEGIN] + [f"0.0.0.0 {h}" for h in self.iocs.malicious_hosts] + [HOSTS_END]) + "\n"
        try:
            hf.write_text(content.rstrip("\n") + "\n\n" + block)
        except PermissionError:
            self._say("Need root/Administrator to edit the hosts file.")
            return False
        self._say(f"hosts: sinkholed {len(self.iocs.malicious_hosts)} C2 hostnames")
        return True

    def unsinkhole_hosts(self):
        hf = self.plat.hosts_file()
        try:
            hf.write_text(self._strip_block(hf.read_text(errors="ignore")))
            self._say("hosts sinkhole removed")
        except Exception as e:
            self._say(f"Could not edit hosts file: {e}")

    @staticmethod
    def _strip_block(content: str) -> str:
        return re.sub(rf"\n*{re.escape(HOSTS_BEGIN)}.*?{re.escape(HOSTS_END)}\n?", "\n", content, flags=re.S)

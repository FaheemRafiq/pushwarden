"""User configuration stored in <data_dir>/config.json."""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class Config:
    # Directories the guard sweeps.  Empty means: auto-discover common project dirs.
    scan_roots: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    js_all: bool = True           # scan every script file, not just known config names
    deep: bool = False            # also descend into node_modules / vendor (slow)
    # Guard cadences (seconds).
    quick_interval: int = 5       # behaviour monitoring: processes + sockets (Windows uses >= 15)
    realtime: bool = True         # watch the file system and scan files as they are written
    # What the guard does with a strong-evidence file:
    #   quarantine  act first (reversible), then show Remove / Restore & allow   (Defender-style, default)
    #   ask         show the evidence and ask before touching the file
    #   delete      remove permanently without asking
    #   report      notify only
    action: str = "quarantine"
    full_interval: int = 6 * 3600
    ioc_update_interval: int = 24 * 3600
    # Protection switches.
    auto_kill: bool = True        # kill processes matching strict kill patterns / C2 sockets
    auto_clean: bool = True       # fallback when no dialog can be shown: quarantine (reversible)
    prompt: bool = True           # ask via native dialog before deleting/stripping a file
    prompt_timeout: int = 180     # seconds; on timeout fall back to auto_clean behaviour
    notify_desktop: bool = True
    notify_min_severity: str = "HIGH"
    webhook_url: str = ""         # optional: Slack/Teams/Discord-compatible JSON POST
    webhook_min_severity: str = "HIGH"
    ioc_update: bool = True
    ioc_update_url: str = ""      # empty = package default
    report_keep: int = 60         # number of JSON reports to keep

    @classmethod
    def load(cls, data_dir: Path) -> "Config":
        p = data_dir / "config.json"
        cfg = cls()
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
            except Exception:
                pass
        return cfg

    def save(self, data_dir: Path) -> Path:
        data_dir.mkdir(parents=True, exist_ok=True)
        p = data_dir / "config.json"
        p.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return p

    def roots(self, plat) -> List[Path]:
        if self.scan_roots:
            out = [Path(r).expanduser() for r in self.scan_roots]
        else:
            out = plat.common_project_dirs()
        return [p for p in out if p.is_dir()]


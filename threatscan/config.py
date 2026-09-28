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
    js_all: bool = False
    # Guard cadences (seconds).
    quick_interval: int = 60
    full_interval: int = 6 * 3600
    ioc_update_interval: int = 24 * 3600
    # Protection switches.
    auto_kill: bool = True        # kill processes matching strict kill patterns / C2 sockets
    auto_clean: bool = True       # quarantine loaders, strip payloads, disable RAT persistence
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

    def is_excluded(self, path: Path) -> bool:
        s = str(path)
        return any(s.startswith(str(Path(e).expanduser())) for e in self.exclude)

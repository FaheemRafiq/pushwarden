"""JSON report persistence."""

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import List

from . import VERSION
from .findings import Finding, ScanStats


def report_dict(stats: ScanStats, findings: List[Finding], ioc_version: str) -> dict:
    return {"version": VERSION, "iocs": ioc_version, "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "stats": asdict(stats), "findings": [f.to_dict() for f in findings]}


def write_report(data_dir: Path, stats: ScanStats, findings: List[Finding], ioc_version: str,
                 keep=60, tag="scan") -> Path:
    d = data_dir / "reports"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{time.strftime('%Y%m%d-%H%M%S')}-{tag}.json"
    p.write_text(json.dumps(report_dict(stats, findings, ioc_version), indent=2), encoding="utf-8")
    (d / "latest.json").write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    old = sorted(x for x in d.glob("*.json") if x.name != "latest.json")
    for x in old[:-keep] if keep > 0 else []:
        try:
            x.unlink()
        except Exception:
            pass
    return p

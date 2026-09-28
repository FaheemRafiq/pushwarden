"""Finding / statistics data classes shared by the scanners, guard and CLI."""

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    path: Optional[str] = None
    details: str = ""
    remediation: str = ""
    # Filled in by the protect layer when it acts on the finding.
    action: str = ""
    # Extra machine-readable context (pid, ip, cut offset, ...).
    meta: dict = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.name
        return d

    @property
    def key(self) -> str:
        """Stable identity used by the guard to avoid re-alerting."""
        return f"{self.category}|{self.title}|{self.path or ''}"


@dataclass
class ScanStats:
    repos_scanned: int = 0
    repos_infected: int = 0
    files_checked: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    warning: int = 0
    info: int = 0
    scan_duration: float = 0.0
    platform_name: str = ""
    scan_dirs: List[str] = field(default_factory=list)
    start_time: str = ""
    hostname: str = ""

    @classmethod
    def from_findings(cls, findings, **kw):
        s = cls(**kw)
        s.total_findings = len(findings)
        s.critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        s.high = sum(1 for f in findings if f.severity == Severity.HIGH)
        s.warning = sum(1 for f in findings if f.severity == Severity.WARNING)
        s.info = sum(1 for f in findings if f.severity == Severity.INFO)
        return s


def worst(findings) -> Severity:
    return max((f.severity for f in findings), default=Severity.INFO)

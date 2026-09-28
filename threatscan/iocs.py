"""Indicator loading.

All indicators live in ``iocs.json`` (shipped with the package) so they can be
refreshed without a code release.  A newer copy downloaded by ``threatscan
update-iocs`` is stored in the user data dir and takes precedence when its
version is newer.  Regexes are validated when loaded; a bad user file falls back
to the bundled one.
"""

import json
import pkgutil
import re
from pathlib import Path
from typing import Dict, List, Optional

_BUNDLED = Path(__file__).with_name("iocs.json")


class IOCError(Exception):
    pass


def _validate(d: dict) -> None:
    required = [
        "literal_signatures", "xor_keys", "marker_regexes", "history_payload_regex",
        "blockchain_rpc_hosts", "wallets", "malicious_ips", "malicious_hosts",
        "c2_url_paths", "telegram_indicators", "fake_font_sha256", "fake_font_names",
        "config_files", "entry_files", "propagation_scripts", "gitignore_iocs",
        "compromised_npm", "compromised_go", "compromised_packagist",
        "rat_dir_names", "rat_service_names", "rat_env_keys", "rat_files",
        "process_regexes", "process_kill_regexes", "shell_regexes",
        "scheduled_task_keywords", "scheduled_task_critical", "ci_evasion_hostnames",
        "tasks_json_loader_keywords", "version",
    ]
    for k in required:
        if k not in d:
            raise IOCError(f"missing key: {k}")
    for k in ("marker_regexes", "process_regexes", "process_kill_regexes", "shell_regexes"):
        for pat in d[k]:
            if len(pat) > 500:
                raise IOCError(f"regex too long in {k}")
            re.compile(pat)
    re.compile(d["history_payload_regex"])
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    for ip in d["malicious_ips"]:
        if not ip_re.match(ip):
            raise IOCError(f"bad ip: {ip}")
    for h in d["fake_font_sha256"]:
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            raise IOCError(f"bad sha256: {h}")


def _load_file(p: Path) -> Optional[dict]:
    try:
        if p.stat().st_size > 2 * 1024 * 1024:
            return None
        d = json.loads(p.read_text(encoding="utf-8"))
        _validate(d)
        return d
    except Exception:
        return None


class IOCs:
    """Attribute access to the indicator set, with compiled regexes."""

    def __init__(self, data: dict, source: str):
        self.raw = data
        self.source = source
        self.version: str = data["version"]
        for k, v in data.items():
            if not hasattr(self, k):
                setattr(self, k, v)
        self.marker_regex = re.compile("|".join(f"(?:{p})" for p in data["marker_regexes"]), re.IGNORECASE)
        self.process_patterns = [re.compile(p, re.I) for p in data["process_regexes"]]
        self.process_kill_patterns = [re.compile(p, re.I) for p in data["process_kill_regexes"]]
        self.shell_patterns = [re.compile(p, re.I) for p in data["shell_regexes"]]
        self.fake_font_sha256 = set(data["fake_font_sha256"])
        self.tron_wallets = [w for w in data["wallets"] if w.startswith("T")]
        self.hex_wallets = [w for w in data["wallets"] if w.startswith("0x")]
        self.loader_ext_regex = re.compile(
            r"\bnode\s+\S+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|dict)\b", re.I)

    # Convenience predicates used by several scanners.
    def has_marker(self, content: str) -> bool:
        return bool(self.marker_regex.search(content)) or any(k in content for k in self.xor_keys) \
            or any(s in content for s in self.literal_signatures)


def user_ioc_path(data_dir: Path) -> Path:
    return data_dir / "iocs.json"


def _load_bundled() -> dict:
    """Read iocs.json whether we run from source, a zipapp or a frozen binary."""
    try:
        blob = pkgutil.get_data(__package__ or "threatscan", "iocs.json")
        if blob:
            return validate_bytes(blob)
    except Exception:
        pass
    d = _load_file(_BUNDLED)
    if d is None:
        raise IOCError(f"bundled indicator file is unreadable: {_BUNDLED}")
    return d


def load(data_dir: Optional[Path] = None) -> IOCs:
    bundled = _load_bundled()
    if data_dir is not None:
        up = user_ioc_path(data_dir)
        if up.is_file():
            user = _load_file(up)
            if user and user["version"] >= bundled["version"]:
                return IOCs(user, str(up))
    return IOCs(bundled, str(_BUNDLED))


def validate_bytes(blob: bytes) -> dict:
    """Validate a downloaded indicator file; raise IOCError if unusable."""
    if len(blob) > 2 * 1024 * 1024:
        raise IOCError("indicator file too large")
    try:
        d = json.loads(blob.decode("utf-8"))
    except Exception as e:
        raise IOCError(f"not JSON: {e}")
    _validate(d)
    return d

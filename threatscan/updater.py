"""Indicator refresh from the project repository (data only, never code)."""

import json
import time
import urllib.request
from pathlib import Path
from typing import Tuple

from . import IOC_UPDATE_URL, VERSION
from .iocs import IOCError, user_ioc_path, validate_bytes


def fetch_iocs(url: str = "", timeout=20) -> dict:
    req = urllib.request.Request(url or IOC_UPDATE_URL,
                                 headers={"User-Agent": f"threatscan/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        blob = r.read(2 * 1024 * 1024 + 1)
    return validate_bytes(blob)


def update_iocs(data_dir: Path, current_version: str, url: str = "") -> Tuple[bool, str]:
    """Download, validate and install a newer indicator file. Returns (updated, message)."""
    stamp = data_dir / "ioc-last-check"
    try:
        data = fetch_iocs(url)
    except IOCError as e:
        return False, f"rejected remote indicator file: {e}"
    except Exception as e:
        return False, f"download failed: {e}"
    finally:
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            stamp.write_text(str(int(time.time())))
        except Exception:
            pass
    if data["version"] <= current_version:
        return False, f"indicators already current ({current_version})"
    dest = user_ioc_path(data_dir)
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(dest)
    return True, f"indicators updated {current_version} -> {data['version']}"


def last_check(data_dir: Path) -> float:
    try:
        return float((data_dir / "ioc-last-check").read_text().strip())
    except Exception:
        return 0.0

"""Small file helpers shared by scanners and the protect layer."""

import hashlib
import re
from pathlib import Path
from typing import Tuple

FONT_EXTENSIONS = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
ASSET_MAGIC = {
    ".woff2": [(0, b"wOF2")],
    ".woff": [(0, b"wOFF")],
    ".ttf": [(0, b"\x00\x01\x00\x00"), (0, b"true"), (0, b"OTTO"), (0, b"ttcf")],
    ".otf": [(0, b"OTTO"), (0, b"\x00\x01\x00\x00")],
    ".eot": [(34, b"LP")],
    ".png": [(0, b"\x89PNG")],
    ".jpg": [(0, b"\xff\xd8\xff")],
    ".jpeg": [(0, b"\xff\xd8\xff")],
    ".gif": [(0, b"GIF87a"), (0, b"GIF89a")],
    ".ico": [(0, b"\x00\x00\x01\x00"), (0, b"\x00\x00\x02\x00")],
    ".webp": [(0, b"RIFF")],
}
# .dict files (spellright) are plain word lists; anything with code markers is a loader.
TEXT_ASSET_EXTENSIONS = {".dict"}

CODE_MARKERS = (b"<html", b"<!doc", b"<script", b"require(", b"global[", b"global.", b"function",
                b"eval(", b"const ", b"var ", b"let ", b"#!/", b"process.env", b"=>")

SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "vendor", "__pycache__",
             ".venv", "venv", "dist", "build", ".next", ".nuxt", ".cache",
             "target", ".gradle", ".idea", ".threatscan",
             # Browser profiles: multi-MB vendor bundles that legitimately reference RPCs.
             "google-chrome", "chromium", "BraveSoftware", "microsoft-edge",
             "Google", "Mozilla", "firefox", "Extensions", "Service Worker",
             "Cache", "Code Cache", "GPUCache", "IndexedDB", "Local Storage"}


def skip_dir(name: str) -> bool:
    return name in SKIP_DIRS


def sha256_of(path: Path, limit_bytes=50 * 1024 * 1024) -> str:
    try:
        if path.stat().st_size > limit_bytes:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def read_text(path: Path, limit_bytes=20 * 1024 * 1024) -> str:
    try:
        if path.stat().st_size > limit_bytes:
            return ""
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def read_bytes(path: Path, limit_bytes=20 * 1024 * 1024) -> bytes:
    try:
        if path.stat().st_size > limit_bytes:
            return b""
        return path.read_bytes()
    except Exception:
        return b""


def asset_verdict(path: Path, marker_regex) -> Tuple[str, str]:
    """Classify a font/image/dict file by content.

    Returns (verdict, detail):
      "real"    header matches the extension's magic bytes
      "code"    file is script/markup (loader payload)
      "text"    plain text where a binary is expected
      "unknown" unreadable or an unrecognised binary
    Leading whitespace is skipped before looking for code: PolinRider pads its
    loader with hundreds of spaces/tabs so the first bytes look blank.  The
    fa-solid-900 variant dropped the padding, which this handles too.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except Exception:
        return "unknown", ""
    if not head:
        return "text", "file is empty"
    ext = path.suffix.lower()
    for offset, sig in ASSET_MAGIC.get(ext, []):
        if head[offset:offset + len(sig)] == sig:
            return "real", ""
    if head.startswith(b"version https://git-lfs"):
        return "real", ""
    body = head.lstrip()
    pad = len(head) - len(body)
    pad_note = f" after {pad} bytes of whitespace padding" if pad >= 32 else ""
    low = body[:2048].lower()
    if any(m in low for m in CODE_MARKERS):
        marker = marker_regex.search(body.decode("latin-1"))
        return "code", (f"JavaScript/HTML{pad_note}" +
                        (f"; campaign marker: {marker.group(0)[:60]}" if marker else ""))
    if ext in TEXT_ASSET_EXTENSIONS:
        return "real", ""
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text", f"plain text{pad_note}"
        except UnicodeDecodeError:
            pass
    return "unknown", ""


def find_payload_cut(content: str, iocs) -> int:
    """Return the byte/char offset where an injected payload starts, or -1.

    The payload is appended after the legitimate export, usually on the same
    line after a long run of whitespace.  Strategy: locate the first campaign
    indicator; if a run of >=32 whitespace characters precedes it on the same
    line, cut at the start of that run; otherwise cut at the start of its line.
    """
    idx = -1
    m = iocs.marker_regex.search(content)
    if m:
        idx = m.start()
    for s in list(iocs.literal_signatures) + list(iocs.xor_keys):
        j = content.find(s)
        if j != -1 and (idx == -1 or j < idx):
            idx = j
    if idx == -1:
        return -1
    line_start = content.rfind("\n", 0, idx) + 1
    line_prefix = content[line_start:idx]
    pad = re.search(r"[ \t]{32,}", line_prefix)
    if pad:
        return line_start + pad.start()
    # The obfuscated block often starts a little before the first marker on
    # the same line (e.g. "(function(){...global['_V']=").  If there is code
    # before the marker on this line and no padding, keep the whole line out.
    return line_start

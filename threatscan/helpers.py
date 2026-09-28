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

# Every text file type the campaign has used to carry or launch a payload.
SCRIPT_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts",
                     ".json", ".jsonc", ".py", ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs",
                     ".html", ".htm", ".env", ".yml", ".yaml", ".toml", ".txt", ".md"}

# Files that legitimately contain campaign strings (signature databases, tests,
# detection rules) declare it with this token in their first 512 bytes.  It is
# never honoured for framework config files, entry files or binary assets.
ALLOW_TOKEN = "threatscan:allow-signatures"

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


def is_under(path: Path, roots) -> bool:
    """True if path equals or lies inside any of roots (path-component aware)."""
    try:
        p = Path(path).resolve()
    except Exception:
        p = Path(path)
    for r in roots:
        try:
            r = Path(r).expanduser().resolve()
        except Exception:
            r = Path(r).expanduser()
        if p == r or r in p.parents:
            return True
    return False


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


JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", ".html", ".htm"}


def is_allowlisted(path: Path, iocs) -> bool:
    if path.name in iocs.config_files or path.name in iocs.entry_files or path.name in iocs.fake_font_names:
        return False
    ext = path.suffix.lower()
    if ext in ASSET_MAGIC or ext in TEXT_ASSET_EXTENSIONS or ext in JS_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as fh:
            return ALLOW_TOKEN.encode() in fh.read(512)
    except Exception:
        return False


def evidence(content: str, iocs, limit=12) -> list:
    """Human-readable list of the concrete indicators found in `content`."""
    ev = []
    for sig in iocs.literal_signatures:
        if sig in content:
            ev.append(f"literal signature {sig!r}")
    for m in iocs.marker_regex.finditer(content):
        snippet = m.group(0)[:60]
        ev.append(f"campaign marker {snippet!r} at offset {m.start()}")
        if len(ev) >= limit:
            break
    for k in iocs.xor_keys:
        if k in content:
            ev.append(f"payload XOR key {k!r}")
    low = content.lower()
    for w in iocs.wallets:
        if w.lower() in low:
            ev.append(f"dead-drop wallet {w[:14]}...")
    for h in iocs.malicious_hosts:
        if h in content:
            ev.append(f"C2 host {h}")
    for ip in iocs.malicious_ips:
        if ip in content:
            ev.append(f"C2 IP {ip}")
    for p in iocs.c2_url_paths:
        if p in content and "http" in content:
            ev.append(f"C2 path {p}")
    for t in iocs.telegram_indicators:
        if t in content:
            ev.append("Telegram exfiltration bot id")
    pad = re.search(r"[ \t]{40,}\S", content)
    if pad:
        ev.append(f"{len(pad.group(0)) - 1} whitespace characters hiding code on one line")
    # de-dup, keep order
    seen, out = set(), []
    for e in ev:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out[:limit]


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

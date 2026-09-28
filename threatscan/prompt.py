"""Ask the user to decide about a file through a native dialog.

Returns one of: "delete", "keep", "timeout", "unavailable".
Linux: zenity / kdialog / yad / xmessage.  macOS: osascript display dialog.
Windows: WScript.Shell Popup via PowerShell (supports a timeout).
A terminal fallback is used when stdin is an interactive TTY.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List

from .findings import Finding

DELETE = "delete"
KEEP = "keep"
TIMEOUT = "timeout"
UNAVAILABLE = "unavailable"


def _ensure_display_env():
    """systemd --user / cron may lack DISPLAY; guess the usual session values."""
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return
    uid = os.getuid() if hasattr(os, "getuid") else 0
    run = Path(f"/run/user/{uid}")
    for cand in ("wayland-0", "wayland-1"):
        if (run / cand).exists():
            os.environ.setdefault("WAYLAND_DISPLAY", cand)
            break
    for n in range(0, 3):
        if Path(f"/tmp/.X11-unix/X{n}").exists():
            os.environ.setdefault("DISPLAY", f":{n}")
            break
    if (run / "bus").exists():
        os.environ.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={run}/bus")
    os.environ.setdefault("XDG_RUNTIME_DIR", str(run))


def build_message(f: Finding, action_word: str) -> str:
    lines = [f"Threat: {threat_name(f)}", f"File:   {f.path}", ""]
    ev: List[str] = f.meta.get("evidence") or []
    if ev:
        lines.append("Evidence:")
        lines += [f"  - {e}" for e in ev[:8]]
        if len(ev) > 8:
            lines.append(f"  - ... {len(ev) - 8} more")
    else:
        lines.append(f.details.strip())
    lines += ["", f"{action_word}?  The original is kept in ~/.threatscan/quarantine and can be restored."
              if action_word != "Delete the file" else
              f"{action_word}?  This removes it permanently (a record is kept in ~/.threatscan/quarantine/index.jsonl)."]
    return "\n".join(lines)


def ask(plat, f: Finding, action_word: str, timeout: int = 180) -> str:
    """Before-action dialog: <action_word> vs Keep."""
    title = f"ThreatScan: {f.severity.name} - {f.title}"
    return dialog(plat, title, build_message(f, action_word), action_word, "Keep", timeout)


def ask_quarantined(plat, f: Finding, timeout: int = 180) -> str:
    """Defender-style after-action dialog: the file is already in quarantine.
    DELETE = remove permanently, KEEP = restore the file and allow it."""
    title = f"ThreatScan: threat quarantined - {threat_name(f)}"
    ev: List[str] = f.meta.get("evidence") or []
    lines = [f"Threat: {threat_name(f)}", f"File:   {f.path}", "",
             "The file was quarantined and can no longer run.", ""]
    if ev:
        lines.append("Evidence:")
        lines += [f"  - {e}" for e in ev[:8]]
    lines += ["", "Remove it permanently, or restore it and allow this exact file?"]
    return dialog(plat, title, "\n".join(lines), "Remove", "Restore & allow", timeout)


def dialog(plat, title: str, msg: str, ok_label: str, cancel_label: str, timeout: int = 180) -> str:
    """The message (which quotes malware indicators) is handed to the dialog
    tool through a temp file, never on its command line: otherwise the guard's
    own process monitor (and Falco) would see campaign markers in a process
    argument list and kill the dialog."""
    fd, path = tempfile.mkstemp(prefix="threatscan-", suffix=".txt")
    started = time.time()
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(msg)
        if plat.is_linux:
            verdict = _ask_linux(title, path, ok_label, cancel_label, timeout)
        elif plat.is_macos:
            verdict = _ask_macos(title, path, ok_label, cancel_label, timeout)
        elif plat.is_windows:
            verdict = _ask_windows(title, path, ok_label, cancel_label, timeout)
        else:
            verdict = UNAVAILABLE
        # Defence in depth: a destructive answer that arrives exactly when the
        # dialog would have timed out is treated as a timeout, whatever the tool
        # reported.  Nothing is ever deleted because nobody answered.
        if verdict == DELETE and time.time() - started >= timeout - 0.5:
            return TIMEOUT
        return verdict
    except Exception:
        pass
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return UNAVAILABLE


THREAT_NAMES = {
    "config_injection": "Trojan:JS/PolinRider.ConfigInject",
    "xor_key": "Trojan:JS/PolinRider.ConfigInject",
    "entry_hook": "Trojan:JS/PolinRider.EntryHook",
    "fake_font_loader": "Trojan:JS/PolinRider.FakeFont",
    "disguised_payload": "Trojan:JS/PolinRider.Disguised",
    "vscode_autorun": "Trojan:Script/PolinRider.TaskJacker",
    "propagation_script": "Trojan:BAT/PolinRider.AutoPush",
    "blockchain_c2": "Trojan:JS/PolinRider.DeadDrop",
    "c2_reference": "Trojan:JS/PolinRider.C2",
    "telegram_exfil": "Trojan:JS/OmniStealer.Exfil",
    "git_hook": "Trojan:Script/PolinRider.GitHook",
    "compromised_package": "Trojan:JS/PolinRider.Package",
    "malicious_process": "Behavior:Node/PolinRider.Payload",
    "c2_connection": "Behavior:Net/PolinRider.C2",
    "rat_footprint": "Backdoor:JS/RuntimeDevLink",
    "stage4_runtime": "Backdoor:JS/RuntimeDevLink",
    "editor_injection": "Trojan:JS/PolinRider.EditorInject",
}


def threat_name(f: Finding) -> str:
    if f.category.startswith("persistence_"):
        return "Backdoor:Script/PolinRider.Persist"
    return THREAT_NAMES.get(f.category, "Trojan:Script/PolinRider")


def ask_terminal(f: Finding, action_word: str) -> str:
    if not sys.stdin or not sys.stdin.isatty():
        return UNAVAILABLE
    print()
    print(build_message(f, action_word))
    try:
        ans = input(f"  [{action_word[0].lower()}] {action_word} / [k] keep > ").strip().lower()
    except EOFError:
        return UNAVAILABLE
    return DELETE if ans in (action_word[0].lower(), "y", "yes", "delete", "remove") else KEEP


# ── per-OS implementations ────────────────────────────────────────────────────

def _ask_linux(title, msg_file, action_word, cancel_label, timeout):
    _ensure_display_env()
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return UNAVAILABLE
    if shutil.which("zenity"):
        r = subprocess.run(["zenity", "--text-info", f"--filename={msg_file}", "--width=640", "--height=420",
                            f"--title={title}", f"--ok-label={action_word}", f"--cancel-label={cancel_label}",
                            f"--timeout={timeout}"],
                           capture_output=True, timeout=timeout + 15)
        return {0: DELETE, 1: KEEP, 5: TIMEOUT}.get(r.returncode, UNAVAILABLE)
    if shutil.which("yad"):
        r = subprocess.run(["yad", "--text-info", f"--filename={msg_file}", "--image=dialog-warning", f"--title={title}",
                            f"--button={action_word}:0", f"--button={cancel_label}:1", f"--timeout={timeout}",
                            "--width=640", "--height=420"],
                           capture_output=True, timeout=timeout + 15)
        return {0: DELETE, 1: KEEP, 70: TIMEOUT}.get(r.returncode, UNAVAILABLE)
    if shutil.which("kdialog"):
        # kdialog has no file option for yes/no; the text goes on the command
        # line, which the process monitor tolerates because the title says ThreatScan.
        text = Path(msg_file).read_text(encoding="utf-8")
        r = subprocess.run(["kdialog", "--title", title, "--warningyesno", text,
                            "--yes-label", action_word, "--no-label", cancel_label],
                           capture_output=True, timeout=timeout + 15)
        return DELETE if r.returncode == 0 else KEEP
    if shutil.which("xmessage"):
        r = subprocess.run(["xmessage", "-center", "-timeout", str(timeout), "-title", title,
                            "-buttons", f"{action_word}:0,{cancel_label}:1", "-file", msg_file],
                           capture_output=True, timeout=timeout + 15)
        return {0: DELETE, 1: KEEP}.get(r.returncode, TIMEOUT)
    return UNAVAILABLE


def _esc_markup(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _ask_macos(title, msg_file, action_word, cancel_label, timeout):
    def q(x):
        return x.replace("\\", "\\\\").replace('"', '\\"')
    script = (f'set msg to read POSIX file "{q(msg_file)}" as «class utf8»\n'
              f'display dialog msg with title "{q(title)}" with icon caution '
              f'buttons {{"{q(cancel_label)}", "{q(action_word)}"}} default button "{q(cancel_label)}" '
              f'cancel button "{q(cancel_label)}" giving up after {timeout}')
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=timeout + 15)
    out = r.stdout
    if "gave up:true" in out:
        return TIMEOUT
    if r.returncode != 0:            # cancel button -> "User canceled." (-128), exit 1
        return KEEP if "-128" in (r.stderr or "") or r.returncode == 1 else UNAVAILABLE
    return DELETE if f"button returned:{action_word}" in out else KEEP


def _ask_windows(title, msg_file, action_word, cancel_label, timeout):
    def q(x):
        return x.replace("'", "''")
    # vbYesNo(4) + vbExclamation(48) + vbDefaultButton2(256) + vbSystemModal(4096)
    ps = (f"$m = [IO.File]::ReadAllText('{q(msg_file)}'); "
          f"$s = New-Object -ComObject WScript.Shell; "
          f"$r = $s.Popup($m + \"`n`nYES = {q(action_word)}    NO = {q(cancel_label)}\", {int(timeout)}, '{q(title)}', 4 + 48 + 256 + 4096); "
          f"Write-Output $r")
    r = subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                       capture_output=True, text=True, timeout=timeout + 30,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    code = (r.stdout or "").strip().splitlines()[-1] if (r.stdout or "").strip() else ""
    return {"6": DELETE, "7": KEEP, "-1": TIMEOUT}.get(code, UNAVAILABLE)

"""Preventive hardening: editor settings, npm, git."""

import json
import re
import shutil
import time
from pathlib import Path
from typing import Dict, List, Tuple

# Settings that neutralise PolinRider's stage 1 (folderOpen tasks) and
# make VS Code ask before trusting a freshly cloned folder.
EDITOR_SETTINGS = {
    "task.allowAutomaticTasks": "off",
    "security.workspace.trust.enabled": True,
    "security.workspace.trust.startupPrompt": "always",
    "security.workspace.trust.untrustedFiles": "prompt",
    "security.workspace.trust.emptyWindow": False,
    "git.openRepositoryInParentFolders": "prompt",
}


def _strip_json_comments(text: str) -> str:
    """settings.json is JSONC. Remove // and /* */ comments and trailing commas
    without touching string contents (globs like "**/*.pyc" must survive)."""
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    cleaned = "".join(out)
    # trailing commas (outside strings now, since comments are gone and we only
    # touch ", }" / ", ]" sequences that cannot occur inside a JSON string value
    # without an escaped quote before them)
    return _strip_trailing_commas(cleaned)


def _strip_trailing_commas(text: str) -> str:
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def harden_editor(settings_path: Path, dry_run=False) -> Tuple[bool, List[str]]:
    """Merge EDITOR_SETTINGS into a user settings.json.  Returns (changed, notes)."""
    notes = []
    data: Dict = {}
    if settings_path.is_file():
        raw = settings_path.read_text(encoding="utf-8", errors="ignore")
        try:
            data = json.loads(_strip_json_comments(raw)) if raw.strip() else {}
        except Exception as e:
            return False, [f"could not parse {settings_path} ({e}); set task.allowAutomaticTasks=off by hand"]
        if not isinstance(data, dict):
            return False, [f"{settings_path} is not a JSON object"]
    changed = False
    for k, v in EDITOR_SETTINGS.items():
        if data.get(k) != v:
            notes.append(f"{k}: {data.get(k, '<unset>')!r} -> {v!r}")
            data[k] = v
            changed = True
    if changed and not dry_run:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        if settings_path.is_file():
            shutil.copy2(settings_path, settings_path.with_suffix(f".json.threatscan-{int(time.time())}.bak"))
        settings_path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
    return changed, notes


def harden_npm(home: Path, dry_run=False) -> Tuple[bool, str]:
    """Set ignore-scripts=true in ~/.npmrc (opt-in: breaks packages that need postinstall)."""
    rc = home / ".npmrc"
    content = rc.read_text(encoding="utf-8", errors="ignore") if rc.is_file() else ""
    if re.search(r"(?m)^\s*ignore-scripts\s*=\s*true\s*$", content):
        return False, "already set"
    content = re.sub(r"(?m)^\s*ignore-scripts\s*=.*\n?", "", content)
    content = content.rstrip("\n") + ("\n" if content.strip() else "") + "ignore-scripts=true\n"
    if not dry_run:
        rc.write_text(content, encoding="utf-8")
    return True, "ignore-scripts=true written (run `npm rebuild` / `npm install --ignore-scripts=false` for packages that need it)"


def unharden_npm(home: Path) -> bool:
    rc = home / ".npmrc"
    if not rc.is_file():
        return False
    content = rc.read_text(encoding="utf-8", errors="ignore")
    new = re.sub(r"(?m)^\s*ignore-scripts\s*=\s*true\s*\n?", "", content)
    if new != content:
        rc.write_text(new, encoding="utf-8")
        return True
    return False


def editor_status(settings_path: Path) -> Dict[str, object]:
    if not settings_path.is_file():
        return {}
    try:
        data = json.loads(_strip_json_comments(settings_path.read_text(encoding="utf-8", errors="ignore")) or "{}")
    except Exception:
        return {"parse_error": True}
    return {k: data.get(k, "<unset>") for k in EDITOR_SETTINGS}


PRE_COMMIT_HOOK = r'''#!/bin/sh
# ThreatScan pre-commit hook: refuse to commit files with PolinRider indicators.
if command -v threatscan >/dev/null 2>&1; then
  threatscan check-staged || exit 1
elif [ -n "$THREATSCAN_PY" ]; then
  "$THREATSCAN_PY" -m threatscan check-staged || exit 1
fi
exit 0
'''


def install_pre_commit(repo: Path, dry_run=False) -> Tuple[bool, str]:
    hooks = repo / ".git" / "hooks"
    if not hooks.is_dir():
        return False, f"{repo} is not a git repository"
    hook = hooks / "pre-commit"
    if hook.exists():
        existing = hook.read_text(errors="ignore")
        if "threatscan" in existing:
            return False, "already installed"
        # chain: keep the existing hook, call it after ours
        if not dry_run:
            shutil.move(str(hook), str(hooks / "pre-commit.pre-threatscan"))
        body = PRE_COMMIT_HOOK.replace("exit 0\n", 'exec "$(dirname "$0")/pre-commit.pre-threatscan" "$@"\n')
    else:
        body = PRE_COMMIT_HOOK
    if not dry_run:
        hook.write_text(body)
        hook.chmod(0o755)
    return True, f"installed {hook}"

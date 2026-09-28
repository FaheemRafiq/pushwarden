# threatscan:allow-signatures
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolated THREATSCAN_HOME so tests never touch the real ~/.threatscan."""
    d = tmp_path / "tshome"
    d.mkdir()
    monkeypatch.setenv("THREATSCAN_HOME", str(d))
    return d


# ── Inert fixtures ────────────────────────────────────────────────────────────
# These reproduce the *shape* of PolinRider artefacts (marker strings, padding,
# fake magic bytes) with no working code.  Nothing here connects anywhere.

CLEAN_POSTCSS = "export default {\n  plugins: { '@tailwindcss/postcss': {} },\n};\n"

INFECTED_POSTCSS = (
    "export default {\n  plugins: { '@tailwindcss/postcss': {} },\n};" + " " * 280 +
    "global['_V']='8-st17';(function(){var MDy=function(){return 'inert'};})();\n"
)

FAKE_WOFF2 = (b"\t" * 421 + b"var a = require('inert'); global['!']='A10-010'; // not a font\n")

TASKS_JSON = """{
  "version": "2.0.0",
  "tasks": [{
    "label": "setup",
    "type": "shell",
    "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-900.woff2) || true",
    "runOptions": { "runOn": "folderOpen" },
    "presentation": { "reveal": "never", "echo": false }
  }]
}
"""


@pytest.fixture
def infected_repo(tmp_path):
    repo = tmp_path / "victim"
    (repo / ".git").mkdir(parents=True)
    (repo / ".vscode").mkdir()
    (repo / "public" / "fonts").mkdir(parents=True)
    (repo / "postcss.config.mjs").write_text(INFECTED_POSTCSS)
    (repo / "public" / "fonts" / "fa-solid-900.woff2").write_bytes(FAKE_WOFF2)
    (repo / ".vscode" / "tasks.json").write_text(TASKS_JSON)
    (repo / "temp_auto_push.bat").write_text("@echo off\nrem inert\n")
    (repo / ".gitignore").write_text("node_modules\ntemp_auto_push.bat\n.gitignore\n")
    (repo / "package.json").write_text('{"dependencies": {"tailwindcss-style-animate": "^1.1.6"}}')
    return repo


@pytest.fixture
def clean_repo(tmp_path):
    repo = tmp_path / "clean"
    (repo / ".git").mkdir(parents=True)
    (repo / "public" / "fonts").mkdir(parents=True)
    (repo / "postcss.config.mjs").write_text(CLEAN_POSTCSS)
    (repo / "public" / "fonts" / "fa-solid-900.woff2").write_bytes(b"wOF2" + b"\x00" * 100)
    (repo / "package.json").write_text('{"dependencies": {"react": "^19.0.0"}}')
    return repo

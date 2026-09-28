#!/usr/bin/env python3
"""ThreatScan compatibility entry point.

The scanner now lives in the ``threatscan`` package (this directory).  This
file keeps ``python3 threat_scanner.py [options] [dirs]`` working for scripts
and CI jobs written against v4.x.  For a single-file download use the
``threatscan.pyz`` build from the Releases page instead.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from threatscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

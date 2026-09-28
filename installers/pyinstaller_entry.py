"""Entry point for the PyInstaller single-file build (absolute import required)."""
import sys

from threatscan.cli import main

if __name__ == "__main__":
    sys.exit(main())

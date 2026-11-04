"""Frozen entry point for PyInstaller / nicegui-pack builds."""

from __future__ import annotations

from opsai.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

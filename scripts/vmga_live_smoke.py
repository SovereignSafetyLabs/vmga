#!/usr/bin/env python3
"""Run the importable VMGA live smoke helper from a checkout."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vmga.live_smoke import main


if __name__ == "__main__":
    raise SystemExit(main())

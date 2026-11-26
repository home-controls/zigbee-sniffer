"""The app's modules import each other by plain name (they run from /app in the container), so
the tests put ../app on sys.path. ../dev holds the simulators (test_devsim.py)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
DEV = ROOT / "dev"
for p in (APP, DEV):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

#!/usr/bin/env python3
"""Generate manuscript variables from the live system → output/data/manuscript_variables.json.

Thin orchestrator over ``src/manuscript_vars.py``. Every value is derived from a code
constant or the repository, so the manuscript never hard-codes a drift-prone number.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from manuscript_vars import variables
from project_paths import ensure_output_dirs


def main() -> int:
    dirs = ensure_output_dirs()
    out = dirs["data"] / "manuscript_variables.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(variables(), indent=2, sort_keys=True))
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

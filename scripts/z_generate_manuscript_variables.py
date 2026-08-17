#!/usr/bin/env python3
"""Generate manuscript variables from the live system → output/data/manuscript_variables.json.

Thin orchestrator over ``src/docxplus/manuscript_vars.py``. Every value is derived from a code
constant or the repository, so the manuscript never hard-codes a drift-prone number.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Installed, `docxplus` is a real package and this is a no-op. Run out of a checkout
# the package lives under src/ and nothing has put it on the path yet. Importing
# first keeps an installed copy authoritative instead of being shadowed.
try:  # pragma: no cover - one branch or the other, trivially
    import docxplus as _docxplus  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from docxplus.manuscript_vars import variables
from docxplus.project_paths import ensure_output_dirs


def main() -> int:
    dirs = ensure_output_dirs()
    out = dirs["data"] / "manuscript_variables.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(variables(), indent=2, sort_keys=True))
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

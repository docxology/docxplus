#!/usr/bin/env python3
"""Generate the manuscript figures.

Thin orchestrator: every plate is drawn by ``docxplus.manuscript_figures``; this
script bootstraps the package path, skips loudly without failing when matplotlib
is absent, and delegates the capacity figure to its numbered pipeline stage.

Builds:
  - output/figures/cover.png                  Cover plate
  - output/figures/architecture.png           Fig 1: dual-contract package topology
  - output/figures/cryptographic_pipeline.png Fig 2: sealing lineages and provenance
  - output/figures/capacity.png               Fig 3: per-channel payload capacity
  - output/figures/reproduction_lifecycle.png Fig 4: reproduction and transparency
  - output/figures/redteam_matrix.png         Fig 5: threat model and hardening

Every number a figure prints is read from ``manuscript_vars.variables()`` — the same
source the manuscript prose draws its ``{{TOKENS}}`` from. Figures used to carry
hand-typed values and drifted: one advertised a 255-byte metadata ceiling against an
actual 8000, and another a PBKDF2 count from the legacy compatibility API rather than
the shipped one. A figure is a claim; it derives from the code like every other claim.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Installed, `docxplus` is a real package and this is a no-op. Run out of a checkout
# the package lives under src/ and nothing has put it on the path yet. Importing
# first keeps an installed copy authoritative instead of being shadowed.
try:  # pragma: no cover - one branch or the other, trivially
    import docxplus as _docxplus  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    import matplotlib  # noqa: F401
except ImportError:
    sys.stderr.write("matplotlib not installed; skipping figure generation\n")
    sys.exit(0)

from docxplus.manuscript_figures import main as build_plates


def main() -> int:
    build_plates()

    # The capacity figure is a numbered pipeline stage in its own right; composing
    # it here keeps a single `build_figures.py` invocation — and therefore the
    # `render` stage — producing every plate, as it always has.
    subprocess.run([sys.executable, str(Path(__file__).parent / "03_capacity_figure.py")], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

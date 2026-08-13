#!/usr/bin/env python3
"""Plot per-channel payload capacity (optional; needs matplotlib).

Illustrates the engineering trade-off the format exposes: metadata is a
short-string channel, custom-XML / package-part are effectively unbounded, and the
media channel scales with carrier pixels. Writes ``output/figures/capacity.png``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from project_paths import ensure_output_dirs


def main() -> int:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        sys.stderr.write("matplotlib not installed; skipping (uv sync --extra figures)\n")
        return 0

    import lsb
    from channels.metadata import MAX_PAYLOAD

    labels = ["metadata", "custom_xml", "package_part", "stego 256²", "stego 512²"]
    # custom_xml / package_part are unbounded; show a representative 1 MiB bar.
    values = [MAX_PAYLOAD, 1_048_576, 1_048_576, lsb.capacity_bytes(256, 256), lsb.capacity_bytes(512, 512)]

    dirs = ensure_output_dirs()
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(labels, values, color="#3B82F6")
    ax.set_ylabel("payload capacity (bytes, log)")
    ax.set_yscale("log")
    ax.set_title("DOCX+ per-channel payload capacity")
    fig.tight_layout()
    out = dirs["figures"] / "capacity.png"
    fig.savefig(out, dpi=120)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

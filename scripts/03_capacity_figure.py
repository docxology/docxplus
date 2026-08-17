#!/usr/bin/env python3
"""Plot per-channel payload capacity (optional; needs matplotlib).

The point of the figure is that the five channels do not have *comparable* limits,
so putting them side by side as bars was the wrong shape. Three are bounded only by
what a ZIP will hold; one has a hard, carrier-independent ceiling in the format; one
scales with carrier area. A bar chart forced the unbounded three to stand at an
invented height — a 1 MiB stand-in that a reader had no way to distinguish from a
measurement, and that put the visual emphasis on the one number in the plot that
meant nothing.

This version plots the axis the differences actually live on: carrier size. The
media channel becomes a line with slope 2 in log-log (capacity goes with area), the
metadata ceiling a flat rule that the line crosses at a computable point, and the
unbounded channels a band with no upper edge drawn, because there is none to draw.

Every stego point is **measured, not asserted**: a payload of exactly the stated
capacity is embedded into a real carrier and extracted again, and the point is only
plotted filled if the bytes came back identical. Writes ``output/figures/capacity.png``.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

# Installed, `docxplus` is a real package and this is a no-op. Run out of a checkout
# the package lives under src/ and nothing has put it on the path yet. Importing
# first keeps an installed copy authoritative instead of being shadowed.
try:  # pragma: no cover - one branch or the other, trivially
    import docxplus as _docxplus  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from docxplus.project_paths import ensure_output_dirs

#: Square carrier edges that are actually round-tripped. Kept square because the
#: capacity law depends on the pixel *count*, so one dimension tells the whole story.
MEASURED_EDGES = (64, 128, 256, 512, 1024)

SEAL = "#7C3AED"
WARN = "#D97706"
INK = "#0F172A"
MUTED = "#64748B"
RULE = "#CBD5E1"


def _fmt(n: float) -> str:
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MiB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f} KiB"
    return f"{int(n)} B"


def measure(edge: int) -> tuple[int, bool]:
    """Capacity of an ``edge``×``edge`` carrier, and whether it survives a real trip.

    Filling a carrier to its exact stated capacity is the case where an off-by-one in
    the header accounting would show up, so it is the case worth running.
    """
    from docxplus import lsb

    capacity = lsb.capacity_bytes(edge, edge)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        carrier = lsb.make_carrier(tmp / "carrier.png", (edge, edge))
        seed = hashlib.sha256(f"docxplus-capacity-{edge}".encode()).digest()
        payload = (seed * (capacity // len(seed) + 1))[:capacity]
        stego = lsb.embed(carrier, payload, tmp / "stego.png")
        return capacity, lsb.extract(stego) == payload


def main() -> int:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        sys.stderr.write("matplotlib not installed; skipping (uv sync --extra figures)\n")
        return 0

    from docxplus import lsb
    from docxplus.channels.metadata import MAX_PAYLOAD

    measured = [(e, *measure(e)) for e in MEASURED_EDGES]
    if not all(ok for _, _, ok in measured):
        failed = [e for e, _, ok in measured if not ok]
        sys.stderr.write(f"capacity round trip failed at edges {failed}\n")
        return 1

    fig, ax = plt.subplots(figsize=(8.6, 5.0), dpi=300)

    # -- the unbounded three: a band with no top, because there is no top ------
    top = 1 << 25
    ax.axhspan(1 << 23, top, color="#94A3B8", alpha=0.12, zorder=0)
    ax.text(38, (1 << 24),
            "custom_xml  ·  package_part  ·  mce\n"
            "no channel-imposed ceiling — bounded by the package, not the format",
            fontsize=8.2, color=INK, va="center", ha="left", fontweight="bold",
            linespacing=1.6)

    # -- metadata: a hard ceiling, flat in carrier size -----------------------
    ax.axhline(MAX_PAYLOAD, color=SEAL, lw=2.0, zorder=3)
    ax.text(3400, MAX_PAYLOAD * 1.35, f"metadata — {MAX_PAYLOAD:,} B, fixed by the format",
            fontsize=8.4, color=SEAL, fontweight="bold", ha="right", va="bottom")

    # -- stego_media: the scaling law, drawn continuous and marked where measured
    edges = np.logspace(np.log10(32), np.log10(4096), 240)
    ax.plot(edges, [lsb.capacity_bytes(int(e), int(e)) for e in edges],
            color=WARN, lw=2.2, zorder=4)
    ax.scatter([e for e, _, _ in measured], [c for _, c, _ in measured],
               s=52, color=WARN, edgecolor="#FFFFFF", lw=1.4, zorder=6)
    for edge, capacity, _ in measured:
        ax.annotate(f"{edge}×{edge}\n{_fmt(capacity)}", (edge, capacity),
                    textcoords="offset points", xytext=(0, 15), ha="center",
                    fontsize=7.4, color=INK, fontweight="bold", linespacing=1.35)
    ax.text(4000, 2.2e3, "stego_media — 3 bits per pixel,\nless an 8-byte frame",
            fontsize=8.4, color=WARN, fontweight="bold", ha="right", va="center",
            linespacing=1.5)

    # -- where the scaling line overtakes the fixed ceiling -------------------
    crossover = next(e for e in range(16, 4096) if lsb.capacity_bytes(e, e) >= MAX_PAYLOAD)
    ax.plot([crossover, crossover], [1e2, MAX_PAYLOAD], color=MUTED, lw=1.0,
            ls=(0, (2, 2.5)), zorder=2)
    ax.annotate(f"a {crossover}×{crossover} carrier holds\nmore than the metadata channel ever can",
                (crossover, 3.2e2), textcoords="offset points", xytext=(12, 0),
                ha="left", va="center", fontsize=7.6, color=MUTED, style="italic",
                linespacing=1.5)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(32, 4096)
    ax.set_ylim(1e2, top)
    ax.set_xticks([32, 64, 128, 256, 512, 1024, 2048, 4096])
    ax.set_xticklabels(["32", "64", "128", "256", "512", "1024", "2048", "4096"], fontsize=8.5)
    ax.set_xlabel("carrier edge (pixels, square)", fontsize=9)
    ax.set_ylabel("payload capacity (bytes)", fontsize=9)
    ax.set_title("What bounds each channel", fontsize=12.5, fontweight="bold",
                 color=INK, pad=26)
    ax.text(0.5, 1.035,
            "Marked points are measured: a payload of exactly that size was embedded and read back",
            transform=ax.transAxes, fontsize=8.6, color=MUTED, ha="center", style="italic")
    ax.grid(color=RULE, lw=0.6, alpha=0.65)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(RULE)
    ax.spines["bottom"].set_color(RULE)

    fig.tight_layout()
    out = ensure_output_dirs()["figures"] / "capacity.png"
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

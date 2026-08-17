#!/usr/bin/env python3
"""Generate the manuscript figures.

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

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from project_paths import ensure_output_dirs

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.patches as patches
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    sys.stderr.write("matplotlib not installed; skipping figure generation\n")
    sys.exit(0)

import manuscript_vars

# -- shared visual language ---------------------------------------------------
INK = "#0F172A"      # primary text
MUTED = "#64748B"    # subtitles, secondary text
BODY = "#334155"     # body text
RULE = "#CBD5E1"     # hairlines
PANEL = "#F8FAFC"    # panel fill

SURFACE = "#2563EB"  # the surface contract, throughout
INTEL = "#059669"    # the intelligence contract, throughout
SEAL = "#7C3AED"     # crypto / provenance
WARN = "#D97706"     # execution
RISK = "#DC2626"     # adversarial

# Per-channel colour, held constant across every figure so a reader can track a
# channel between the topology, capacity, and pipeline plots.
CHANNEL_COLOR = {
    "custom_xml": "#2563EB",
    "package_part": "#059669",
    "metadata": "#7C3AED",
    "stego_media": "#D97706",
    "mce": "#DB2777",
}


def _fmt(n: int) -> str:
    """Human-readable byte count for axis and badge labels."""
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MiB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f} KiB"
    return f"{n} B"


def _titles(ax, x, title, subtitle, y_title, y_sub):
    ax.text(x, y_title, title, color=INK, fontsize=13.5, fontweight="bold", ha="center")
    ax.text(x, y_sub, subtitle, color=MUTED, fontsize=9, ha="center", style="italic")


def _canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h), dpi=300)
    ax.set_facecolor("#FFFFFF")
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    return fig, ax


# -- cover --------------------------------------------------------------------
def build_cover_art(out_path: Path, v: dict) -> None:
    """Cover plate.

    The dark ground is set on the *figure*, not the axes: ``ax.axis("off")`` hides
    the axes patch, so an axes-level facecolor silently renders white and the
    low-contrast type on top of it becomes unreadable.
    """
    fig = plt.figure(figsize=(11, 6.8), dpi=300, facecolor="#090D16")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 6.8)
    ax.axis("off")
    ax.add_patch(patches.Rectangle((0, 0), 11, 6.8, fc="#090D16", ec="none", zorder=0))

    for row in range(-1, 9):
        for col in range(-1, 14):
            hx = col * 0.95 + (row % 2) * 0.475
            ax.add_patch(patches.RegularPolygon(
                (hx, row * 0.85), numVertices=6, radius=0.42, fill=False,
                edgecolor="#1E293B", linewidth=0.4, alpha=0.55, zorder=1))
    for r, a in zip(np.linspace(0.4, 3.2, 16), np.linspace(0.12, 0.01, 16)):
        ax.add_patch(plt.Circle((5.5, 3.4), r, color="#0284C7", alpha=a, zorder=1))

    ax.text(5.5, 5.98, "D O C X +", color="#38BDF8", fontsize=33, fontweight="heavy",
            ha="center", va="center", zorder=10)
    ax.text(5.5, 5.42, "An Intelligent Document Container over Standards-Conforming OOXML",
            color="#E2E8F0", fontsize=12.5, fontweight="semibold", ha="center", va="center", zorder=10)
    ax.text(5.5, 5.04, "Daniel Ari Friedman  ·  Active Inference Institute  ·  ORCID: 0000-0001-6232-9096",
            color="#94A3B8", fontsize=9.5, ha="center", va="center", zorder=10)

    def card(x, edge, fill_head, head, rows):
        ax.add_patch(patches.FancyBboxPatch((x, 1.15), 4.0, 3.35, boxstyle="round,pad=0.12",
                                            ec=edge, fc="#0F172A", lw=2, zorder=5))
        ax.add_patch(patches.FancyBboxPatch((x, 4.05), 4.0, 0.45, boxstyle="round,pad=0.07",
                                            ec=edge, fc=fill_head, lw=1.5, zorder=6))
        ax.text(x + 2.0, 4.27, head, color="#FFFFFF", fontsize=10.5, fontweight="bold",
                ha="center", va="center", zorder=7)
        for idx, (title, detail) in enumerate(rows):
            y = 3.62 - idx * 0.49
            ax.text(x + 0.26, y + 0.10, f"• {title}", color=edge, fontsize=8.8,
                    fontweight="bold", zorder=6)
            ax.text(x + 0.42, y - 0.11, detail, color="#CBD5E1", fontsize=7.4, zorder=6)

    card(0.5, "#38BDF8", "#0284C7", "Surface Contract (ISO/IEC 29500)", [
        ("Structural index", "[Content_Types].xml, _rels/.rels"),
        ("Visible narrative", "word/document.xml and story parts"),
        ("Document metadata", "docProps/core.xml, docProps/app.xml"),
        ("Conforming consumers", "Word, LibreOffice, Google Docs, Pages"),
        ("Archival openability", "no whole-package MS-OFFCRYPTO wrapper"),
    ])
    card(6.5, "#34D399", "#059669", "Intelligence Contract (modular payloads)", [
        ("Authoritative manifest", "intelligence/manifest.json"),
        ("Sealing lineages", f"Argon2id / Scrypt + AES-{v['KEY_BITS']}-GCM / X25519"),
        ("Threshold quorums", f"(k, n) Shamir with VSS, n \u2264 {v['SHAMIR_MAX_SHARES']}"),
        ("Narrative provenance", "signed Merkle root + surface digest"),
        ("Reproducible execution", "opt-in sandbox + anchored transparency log"),
    ])

    ax.add_patch(patches.FancyBboxPatch((4.78, 2.25), 1.44, 1.15, boxstyle="round,pad=0.09",
                                        ec="#F59E0B", fc="#1E293B", lw=2, zorder=8))
    ax.text(5.5, 3.05, "Ed25519", color="#FBBF24", fontsize=10, fontweight="bold",
            ha="center", va="center", zorder=9)
    ax.text(5.5, 2.72, "SIGNED", color="#FBBF24", fontsize=8.5, fontweight="bold",
            ha="center", va="center", zorder=9)
    ax.text(5.5, 2.45, "PROVENANCE", color="#FDE68A", fontsize=7, fontweight="bold",
            ha="center", va="center", zorder=9)
    ax.annotate("", xy=(4.62, 2.83), xytext=(4.76, 2.83),
                arrowprops=dict(arrowstyle="->", color="#F59E0B", lw=2), zorder=8)
    ax.annotate("", xy=(6.38, 2.83), xytext=(6.24, 2.83),
                arrowprops=dict(arrowstyle="->", color="#F59E0B", lw=2), zorder=8)

    ax.text(5.5, 0.62,
            f"v{v['VERSION']}  ·  {v['CHANNEL_COUNT']} transport channels  ·  "
            f"{v['TEST_COUNT']} mock-free test functions at a {v['COVERAGE_GATE']}% gate  ·  dual OOXML/ODF profile",
            color="#94A3B8", fontsize=9, ha="center", va="center", zorder=10)

    fig.savefig(out_path, dpi=300, facecolor="#090D16", edgecolor="none")
    plt.close(fig)
    print(f"Generated: {out_path}")


# -- Figure 1: dual-contract topology ----------------------------------------
def build_architecture_diagram(out_path: Path, v: dict) -> None:
    """The package tree and the channel list, aligned into one figure.

    They used to be two side-by-side panels: a tree on the left, a channel table on
    the right, and nothing connecting them. A reader had to match path strings by eye
    to learn which part a channel actually writes into. Placing each channel on the
    row of the part it occupies makes that mapping positional, and it exposes the
    architectural point the two-panel version buried — three of the five channels
    write into parts the surface contract *already requires*, so carrying a payload
    adds no part a conforming reader would find surprising. The rows with no badge
    are the parts that stay pure surface.
    """
    fig, ax = _canvas(11.6, 7.6)
    _titles(ax, 5.8, "One archive, two contracts",
            "Each channel is drawn on the row of the package part it writes into",
            7.30, 6.96)

    ax.text(0.50, 6.52, "OPC package layout", color=INK, fontsize=9.6,
            fontweight="bold", ha="left")
    ax.text(5.30, 6.52, "transport channel", color=INK, fontsize=9.6,
            fontweight="bold", ha="left")
    ax.text(11.35, 6.52, "capacity", color=INK, fontsize=9.6,
            fontweight="bold", ha="right")
    ax.plot([0.45, 11.35], [6.38, 6.38], color=INK, lw=1.1)

    #: depth, path, contract, note, channel-or-None. Ordered so that every connector
    #: runs straight across its own row and none crosses another.
    tree = [
        (0, "report.docx", None, "ZIP / OPC package", None),
        (1, "[Content_Types].xml", "surface", "mandatory type index", None),
        (1, "_rels/.rels", "surface", "package relationships", None),
        (1, "docProps/custom.xml", "both", "document properties", "metadata"),
        (1, "word/document.xml", "both", "the main story part", "mce"),
        (2, "media/imageN.png", "both", "a figure the document displays", "stego_media"),
        (1, "customXml/itemN.xml", "intel", "custom XML datastore", "custom_xml"),
        (1, "intelligence/manifest.json", "intel", "the signed root of the second contract", None),
        (1, "intelligence/payloadN.dxp", "intel", "additional package parts", "package_part"),
    ]
    detail = {
        "metadata": ("base64 in a named custom property",
                     f"≤ {int(v['METADATA_MAX_BYTES']):,} B"),
        "mce": ("<mc:Choice> under an ignorable namespace", "unbounded"),
        "stego_media": ("least-significant bits of the carrier's pixels", "pixel-bounded"),
        "custom_xml": ("base64 in a custom XML datastore part", "unbounded"),
        "package_part": ("raw bytes under a declared content type", "unbounded"),
    }
    BAR = {"surface": [SURFACE], "intel": [INTEL], "both": [SURFACE, INTEL]}

    for i, (depth, name, contract, note, cid) in enumerate(tree):
        y = 6.00 - i * 0.575
        x = 0.50 + depth * 0.34
        if contract is None:
            ax.text(x, y, name, color=INK, fontsize=9.4, fontweight="bold",
                    fontfamily="monospace", va="center")
        else:
            # A "both" part gets a split bar: it is mandated by the surface contract
            # and reused as intelligence transport. That reuse is the whole design.
            segs = BAR[contract]
            for k, col in enumerate(segs):
                ax.add_patch(patches.Rectangle(
                    (x - 0.07, y - 0.13 + k * 0.26 / len(segs)), 0.09, 0.26 / len(segs),
                    ec="none", fc=col))
            ax.text(x + 0.10, y, name, color=INK, fontsize=8.7,
                    fontfamily="monospace", va="center")
        ax.text(x + 0.10, y - 0.225, note, color=MUTED, fontsize=7.0, va="center")

        if cid is None:
            continue
        col = CHANNEL_COLOR[cid]
        how, cap = detail[cid]
        ax.plot([x + 0.26 + 0.0785 * len(name), 5.22], [y, y],
                color=col, lw=0.9, ls=(0, (2, 2.4)), alpha=0.85, zorder=1)
        ax.add_patch(patches.FancyBboxPatch((5.28, y - 0.21), 1.72, 0.42,
                                            boxstyle="round,pad=0.05", ec=col, fc=col,
                                            alpha=0.15, lw=1.4, zorder=2))
        ax.text(6.14, y, cid, color=col, fontsize=8.8, fontweight="bold",
                ha="center", va="center", zorder=3)
        ax.text(7.16, y, how, color=BODY, fontsize=7.8, va="center")
        ax.text(11.35, y, cap, color=MUTED, fontsize=7.8, ha="right", va="center",
                fontweight="bold")

    ax.plot([0.45, 11.35], [1.02, 1.02], color=RULE, lw=0.9)
    legend = [
        ([SURFACE], "surface contract"),
        ([INTEL], "intelligence contract"),
        ([SURFACE, INTEL], "a surface part reused as transport"),
    ]
    lx = 0.50
    for segs, text in legend:
        for k, col in enumerate(segs):
            ax.add_patch(patches.Rectangle((lx, 0.62 + k * 0.20 / len(segs)), 0.09,
                                           0.20 / len(segs), ec="none", fc=col))
        ax.text(lx + 0.17, 0.72, text, color=BODY, fontsize=7.8, va="center")
        lx += 0.50 + 0.062 * len(text)

    ax.text(5.9, 0.10,
            f"All {v['CHANNEL_COUNT']} channels are spec-sanctioned: each writes a construct its "
            "format defines and conforming consumers already ignore. A row with no badge is a part\n"
            "that stays pure surface. The manifest is authoritative — a reader resolves modules by "
            "declaration, never by scanning ZIP entries for things that look like payloads.",
            color=INK, fontsize=7.9, ha="center", va="bottom", style="italic",
            linespacing=1.5)

    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {out_path}")


# -- Figure 2: sealing lineages and provenance --------------------------------
def _arrow(ax, x0, y0, x1, y1, color=None, lw=1.6, style="->"):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle=style, color=color or "#94A3B8", lw=lw,
                                shrinkA=0, shrinkB=0))


def _node(ax, x, y, w, h, label, sub=None, ec=INK, fc="#FFFFFF", fs=8.6, lw=1.5):
    ax.add_patch(patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.055",
                                        ec=ec, fc=fc, lw=lw))
    cy = y + h / 2 + (0.10 if sub else 0)
    ax.text(x + w / 2, cy, label, color=INK, fontsize=fs, fontweight="bold",
            ha="center", va="center")
    if sub:
        ax.text(x + w / 2, y + h / 2 - 0.16, sub, color=MUTED, fontsize=6.9,
                ha="center", va="center", linespacing=1.35)


def build_crypto_diagram(out_path: Path, v: dict) -> None:
    """The sealing pipeline as a dataflow, not a bulleted list.

    The previous version was three columns of prose in a PNG: its layout carried no
    information a reader could not get from the paragraph beside it, and the
    typography was worse than the surrounding LaTeX. What matters about sealing is the
    *path* a payload takes — pack, branch by mode, place, digest, bind, sign — so the
    figure draws that path and lets the branch structure do the explaining.

    Lane order is deliberate: `password` sits last so the key-derivation box can hang
    directly beneath it. Ordering it first forced the KDF arrow to cross two unrelated
    lanes, which read as a dependency that does not exist.
    """
    fig, ax = _canvas(11.6, 7.9)
    _titles(ax, 5.8, "How a payload becomes a signed module",
            "One path, branching only at the sealing mode; every branch reconverges on the same digest",
            7.55, 7.18)

    SPINE_Y = 5.05

    _node(ax, 0.30, 4.67, 1.52, 0.76, "typed payload",
          "bytes · text · json\nproject · docxplus", ec=SURFACE, fc="#EFF6FF")
    _node(ax, 2.12, 4.67, 1.20, 0.76, "pack", "the type owns\nthe encoding", ec=SURFACE, fc="#EFF6FF")
    _arrow(ax, 1.84, SPINE_Y, 2.10, SPINE_Y, SURFACE)

    lanes = [
        ("plain", "no envelope", "#64748B", "#F8FAFC"),
        ("recipients", "DXE2 · X25519\none wrapped key per recipient", "#0891B2", "#ECFEFF"),
        ("threshold", f"content key split k-of-n\nVSS tagged, n \u2264 {v['SHAMIR_MAX_SHARES']}", SEAL, "#F5F3FF"),
        ("password", f"DXE1 · AES-{v['KEY_BITS']}-GCM\n+ an indistinguishable chaff frame", INTEL, "#ECFDF5"),
    ]
    lane_x, lane_w, lane_h = 4.30, 2.55, 0.76
    for i, (name, sub, col, fill) in enumerate(lanes):
        y = 6.10 - i * 0.95
        _node(ax, lane_x, y, lane_w, lane_h, name, sub, ec=col, fc=fill, fs=8.4)
        _arrow(ax, 3.34, SPINE_Y, lane_x - 0.02, y + lane_h / 2, col, lw=1.15)
        _arrow(ax, lane_x + lane_w + 0.02, y + lane_h / 2, 7.53, SPINE_Y, col, lw=1.15)

    # Key derivation hangs below the one lane that uses it.
    _node(ax, 4.30, 2.12, lane_w, 0.80, "key derivation",
          f"Argon2id {v['ARGON2_MEMORY_MIB']} MiB · Scrypt 2^{v['SCRYPT_N_LOG2']} · "
          f"PBKDF2 {int(v['PBKDF2_ITERATIONS']):,}\n"
          f"attacker-declared work factors capped at {v['MAX_SCRYPT_MEMORY_MIB']} MiB",
          ec=WARN, fc="#FFFBEB", fs=8.2)
    _arrow(ax, 5.58, 2.94, 5.58, 3.23, WARN, lw=1.4)

    _node(ax, 7.55, 4.67, 1.45, 0.76, "stored bytes", "what actually\ntravels", ec=INK, fc=PANEL)
    _node(ax, 9.40, 4.60, 1.85, 0.90, "a channel places it",
          "custom_xml · package_part\nmetadata · stego_media\nmce", ec=INK, fc=PANEL, fs=8.0)
    _arrow(ax, 9.02, SPINE_Y, 9.38, SPINE_Y, INK)

    _node(ax, 7.55, 3.35, 3.70, 0.74, "manifest record",
          "digest of the STORED bytes, never the plaintext —\na plaintext digest would be an offline oracle",
          ec=INTEL, fc="#ECFDF5", fs=8.4)
    _arrow(ax, 8.27, 4.65, 8.27, 4.11, INTEL, lw=1.3)

    _node(ax, 7.55, 2.12, 1.75, 0.74, "Merkle root", "binds the set", ec=SEAL, fc="#F5F3FF", fs=8.2)
    _node(ax, 9.50, 2.12, 1.75, 0.74, "surface digest", "binds the package", ec=SEAL, fc="#F5F3FF", fs=8.2)
    _arrow(ax, 8.42, 3.33, 8.42, 2.88, SEAL, lw=1.2)
    _arrow(ax, 10.37, 3.33, 10.37, 2.88, SEAL, lw=1.2)

    ax.add_patch(patches.FancyBboxPatch((0.30, 0.62), 10.95, 0.86, boxstyle="round,pad=0.06",
                                        ec=RISK, fc="#FEF2F2", lw=1.8))
    ax.text(5.775, 1.24, "Ed25519 signature over the canonical body",
            color=RISK, fontsize=10, fontweight="bold", ha="center", va="center")
    ax.text(5.775, 0.94,
            "covers every module record, the Merkle root, and the surface digest — and still proves "
            "only that SOME key signed it, until the reader pins the one they trust",
            color=BODY, fontsize=7.6, ha="center", va="center")
    _arrow(ax, 8.42, 2.10, 8.42, 1.52, RISK, lw=1.4)
    _arrow(ax, 10.37, 2.10, 10.37, 1.52, RISK, lw=1.4)

    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {out_path}")


# -- Figure 4: reproduction and transparency ----------------------------------
def build_reproduction_diagram(out_path: Path, v: dict) -> None:
    """The lifecycle as a fork, because that is what it is.

    Drawn as four boxes in a row, the figure said Verify then Reproduce — a sequence,
    every reader performing both. The design is the opposite: verification is the
    default and complete path, and re-execution is a separate opt-in branch that a
    reader may never take. Worse, the linear form gave no way to show the thing that
    actually justifies the split, which is that the two branches end in *different
    claims*. Forking after the document arrives puts the gate, the confinement, and
    the two verdicts where a reader can compare them.
    """
    fig, ax = _canvas(11.8, 6.5)
    _titles(ax, 5.9, "From the author's run to the reader's verdict",
            "Verification is the whole default path; re-execution is a separate branch nobody is obliged to take",
            6.14, 5.80)

    AUTHOR_Y = 4.62
    ax.text(0.30, 5.42, "AUTHOR", color=MUTED, fontsize=8, fontweight="bold", ha="left")
    _node(ax, 0.30, AUTHOR_Y - 0.40, 1.95, 0.80, "pack",
          "deterministic tarball\nbomb + traversal guards", ec=SURFACE, fc="#EFF6FF")
    _node(ax, 2.70, AUTHOR_Y - 0.40, 2.15, 0.80, "attest",
          "run the recipe once, pin\nthe toolchain and outputs", ec=INTEL, fc="#ECFDF5")
    _node(ax, 5.30, AUTHOR_Y - 0.40, 2.15, 0.80, "sign + log",
          "Ed25519 over the manifest,\nappend to the transparency log", ec=INTEL, fc="#ECFDF5")
    _arrow(ax, 2.27, AUTHOR_Y, 2.68, AUTHOR_Y, INK)
    _arrow(ax, 4.87, AUTHOR_Y, 5.28, AUTHOR_Y, INK)

    # The document is the hinge: everything left of it is authoring, everything
    # right and below is what a reader can do with it.
    ax.add_patch(patches.FancyBboxPatch((7.95, AUTHOR_Y - 0.46), 2.15, 0.92,
                                        boxstyle="round,pad=0.06", ec=INK, fc=PANEL, lw=2.0))
    ax.text(9.025, AUTHOR_Y + 0.14, "the document", color=INK, fontsize=9.4,
            fontweight="bold", ha="center", va="center")
    ax.text(9.025, AUTHOR_Y - 0.20, "one file, self-contained", color=MUTED,
            fontsize=7.2, ha="center", va="center")
    _arrow(ax, 7.47, AUTHOR_Y, 7.93, AUTHOR_Y, INK, lw=2.0)

    ax.plot([0.30, 11.50], [3.86, 3.86], color=RULE, lw=1.0, ls=(0, (4, 3)))
    ax.text(0.30, 3.62, "READER", color=MUTED, fontsize=8, fontweight="bold", ha="left")

    # The fork itself: one incoming edge, two outgoing, one of them gated.
    ax.plot([9.025, 9.025], [AUTHOR_Y - 0.46, 3.30], color=INK, lw=1.6)
    ax.plot([2.55, 9.025], [3.30, 3.30], color=INK, lw=1.6)
    _arrow(ax, 2.55, 3.30, 2.55, 2.86, SEAL, lw=1.8)
    _arrow(ax, 7.30, 3.30, 7.30, 2.86, RISK, lw=1.8)
    ax.plot([7.30, 9.025], [3.30, 3.30], color=INK, lw=1.6)

    # -- default branch ------------------------------------------------------
    ax.add_patch(patches.FancyBboxPatch((0.30, 1.28), 4.50, 1.56,
                                        boxstyle="round,pad=0.08", ec=SEAL, fc="#FAF9FF", lw=1.8))
    ax.text(2.55, 2.60, "DEFAULT — verify", color=SEAL, fontsize=10, fontweight="bold",
            ha="center", va="center")
    ax.text(2.55, 2.24, "no flag, no sandbox, nothing runs", color=SEAL, fontsize=7.6,
            ha="center", va="center", style="italic")
    for i, line in enumerate([
        "signature checks against a pinned key",
        "Merkle root recomputes over every module",
        "surface digest still binds the part graph",
        "log entry proved under a signed tree head",
    ]):
        ax.text(0.62, 1.94 - i * 0.20, f"·  {line}", color=BODY, fontsize=7.7, va="center")

    # -- opt-in branch -------------------------------------------------------
    ax.add_patch(patches.FancyBboxPatch((6.05, 1.28), 5.45, 1.56,
                                        boxstyle="round,pad=0.08", ec=RISK, fc="#FFFAFA", lw=1.8))
    ax.text(8.775, 2.60, "OPT-IN — reproduce", color=RISK, fontsize=10, fontweight="bold",
            ha="center", va="center")
    ax.add_patch(patches.FancyBboxPatch((6.30, 2.06), 1.72, 0.34, boxstyle="round,pad=0.04",
                                        ec=RISK, fc=RISK, alpha=0.14, lw=1.2))
    ax.text(7.16, 2.23, "--allow-execution", color=RISK, fontsize=7.6,
            fontweight="bold", ha="center", va="center", fontfamily="monospace")
    ax.text(8.20, 2.23, "refused without it, with the reason printed",
            color=BODY, fontsize=7.6, ha="left", va="center", style="italic")
    for i, line in enumerate([
        "network denied · writes confined to a scratch tree",
        "environment scrubbed · rlimits and a hard timeout set",
        "declared outputs re-digested and compared one by one",
    ]):
        ax.text(6.35, 1.86 - i * 0.20, f"·  {line}", color=BODY, fontsize=7.7, va="center")

    # -- the two verdicts, which are the reason the branch exists ------------
    for x, w, col, verdict in [
        (0.30, 4.50, SEAL, "this attestation is authentic and intact —\n"
                           "the author's claim has not been altered"),
        (6.05, 5.45, RISK, "the outputs reproduce on this machine —\n"
                           "the author's claim has now been re-run"),
    ]:
        _arrow(ax, x + w / 2, 1.26, x + w / 2, 1.06, col, lw=1.6)
        ax.text(x + w / 2, 0.82, verdict, color=col, fontsize=8.2, fontweight="bold",
                ha="center", va="center", linespacing=1.5)

    ax.text(5.9, 0.04,
            "The two verdicts are not interchangeable, which is the reason the branch exists at all. "
            f"Negative controls hold each honest: one altered source byte, a declared\noutput the run "
            "never produces, an output that is a carried input unchanged, and a timeout beyond "
            f"{v['REPRO_TIMEOUT_MAX']} s must each be reported as a failure.",
            color=INK, fontsize=7.7, ha="center", va="bottom", style="italic", linespacing=1.5)

    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {out_path}")


# -- Figure 5: threat model and hardening -------------------------------------
def build_redteam_matrix(out_path: Path, v: dict) -> None:
    """Threats grouped by the layer they attack, each stopped at a drawn boundary.

    This was a three-column table rendered as a PNG — a shape LaTeX sets better than
    matplotlib, carrying no information its own text did not already carry, and
    ordering the entries arbitrarily. Two things were missing and both are structural.
    First, the threats are not a flat list: each one attacks a specific layer, and
    seeing them grouped shows the coverage is not lopsided. Second, the figure never
    drew the thing every row is about — the boundary the attack fails at. The wall
    down the middle is that boundary; every arrow stops on it.
    """
    import textwrap

    layers = [
        ("SURFACE CONTRACT", SURFACE, [
            ("Document swap",
             "repoints the officeDocument relationship at a part they added",
             "the surface digest binds every part, content type, and\n"
             "relationship in the graph — not a list of names"),
            ("Part-name smuggling",
             "names an entry so the reader stores it under a different name",
             "entry names must arrive canonical or be refused, so no\n"
             "consumer disagrees about which part this is"),
        ]),
        ("INTELLIGENCE MANIFEST", INTEL, [
            ("Trust-anchor spoofing",
             "signs a forged container with a key of their own",
             "authenticity requires a caller-pinned key, compared in\n"
             "constant time; an unpinned verify exits nonzero and says why"),
            ("Unimplemented claim",
             "relies on a capability only the prose ever provided",
             "the ODF profile shares the OPC sealing and unsealing code\n"
             "rather than a lookalike of it"),
            ("Provenance ambiguity",
             "pads the module set so two sets share one Merkle root",
             "RFC 6962 tree splitting, so the root is unambiguous by\n"
             "construction rather than by a caller's diligence"),
        ]),
        ("CRYPTOGRAPHIC SEALING", SEAL, [
            ("Slot splicing",
             "relocates a sealed ciphertext into a different slot",
             "the slot name is authenticated data, so the GCM tag fails\n"
             "closed on a moved payload"),
            ("Verifiable-share downgrade",
             "strips the VSS header off a tampered Shamir share",
             "the signed manifest demands the tag, so the demand itself\n"
             "cannot be downgraded"),
            ("Algorithmic denial of service",
             "declares KDF work factors no honest author would",
             f"scrypt is bounded on memory as well as iterations:\n128·N·r ≤ {v['MAX_SCRYPT_MEMORY_MIB']} MiB"),
        ]),
        ("EXECUTION SANDBOX", RISK, [
            ("Sandbox profile injection",
             "names a directory so that it closes the SBPL literal",
             "a path that cannot be quoted is refused outright, never\n"
             "escaped and passed on"),
        ]),
    ]

    HEADER_H, ROW_H, WALL = 0.40, 0.66, 5.92
    total = sum(HEADER_H + ROW_H * len(rows) for _, _, rows in layers)
    top = 1.05 + total
    fig, ax = _canvas(11.8, top + 1.32)

    _titles(ax, 5.9, "Where each threat attacks, and what refuses it",
            "Every class below was found by adversarial review of this codebase, and each is pinned by a regression test",
            top + 1.02, top + 0.66)

    ax.text(0.40, top + 0.24, "THREAT CLASS", color=MUTED, fontsize=7.4, fontweight="bold")
    ax.text(2.95, top + 0.24, "WHAT THE ATTACKER DOES", color=MUTED, fontsize=7.4, fontweight="bold")
    ax.text(6.18, top + 0.24, "THE INVARIANT IT FAILS AGAINST", color=MUTED, fontsize=7.4,
            fontweight="bold")
    ax.plot([0.35, 11.45], [top + 0.10, top + 0.10], color=INK, lw=1.1)

    y = top
    for name, col, rows in layers:
        y -= HEADER_H
        ax.add_patch(patches.Rectangle((0.35, y + 0.02), 0.075, HEADER_H - 0.14,
                                       ec="none", fc=col))
        ax.text(0.54, y + HEADER_H / 2 - 0.06, name, color=col, fontsize=7.8,
                fontweight="bold", va="center")
        # The wall is drawn in the layer's own colour, so a reader can see at a glance
        # that the boundary is not one mechanism but four, each owning its own attacks.
        ax.plot([WALL, WALL], [y + HEADER_H - 0.06, y - ROW_H * len(rows)],
                color=col, lw=3.4, solid_capstyle="butt", zorder=4)

        for threat, attack, control in rows:
            y -= ROW_H
            mid = y + ROW_H / 2
            ax.text(0.54, mid, "\n".join(textwrap.wrap(threat, 24)), color=col,
                    fontsize=8.4, fontweight="bold", va="center", linespacing=1.4)
            ax.text(2.95, mid, "\n".join(textwrap.wrap(attack, 36)), color=BODY,
                    fontsize=7.7, va="center", linespacing=1.45, style="italic")
            # The attack arrow ends on the wall, not past it: nothing gets through.
            _arrow(ax, 5.05, mid, WALL - 0.045, mid, RISK, lw=1.5)
            ax.text(6.18, mid, control, color=INK, fontsize=7.7, va="center",
                    linespacing=1.45)

    ax.plot([0.35, 11.45], [y - 0.12, y - 0.12], color=RULE, lw=0.9)
    ax.text(5.9, 0.14,
            f"{v['REDTEAM_FINDING_COUNT']} confirmed findings across {v['REDTEAM_AUDIT_COUNT']} rounds of review "
            f"stand behind these classes, and {v['TEST_COUNT']} test functions keep them closed. Three of the entries "
            "are second passes:\nan earlier fix bounded scrypt's iteration count but not its memory, shipped "
            "verifiable shares the container never asked for, and documented a profile that had no code path.",
            color=MUTED, fontsize=7.7, ha="center", va="bottom", style="italic", linespacing=1.5)

    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {out_path}")


# -- Figure 6: the trust ladder ----------------------------------------------
def build_trust_ladder(out_path: Path, v: dict) -> None:
    """An actual staircase, because the point is the *shape* of the gain.

    Drawn as a table this was six rows a reader scans and forgets. The claim is that
    each rung buys strictly more than the last and that one step is far larger than
    the others; a staircase states that in its geometry, and the oversized riser
    between rungs 3 and 4 is the argument the figure exists to make.
    """
    fig, ax = _canvas(11.6, 7.9)
    _titles(ax, 5.8, "The trust ladder",
            "Each rung buys strictly more than the last. One riser is much taller than the others.",
            7.60, 7.24)

    rungs = [
        ("open it", 0.70, "It is a valid\ndocument.", "Nothing about\nthe payloads.", SURFACE),
        ("validate", 1.40, "Structure conforms;\nstored digests match.", "Self-consistent,\nnot authentic.", INTEL),
        ("verify signature", 2.10, "SOME key signed this\npackage and its text.", "You do not know\nwhose key.", SEAL),
        ("pin the key", 3.70, "THAT signer signed it.\nAuthenticity.", "Nothing about whether\noutputs follow from code.", "#0891B2"),
        ("verify-reproduction", 4.40, "The attestation binds\nexactly these bytes.", "You trust the\nsigner's run.", WARN),
        ("reproduce", 5.10, "It reproduces here,\non your hardware.", "Process, never\nscientific validity.", RISK),
    ]

    step_w, x0, BASE = 1.78, 0.42, 1.02
    for i, (name, height, buys, limit, col) in enumerate(rungs):
        x = x0 + i * step_w
        ax.add_patch(patches.Rectangle((x, BASE), step_w, height, fc=col, ec="white",
                                       lw=1.4, alpha=0.30))
        ax.add_patch(patches.Rectangle((x, BASE + height - 0.055), step_w, 0.055,
                                       fc=col, ec="none"))
        ax.text(x + step_w / 2, BASE + height - 0.30, name, color=col, fontsize=8.6,
                fontweight="bold", ha="center", va="center")
        ax.text(x + step_w / 2, BASE + height + 0.28, buys, color=INK, fontsize=7.4,
                ha="center", va="bottom", linespacing=1.4)
        ax.text(x + step_w / 2, BASE - 0.20, limit, color=MUTED, fontsize=6.9,
                ha="center", va="top", linespacing=1.4, style="italic")

    # The riser that matters, annotated *inside* the block it rises into: the only
    # region large enough to hold the note without crossing a neighbour's label.
    jump_x = x0 + 3 * step_w
    _arrow(ax, jump_x - 0.10, BASE + 2.10, jump_x - 0.10, BASE + 3.66, RISK, lw=2.0, style="-|>")
    ax.text(jump_x + 0.16, BASE + 2.30,
            "the authenticity\nstep\n\na signature is\nonly an identity\nclaim until the\nreader supplies\nthe identity",
            color=RISK, fontsize=7.4, ha="left", va="center", linespacing=1.5,
            fontweight="bold")

    ax.text(x0, 6.98, "WHAT THE RUNG BUYS", color=MUTED, fontsize=7.2, fontweight="bold")
    ax.text(x0, 0.20, "WHAT IT STILL DOES NOT BUY", color=MUTED, fontsize=7.2, fontweight="bold")
    ax.plot([x0, x0 + 6 * step_w], [BASE, BASE], color=INK, lw=1.2)

    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {out_path}")


# -- Figure 7: project round-trip fidelity ------------------------------------
def build_fidelity_figure(out_path: Path, v: dict, report: dict | None) -> None:
    """Fidelity as a flow: what continues through, and what diverts where.

    Four columns of prose told a reader the categories but not the *shape* of the
    claim — that one path runs straight through unchanged and three others leave it
    at named points. Drawing the diversions makes "lossless for what it carries"
    checkable at a glance, and makes the refusal branch impossible to overlook.
    """
    import textwrap

    fb = (report or {}).get("fidelity_boundary", {})
    checks = (report or {}).get("checks", [])
    passed = sum(1 for c in checks if c.get("ok"))
    proj = (report or {}).get("project", {})

    fig, ax = _canvas(11.6, 6.6)
    _titles(ax, 5.8, "What survives the round trip",
            "Measured by carrying a real project into both containers and diffing what came back",
            6.32, 5.98)

    SPINE = 3.35
    _node(ax, 0.30, SPINE - 0.42, 1.70, 0.84, "project tree",
          f"{proj.get('files', '?')} files\n{proj.get('directories', '?')} directories",
          ec=INK, fc=PANEL)
    _node(ax, 2.45, SPINE - 0.42, 1.35, 0.84, "pack", "deterministic\ntar.gz", ec=SURFACE, fc="#EFF6FF")
    _arrow(ax, 2.02, SPINE, 2.43, SPINE, INK)

    _node(ax, 7.55, SPINE - 0.42, 1.35, 0.84, "unpack", "guarded\nextraction", ec=SURFACE, fc="#EFF6FF")
    _node(ax, 9.60, SPINE - 0.42, 1.70, 0.84, "tree returned",
          "compared byte\nby byte, mode by mode", ec=INTEL, fc="#ECFDF5")
    _arrow(ax, 8.92, SPINE, 9.58, SPINE, INTEL, lw=2.2)

    # The through-line: what is carried unchanged.
    ax.add_patch(patches.FancyBboxPatch((3.95, SPINE - 0.62), 3.45, 1.24,
                                        boxstyle="round,pad=0.05", ec=INTEL, fc="#ECFDF5", lw=2.0))
    ax.text(5.675, SPINE + 0.42, "PRESERVED", color=INTEL, fontsize=9, fontweight="bold",
            ha="center", va="center")
    # Wrapped to the box, not to the page: an unwrapped join ran straight through the
    # pack and unpack nodes on either side.
    preserved = "\n".join(textwrap.wrap(" · ".join(fb.get("preserved", [])), 46))
    ax.text(5.675, SPINE - 0.06, preserved, color=BODY, fontsize=6.9,
            ha="center", va="center", linespacing=1.4)
    _arrow(ax, 3.82, SPINE, 3.93, SPINE, INTEL, lw=2.2)
    _arrow(ax, 7.42, SPINE, 7.53, SPINE, INTEL, lw=2.2)

    # Three diversions, each leaving the spine at the point where it happens.
    diversions = [
        (4.55, "NORMALISED", fb.get("normalised_by_design", []), SEAL, "#F5F3FF",
         "determinism beats this metadata", -1, "right"),
        (5.70, "REFUSED", [x.split(" (")[0] for x in fb.get("refused", [])], RISK, "#FEF2F2",
         "packing one would embed its target", 1, "left"),
        (6.85, "EXCLUDED", fb.get("excluded_by_policy", [])[:5] + ["…"], MUTED, "#F8FAFC",
         "build junk, never source", -1, "left"),
    ]
    # The two downward reasons share a y, so they are anchored away from each other:
    # left-aligned on both would have run the first straight into the second.
    for x, label, items, col, fill, why, direction, side in diversions:
        y_box = SPINE + direction * 1.95
        box_y = y_box - 0.38
        ax.add_patch(patches.FancyBboxPatch((x - 0.95, box_y), 1.90, 0.76,
                                            boxstyle="round,pad=0.05", ec=col, fc=fill, lw=1.5))
        ax.text(x, y_box + 0.20, label, color=col, fontsize=8.2, fontweight="bold",
                ha="center", va="center")
        body = "\n".join(textwrap.wrap(" · ".join(str(i) for i in items), 30)[:2])
        ax.text(x, y_box - 0.12, body, color=BODY, fontsize=6.6, ha="center",
                va="center", linespacing=1.35)
        edge = SPINE + direction * 0.62
        _arrow(ax, x, edge, x, box_y if direction > 0 else box_y + 0.76, col, lw=1.4)
        ax.text(x + (0.10 if side == "left" else -0.10), edge + direction * 0.45, why,
                color=MUTED, fontsize=6.3, ha=side, va="center", style="italic")

    ax.text(5.8, 0.16,
            f"{passed}/{len(checks)} invariants hold across both container profiles. The carried tree "
            "deliberately contains an executable, an empty\ndirectory, a zero-byte file, spaced and "
            "non-ASCII filenames, and real source under directory names excluded only at the root.",
            color=INK, fontsize=7.8, ha="center", va="bottom", fontweight="bold", linespacing=1.5)

    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {out_path}")


# -- Figure 8: profile parity -------------------------------------------------
def build_parity_figure(out_path: Path, v: dict) -> None:
    """The shared core, drawn as a core, with the two profiles as shells around it.

    A twelve-row checklist with two dots per row spent most of its ink repeating the
    same answer, and it let a reader believe parity is a coincidence that happened to
    hold twelve times. It is not: the two profiles agree because they call the same
    functions, and the figure should show that as one block both sides reach into.
    Drawn this way the asymmetry also lands correctly — the divergence sits entirely
    at the transport edge, where the two standards genuinely differ, and never in the
    layer that carries the guarantee.
    """
    #: The OOXML-only channels and why the ODF profile has no equivalent.
    #: "standard" — ODF defines no such construct, so the gap is the specification's.
    #: "unbuilt"  — an analogue is plausible and tracked, but is not shipped.
    #: Both the ODF panel's counts and the manuscript caption's counts are checked
    #: against this list, so neither can drift away from the figure.
    ooxml_only = [
        ("custom_xml", "a custom XML datastore part", "standard"),
        ("mce", "an ignorable-namespace Choice", "standard"),
        ("metadata", "a custom document property", "unbuilt"),
        ("stego_media", "LSBs of a displayed figure", "unbuilt"),
    ]

    fig, ax = _canvas(11.8, 7.0)
    _titles(ax, 5.9, "Two containers, one implementation",
            "The profiles differ only where the standards do; the layer that carries the guarantee is literally shared code",
            6.60, 6.26)

    CORE_X, CORE_W = 3.62, 4.56
    ax.add_patch(patches.FancyBboxPatch((CORE_X, 1.28), CORE_W, 4.52,
                                        boxstyle="round,pad=0.10", ec=INK, fc=PANEL, lw=2.2))
    ax.text(CORE_X + CORE_W / 2, 5.56, "ONE SHARED IMPLEMENTATION", color=INK,
            fontsize=10, fontweight="bold", ha="center", va="center")
    ax.text(CORE_X + CORE_W / 2, 5.28, "both profiles call these, so they cannot drift apart",
            color=MUTED, fontsize=7.6, ha="center", va="center", style="italic")

    shared = [
        ("signed manifest + Merkle root", "manifest.py · provenance.py"),
        ("four sealing lineages", "container.seal_module"),
        ("unsealing, VSS refusal, threshold recombination", "DocxPlusReader._unseal"),
        ("co-signatures and log inclusion proofs", "transparency.py"),
        ("carried project trees and attestations", "payloads.pack_project"),
        ("nested containers, dispatched by content", "odt_container.open_document"),
        ("intake caps: entry count, bomb ratio, traversal", "intake.py"),
        ("reproduction under confinement", "reproduce.py"),
    ]
    for i, (what, where) in enumerate(shared):
        y = 4.90 - i * 0.44
        ax.add_patch(patches.Rectangle((CORE_X + 0.22, y - 0.055), 0.075, 0.11,
                                       ec="none", fc=INTEL))
        ax.text(CORE_X + 0.40, y + 0.055, what, color=INK, fontsize=7.9, va="center")
        ax.text(CORE_X + 0.40, y - 0.135, where, color=MUTED, fontsize=7.0, va="center",
                fontfamily="monospace")

    # -- the two shells, identical in shape because they are identical in role --
    for x0, name, exts, col, fill in [
        (0.30, "OOXML profile", ".docx  ·  .docxplus", SURFACE, "#EFF6FF"),
        (8.72, "ODF profile", ".odt  ·  .odtplus", INTEL, "#ECFDF5"),
    ]:
        ax.add_patch(patches.FancyBboxPatch((x0, 4.34), 2.78, 1.46,
                                            boxstyle="round,pad=0.08", ec=col, fc=fill, lw=1.8))
        ax.text(x0 + 1.39, 5.46, name, color=col, fontsize=9.6, fontweight="bold",
                ha="center", va="center")
        ax.text(x0 + 1.39, 5.14, exts, color=INK, fontsize=8.2, ha="center",
                va="center", fontfamily="monospace")
        ax.text(x0 + 1.39, 4.72, "writes its own surface parts,\nvalidates against its own spec",
                color=BODY, fontsize=7.4, ha="center", va="center", linespacing=1.45)
    _arrow(ax, 3.18, 5.07, 3.50, 5.07, INK, lw=2.4)
    _arrow(ax, 8.72, 5.07, 8.40, 5.07, INK, lw=2.4)

    # -- what each profile carries alone, and why that is the standards' doing --
    ax.add_patch(patches.FancyBboxPatch((0.30, 1.28), 2.78, 2.76,
                                        boxstyle="round,pad=0.08", ec=SURFACE, fc="#FFFFFF",
                                        lw=1.4, linestyle=(0, (4, 3))))
    ax.text(1.69, 3.78, "OOXML-only transport", color=SURFACE, fontsize=8.6,
            fontweight="bold", ha="center", va="center")
    for i, (cid, note, _reason) in enumerate(ooxml_only):
        y = 3.36 - i * 0.56
        ax.text(0.52, y, cid, color=CHANNEL_COLOR[cid], fontsize=8.0, fontweight="bold",
                va="center", fontfamily="monospace")
        ax.text(0.52, y - 0.22, note, color=MUTED, fontsize=7.1, va="center")

    ax.add_patch(patches.FancyBboxPatch((8.72, 1.28), 2.78, 2.76,
                                        boxstyle="round,pad=0.08", ec=INTEL, fc="#FFFFFF",
                                        lw=1.4, linestyle=(0, (4, 3))))
    ax.text(10.11, 3.78, "ODF transport", color=INTEL, fontsize=8.6,
            fontweight="bold", ha="center", va="center")
    ax.text(8.94, 3.36, "odt_package_part", color=INTEL, fontsize=8.0, fontweight="bold",
            va="center", fontfamily="monospace")
    ax.text(8.94, 3.14, "carries every module, declared in\nMETA-INF/manifest.xml",
            color=MUTED, fontsize=7.1, va="center", linespacing=1.4)
    by_standard = [c for c, _, r in ooxml_only if r == "standard"]
    unbuilt = [c for c, _, r in ooxml_only if r == "unbuilt"]
    ax.text(8.94, 2.62, f"no analogue by the standard ({len(by_standard)})", color=RISK,
            fontsize=7.6, fontweight="bold", va="center")
    ax.text(8.94, 2.30, "ODF defines no custom XML datastore\nand no Markup Compatibility element",
            color=MUTED, fontsize=7.1, va="center", linespacing=1.4)
    ax.text(8.94, 1.86, f"no analogue yet built ({len(unbuilt)})", color=WARN, fontsize=7.6,
            fontweight="bold", va="center")
    ax.text(8.94, 1.58, "meta.xml fields and Pictures/ carriers\nare plausible and tracked, not shipped",
            color=MUTED, fontsize=7.1, va="center", linespacing=1.4)

    _arrow(ax, 1.69, 4.08, 1.69, 4.30, SURFACE, lw=1.4)
    _arrow(ax, 10.11, 4.08, 10.11, 4.30, INTEL, lw=1.4)

    ax.text(5.9, 0.20,
            "Divergence is confined to the dashed boxes, and every entry there is a property of the "
            "two standards or an admitted gap — never a difference in how\na payload is sealed, "
            "digested, signed, or refused. That is what stops the weaker profile becoming the one an "
            "attacker chooses to present.",
            color=INK, fontsize=7.8, ha="center", va="bottom", style="italic", linespacing=1.5)

    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Generated: {out_path}")


def main() -> int:
    fig_dir = ensure_output_dirs()["figures"]
    fig_dir.mkdir(parents=True, exist_ok=True)
    v = manuscript_vars.variables(include_dossier=False)

    build_cover_art(fig_dir / "cover.png", v)
    build_architecture_diagram(fig_dir / "architecture.png", v)
    build_crypto_diagram(fig_dir / "cryptographic_pipeline.png", v)
    build_reproduction_diagram(fig_dir / "reproduction_lifecycle.png", v)
    build_redteam_matrix(fig_dir / "redteam_matrix.png", v)
    build_trust_ladder(fig_dir / "trust_ladder.png", v)
    build_parity_figure(fig_dir / "profile_parity.png", v)

    # The fidelity figure reports measurements, so it reads the harness output rather
    # than restating it. Absent report -> the figure still renders, visibly empty.
    import json as _json

    report_path = ensure_output_dirs()["reports"] / "project_roundtrip.json"
    report = _json.loads(report_path.read_text()) if report_path.is_file() else None
    build_fidelity_figure(fig_dir / "roundtrip_fidelity.png", v, report)

    import subprocess

    subprocess.run([sys.executable, str(Path(__file__).parent / "03_capacity_figure.py")], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

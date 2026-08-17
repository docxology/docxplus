#!/usr/bin/env python3
"""Preflight: report which docxplus capabilities are available in this environment.

Thin orchestrator — all checks live in ``src``. Never masks an absent tool as a
pass; it reports each capability's real status and exits 0 (informational).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import steg_bridge


def main() -> int:
    print("docxplus preflight")
    print("  core (opc/crypto/channels): available")

    try:
        import PIL  # noqa: F401

        print("  media backend python_lsb (Pillow): available")
    except ImportError:
        print("  media backend python_lsb (Pillow): MISSING — `uv sync --extra media`")

    tool = steg_bridge.locate()
    if tool is None:
        print("  media backend steganographer (Rust CLI): not built (optional)")
    else:
        print(f"  media backend steganographer: available via {tool.kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

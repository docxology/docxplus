#!/usr/bin/env python3
"""Build a demonstration docxplus carrying intelligence across every pure channel.

Emits a real ``.docx`` to ``output/documents/`` that opens as an ordinary Word
document yet carries a signed manifest and several payload modules. Prints the
output path for manifest collection.
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

from docxplus import crypto
from docxplus.container import DocxPlusBuilder
from docxplus.project_paths import ensure_output_dirs


def main() -> int:
    dirs = ensure_output_dirs()
    out = dirs["documents"] / "example_docxplus.docx"

    brief = json.dumps(
        {"classification": "internal", "priority": 2, "note": "structured brief"}
    ).encode()
    priv, _ = crypto.generate_signing_key()

    builder = (
        DocxPlusBuilder(
            paragraphs=[
                "Quarterly Operations Summary",
                "This document reads as an ordinary report in any word processor.",
            ],
            title="Quarterly Operations Summary",
        )
        .add_module("brief", "custom_xml", brief)
        .add_module("routing", "metadata", b"channel=alpha;ttl=7d")
        .add_module("dossier", "package_part", b"detailed dossier bytes...")
        .add_module("secret", "package_part", b"eyes-only payload", password="correct horse")
        .sign(priv)
    )

    # Media channel is opt-in on Pillow; include it when available.
    try:
        import PIL  # noqa: F401

        builder.add_module(
            "figure", "stego_media", b"payload hidden in the figure's pixels",
            backend="python_lsb",
        )
    except ImportError:
        pass

    from docxplus.fileext import write_document

    for w in write_document(builder.build(), out):
        print(str(w))

    # The ODT sibling, built from the same primitives. Shipping one proves the
    # profile end to end in the artifact set rather than only in the test suite.
    from docxplus.odt_container import OdtPlusBuilder

    odt_out = out.parent / "example_docxplus.odt"
    odt = OdtPlusBuilder(
        paragraphs=["This is an ordinary OpenDocument text file."],
        title="docxplus ODT example",
    )
    odt.add_module("brief", brief)  # `brief` is already packed bytes
    odt.add_module("secret", b"eyes-only payload", password="correct horse")
    odt.sign(priv)
    for w in write_document(odt.build(), odt_out):
        print(str(w))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

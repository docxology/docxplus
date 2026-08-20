"""Reusable reference documents used by both the showcase scripts and the
manuscript-variable generator, so the "one document, every capability" example is
defined once and never restated.
"""

from __future__ import annotations

from . import crypto
from .container import DocxPlusBuilder, DocxPlusReader


def build_reference_dossier() -> DocxPlusReader:
    """Build the self-verifying dossier in memory and return a reader over it.

    Exercises every sealing lineage in one signed document: a nested sub-document,
    a multi-recipient module, a k-of-n threshold module, and a decoy — under a
    signed Merkle provenance root. Returns a reader (the caller inspects modules).
    """
    sign_priv, _ = crypto.generate_signing_key()
    _ref_priv, ref_pub = crypto.generate_recipient_key()

    inner = (
        DocxPlusBuilder(paragraphs=["Confidential annex."])
        .add_module("annex", "package_part", b"eyes-only annex")
        .build()
    )
    data = (
        DocxPlusBuilder(
            paragraphs=["Self-Verifying Dossier", "Opens as an ordinary report."],
            title="Self-Verifying Dossier",
        )
        .add_nested("annex", inner, password="annex-key")
        .add_module("review", "package_part", b"manuscript.pdf bytes", recipients=[ref_pub])
        .add_decoy("notes", real=b"real coordinates", real_password="a",
                   decoy=b"grocery list", decoy_password="b")
        .add_threshold("vault", b"the combination", k=3, n=5)
        .add_module("brief", "custom_xml", b'{"note": "structured brief"}')
        .sign(sign_priv)
        .build()
    )
    return DocxPlusReader.from_bytes(data)


__all__ = [
    "build_reference_dossier",
]


"""The delivered dossier specimen and the credentials used to evaluate it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import crypto
from .container import DocxPlusBuilder, DocxPlusReader
from .project_paths import project_root


@dataclass(frozen=True)
class ReferenceDossier:
    """Actual package bytes plus ephemeral credentials for pinned behavioral checks."""

    data: bytes
    signing_public_key: bytes
    recipient_private_key: bytes
    threshold_shares: list[bytes]

    def reader(self) -> DocxPlusReader:
        """Read the serialized specimen, not a separately constructed document."""
        return DocxPlusReader.from_bytes(self.data)


def build_reference_dossier(project_dir: Path | None = None) -> ReferenceDossier:
    """Build the shipped source/nested/recipient/decoy/threshold specimen.

    Source extraction is not execution or a reproduction attestation. The source
    uses Argon2id; the nested annex uses the default Scrypt password envelope.
    """
    source = project_root() / "src" if project_dir is None else project_dir
    sign_priv, sign_pub = crypto.generate_signing_key()
    ref_priv, ref_pub = crypto.generate_recipient_key()
    inner = (
        DocxPlusBuilder(paragraphs=["Confidential annex."])
        .add_module("annex", "package_part", b"eyes-only annex")
        .build()
    )
    builder = (
        DocxPlusBuilder(
            paragraphs=["Self-Verifying Dossier", "Opens as an ordinary report."],
            title="Self-Verifying Dossier",
        )
        .add_project("source", source, password="reproduce", kdf="argon2id")
        .add_nested("annex", inner, password="annex-key")
        .add_module("review", "package_part", b"manuscript.pdf bytes", recipients=[ref_pub])
        .add_decoy("notes", real=b"real coordinates", real_password="a",
                   decoy=b"grocery list", decoy_password="b")
        .add_threshold("vault", b"the combination", k=3, n=5)
        .sign(sign_priv)
    )
    data = builder.build()
    return ReferenceDossier(data, sign_pub, ref_priv, builder.threshold_shares["vault"])


__all__ = ["ReferenceDossier", "build_reference_dossier"]

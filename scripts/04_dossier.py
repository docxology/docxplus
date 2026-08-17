#!/usr/bin/env python3
"""Build and verify a v0.2 "self-verifying dossier" showcasing every capability.

One ordinary-looking .docx that carries: a whole reproducible project (this repo's
src/), a nested sealed sub-document, a multi-recipient module, a k-of-n threshold
module, a plausible-deniability decoy, and a signed Merkle provenance root. Builds
with ephemeral keys, verifies every path in-process, and writes a JSON report.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import crypto
from container import DocxPlusBuilder, DocxPlusReader
from project_paths import ensure_output_dirs, project_root
from validate import validate_bytes


def main() -> int:
    dirs = ensure_output_dirs()
    sign_priv, _ = crypto.generate_signing_key()
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
        .add_project("source", project_root() / "src", password="reproduce")
        .add_nested("annex", inner, password="annex-key")
        .add_module("review", "package_part", b"manuscript.pdf bytes", recipients=[ref_pub])
        .add_decoy("notes", real=b"real coordinates", real_password="a",
                   decoy=b"grocery list", decoy_password="b")
        .add_threshold("vault", b"the combination", k=3, n=5)
        .sign(sign_priv)
    )
    data = builder.build()
    shares = builder.threshold_shares["vault"]
    out = dirs["documents"] / "dossier.docx"
    out.write_bytes(data)

    reader = DocxPlusReader.from_bytes(data)
    checks: dict[str, object] = {"opc_valid": validate_bytes(data).ok,
                                 "provenance": reader.verify_provenance(),
                                 "merkle_root": reader.merkle_root()[:16] + "…"}

    with tempfile.TemporaryDirectory() as td:
        reader.extract_project("source", Path(td) / "src", password="reproduce")
        checks["project_reproduced"] = (Path(td) / "src" / "container.py").exists()
    checks["nested_opened"] = (
        reader.open_nested("annex", password="annex-key").extract("annex") == b"eyes-only annex"
    )
    checks["multi_recipient"] = reader.extract("review", private_key=ref_priv) == b"manuscript.pdf bytes"
    checks["threshold_3of5"] = reader.extract("vault", shares=shares[:3]) == b"the combination"
    checks["decoy_real"] = reader.extract("notes", password="a") == b"real coordinates"
    checks["decoy_cover"] = reader.extract("notes", password="b") == b"grocery list"

    report = {"document": str(out), "modules": reader.list_modules(), "checks": checks}
    report_path = dirs["reports"] / "dossier.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(str(out))
    print(str(report_path))
    return 0 if all(v is True for k, v in checks.items() if k != "merkle_root") else 1


if __name__ == "__main__":
    raise SystemExit(main())

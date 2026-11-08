#!/usr/bin/env python3
"""Build and evaluate the shipped source/nested/recipient/threshold/decoy dossier.

The source-project extraction check is not a reproduction execution attestation.
Ephemeral signing credentials pin the checks performed by this invocation.
"""

from __future__ import annotations

import json
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

from docxplus import payloads
from docxplus.fileext import write_document
from docxplus.manuscript_vars import dossier_table
from docxplus.project_paths import ensure_output_dirs, project_root
from docxplus.reference_docs import build_reference_dossier
from docxplus.validate import validate_bytes


def main() -> int:
    dirs = ensure_output_dirs()
    specimen = build_reference_dossier()
    data = specimen.data
    shares = specimen.threshold_shares
    out = dirs["documents"] / "dossier.docx"
    written = write_document(data, out)

    reader = specimen.reader()
    checks: dict[str, object] = {"opc_valid": validate_bytes(data).ok,
                                 "provenance_pinned": reader.verify_provenance(
                                     expected_public_key=specimen.signing_public_key),
                                 "merkle_root": reader.merkle_root()[:16] + "…"}

    with tempfile.TemporaryDirectory() as td:
        restored = reader.extract_project("source", Path(td) / "src", password="reproduce")
        checks["project_extracted"] = (
            payloads.pack_project(restored) == payloads.pack_project(project_root() / "src")
        )
    checks["nested_opened"] = (
        reader.open_nested("annex", password="annex-key").extract("annex") == b"eyes-only annex"
    )
    checks["multi_recipient"] = (
        reader.extract("review", private_key=specimen.recipient_private_key) == b"manuscript.pdf bytes"
    )
    checks["threshold_3of5"] = reader.extract("vault", shares=shares[:3]) == b"the combination"
    checks["decoy_real"] = reader.extract("notes", password="a") == b"real coordinates"
    checks["decoy_cover"] = reader.extract("notes", password="b") == b"grocery list"

    ok = all(v is True for k, v in checks.items() if k != "merkle_root")
    report = {"document": str(out), "paths": [str(p) for p in written],
              "modules": reader.list_modules(), "checks": checks, "ok": ok,
              "module_table": dossier_table(reader)[0]}
    report_path = dirs["reports"] / "dossier.json"
    report_path.write_text(json.dumps(report, indent=2))
    for path in written:
        print(str(path))
    print(str(report_path))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

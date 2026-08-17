#!/usr/bin/env python3
"""Read back the example docxplus, verify every module, emit a JSON report.

Proves the round trip end-to-end: OPC validity, manifest signature, and per-module
digest match. Writes ``output/reports/roundtrip.json`` and prints its path.
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

from docxplus.container import DocxPlusReader
from docxplus.project_paths import ensure_output_dirs
from docxplus.validate import validate_bytes

_PASSWORDS = {"secret": "correct horse"}


def main() -> int:
    dirs = ensure_output_dirs()
    docx = dirs["documents"] / "example_docxplus.docx"
    if not docx.exists():
        sys.stderr.write("run scripts/01_build_example.py first\n")
        return 1

    data = docx.read_bytes()
    validation = validate_bytes(data)
    reader = DocxPlusReader.from_bytes(data)

    modules = []
    for slot in reader.list_modules():
        record = reader.manifest.slot(slot)
        try:
            payload = reader.extract(slot, password=_PASSWORDS.get(slot))
            status = "ok"
            size = len(payload)
        except Exception as exc:  # noqa: BLE001 - report per-module failures
            status = f"error: {exc}"
            size = 0
        modules.append(
            {"slot": slot, "channel": record.channel, "encrypted": record.encrypted,
             "status": status, "recovered_bytes": size}
        )

    report = {
        "document": str(docx),
        "opc_valid": validation.ok,
        "signature": reader.signature_status(),
        "modules": modules,
    }
    out = dirs["reports"] / "roundtrip.json"
    out.write_text(json.dumps(report, indent=2))
    print(str(out))
    return 0 if validation.ok and all(m["status"] == "ok" for m in modules) else 1


if __name__ == "__main__":
    raise SystemExit(main())

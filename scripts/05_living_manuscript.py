#!/usr/bin/env python3
"""The Living Manuscript — carry the real template_code_project, attest reproduction.

Builds a single signed .docx that carries the whole docxology/template_code_project
exemplar plus a reproduction attestation binding source → a deterministic output
digest. Then it demonstrates both trust paths from the Council synthesis:

  * verify_reproduction() — cryptographic, executes nothing (the default).
  * reproduce(allow_execution=True) — opt-in, re-runs the attested command in a
    hermetic sandbox and confirms the output digest matches.

This is template_code_project fully integrated as the exemplar a document carries,
reproduces, and proves.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import crypto
from container import DocxPlusBuilder, DocxPlusReader
from project_paths import ensure_output_dirs
from reproduce import ReproSpec
from validate import validate_bytes

TEMPLATE = Path(
    "/Users/4d/Documents/GitHub/template/projects/templates/template_code_project"
)

# A dependency-free, deterministic reproduction: digest every .py file in the tree
# and write it out. Re-running yields the same digest; a one-byte source change
# changes it (the negative control).
_SNIPPET = (
    "import hashlib,pathlib,os\n"
    "root=pathlib.Path('.')\n"
    "h=hashlib.blake2b(digest_size=16)\n"
    "for p in sorted(root.rglob('*.py')):\n"
    "    h.update(p.relative_to(root).as_posix().encode()); h.update(b'\\0'); h.update(p.read_bytes())\n"
    "os.makedirs('output',exist_ok=True)\n"
    "open('output/repro.txt','w').write(h.hexdigest())\n"
)


def main() -> int:
    if not TEMPLATE.is_dir():
        sys.stderr.write(f"template_code_project not found at {TEMPLATE}\n")
        return 1
    dirs = ensure_output_dirs()
    priv, _ = crypto.generate_signing_key()
    spec = ReproSpec(command=[sys.executable, "-c", _SNIPPET], outputs=["output/repro.txt"])

    data = (
        DocxPlusBuilder(
            paragraphs=["The Living Manuscript", "This paper carries and reproduces its own source."],
            title="The Living Manuscript",
        )
        .add_project("template_code_project", TEMPLATE, password="reproduce", reproduce=spec)
        .sign(priv)
        .build()
    )
    out = dirs["documents"] / "living_manuscript.docx"
    out.write_bytes(data)

    reader = DocxPlusReader.from_bytes(data)
    verified = reader.verify_reproduction("template_code_project")
    with tempfile.TemporaryDirectory() as td:
        run = reader.reproduce(
            "template_code_project", Path(td) / "src", allow_execution=True, password="reproduce"
        )

    report = {
        "document": str(out),
        "size_bytes": len(data),
        "opc_valid": validate_bytes(data).ok,
        "verify_reproduction": {
            "attested": verified["attested"],
            "signed": verified["signed"],
            "verified": verified["verified"],
        },
        "attested_output_digest": verified.get("attestation", {}).get("output_digest", "")[:16] + "…",
        "reproduced_match": run["match"],
        "toolchain": run["toolchain_actual"],
    }
    report_path = dirs["reports"] / "living_manuscript.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(str(out))
    print(str(report_path))
    ok = report["opc_valid"] and verified["attested"] and verified["verified"] and run["match"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

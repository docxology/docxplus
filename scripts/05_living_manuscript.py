#!/usr/bin/env python3
"""The Living Manuscript — carry source and attest a dependency-free source hash.

Writes paired signed .docx/.docxplus exports carrying the docxplus repository.
The attested Python command hashes source files, not a PDF regeneration recipe.

  * verify_reproduction(slot) — cryptographic, executes nothing (the default path);
  * reproduce(allow_execution=True) — opt-in, re-runs the attested command in a
    confined sandbox and compares digests.

The carried tree is resolved from the repository root, so the claim "this paper
carries its own source" is true wherever the script runs. It previously pointed at
an external exemplar on one machine, which made the claim false everywhere else and
broke `run.sh` on any other checkout.
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

from docxplus import crypto
from docxplus.container import DocxPlusBuilder, DocxPlusReader
from docxplus.fileext import write_document
from docxplus.project_paths import ensure_output_dirs, project_root
from docxplus.reproduce import ReproSpec
from docxplus.validate import validate_bytes

# The document carries *this* repository. That is the whole claim, so the source is
# resolved from the repo itself rather than from a path on one machine: the previous
# hardcoded absolute path pointed at an unrelated external exemplar, which made the
# manuscript's "carries its own source" statement false everywhere and made `run.sh`
# fail on every machine but one.
CARRIED_PROJECT = project_root()
CARRIED_SLOT = "docxplus_source"

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
    if not CARRIED_PROJECT.is_dir():
        sys.stderr.write(f"repository root not found at {CARRIED_PROJECT}\n")
        return 1
    dirs = ensure_output_dirs()
    priv, pub = crypto.generate_signing_key()
    spec = ReproSpec(command=["python3", "-c", _SNIPPET], outputs=["output/repro.txt"])

    data = (
        DocxPlusBuilder(
            paragraphs=["The Living Manuscript", "This document carries and hashes its own source."],
            title="The Living Manuscript",
        )
        .add_project(CARRIED_SLOT, CARRIED_PROJECT, password="reproduce", reproduce=spec)
        .sign(priv)
        .build()
    )
    out = dirs["documents"] / "living_manuscript.docx"
    written = write_document(data, out)

    reader = DocxPlusReader.from_bytes(data)
    verified = reader.verify_reproduction(CARRIED_SLOT, expected_public_key=pub)
    with tempfile.TemporaryDirectory() as td:
        run = reader.reproduce(
            CARRIED_SLOT, Path(td) / "src", allow_execution=True, password="reproduce"
        )

    report = {
        "document": str(out),
        "paths": [str(p) for p in written],
        "size_bytes": len(data),
        "opc_valid": validate_bytes(data).ok,
        "verify_reproduction": verified,
        "authored_command": spec.command,
        "attested_output_digest": verified.get("attestation", {}).get("output_digest", "")[:16] + "…",
        "reproduced_match": run["match"],
        "reproduction": run,
        "toolchain": run["toolchain_actual"],
    }
    report_path = dirs["reports"] / "living_manuscript.json"
    report_path.write_text(json.dumps(report, indent=2))
    for path in written:
        print(str(path))
    print(str(report_path))
    ok = report["opc_valid"] and verified["attested"] and verified["verified"] and run["match"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

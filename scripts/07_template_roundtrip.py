#!/usr/bin/env python3
"""Carry a real external project through all four formats, and prove it came back.

`06_project_roundtrip.py` uses a synthetic tree built to contain the awkward cases.
This script does the complementary job: it carries a *real* repository — the
docxology `template_code_project` exemplar, 100+ source files across a nested tree —
and confirms it survives the trip in every format the container emits:

    .docx  .docxplus   (OOXML surface / intelligence names, byte-identical)
    .odt   .odtplus    (ODF surface / intelligence names, byte-identical)

For each, the document is built, validated against its own conformance rules, read
back, and the extracted tree compared to the original file by file, byte by byte, and
mode by mode. All four artefacts and the report land in ``output/``.

A synthetic tree can be shaped to pass. A real one cannot, which is the point.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import crypto
import payloads
from container import DocxPlusBuilder, DocxPlusReader
from fileext import PLUS_EXTENSION, write_document
from odt_container import OdtPlusBuilder, OdtPlusReader, open_document
from project_paths import ensure_output_dirs
from validate import validate_bytes, validate_odt_bytes

#: The exemplar carried. Overridable so the script is not welded to one checkout.
DEFAULT_TEMPLATE = Path(
    os.environ.get(
        "DOCXPLUS_TEMPLATE_PROJECT",
        Path.home() / "Documents/GitHub/template/projects/templates/template_code_project",
    )
)


def snapshot(root: Path) -> dict:
    """Content digest and executable bit for every carried file, plus directories."""
    files, dirs = {}, set()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if payloads._excluded(rel):
            continue
        if path.is_symlink():
            continue  # refused at pack time; not part of the carried set
        if path.is_dir():
            dirs.add(str(rel))
        elif path.is_file():
            files[str(rel)] = {
                "digest": crypto.digest(path.read_bytes()),
                "executable": bool(os.stat(path).st_mode & stat.S_IXUSR),
            }
    return {"files": files, "dirs": dirs}


def compare(before: dict, after: dict) -> dict:
    want, got = before["files"], after["files"]
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    content = sorted(k for k in set(want) & set(got) if want[k]["digest"] != got[k]["digest"])
    mode = sorted(k for k in set(want) & set(got) if want[k]["executable"] != got[k]["executable"])
    return {
        "files_compared": len(want),
        "missing": missing,
        "unexpected": extra,
        "content_mismatches": content,
        "executable_bit_mismatches": mode,
        "identical": not (missing or extra or content or mode),
    }


def main() -> int:
    template = DEFAULT_TEMPLATE
    if not template.is_dir():
        sys.stderr.write(
            f"template project not found at {template}\n"
            "Set DOCXPLUS_TEMPLATE_PROJECT to a real project tree.\n"
        )
        return 1

    dirs = ensure_output_dirs()
    docs = dirs["documents"]
    priv, pub = crypto.generate_signing_key()
    before = snapshot(template)
    report: dict = {"source": str(template), "checks": [], "formats": {}}
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            failures.append(name)

    report["project"] = {
        "files_carried": len(before["files"]),
        "directories": len(before["dirs"]),
        "has_executable": any(f["executable"] for f in before["files"].values()),
    }

    # -- OOXML: .docx + .docxplus ------------------------------------------
    docx_builder = DocxPlusBuilder(
        paragraphs=[
            "Template Code Project — carried, sealed, and attested.",
            "This document contains the complete source tree of the exemplar it describes.",
        ],
        title="docxplus: carried template_code_project",
    )
    docx_builder.add_project("template_code_project", template, password="round-trip", kdf="argon2id")
    docx_builder.sign(priv)
    docx_bytes = docx_builder.build()
    docx_written = write_document(docx_bytes, docs / "template_code_project.docx")
    check("docx.writes_both_names", [p.suffix for p in docx_written] == [".docx", ".docxplus"])
    check("docx.names_are_byte_identical",
          docx_written[0].read_bytes() == docx_written[1].read_bytes())

    docx_report = validate_bytes(docx_bytes)
    check("docx.validates", docx_report.ok,
          "; ".join(docx_report.opc_errors + docx_report.intelligence_errors))

    # Read back from the .docxplus name specifically: the plus extension must be a
    # first-class input, not a decorative copy.
    docx_reader = DocxPlusReader.from_bytes(docx_written[1].read_bytes())
    check("docxplus.provenance_pinned", docx_reader.verify_provenance(expected_public_key=pub))
    docx_out = docx_reader.extract_project(
        "template_code_project", dirs["output"] / "roundtrip" / "from_docxplus",
        password="round-trip",
    )
    docx_cmp = compare(before, snapshot(docx_out))
    check("docxplus.roundtrip_identical", docx_cmp["identical"], json.dumps(docx_cmp)[:400])
    report["formats"]["docx"] = {
        "paths": [str(p) for p in docx_written],
        "bytes": len(docx_bytes),
        "comparison": docx_cmp,
    }

    # -- ODF: .odt + .odtplus ----------------------------------------------
    odt_builder = OdtPlusBuilder(
        paragraphs=[
            "Template Code Project — carried, sealed, and attested.",
            "The same source tree, in an OpenDocument container.",
        ],
        title="docxplus: carried template_code_project (ODF)",
    )
    odt_builder.add_project("template_code_project", template, password="round-trip", kdf="argon2id")
    odt_builder.sign(priv)
    odt_bytes = odt_builder.build()
    odt_written = write_document(odt_bytes, docs / "template_code_project.odt")
    check("odt.writes_both_names", [p.suffix for p in odt_written] == [".odt", ".odtplus"])
    check("odt.names_are_byte_identical",
          odt_written[0].read_bytes() == odt_written[1].read_bytes())

    odt_report = validate_odt_bytes(odt_bytes)
    check("odt.validates", odt_report.ok,
          "; ".join(odt_report.opc_errors + odt_report.intelligence_errors))

    odt_reader = OdtPlusReader.from_bytes(odt_written[1].read_bytes())
    check("odtplus.provenance_pinned", odt_reader.verify_provenance(expected_public_key=pub))
    odt_out = odt_reader.extract_project(
        "template_code_project", dirs["output"] / "roundtrip" / "from_odtplus",
        password="round-trip",
    )
    odt_cmp = compare(before, snapshot(odt_out))
    check("odtplus.roundtrip_identical", odt_cmp["identical"], json.dumps(odt_cmp)[:400])
    report["formats"]["odt"] = {
        "paths": [str(p) for p in odt_written],
        "bytes": len(odt_bytes),
        "comparison": odt_cmp,
    }

    # -- the two profiles must agree on the payload, not merely each succeed --
    docx_blob = docx_reader.extract("template_code_project", password="round-trip")
    odt_blob = odt_reader.extract("template_code_project", password="round-trip")
    check("cross.same_project_bytes", docx_blob == odt_blob)
    report["project_payload_digest"] = crypto.digest(docx_blob)

    # -- every emitted name opens through the profile-detecting entry point --
    for path in docx_written + odt_written:
        reader = open_document(path.read_bytes())
        check(f"dispatch.{path.suffix.lstrip('.')}",
              reader.verify_provenance(expected_public_key=pub),
              f"{path.name} -> {type(reader).__name__}")

    report["ok"] = not failures
    report["failures"] = failures
    out_path = dirs["reports"] / "template_roundtrip.json"
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))

    width = max(len(c["name"]) for c in report["checks"])
    print(f"\nTemplate project round trip — all four formats\n\n  source: {template}")
    print(f"  carrying {report['project']['files_carried']} files "
          f"in {report['project']['directories']} directories\n")
    for c in report["checks"]:
        print(f"  {'PASS' if c['ok'] else 'FAIL'}  {c['name']:<{width}}"
              + (f"  {c['detail'][:80]}" if not c["ok"] else ""))
    for fmt, info in report["formats"].items():
        print(f"\n  {fmt:5} {info['bytes']:>9,} bytes  "
              f"{info['comparison']['files_compared']} files identical")
        for p in info["paths"]:
            print(f"        {p}")
    print(f"\n  {'ALL CHECKS PASSED' if report['ok'] else 'FAILURES: ' + ', '.join(failures)}")
    print(f"  {out_path}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

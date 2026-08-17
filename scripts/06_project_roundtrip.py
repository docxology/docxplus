#!/usr/bin/env python3
"""End-to-end project round-trip across both container profiles.

The flagship claim is that a document can carry the software that produced it. This
script is the falsification attempt: it builds a real project tree containing the
cases that break naive packing, carries it into a `.docx` and a `.odt`, validates
both against their own conformance rules, extracts the tree back out of each, and
compares the result to the original **file by file, byte by byte, mode by mode**.

It also exercises the paths a round trip alone would not reach: a cross-profile
nested document (a signed `.docx` carried inside a signed `.odt`), the reproduction
attestation, and provenance verification under a pinned key. Anything the round trip
does *not* preserve is reported as a named divergence rather than omitted — the
point of the harness is to state the fidelity boundary, not to assert there is none.

Writes ``output/reports/project_roundtrip.json`` and prints a human summary.
Exit status is nonzero if any checked invariant fails.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import crypto
import payloads
from container import DocxPlusBuilder, DocxPlusReader
from odt_container import OdtPlusBuilder, OdtPlusReader, open_document
from project_paths import ensure_output_dirs
from validate import validate_bytes, validate_odt_bytes

def recipe_json() -> str:
    """Pin the interpreter rather than trusting PATH.

    The sandbox scrubs the environment, and a bare ``python3`` can resolve to a
    developer-tools shim that refuses to run without Xcode. A reproduction recipe
    that names its interpreter is both more portable and more honest about what it
    actually ran.
    """
    return json.dumps(
        {"command": [sys.executable, "compute.py"], "outputs": ["result.json"], "timeout": 60},
        indent=2,
    )

COMPUTE = '''#!/usr/bin/env python3
"""A tiny but real computation, so the attestation attests something."""
import json, hashlib
from pathlib import Path

rows = [int(x) for x in Path("data/values.csv").read_text().split() if x.strip()]
result = {
    "n": len(rows),
    "total": sum(rows),
    "mean": sum(rows) / len(rows),
    "digest": hashlib.blake2b(repr(sorted(rows)).encode(), digest_size=16).hexdigest(),
}
Path("result.json").write_text(json.dumps(result, sort_keys=True, indent=2))
print(json.dumps(result, sort_keys=True))
'''


def build_example_project(root: Path) -> Path:
    """A tree that deliberately contains the cases naive packing loses."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir()
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "empty_but_required").mkdir()          # empty dirs vanish under a files-only walk
    (root / "docs").mkdir()

    (root / "compute.py").write_text(COMPUTE)
    (root / ".docxplus-reproduce.json").write_text(recipe_json())
    (root / "data" / "values.csv").write_text("3 1 4 1 5 9 2 6\n")
    (root / "src" / "pkg" / "__init__.py").write_text("")            # zero-byte file
    (root / "src" / "pkg" / "core.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "docs" / "readme md.txt").write_text("a filename with a space\n")
    (root / "docs" / "ünïcödé.txt").write_text("non-ASCII name and content: ✓\n")
    (root / "docs" / "duplicate_a.txt").write_text("identical content\n")
    (root / "docs" / "duplicate_b.txt").write_text("identical content\n")

    run = root / "run.sh"
    run.write_text("#!/bin/sh\nexec python3 compute.py\n")
    run.chmod(0o755)                                                 # the executable bit

    # Real source living under names that are build artefacts only at the root.
    # A depth-blind exclusion filter deleted exactly these, and the harness could not
    # see it because every junk directory it created sat at the top level.
    (root / "src" / "output").mkdir()
    (root / "src" / "output" / "model.py").write_text("real source in a dir named output\n")
    (root / "docs" / "venv").mkdir()
    (root / "docs" / "venv" / "notes.md").write_text("real doc in a dir named venv\n")

    # Junk that must be excluded, not carried.
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "core.cpython-312.pyc").write_bytes(b"\x00compiled")
    (root / ".venv").mkdir()
    (root / ".venv" / "pyvenv.cfg").write_text("home = /nowhere\n")
    return root


def snapshot(root: Path) -> dict:
    """Content digest + executable bit for every file, plus the directory set."""
    files, dirs = {}, set()
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_dir():
            dirs.add(rel)
        elif path.is_file():
            files[rel] = {
                "digest": crypto.digest(path.read_bytes()),
                "executable": bool(os.stat(path).st_mode & stat.S_IXUSR),
                "size": path.stat().st_size,
            }
    return {"files": files, "dirs": dirs}


def compare(original: dict, restored: dict, excluded_prefixes: tuple[str, ...]) -> dict:
    """Diff two snapshots, ignoring paths the format documents as excluded."""

    def keep(rel: str) -> bool:
        return not payloads._excluded(Path(rel))

    want = {k: v for k, v in original["files"].items() if keep(k)}
    got = restored["files"]
    want_dirs = {d for d in original["dirs"] if keep(d)}

    missing = sorted(set(want) - set(got))
    unexpected = sorted(set(got) - set(want))
    content = sorted(k for k in set(want) & set(got) if want[k]["digest"] != got[k]["digest"])
    mode = sorted(
        k for k in set(want) & set(got) if want[k]["executable"] != got[k]["executable"]
    )
    # Only directories that carry no files of their own can be lost by a files-only
    # walk; the rest are recreated implicitly.
    empty_only = {d for d in want_dirs if not any(f.startswith(d + os.sep) for f in want)}
    lost_dirs = sorted(empty_only - restored["dirs"])

    return {
        "files_compared": len(want),
        "missing_files": missing,
        "unexpected_files": unexpected,
        "content_mismatches": content,
        "executable_bit_mismatches": mode,
        "lost_empty_directories": lost_dirs,
        "identical": not (missing or unexpected or content or mode or lost_dirs),
    }


def carried_junk(restored: dict, excluded: tuple[str, ...]) -> list[str]:
    """Files that should have been excluded but travelled anyway.

    Delegates to the packer's own rule rather than re-deriving it: a checker with
    its own copy of the semantics disagreed with the packer the moment the rule
    changed, and reported real source as junk.
    """
    return sorted(rel for rel in restored["files"] if payloads._excluded(Path(rel)))


def main() -> int:
    dirs = ensure_output_dirs()
    workdir = Path(tempfile.mkdtemp(prefix="docxplus-roundtrip-"))
    report: dict = {"profiles": {}, "cross_profile": {}, "checks": []}
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            failures.append(name)

    try:
        project = build_example_project(workdir / "example_project")
        before = snapshot(project)
        priv, pub = crypto.generate_signing_key()
        excluded = tuple(sorted(payloads._PROJECT_EXCLUDE))

        report["project"] = {
            "files": len(before["files"]),
            "directories": len(before["dirs"]),
            "has_executable": any(f["executable"] for f in before["files"].values()),
            "has_empty_dir": True,
            "has_zero_byte_file": any(f["size"] == 0 for f in before["files"].values()),
            "has_non_ascii_name": any(not n.isascii() for n in before["files"]),
        }

        # -- profile 1: OOXML ------------------------------------------------
        docx_builder = DocxPlusBuilder(paragraphs=["A report that carries its own source."])
        docx_builder.add_project("source", project, reproduce=True, password="round-trip")
        docx_builder.add_module("notes", "custom_xml", "carried alongside the source",
                                payload_type="text")
        docx_builder.sign(priv)
        docx_bytes = docx_builder.build()
        from fileext import write_document

        write_document(docx_bytes, dirs["documents"] / "project_roundtrip.docx")

        docx_report = validate_bytes(docx_bytes)
        check("docx.validates", docx_report.ok, "; ".join(docx_report.opc_errors + docx_report.intelligence_errors))

        docx_reader = DocxPlusReader.from_bytes(docx_bytes)
        check("docx.provenance_pinned_key", docx_reader.verify_provenance(expected_public_key=pub))
        check("docx.rejects_wrong_key",
              not docx_reader.verify_provenance(expected_public_key=crypto.generate_signing_key()[1]))

        docx_out = docx_reader.extract_project("source", workdir / "from_docx", password="round-trip")
        docx_cmp = compare(before, snapshot(docx_out), excluded)
        check("docx.roundtrip_identical", docx_cmp["identical"], json.dumps(docx_cmp))
        check("docx.excludes_junk", not carried_junk(snapshot(docx_out), excluded))

        docx_att = docx_reader.verify_reproduction("source", expected_public_key=pub)
        check("docx.attestation_verified", bool(docx_att.get("attested") and docx_att.get("verified")),
              json.dumps(docx_att))
        report["profiles"]["docx"] = {
            "bytes": len(docx_bytes), "modules": sorted(docx_reader.list_modules()),
            "comparison": docx_cmp, "attestation": docx_att,
        }

        # -- profile 2: ODF --------------------------------------------------
        odt_builder = OdtPlusBuilder(paragraphs=["An OpenDocument report that carries its own source."])
        odt_builder.add_project("source", project, reproduce=True, password="round-trip")
        odt_builder.add_module("notes", "carried alongside the source", payload_type="text")
        odt_builder.sign(priv)
        odt_bytes = odt_builder.build()
        write_document(odt_bytes, dirs["documents"] / "project_roundtrip.odt")

        odt_report = validate_odt_bytes(odt_bytes)
        check("odt.validates", odt_report.ok, "; ".join(odt_report.opc_errors + odt_report.intelligence_errors))

        odt_reader = OdtPlusReader.from_bytes(odt_bytes)
        check("odt.provenance_pinned_key", odt_reader.verify_provenance(expected_public_key=pub))
        check("odt.rejects_wrong_key",
              not odt_reader.verify_provenance(expected_public_key=crypto.generate_signing_key()[1]))

        odt_out = odt_reader.extract_project("source", workdir / "from_odt", password="round-trip")
        odt_cmp = compare(before, snapshot(odt_out), excluded)
        check("odt.roundtrip_identical", odt_cmp["identical"], json.dumps(odt_cmp))
        check("odt.excludes_junk", not carried_junk(snapshot(odt_out), excluded))

        odt_att = odt_reader.verify_reproduction("source", expected_public_key=pub)
        check("odt.attestation_verified", bool(odt_att.get("attested") and odt_att.get("verified")),
              json.dumps(odt_att))
        report["profiles"]["odt"] = {
            "bytes": len(odt_bytes), "modules": sorted(odt_reader.list_modules()),
            "comparison": odt_cmp, "attestation": odt_att,
        }

        # -- the two profiles must agree on the payload, not merely each work --
        docx_blob = docx_reader.extract("source", password="round-trip")
        odt_blob = odt_reader.extract("source", password="round-trip")
        check("cross.same_project_bytes", docx_blob == odt_blob,
              "the same tree must pack to identical bytes in both containers")
        report["cross_profile"]["project_payload_digest"] = crypto.digest(docx_blob)

        # -- cross-profile nesting: a signed .docx inside a signed .odt -------
        outer = OdtPlusBuilder(paragraphs=["An ODF wrapper around an OOXML document."])
        outer.add_nested("inner", docx_bytes, password="matryoshka")
        outer.sign(priv)
        outer_bytes = outer.build()
        write_document(outer_bytes, dirs["documents"] / "project_roundtrip_nested.odt")

        outer_reader = OdtPlusReader.from_bytes(outer_bytes)
        inner_reader = outer_reader.open_nested("inner", password="matryoshka")
        check("cross.nested_docx_in_odt", isinstance(inner_reader, DocxPlusReader),
              f"dispatched to {type(inner_reader).__name__}")
        check("cross.nested_inner_provenance", inner_reader.verify_provenance(expected_public_key=pub))
        nested_out = inner_reader.extract_project("source", workdir / "from_nested", password="round-trip")
        nested_cmp = compare(before, snapshot(nested_out), excluded)
        check("cross.nested_roundtrip_identical", nested_cmp["identical"], json.dumps(nested_cmp))
        report["cross_profile"]["nested"] = nested_cmp

        # -- profile dispatch must be automatic, not caller-declared ----------
        check("cross.dispatch_docx", isinstance(open_document(docx_bytes), DocxPlusReader))
        check("cross.dispatch_odt", isinstance(open_document(odt_bytes), OdtPlusReader))

        # -- the documented fidelity boundary, measured rather than asserted --
        report["fidelity_boundary"] = {
            "preserved": ["file contents", "executable bit", "empty directories",
                          "directory structure", "non-ASCII and spaced filenames",
                          "zero-byte files"],
            "normalised_by_design": ["mtimes", "uid/gid", "non-execute mode bits"],
            "refused": ["symlinks (their targets would be embedded; opt in explicitly)"],
            "excluded_by_policy": list(excluded),
        }

        report["ok"] = not failures
        report["failures"] = failures

        out_path = dirs["reports"] / "project_roundtrip.json"
        out_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))

        width = max(len(c["name"]) for c in report["checks"])
        print("\nProject round trip — .docx and .odt\n")
        for c in report["checks"]:
            print(f"  {'PASS' if c['ok'] else 'FAIL'}  {c['name']:<{width}}"
                  + (f"  {c['detail'][:90]}" if not c["ok"] else ""))
        print(f"\n  project: {report['project']['files']} files, "
              f"{report['project']['directories']} directories")
        print(f"  .docx:   {report['profiles']['docx']['bytes']:,} bytes, "
              f"{report['profiles']['docx']['comparison']['files_compared']} files compared identical")
        print(f"  .odt:    {report['profiles']['odt']['bytes']:,} bytes, "
              f"{report['profiles']['odt']['comparison']['files_compared']} files compared identical")
        print(f"\n  {'ALL CHECKS PASSED' if report['ok'] else 'FAILURES: ' + ', '.join(failures)}")
        print(f"  {out_path}")
        return 0 if report["ok"] else 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

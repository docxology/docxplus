"""What a `project` payload preserves, and what it refuses to carry.

The flagship claim is that a document can carry the software that produced it. That
is only true to the extent the round trip is lossless, so the boundary is pinned
here rather than assumed: contents, the executable bit, empty directories, awkward
filenames — and a hard refusal to dereference symlinks, which silently embedded
whatever they pointed at.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile

import pytest

import payloads


def _tree(root):
    (root / "src").mkdir(parents=True)
    (root / "empty").mkdir()
    (root / "src" / "core.py").write_text("X = 1\n")
    (root / "src" / "__init__.py").write_text("")            # zero bytes
    (root / "notes with spaces.txt").write_text("spaced\n")
    (root / "ünïcödé.txt").write_text("nön-ascii ✓\n")
    run = root / "run.sh"
    run.write_text("#!/bin/sh\necho hi\n")
    run.chmod(0o755)
    return root


def _roundtrip(tmp_path, root, **kw):
    blob = payloads.pack_project(root, **kw)
    return blob, payloads.unpack_project(blob, tmp_path / "out")


def test_contents_survive_byte_for_byte(tmp_path):
    root = _tree(tmp_path / "proj")
    _blob, out = _roundtrip(tmp_path, root)
    for rel in ("src/core.py", "src/__init__.py", "notes with spaces.txt", "ünïcödé.txt"):
        assert (out / rel).read_bytes() == (root / rel).read_bytes(), rel


def test_executable_bit_survives(tmp_path):
    """A carried entrypoint that comes back non-executable is not carried software."""
    root = _tree(tmp_path / "proj")
    _blob, out = _roundtrip(tmp_path, root)
    assert os.stat(out / "run.sh").st_mode & stat.S_IXUSR
    assert not os.stat(out / "src" / "core.py").st_mode & stat.S_IXUSR


def test_empty_directories_survive(tmp_path):
    root = _tree(tmp_path / "proj")
    _blob, out = _roundtrip(tmp_path, root)
    assert (out / "empty").is_dir()


def test_mode_bits_other_than_execute_are_normalised(tmp_path):
    """Determinism beats ownership metadata, and arbitrary modes are an unpack hazard."""
    root = _tree(tmp_path / "proj")
    (root / "odd.txt").write_text("x")
    (root / "odd.txt").chmod(0o600)
    blob = payloads.pack_project(root)
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        modes = {m.name: m.mode for m in tar.getmembers() if m.isfile()}
        assert set(modes.values()) <= {0o644, 0o755}
        assert all(m.uid == 0 and m.gid == 0 and m.uname == "" for m in tar.getmembers())


def test_packing_is_deterministic(tmp_path):
    root = _tree(tmp_path / "proj")
    assert payloads.pack_project(root) == payloads.pack_project(root)


def test_gzip_wrapper_carries_no_timestamp(tmp_path):
    """Determinism must not depend on two packs landing in the same second.

    The obvious equality test above passes even when the gzip header embeds
    wall-clock time, because both calls usually happen within one second — which is
    exactly how a silent no-op survived. Assert the header field itself instead.
    """
    root = _tree(tmp_path / "proj")
    blob = payloads.pack_project(root)
    assert blob[:2] == b"\x1f\x8b"                       # gzip magic
    assert int.from_bytes(blob[4:8], "little") == 0       # MTIME field
    assert blob[3] & 0x08 == 0                            # no embedded filename


def test_packing_is_deterministic_across_a_time_boundary(tmp_path, monkeypatch):
    """Simulate the clock advancing between two packs of the same tree."""
    import time as _time

    root = _tree(tmp_path / "proj")
    first = payloads.pack_project(root)
    real = _time.time
    monkeypatch.setattr(_time, "time", lambda: real() + 3600)
    assert payloads.pack_project(root) == first


def test_junk_directories_are_excluded(tmp_path):
    root = _tree(tmp_path / "proj")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "core.pyc").write_bytes(b"\x00")
    (root / ".venv").mkdir()
    (root / ".venv" / "cfg").write_text("x")
    _blob, out = _roundtrip(tmp_path, root)
    assert not (out / "__pycache__").exists()
    assert not (out / ".venv").exists()


# -- the symlink refusal ------------------------------------------------------


def test_symlink_is_refused_by_default(tmp_path):
    """Following the link would embed its target's bytes under the link's name."""
    root = _tree(tmp_path / "proj")
    secret = tmp_path / "OUTSIDE_SECRET"
    secret.write_text("sensitive host data")
    os.symlink(secret, root / "creds")

    with pytest.raises(payloads.ProjectPackError, match="refusing to pack symlinks"):
        payloads.pack_project(root)


def test_symlink_refusal_names_the_offending_paths(tmp_path):
    root = _tree(tmp_path / "proj")
    os.symlink(tmp_path / "elsewhere", root / "link_one")
    with pytest.raises(payloads.ProjectPackError) as exc:
        payloads.pack_project(root)
    assert "link_one" in str(exc.value)
    assert "follow_symlinks=True" in str(exc.value)


def test_dereferencing_requires_an_explicit_opt_in(tmp_path):
    """The dangerous behaviour remains reachable, but only when asked for by name."""
    root = _tree(tmp_path / "proj")
    target = tmp_path / "target.txt"
    target.write_text("dereferenced content")
    os.symlink(target, root / "link.txt")

    blob = payloads.pack_project(root, follow_symlinks=True)
    out = payloads.unpack_project(blob, tmp_path / "out")
    assert (out / "link.txt").read_text() == "dereferenced content"


@pytest.mark.parametrize(
    "kind,setup",
    [
        ("symlink", lambda i: (setattr(i, "type", tarfile.SYMTYPE), setattr(i, "linkname", "/etc/passwd"))),
        ("hard link", lambda i: (setattr(i, "type", tarfile.LNKTYPE), setattr(i, "linkname", "/etc/passwd"))),
        ("FIFO", lambda i: setattr(i, "type", tarfile.FIFOTYPE)),
        ("character device", lambda i: (setattr(i, "type", tarfile.CHRTYPE), setattr(i, "devmajor", 1))),
        ("block device", lambda i: (setattr(i, "type", tarfile.BLKTYPE), setattr(i, "devmajor", 8))),
    ],
)
def test_unpack_refuses_every_member_that_is_not_a_file_or_directory(tmp_path, kind, setup):
    """The guard tests for what is *allowed*, not for a list of what is not.

    It previously refused links only, leaving FIFOs and device nodes to whatever the
    interpreter's extraction filter happened to do. A positive check means a tar
    member type nobody has thought about is refused rather than admitted by default.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        info = tarfile.TarInfo("evil")
        setup(info)
        tar.addfile(info)
    with pytest.raises(ValueError, match="only plain files and directories"):
        payloads.unpack_project(raw.getvalue(), tmp_path / "out")


# -- both container profiles carry the same guarantees ------------------------


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_project_round_trips_through_both_containers(tmp_path, profile):
    import crypto

    root = _tree(tmp_path / "proj")
    priv, pub = crypto.generate_signing_key()

    if profile == "docx":
        from container import DocxPlusBuilder, DocxPlusReader

        builder = DocxPlusBuilder(paragraphs=["carrier"])
        builder.add_project("source", root, password="pw").sign(priv)
        reader = DocxPlusReader.from_bytes(builder.build())
    else:
        from odt_container import OdtPlusBuilder, OdtPlusReader

        builder = OdtPlusBuilder(paragraphs=["carrier"])
        builder.add_project("source", root, password="pw").sign(priv)
        reader = OdtPlusReader.from_bytes(builder.build())

    assert reader.verify_provenance(expected_public_key=pub) is True
    out = reader.extract_project("source", tmp_path / f"out_{profile}", password="pw")
    assert (out / "src" / "core.py").read_text() == "X = 1\n"
    assert os.stat(out / "run.sh").st_mode & stat.S_IXUSR
    assert (out / "empty").is_dir()


def test_the_same_tree_packs_identically_for_both_profiles(tmp_path):
    """Profile parity means the payload bytes agree, not merely that both succeed."""
    from container import DocxPlusBuilder, DocxPlusReader
    from odt_container import OdtPlusBuilder, OdtPlusReader

    root = _tree(tmp_path / "proj")
    docx = DocxPlusBuilder(paragraphs=["c"]).add_project("s", root).build()
    odt = OdtPlusBuilder(paragraphs=["c"]).add_project("s", root).build()
    assert (
        DocxPlusReader.from_bytes(docx).extract("s")
        == OdtPlusReader.from_bytes(odt).extract("s")
    )


def test_open_document_dispatches_on_the_container(tmp_path):
    from container import DocxPlusBuilder, DocxPlusReader
    from odt_container import OdtPlusBuilder, OdtPlusReader, open_document

    docx = DocxPlusBuilder(paragraphs=["c"]).add_module("m", "package_part", b"x").build()
    odt = OdtPlusBuilder(paragraphs=["c"]).add_module("m", b"x").build()
    assert isinstance(open_document(docx), DocxPlusReader)
    assert isinstance(open_document(odt), OdtPlusReader)


def test_open_document_rejects_a_non_package(tmp_path):
    from container import ContainerError
    from odt_container import open_document

    with pytest.raises(ContainerError, match="not a readable document package"):
        open_document(b"definitely not a zip")


def test_a_docx_nests_inside_an_odt_and_still_verifies(tmp_path):
    """Matryoshka nesting must not care which container the inner document uses."""
    import crypto
    from container import DocxPlusBuilder, DocxPlusReader
    from odt_container import OdtPlusBuilder, OdtPlusReader

    priv, pub = crypto.generate_signing_key()
    root = _tree(tmp_path / "proj")

    inner = DocxPlusBuilder(paragraphs=["inner"])
    inner.add_project("source", root).sign(priv)
    inner_bytes = inner.build()

    outer = OdtPlusBuilder(paragraphs=["outer"])
    outer.add_nested("inner", inner_bytes, password="matryoshka").sign(priv)

    reader = OdtPlusReader.from_bytes(outer.build())
    nested = reader.open_nested("inner", password="matryoshka")
    assert isinstance(nested, DocxPlusReader)
    assert nested.verify_provenance(expected_public_key=pub) is True
    out = nested.extract_project("source", tmp_path / "deep")
    assert (out / "src" / "core.py").read_text() == "X = 1\n"


def test_odt_carries_and_verifies_a_reproduction_attestation(tmp_path):
    """Attestation parity: an ODF document that could not attest would be second-class."""
    import json
    import sys

    import crypto
    from odt_container import OdtPlusBuilder, OdtPlusReader

    root = tmp_path / "proj"
    root.mkdir()
    (root / "compute.py").write_text("from pathlib import Path\nPath('out.txt').write_text('42')\n")
    (root / ".docxplus-reproduce.json").write_text(
        json.dumps({"command": [sys.executable, "compute.py"], "outputs": ["out.txt"], "timeout": 60})
    )

    priv, pub = crypto.generate_signing_key()
    builder = OdtPlusBuilder(paragraphs=["carrier"])
    builder.add_project("source", root, reproduce=True).sign(priv)
    reader = OdtPlusReader.from_bytes(builder.build())

    info = reader.verify_reproduction("source", expected_public_key=pub)
    assert info["attested"] is True
    assert info["verified"] is True
    assert info["attestation"]["output_digest"]


def test_exclusion_does_not_delete_real_source_at_depth(tmp_path):
    """`output` and `venv` are build artefacts at the root and ordinary words below it.

    Matching the bare name at any depth silently deleted `src/output/model.py` and
    `docs/venv/notes.md` from carried projects — data loss under the flagship claim,
    invisible because the round-trip harness only placed junk at the root.
    """
    root = tmp_path / "proj"
    for rel, txt in [
        ("src/output/model.py", "REAL SOURCE\n"),
        ("docs/venv/notes.md", "REAL DOC\n"),
        ("src/main.py", "x\n"),
    ]:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt)

    _blob, out = _roundtrip(tmp_path, root)
    assert (out / "src" / "output" / "model.py").read_text() == "REAL SOURCE\n"
    assert (out / "docs" / "venv" / "notes.md").read_text() == "REAL DOC\n"


def test_root_level_build_directories_are_still_excluded(tmp_path):
    root = tmp_path / "proj"
    for rel in ("output/build.log", ".venv/cfg", "node_modules/pkg/index.js", "src/main.py"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n")

    _blob, out = _roundtrip(tmp_path, root)
    assert not (out / "output").exists()
    assert not (out / ".venv").exists()
    assert not (out / "node_modules").exists()
    assert (out / "src" / "main.py").exists()


def test_tool_caches_are_excluded_at_any_depth(tmp_path):
    """A __pycache__ is never source, wherever it sits."""
    root = tmp_path / "proj"
    for rel in ("src/__pycache__/m.pyc", "deep/nested/.pytest_cache/x", "src/main.py"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n")

    _blob, out = _roundtrip(tmp_path, root)
    assert not (out / "src" / "__pycache__").exists()
    assert not (out / "deep" / "nested" / ".pytest_cache").exists()
    assert (out / "src" / "main.py").exists()


# -- the four emitted formats are one guarantee, not four ---------------------


def test_all_four_formats_carry_and_return_the_same_tree(tmp_path):
    """`.docx`, `.docxplus`, `.odt`, `.odtplus` must be interchangeable as inputs.

    A plus extension that only *looks* like a document — written but never read back
    from — would be decoration. Each name is opened here as a first-class input.
    """
    import crypto
    from fileext import write_document
    from odt_container import OdtPlusBuilder, open_document

    from container import DocxPlusBuilder

    root = _tree(tmp_path / "proj")
    priv, pub = crypto.generate_signing_key()

    docx = DocxPlusBuilder(paragraphs=["carrier"])
    docx.add_project("src", root, password="pw").sign(priv)
    odt = OdtPlusBuilder(paragraphs=["carrier"])
    odt.add_project("src", root, password="pw").sign(priv)

    written = write_document(docx.build(), tmp_path / "doc.docx")
    written += write_document(odt.build(), tmp_path / "doc.odt")
    assert [p.suffix for p in written] == [".docx", ".docxplus", ".odt", ".odtplus"]

    for path in written:
        reader = open_document(path.read_bytes())
        assert reader.verify_provenance(expected_public_key=pub) is True, path.name
        out = reader.extract_project("src", tmp_path / f"out{path.suffix}", password="pw")
        assert (out / "src" / "core.py").read_text() == "X = 1\n", path.name
        assert os.stat(out / "run.sh").st_mode & stat.S_IXUSR, path.name


def test_the_template_roundtrip_report_records_a_real_external_project():
    """The committed evidence must describe a real tree, not a fixture.

    A synthetic tree can be shaped to pass; carrying an external repository is what
    makes the round-trip claim load-bearing.
    """
    import json

    from project_paths import project_root

    path = project_root() / "output" / "reports" / "template_roundtrip.json"
    if not path.is_file():
        pytest.skip("run scripts/07_template_roundtrip.py to produce the report")
    report = json.loads(path.read_text())

    assert report["ok"] is True, report.get("failures")
    assert report["project"]["files_carried"] > 50, "a handful of files proves little"
    assert set(report["formats"]) == {"docx", "odt"}
    for info in report["formats"].values():
        assert info["comparison"]["identical"] is True
        assert len(info["paths"]) == 2  # surface + plus name
    # Every emitted name must have been opened through the profile detector.
    dispatched = {c["name"] for c in report["checks"] if c["name"].startswith("dispatch.")}
    assert dispatched == {"dispatch.docx", "dispatch.docxplus",
                          "dispatch.odt", "dispatch.odtplus"}

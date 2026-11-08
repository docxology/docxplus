"""What a `project` payload preserves, and what it refuses to carry.

The flagship claim is that a document can carry the software that produced it. That
is only true to the extent the round trip is lossless, so the boundary is pinned
here rather than assumed: contents, the executable bit, empty directories, awkward
filenames — and a hard refusal to dereference symlinks, which silently embedded
whatever they pointed at.
"""

from __future__ import annotations

import gzip
import io
import os
import stat
import tarfile

import pytest

from docxplus import payloads


def _tree(root):
    (root / "src").mkdir(parents=True)
    (root / "empty").mkdir()
    (root / "src" / "core.py").write_text("X = 1\n")
    (root / "src" / "__init__.py").write_text("")  # zero bytes
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
    assert blob[:2] == b"\x1f\x8b"  # gzip magic
    assert int.from_bytes(blob[4:8], "little") == 0  # MTIME field
    assert blob[3] & 0x08 == 0  # no embedded filename


def test_packing_is_deterministic_across_a_time_boundary(tmp_path, monkeypatch):
    """Simulate the clock advancing between two packs of the same tree."""
    import time as _time

    root = _tree(tmp_path / "proj")
    first = payloads.pack_project(root)
    real = _time.time
    monkeypatch.setattr(_time, "time", lambda: real() + 3600)
    assert payloads.pack_project(root) == first


def test_pack_project_size_cap(tmp_path):
    """A tree over max_uncompressed is refused at pack time, naming the offending member.

    Both halves matter: the refusal fires at authoring time (so an over-cap tree
    can never seal into an unextractable document), and the message says what to
    shrink rather than merely that something failed.
    """
    root = _tree(tmp_path / "proj")
    with pytest.raises(
        payloads.ProjectPackError, match="over the 10-byte decompression cap"
    ) as info:
        payloads.pack_project(root, max_uncompressed=10)
    assert "run.sh" in str(info.value)


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
        (
            "symlink",
            lambda i: (setattr(i, "type", tarfile.SYMTYPE), setattr(i, "linkname", "/etc/passwd")),
        ),
        (
            "hard link",
            lambda i: (setattr(i, "type", tarfile.LNKTYPE), setattr(i, "linkname", "/etc/passwd")),
        ),
        ("FIFO", lambda i: setattr(i, "type", tarfile.FIFOTYPE)),
        (
            "character device",
            lambda i: (setattr(i, "type", tarfile.CHRTYPE), setattr(i, "devmajor", 1)),
        ),
        (
            "block device",
            lambda i: (setattr(i, "type", tarfile.BLKTYPE), setattr(i, "devmajor", 8)),
        ),
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
    with pytest.raises(ValueError):
        payloads.unpack_project(raw.getvalue(), tmp_path / "out")


# -- both container profiles carry the same guarantees ------------------------


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_project_round_trips_through_both_containers(tmp_path, profile):
    from docxplus import crypto

    root = _tree(tmp_path / "proj")
    priv, pub = crypto.generate_signing_key()

    if profile == "docx":
        from docxplus.container import DocxPlusBuilder, DocxPlusReader

        builder = DocxPlusBuilder(paragraphs=["carrier"])
        builder.add_project("source", root, password="pw").sign(priv)
        reader = DocxPlusReader.from_bytes(builder.build())
    else:
        from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

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
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    root = _tree(tmp_path / "proj")
    docx = DocxPlusBuilder(paragraphs=["c"]).add_project("s", root).build()
    odt = OdtPlusBuilder(paragraphs=["c"]).add_project("s", root).build()
    assert DocxPlusReader.from_bytes(docx).extract("s") == OdtPlusReader.from_bytes(odt).extract(
        "s"
    )


def test_open_document_dispatches_on_the_container(tmp_path):
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader, open_document

    docx = DocxPlusBuilder(paragraphs=["c"]).add_module("m", "package_part", b"x").build()
    odt = OdtPlusBuilder(paragraphs=["c"]).add_module("m", b"x").build()
    assert isinstance(open_document(docx), DocxPlusReader)
    assert isinstance(open_document(odt), OdtPlusReader)


def test_open_document_rejects_a_non_package(tmp_path):
    from docxplus.container import ContainerError
    from docxplus.odt_container import open_document

    with pytest.raises(ContainerError):
        open_document(b"definitely not a zip")


def test_a_docx_nests_inside_an_odt_and_still_verifies(tmp_path):
    """Matryoshka nesting must not care which container the inner document uses."""
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

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

    from docxplus import crypto
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    root = tmp_path / "proj"
    root.mkdir()
    (root / "compute.py").write_text("from pathlib import Path\nPath('out.txt').write_text('42')\n")
    (root / ".docxplus-reproduce.json").write_text(
        json.dumps(
            {"command": [sys.executable, "compute.py"], "outputs": ["out.txt"], "timeout": 60}
        )
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
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder
    from docxplus.fileext import write_document
    from docxplus.odt_container import OdtPlusBuilder, open_document

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

    from docxplus.project_paths import project_root

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
    assert dispatched == {"dispatch.docx", "dispatch.docxplus", "dispatch.odt", "dispatch.odtplus"}


def test_add_project_refuses_oversized_tree_at_authoring_time_both_profiles(tmp_path):
    """The refusal must reach the builder API, not only payloads.pack_project.

    A tree over the decompression cap used to seal happily into a signed, validated
    document whose payload could never be extracted. Both profiles share one sealing
    lineage, so both must refuse at authoring time — and a deliberately raised
    max_uncompressed must be honoured by both, symmetric with unpack.
    """
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "blob.bin").write_bytes(b"\0" * 1000)

    cases = (
        (DocxPlusBuilder, DocxPlusReader),
        (OdtPlusBuilder, OdtPlusReader),
    )
    for builder_cls, reader_cls in cases:
        b = builder_cls(paragraphs=["cover"], title="t")
        with pytest.raises(ValueError, match="decompression cap"):
            b.add_project("p", proj, max_uncompressed=500)

        raised = builder_cls(paragraphs=["cover"], title="t")
        raised.add_project("p", proj, max_uncompressed=2000)
        extracted_dir = tmp_path / f"out_{builder_cls.__name__}"
        extracted_dir.mkdir()
        reader = reader_cls.from_bytes(raised.build())
        with pytest.raises(ValueError, match="decompression cap"):
            reader.extract_project("p", extracted_dir, max_uncompressed=500)
        reader.extract_project("p", extracted_dir, max_uncompressed=2000)
        assert (extracted_dir / "blob.bin").read_bytes() == b"\0" * 1000


def _project_archive(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return raw.getvalue()


def test_extraction_refuses_nonempty_destination_without_touching_hardlinks(tmp_path):
    """Project recovery never merges into a tree containing outside inode aliases."""
    outside = tmp_path / "outside"
    outside.write_bytes(b"preserved outside data")
    dest = tmp_path / "out"
    dest.mkdir()
    os.link(outside, dest / "file")
    blob = _project_archive([("file", b"new private contents")])
    with pytest.raises(FileExistsError, match="nonempty"):
        payloads.unpack_project(blob, dest)
    assert outside.read_bytes() == (dest / "file").read_bytes() == b"preserved outside data"
    assert set(tmp_path.iterdir()) == {outside, dest}


def test_empty_destination_is_replaced_by_private_faithful_tree(tmp_path):
    """An existing empty directory is supported, but no old inode becomes the tree."""
    root = _tree(tmp_path / "source")
    dest = tmp_path / "out"
    dest.mkdir(mode=0o755)
    previous_inode = dest.stat().st_ino
    payloads.unpack_project(payloads.pack_project(root), dest)
    assert dest.stat().st_ino != previous_inode
    assert dest.stat().st_mode & 0o777 == 0o700
    assert (dest / "empty").is_dir()
    assert (dest / "run.sh").stat().st_mode & stat.S_IXUSR
    assert (dest / "src" / "core.py").read_bytes() == b"X = 1\n"


def test_project_destination_symlink_is_never_followed(tmp_path):
    """A destination alias must not direct project writes outside the fresh tree."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_bytes(b"sentinel")
    dest = tmp_path / "out"
    dest.symlink_to(outside, target_is_directory=True)
    with pytest.raises(FileExistsError):
        payloads.unpack_project(_project_archive([("file", b"replacement")]), dest)
    assert (outside / "file").read_bytes() == b"sentinel"
    assert dest.is_symlink()


@pytest.mark.parametrize(
    "entries",
    [
        [("first", b"would otherwise be written"), ("../outside", b"escape")],
        [("same", b"first"), ("same", b"second")],
        [("dir/child", b"child"), ("dir", b"conflicting file")],
        [("dir", b"conflicting file"), ("dir/child", b"child")],
    ],
)
def test_entire_project_is_validated_before_any_destination_publication(tmp_path, entries):
    """Late traversal/duplicate/type conflicts cannot leave a partial recovered tree."""
    dest = tmp_path / "out"
    with pytest.raises(ValueError):
        payloads.unpack_project(_project_archive(entries), dest)
    assert list(tmp_path.iterdir()) == []


def test_project_zero_length_member_count_is_bounded_before_writing(tmp_path):
    """Empty files do not consume content budget, but must consume member budget."""
    blob = _project_archive([("one", b""), ("two", b"")])
    with pytest.raises(ValueError):
        payloads.unpack_project(blob, tmp_path / "out", max_uncompressed=0, max_members=1)
    assert list(tmp_path.iterdir()) == []


def test_implicit_directories_consume_the_project_node_budget(tmp_path):
    """A single deeply named file cannot create unaccounted filesystem objects."""
    blob = _project_archive([("one/two/three", b"")])
    with pytest.raises(ValueError, match="node count"):
        payloads.unpack_project(blob, tmp_path / "out", max_members=2)
    assert list(tmp_path.iterdir()) == []


def test_project_tar_header_metadata_is_bounded_before_writing(tmp_path):
    """Header bytes count independently from zero-length file contents."""
    blob = _project_archive([("one", b"")])
    with pytest.raises(ValueError):
        payloads.unpack_project(blob, tmp_path / "out", max_uncompressed=0, max_metadata=511)
    assert list(tmp_path.iterdir()) == []


def test_project_pax_metadata_has_an_individual_preparse_bound(tmp_path):
    """A small gzip with oversized PAX text refuses before tarfile materializes it."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("file")
        info.pax_headers = {"path": "x" * (payloads.MAX_PROJECT_PAX + 1)}
        archive.addfile(info)
    with pytest.raises(ValueError):
        payloads.unpack_project(raw.getvalue(), tmp_path / "out")
    assert list(tmp_path.iterdir()) == []


def test_project_pax_size_override_cannot_bypass_raw_tar_accounting(tmp_path):
    """Only supported inert PAX metadata is admitted; content sizing is not delegated."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("file")
        info.pax_headers = {"size": "999999999"}
        archive.addfile(info)
    with pytest.raises(ValueError):
        payloads.unpack_project(raw.getvalue(), tmp_path / "out")
    assert list(tmp_path.iterdir()) == []


def test_project_compressed_bytes_have_a_separate_budget(tmp_path):
    blob = _project_archive([("file", b"data")])
    with pytest.raises(ValueError, match="compressed project"):
        payloads.unpack_project(blob, tmp_path / "out", max_compressed=len(blob) - 1)
    assert list(tmp_path.iterdir()) == []


def test_decompressed_tar_padding_is_bounded_even_without_members(tmp_path):
    """All decompressed bytes count, including metadata and trailing zero padding."""
    blob = gzip.compress(b"\0" * 10241, mtime=0)
    with pytest.raises(ValueError):
        payloads.unpack_project(
            blob,
            tmp_path / "out",
            max_uncompressed=0,
            max_members=0,
            max_metadata=0,
        )
    assert list(tmp_path.iterdir()) == []


def test_pack_enforces_member_and_compressed_budgets(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "one").write_bytes(b"")
    (root / "two").write_bytes(b"")
    with pytest.raises(payloads.ProjectPackError, match="member count"):
        payloads.pack_project(root, max_members=1)
    with pytest.raises(payloads.ProjectPackError, match="compressed project"):
        payloads.pack_project(root, max_compressed=1)


def test_packing_refuses_symlinked_source_ancestors(tmp_path):
    """No-follow capture applies to directory traversal, not only the leaf file."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"outside sentinel")
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        payloads.pack_project(alias)


def test_pax_extension_chains_are_bounded_before_recursive_tar_parsing(tmp_path):
    """A bounded byte stream must not imply an unbounded parser recursion chain."""
    extension = tarfile.TarInfo("pax")
    extension.type = tarfile.XHDTYPE
    file = tarfile.TarInfo("file")
    blob = gzip.compress(extension.tobuf() * 3 + file.tobuf() + b"\0" * 1024, mtime=0)
    with pytest.raises(ValueError):
        payloads.unpack_project(blob, tmp_path / "out")
    assert list(tmp_path.iterdir()) == []


def test_project_parent_symlink_cannot_create_outside_directories(tmp_path):
    """Even creating missing destination ancestors must remain descriptor-relative."""
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        payloads.unpack_project(_project_archive([("file", b"new")]), alias / "new" / "out")
    assert list(outside.iterdir()) == []


def test_portable_literal_colon_filenames_survive(tmp_path):
    """An embedded colon is not a drive prefix and remains an ordinary filename."""
    root = tmp_path / "source"
    root.mkdir()
    name = "part:name.txt"
    (root / name).write_text(name)
    out = payloads.unpack_project(payloads.pack_project(root), tmp_path / "out")
    assert (out / name).read_text() == name


def test_private_tree_retains_fidelity_under_a_restrictive_umask(tmp_path):
    """The root is private while carried execute/plain/directory modes stay normalized."""
    root = _tree(tmp_path / "source")
    blob = payloads.pack_project(root)
    previous = os.umask(0o077)
    try:
        dest = payloads.unpack_project(blob, tmp_path / "out")
    finally:
        os.umask(previous)
    assert dest.stat().st_mode & 0o777 == 0o700
    assert (dest / "empty").stat().st_mode & 0o777 == 0o755
    assert (dest / "src" / "core.py").stat().st_mode & 0o777 == 0o644
    assert (dest / "run.sh").stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize(
    "name", [r"literal\filename.txt", "C:relative.txt", "bad\nname", "bad\x7fname"]
)
def test_pack_refuses_names_the_portable_reader_cannot_accept(tmp_path, name):
    """Authoring must not emit an archive rejected by the reader's path policy."""
    root = tmp_path / "source"
    root.mkdir()
    (root / name).write_bytes(b"contents")
    with pytest.raises(payloads.ProjectPackError, match="unsafe path"):
        payloads.pack_project(root)


def test_pack_prunes_excluded_subtrees_before_symlink_admission(tmp_path):
    """Excluded caches neither expose linked host files nor consume carried nodes."""
    root = tmp_path / "source"
    root.mkdir()
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "secret").symlink_to(tmp_path / "outside")
    (root / "kept").write_bytes(b"content")
    blob = payloads.pack_project(root, max_members=1)
    out = payloads.unpack_project(blob, tmp_path / "out", max_members=1)
    assert [path.name for path in out.iterdir()] == ["kept"]


def test_invalid_physical_tar_header_is_a_controlled_refusal(tmp_path):
    """Malformed untrusted headers must not escape as tarfile parser exceptions."""
    header = bytearray(tarfile.TarInfo("file").tobuf())
    header[0] ^= 1  # Invalidate the physical header checksum.
    blob = gzip.compress(bytes(header) + b"\0" * 1024, mtime=0)
    destination = tmp_path / "out"
    with pytest.raises(ValueError):
        payloads.unpack_project(blob, destination)
    assert not destination.exists()


def _physical_member(kind=tarfile.REGTYPE, content=b""):
    info = tarfile.TarInfo("file")
    info.type = kind
    info.size = len(content)
    return info.tobuf() + content + b"\0" * (-len(content) % 512)


def _pax_record(key, value):
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while True:
        record = str(length).encode("ascii") + b" " + body
        if len(record) == length:
            return record
        length = len(record)


@pytest.mark.parametrize(
    "case",
    [
        "missing_end",
        "partial_end",
        "unaligned",
        "nonzero_tail",
        "orphan",
        "global_pax",
        "stacked_pax",
        "stacked_pathnames",
        "duplicate_pax",
        "size_override",
        "sparse_override",
        "malformed_pax",
        "directory_content",
    ],
)
def test_all_tar_consumers_share_physical_admission(tmp_path, case):
    """Project and release intake refuse the same physical parser ambiguities."""
    from docxplus.archive_limits import ArchiveLimitError, bounded_tar, validate_plain_tar
    from scripts import validate_release as release

    file = _physical_member()
    pax = _physical_member(tarfile.XHDTYPE)
    end = b"\0" * 1024
    cases = {
        "missing_end": file,
        "partial_end": file + end[:512],
        "unaligned": file + end + b"\0",
        "nonzero_tail": file + end + b"x" * 512,
        "orphan": pax + end,
        "global_pax": _physical_member(tarfile.XGLTYPE) + file + end,
        "stacked_pax": pax + pax + file + end,
        "stacked_pathnames": pax
        + _physical_member(tarfile.GNUTYPE_LONGNAME, b"name\0")
        + file
        + end,
        "duplicate_pax": _physical_member(
            tarfile.XHDTYPE,
            _pax_record(b"path", b"first") + _pax_record(b"path", b"second"),
        )
        + file
        + end,
        "size_override": _physical_member(tarfile.XHDTYPE, _pax_record(b"size", b"1")) + file + end,
        "sparse_override": _physical_member(
            tarfile.XHDTYPE,
            _pax_record(b"GNU.sparse.map", b"0,1"),
        )
        + file
        + end,
        "malformed_pax": _physical_member(tarfile.XHDTYPE, b"99 path=x\n") + file + end,
        "directory_content": _physical_member(tarfile.DIRTYPE, b"unexpected") + end,
    }
    plain = cases[case]
    encoded = gzip.compress(plain, mtime=0)
    with pytest.raises(ArchiveLimitError):
        validate_plain_tar(io.BytesIO(plain), max_data_bytes=1024, max_members=4)
    with (
        pytest.raises(ArchiveLimitError),
        bounded_tar(io.BytesIO(encoded), max_data_bytes=1024, max_members=4),
    ):
        pytest.fail("malformed physical TAR was admitted")
    with pytest.raises(ValueError):
        payloads.unpack_project(encoded, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    archive = tmp_path / "evidence.tar.gz"
    archive.write_bytes(encoded)
    with pytest.raises(release.Refusal), release.bounded_tar(archive, 1024, 4):
        pytest.fail("release importer admitted malformed physical TAR")


@pytest.mark.parametrize("suffix", [b"trailing", gzip.compress(b"", mtime=0)])
def test_project_and_release_refuse_gzip_suffixes(tmp_path, suffix):
    """Gzip convenience-reader concatenation must not bypass the single-member rule."""
    from scripts import validate_release as release

    encoded = _project_archive([("file", b"content")]) + suffix
    with pytest.raises(ValueError):
        payloads.unpack_project(encoded, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    archive = tmp_path / "evidence.tar.gz"
    archive.write_bytes(encoded)
    with pytest.raises(release.Refusal), release.bounded_tar(archive, 1024, 4):
        pytest.fail("release importer admitted a gzip suffix")


def test_shared_tar_budgets_bound_headers_content_and_encoded_bytes(tmp_path):
    """Each explicit budget refuses independently before returning an admitted TAR."""
    from docxplus.archive_limits import ArchiveLimitError, bounded_tar, validate_plain_tar

    plain = _physical_member(content=b"ab") + _physical_member(content=b"cd") + b"\0" * 1024
    encoded = gzip.compress(plain, mtime=0)
    budgets = [
        {"max_data_bytes": 3, "max_members": 2},
        {"max_data_bytes": 4, "max_members": 1},
        {"max_data_bytes": 4, "max_members": 2, "max_metadata_bytes": 1023},
    ]
    for budget in budgets:
        with pytest.raises(ArchiveLimitError):
            validate_plain_tar(io.BytesIO(plain), **budget)
        with pytest.raises(ArchiveLimitError), bounded_tar(io.BytesIO(encoded), **budget):
            pytest.fail("archive exceeded an explicit resource budget")
    with (
        pytest.raises(ArchiveLimitError),
        bounded_tar(
            io.BytesIO(encoded),
            max_data_bytes=4,
            max_members=2,
            max_encoded_bytes=len(encoded) - 1,
        ),
    ):
        pytest.fail("encoded archive exceeded its independent byte budget")
    with bounded_tar(
        io.BytesIO(encoded),
        max_data_bytes=4,
        max_members=2,
        max_metadata_bytes=1024,
        max_encoded_bytes=len(encoded),
    ) as admitted:
        assert admitted.read() == plain


def test_author_and_reader_share_exact_header_metadata_budget(tmp_path):
    """A zero-byte file still needs one physical header on both sides of authoring."""
    root = tmp_path / "source"
    root.mkdir()
    (root / "empty").write_bytes(b"")
    with pytest.raises(payloads.ProjectPackError):
        payloads.pack_project(root, max_uncompressed=0, max_metadata=511)
    encoded = payloads.pack_project(root, max_uncompressed=0, max_metadata=512)
    out = payloads.unpack_project(
        encoded,
        tmp_path / "out",
        max_uncompressed=0,
        max_metadata=512,
    )
    assert (out / "empty").read_bytes() == b""


@pytest.mark.parametrize("kind", [tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME])
def test_single_local_pathname_extension_retains_content(tmp_path, kind):
    """One supported local extension remains usable without global parser state."""
    from docxplus.archive_limits import bounded_tar, validate_plain_tar
    from scripts import validate_release as release

    name = "long-" + "n" * 120
    metadata = (
        _pax_record(b"path", name.encode()) if kind == tarfile.XHDTYPE else name.encode() + b"\0"
    )
    plain = _physical_member(kind, metadata) + _physical_member(content=b"contents") + b"\0" * 1024
    validate_plain_tar(io.BytesIO(plain), max_data_bytes=8, max_members=1)
    encoded = gzip.compress(plain, mtime=0)
    with bounded_tar(io.BytesIO(encoded), max_data_bytes=8, max_members=1) as admitted:
        assert admitted.read() == plain
    out = payloads.unpack_project(encoded, tmp_path / "out", max_uncompressed=8)
    assert (out / name).read_bytes() == b"contents"
    archive = tmp_path / "evidence.tar.gz"
    archive.write_bytes(encoded)
    release.extract_archive(archive, tmp_path / "evidence", limit=8, count_limit=1)
    assert (tmp_path / "evidence" / name).read_bytes() == b"contents"

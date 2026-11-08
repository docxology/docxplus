"""Typed payload registry: bytes/text/json and the project/nested types."""

from __future__ import annotations

import pytest

from docxplus import payloads


def test_bytes_type():
    t = payloads.get_type("bytes")
    assert t.pack(b"x") == b"x"
    assert t.unpack(b"x") == b"x"


def test_text_type_roundtrip():
    t = payloads.get_type("text")
    assert t.unpack(t.pack("héllo")) == "héllo"


def test_json_type_roundtrip_and_canonical():
    t = payloads.get_type("json")
    obj = {"b": 2, "a": [1, 2, 3]}
    packed = t.pack(obj)
    assert packed == b'{"a":[1,2,3],"b":2}'  # sorted, compact
    assert t.unpack(packed) == obj


def test_unknown_type():
    with pytest.raises(ValueError, match="unknown payload type"):
        payloads.get_type("nope")


def test_available_types_includes_project_and_docxplus():
    ids = payloads.available_types()
    assert {"bytes", "text", "json", "project", "docxplus"} <= set(ids)


def test_register_custom_type():
    hexcodec = payloads.PayloadType("hex", "text/plain", lambda o: o.encode(), bytes.hex)
    payloads.register_type(hexcodec)
    assert payloads.get_type("hex").id == "hex"


def test_project_pack_unpack_roundtrip(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "a.py").write_text("print('hi')\n")
    (proj / "README.md").write_text("# demo\n")
    (proj / ".venv").mkdir()
    (proj / ".venv" / "junk").write_text("should be excluded")

    blob = payloads.pack_project(proj)
    dest = tmp_path / "out"
    payloads.unpack_project(blob, dest)

    assert (dest / "src" / "a.py").read_text() == "print('hi')\n"
    assert (dest / "README.md").read_text() == "# demo\n"
    assert not (dest / ".venv").exists()  # excluded


def test_project_pack_is_deterministic(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "f.txt").write_text("stable")
    assert payloads.pack_project(proj) == payloads.pack_project(proj)


def test_project_pack_requires_directory(tmp_path):
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(NotADirectoryError):
        payloads.pack_project(f)


def test_unpack_rejects_path_traversal(tmp_path):
    # Hand-craft a malicious tar with a ../ member.
    import io
    import tarfile

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        info = tarfile.TarInfo("../escape.txt")
        data = b"pwned"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError, match="unsafe path"):
        payloads.unpack_project(raw.getvalue(), tmp_path / "dest")


def test_pack_refuses_tree_over_decompression_cap(tmp_path):
    """Authoring-time refusal: an oversized tree must not seal into an unextractable document.

    The known-wrong input this pins is a tree whose inflated size exceeds
    unpack_project's bomb cap. Before pack-side accounting existed, such a tree
    sealed cleanly into a signed, validated document whose payload could never be
    extracted — the failure surfaced at read time on another machine, far from the
    author who caused it. A tiny cap makes the class observable without writing
    half a gigabyte of real bytes.
    """
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "a.bin").write_bytes(b"x" * 100)
    (proj / "b.bin").write_bytes(b"y" * 100)
    (proj / "empty_dir").mkdir()  # dirs carry no bytes; must not affect the total
    with pytest.raises(ValueError, match="decompression cap"):
        payloads.pack_project(proj, max_uncompressed=150)


def test_pack_names_the_over_limit_members(tmp_path):
    """The refusal says what is wrong, not just that something is."""
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "small.txt").write_text("ok")
    big = proj / "big.dat"
    big.write_bytes(b"z" * 500)
    with pytest.raises(ValueError, match="decompression cap") as info:
        payloads.pack_project(proj, max_uncompressed=100)
    # Bounded capture identifies the offending member and selected budget without
    # reading the remaining source merely to calculate an exact oversized total.
    assert "big.dat" in str(info.value)   # the member that pushed it over
    assert "100-byte" in str(info.value)   # the budget it exceeded


def test_pack_under_explicit_cap_roundtrips_through_unpack_with_same_cap(tmp_path):
    """Symmetry: whatever pack accepts under a budget, unpack accepts under the same one.

    This is the contract the asymmetry broke. A pack that succeeds under
    max_uncompressed=N must survive unpack_project(max_uncompressed=N) — otherwise
    the two sides disagree about the format's own limit.
    """
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "run.sh").write_text("#!/bin/sh\necho hi\n")
    blob = payloads.pack_project(proj, max_uncompressed=1_000_000)
    out = payloads.unpack_project(blob, tmp_path / "out", max_uncompressed=1_000_000)
    assert (out / "run.sh").read_text() == "#!/bin/sh\necho hi\n"


def test_default_cap_still_admits_ordinary_trees_and_exclusions_keep_bytes_off_the_total(tmp_path):
    """Normal trees pass untouched; policy exclusions genuinely reduce the measured size."""
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "src.py").write_text("print('real source')")
    cache = proj / "__pycache__"
    cache.mkdir()
    (cache / "junk.bin").write_bytes(b"\0" * 4096)  # excluded at any depth
    blob = payloads.pack_project(proj)  # default 512 MiB cap: no refusal
    payloads.unpack_project(blob, tmp_path / "out")
    out = tmp_path / "out"
    assert (out / "src.py").exists()
    assert not (out / "__pycache__").exists()


def _project_archive(entries, *, pax=None):
    import io
    import tarfile

    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            if data is None:
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
            else:
                member.size = len(data)
            if pax:
                member.pax_headers = pax
            archive.addfile(member, None if data is None else io.BytesIO(data))
    return result.getvalue()


@pytest.mark.parametrize("entries", [
    [("same", b"first"), ("same", b"second")],
    [("a", b"file"), ("a/b", b"child")],
    [("a/b", b"child"), ("a", b"file")],
])
def test_project_conflicts_are_rejected_before_destination_publication(tmp_path, entries):
    """Archive ordering must not partially write a conflicting tree into user storage."""
    destination = tmp_path / "out"
    with pytest.raises(ValueError):
        payloads.unpack_project(_project_archive(entries), destination)
    assert not destination.exists()


def test_project_metadata_is_bounded_before_pax_parsing(tmp_path):
    """An ignored PAX comment must not bypass the extracted-data decompression cap."""
    archive = _project_archive([("file", b"data")], pax={"comment": "x" * (2 * 1024**2)})
    with pytest.raises(ValueError):
        payloads.unpack_project(archive, tmp_path / "out", max_uncompressed=1024)
    assert not (tmp_path / "out").exists()


def test_project_extraction_preserves_existing_files_and_root_privacy(tmp_path):
    """Root directory entries cannot chmod a private destination or overwrite prior work."""
    destination = tmp_path / "out"
    destination.mkdir(mode=0o700)
    archive = _project_archive([(".", None), ("file", b"recovered")])
    payloads.unpack_project(archive, destination)
    assert destination.stat().st_mode & 0o777 == 0o700
    assert (destination / "file").read_bytes() == b"recovered"
    with pytest.raises(FileExistsError):
        payloads.unpack_project(_project_archive([("file", b"replacement")]), destination)
    assert (destination / "file").read_bytes() == b"recovered"


@pytest.mark.parametrize("name", [
    r"dir\file", "C:relative", "c:/absolute", "/absolute", "bad\nname", "bad\x7fname",
    "dir//file", "dir/./file", "dir/../file", "file/",
])
def test_project_portable_path_boundaries_refuse_before_publication(tmp_path, name):
    """No host may reinterpret an archive path as a drive, escape or control name."""
    destination = tmp_path / "out"
    with pytest.raises(ValueError, match="unsafe path"):
        payloads.unpack_project(_project_archive([(name, b"data")]), destination)
    assert not destination.exists()


@pytest.mark.parametrize("name", ["", ".", "./"])
def test_project_root_metadata_is_inert(tmp_path, name):
    """Conventional tar root records neither create members nor widen root modes."""
    destination = tmp_path / "out"
    payloads.unpack_project(_project_archive([(name, None), ("file", b"data")]), destination)
    assert destination.stat().st_mode & 0o777 == 0o700
    assert (destination / "file").read_bytes() == b"data"


@pytest.mark.parametrize("budget", [-1, True, 1.5])
def test_project_content_budget_requires_a_nonnegative_integer(tmp_path, budget):
    """Both boundaries reject invalid budgets rather than interpreting them as sizes."""
    root = tmp_path / "source"
    root.mkdir()
    with pytest.raises(payloads.ProjectPackError):
        payloads.pack_project(root, max_uncompressed=budget)
    destination = tmp_path / "out"
    with pytest.raises(ValueError):
        payloads.unpack_project(_project_archive([]), destination, max_uncompressed=budget)
    assert not destination.exists()


def test_project_content_budget_is_inclusive_and_symmetric(tmp_path):
    """An exact byte budget works for both author and reader; one byte less refuses."""
    root = tmp_path / "source"
    root.mkdir()
    (root / "file").write_bytes(b"data")
    with pytest.raises(payloads.ProjectPackError, match="decompression cap"):
        payloads.pack_project(root, max_uncompressed=3)
    blob = payloads.pack_project(root, max_uncompressed=4)
    destination = tmp_path / "out"
    with pytest.raises(ValueError, match="decompression cap"):
        payloads.unpack_project(blob, destination, max_uncompressed=3)
    assert not destination.exists()
    payloads.unpack_project(blob, destination, max_uncompressed=4)
    assert (destination / "file").read_bytes() == b"data"


def test_global_pax_state_is_refused_before_tree_publication(tmp_path):
    import io
    import tarfile

    encoded = io.BytesIO()
    with tarfile.open(fileobj=encoded, mode="w:gz", format=tarfile.PAX_FORMAT,
                      pax_headers={"comment": "global state"}) as archive:
        for name in ("first", "second"):
            archive.addfile(tarfile.TarInfo(name), io.BytesIO())
    with pytest.raises(ValueError):
        payloads.unpack_project(encoded.getvalue(), tmp_path / "out")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("fault", ["size_override", "directory_body", "stacked", "concatenated_gzip"])
def test_physical_and_effective_tar_offsets_cannot_disagree(tmp_path, fault):
    import gzip
    import tarfile

    header = tarfile.TarInfo("outer")
    header.size = 512
    body = tarfile.TarInfo("smuggled").tobuf()
    prefix = b""
    if fault == "size_override":
        pax = tarfile.TarInfo("pax")
        pax.type, pax.size = tarfile.XHDTYPE, 9
        prefix = pax.tobuf() + b"9 size=0\n" + bytes(503)
    elif fault == "directory_body":
        header.type = tarfile.DIRTYPE
    elif fault == "stacked":
        extension = tarfile.TarInfo("long")
        extension.type, extension.size = tarfile.GNUTYPE_LONGNAME, 2
        prefix = (extension.tobuf() + b"x\0" + bytes(510)) * 2
    encoded = gzip.compress(prefix + header.tobuf() + body + bytes(1024), mtime=0)
    if fault == "concatenated_gzip":
        encoded = gzip.compress(b"", mtime=0) + encoded
    with pytest.raises(ValueError):
        payloads.unpack_project(encoded, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_unicode_and_long_project_paths_still_roundtrip(tmp_path):
    source = tmp_path / "source"
    name = "résumé-" + "long" * 40
    (source / name).mkdir(parents=True)
    (source / name / "数据.txt").write_text("π", encoding="utf-8")
    payloads.unpack_project(payloads.pack_project(source), tmp_path / "out")
    assert (tmp_path / "out" / name / "数据.txt").read_text(encoding="utf-8") == "π"

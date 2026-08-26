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
    # The heaviest members are named — what to shrink or exclude first. The total
    # and the cap are both stated, so the reader can see how far over it is.
    assert "big.dat" in str(info.value)   # the member that pushed it over
    assert "502 bytes" in str(info.value)  # measured inflated size
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

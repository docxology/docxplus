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

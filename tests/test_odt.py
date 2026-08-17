"""Tests for the ODT sibling profile."""

import io
import zipfile

from docxplus.odt import (
    MIMETYPE_ODT,
    OdtPackage,
    new_base_odt,
)


def test_base_odt_package_layout():
    pkg = new_base_odt(["First paragraph in ODT.", "Second paragraph."])
    blob = pkg.to_bytes()

    # Verify zip conformance
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        infolist = zf.infolist()
        # 1. mimetype must be the first entry
        assert infolist[0].filename == "mimetype"
        # 2. mimetype must be uncompressed (ZIP_STORED = 0)
        assert infolist[0].compress_type == zipfile.ZIP_STORED
        assert zf.read("mimetype") == MIMETYPE_ODT

        # 3. META-INF/manifest.xml must exist
        assert "META-INF/manifest.xml" in zf.namelist()
        manifest_data = zf.read("META-INF/manifest.xml").decode("utf-8")
        assert 'manifest:full-path="/"' in manifest_data
        assert 'manifest:full-path="content.xml"' in manifest_data

        # 4. content.xml contains paragraphs
        content = zf.read("content.xml").decode("utf-8")
        assert "First paragraph in ODT." in content
        assert "Second paragraph." in content


def test_odt_roundtrip_with_payloads():
    pkg = new_base_odt(["Base text"])
    pkg.add_part("intelligence/payload1.dxp", b"intelligence data in ODF container", "application/octet-stream")
    blob = pkg.to_bytes()

    loaded = OdtPackage.from_bytes(blob)
    assert loaded.parts["intelligence/payload1.dxp"] == b"intelligence data in ODF container"
    assert "content.xml" in loaded.parts


# -- v0.6.2 intake parity: the ODT front door enforces the OPC caps -----------


def _odt_with(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", MIMETYPE_ODT)
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_odt_uses_the_same_fixed_dos_epoch_as_opc():
    """Determinism invariant: 1980-01-01, not a hand-written year."""
    from docxplus.opc import _FIXED_ZIP_TIME

    with zipfile.ZipFile(io.BytesIO(new_base_odt(["x"]).to_bytes())) as zf:
        assert {i.date_time for i in zf.infolist()} == {_FIXED_ZIP_TIME}


def test_odt_build_is_byte_identical_across_rebuilds():
    assert new_base_odt(["deterministic"]).to_bytes() == new_base_odt(["deterministic"]).to_bytes()


def test_odt_entries_carry_normalised_permissions():
    """No inherited mode or symlink bits ride along in the archive."""
    with zipfile.ZipFile(io.BytesIO(new_base_odt(["x"]).to_bytes())) as zf:
        assert {i.external_attr for i in zf.infolist()} == {0o600 << 16}


def test_odt_rejects_path_traversal_entry_names():
    import pytest
    from docxplus.opc import OpcError

    for hostile in ("../../etc/evil.txt", "/etc/passwd", "..\\..\\evil", "a/../../b"):
        with pytest.raises(OpcError, match="rejected"):
            OdtPackage.from_bytes(_odt_with({hostile: b"x"}))


def test_odt_accepts_ordinary_nested_entry_names():
    pkg = OdtPackage.from_bytes(_odt_with({"Pictures/image.png": b"x", "content.xml": b"<a/>"}))
    assert "Pictures/image.png" in pkg.parts


def test_odt_enforces_the_entry_count_cap():
    import pytest
    from docxplus.opc import MAX_ENTRIES, OpcError

    with pytest.raises(OpcError, match="too many entries"):
        OdtPackage.from_bytes(_odt_with({f"f{i}.txt": b"x" for i in range(MAX_ENTRIES + 10)}))


def test_odt_enforces_the_decompression_bomb_cap():
    import pytest
    from docxplus.opc import MAX_ENTRY_BYTES, OpcError

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", MIMETYPE_ODT)
        zf.writestr("bomb.bin", b"\0" * (MAX_ENTRY_BYTES + 1024))
    with pytest.raises(OpcError):
        OdtPackage.from_bytes(buf.getvalue())


def test_roundtrip_manifest_omits_mimetype_and_itself():
    """A parsed-then-rebuilt package must not start listing the positional parts."""
    original = new_base_odt(["roundtrip"]).to_bytes()
    rebuilt = OdtPackage.from_bytes(original).to_bytes()
    with zipfile.ZipFile(io.BytesIO(rebuilt)) as zf:
        manifest = zf.read("META-INF/manifest.xml").decode("utf-8")
        assert 'full-path="mimetype"' not in manifest
        assert "META-INF/manifest.xml" not in manifest
        assert 'full-path="content.xml"' in manifest
        assert zf.infolist()[0].filename == "mimetype"

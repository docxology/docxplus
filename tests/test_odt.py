"""Tests for the ODT sibling profile."""

import io
import zipfile

from odt import (
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

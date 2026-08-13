"""OPC primitives: deterministic serialisation and documented invariants."""

from __future__ import annotations

import zipfile
from io import BytesIO

import pytest

from opc import (
    CONTENT_TYPES_PART,
    ROOT_RELS_PART,
    OpcError,
    OpcPackage,
    Relationship,
    read_package,
)


def _minimal_package() -> OpcPackage:
    pkg = OpcPackage()
    pkg.set_default_type("rels", "application/vnd.openxmlformats-package.relationships+xml")
    pkg.set_default_type("xml", "application/xml")
    pkg.add_part("word/document.xml", b"<w:document/>", "application/xml")
    pkg.add_relationship(Relationship("rId1", "urn:doc", "word/document.xml"), source_part="")
    return pkg


def test_roundtrip_preserves_parts_and_relationships():
    pkg = _minimal_package()
    data = pkg.to_bytes()
    parsed = read_package(data)
    assert parsed.parts["word/document.xml"] == b"<w:document/>"
    assert parsed.relationships[""][0].target == "word/document.xml"
    assert parsed.content_type_for("word/document.xml") == "application/xml"


def test_serialisation_is_deterministic():
    assert _minimal_package().to_bytes() == _minimal_package().to_bytes()


def test_content_types_part_is_first_entry():
    data = _minimal_package().to_bytes()
    with zipfile.ZipFile(BytesIO(data)) as zf:
        assert zf.namelist()[0] == CONTENT_TYPES_PART


def test_fixed_timestamp_in_archive():
    data = _minimal_package().to_bytes()
    with zipfile.ZipFile(BytesIO(data)) as zf:
        for info in zf.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0)


def test_duplicate_part_name_rejected():
    pkg = _minimal_package()
    with pytest.raises(OpcError, match="duplicate part name"):
        pkg.add_part("word/document.xml", b"x", "application/xml")


def test_missing_content_type_fails_on_serialise():
    pkg = OpcPackage()
    pkg.set_default_type("rels", "application/vnd.openxmlformats-package.relationships+xml")
    pkg.add_part("word/document.xml", b"<w:document/>")  # no default for xml, no override
    pkg.add_relationship(Relationship("rId1", "urn:doc", "word/document.xml"), source_part="")
    with pytest.raises(OpcError, match="no content type"):
        pkg.to_bytes()


def test_missing_root_relationships_fails():
    pkg = OpcPackage()
    pkg.set_default_type("xml", "application/xml")
    pkg.add_part("word/document.xml", b"<w:document/>", "application/xml")
    with pytest.raises(OpcError, match="root relationships"):
        pkg.to_bytes()


def test_override_wins_over_default():
    pkg = _minimal_package()
    pkg.set_default_type("bin", "application/octet-stream")
    pkg.add_part("a/b.bin", b"x", "application/special")
    assert pkg.content_type_for("a/b.bin") == "application/special"


def test_next_rel_id_avoids_collisions():
    pkg = _minimal_package()
    assert pkg.next_rel_id("") == "rId2"
    pkg.add_relationship(Relationship("rId2", "urn:x", "a.xml"), source_part="")
    assert pkg.next_rel_id("") == "rId3"


def test_part_level_rels_land_in_expected_path():
    pkg = _minimal_package()
    pkg.add_part("word/styles.xml", b"<styles/>", "application/xml")
    pkg.add_relationship(
        Relationship("rId1", "urn:styles", "styles.xml"), source_part="word/document.xml"
    )
    data = pkg.to_bytes()
    with zipfile.ZipFile(BytesIO(data)) as zf:
        assert "word/_rels/document.xml.rels" in zf.namelist()
    parsed = read_package(data)
    assert parsed.relationships["word/document.xml"][0].target == "styles.xml"


def test_read_rejects_duplicate_zip_entries():
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(CONTENT_TYPES_PART, "<Types/>")
        zf.writestr("dup.xml", "a")
        zf.writestr("dup.xml", "b")
    with pytest.raises(OpcError, match="duplicate ZIP entry"):
        read_package(buf.getvalue())


def test_read_requires_content_types():
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
    with pytest.raises(OpcError, match="Content_Types"):
        read_package(buf.getvalue())


def test_illegal_part_name_rejected():
    pkg = OpcPackage()
    with pytest.raises(OpcError):
        pkg.add_part("../escape.xml", b"x", "application/xml")


def test_external_relationship_mode_serialised():
    pkg = _minimal_package()
    pkg.add_relationship(
        Relationship("rId9", "urn:ext", "https://example.org", mode="External"),
        source_part="",
    )
    parsed = read_package(pkg.to_bytes())
    ext = [r for r in parsed.relationships[""] if r.id == "rId9"][0]
    assert ext.mode == "External"


def test_root_rels_part_constant():
    assert ROOT_RELS_PART == "_rels/.rels"

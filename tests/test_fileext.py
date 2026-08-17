"""Dual-extension export: the same bytes under both a surface and a docxplus name."""

from __future__ import annotations

import pytest

from docxplus import fileext


def test_every_export_writes_both_names(tmp_path):
    written = fileext.write_document(b"payload", tmp_path / "report.docx")
    assert [p.name for p in written] == ["report.docx", "report.docxplus"]
    assert all(p.read_bytes() == b"payload" for p in written)


def test_odt_exports_both_names(tmp_path):
    written = fileext.write_document(b"payload", tmp_path / "report.odt")
    assert [p.name for p in written] == ["report.odt", "report.odtplus"]


def test_writing_from_the_plus_name_still_produces_both(tmp_path):
    """Either name is a valid target; the pair is what matters."""
    written = fileext.write_document(b"p", tmp_path / "report.docxplus")
    assert sorted(p.suffix for p in written) == [".docx", ".docxplus"]


def test_the_two_files_are_byte_identical(tmp_path):
    """The extension is a claim about content, never a different encoding."""
    surface, plus = fileext.write_document(b"identical bytes", tmp_path / "r.docx")
    assert surface.read_bytes() == plus.read_bytes()


def test_an_unknown_suffix_is_written_once_and_not_guessed(tmp_path):
    written = fileext.write_document(b"p", tmp_path / "report.bin")
    assert [p.name for p in written] == ["report.bin"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [("a.docx", False), ("a.docxplus", True), ("a.odt", False), ("a.odtplus", True),
     ("a.DOCXPLUS", True), ("a.txt", False)],
)
def test_plus_names_are_recognised_case_insensitively(name, expected):
    assert fileext.is_docxplus_name(name) is expected


def test_extension_pairs_round_trip():
    for base, plus in fileext.PLUS_EXTENSION.items():
        assert fileext.plus_path(f"x{base}").suffix == plus
        assert fileext.surface_path(f"x{plus}").suffix == base


def test_every_extension_declares_a_media_type():
    assert set(fileext.MEDIA_TYPES) == set(fileext.ALL_EXTENSIONS)
    # The surface types must remain the registered Office ones.
    assert fileext.MEDIA_TYPES[".docx"].startswith("application/vnd.openxmlformats-")
    assert fileext.MEDIA_TYPES[".odt"] == "application/vnd.oasis.opendocument.text"


def test_a_built_document_validates_under_either_name(tmp_path):
    """The claim the .docxplus name makes is checkable, and it checks out."""
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder
    from docxplus.validate import validate_bytes

    priv, _pub = crypto.generate_signing_key()
    builder = DocxPlusBuilder(paragraphs=["surface"])
    builder.add_module("m", "package_part", b"payload").sign(priv)
    surface, plus = fileext.write_document(builder.build(), tmp_path / "r.docx")

    assert validate_bytes(surface.read_bytes()).ok
    assert validate_bytes(plus.read_bytes()).ok

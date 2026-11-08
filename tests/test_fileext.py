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


@pytest.mark.parametrize("suffix", [".docx", ".docxplus", ".odt", ".odtplus", ".bin"])
def test_document_preflight_selects_the_writer_targets_without_writing(tmp_path, suffix):
    """CLI preflight and actual publication must agree on all output names."""
    requested = tmp_path / f"report{suffix}"
    selected = fileext.document_paths(requested)
    assert fileext.preflight_document(requested) == selected
    assert list(tmp_path.iterdir()) == []
    assert fileext.write_document(b"document bytes", requested) == selected
    assert all(path.read_bytes() == b"document bytes" for path in selected)


def test_paired_preflight_preserves_first_output_when_second_is_a_directory(tmp_path):
    """A known second-sibling failure must precede every replacement."""
    surface = tmp_path / "report.docx"
    surface.write_bytes(b"previous surface")
    plus = tmp_path / "report.docxplus"
    plus.mkdir()
    with pytest.raises(FileExistsError):
        fileext.write_document(b"new contents", surface)
    assert surface.read_bytes() == b"previous surface"
    assert plus.is_dir()
    assert set(tmp_path.iterdir()) == {surface, plus}


def test_paired_publication_refuses_a_symlink_without_following_it(tmp_path):
    """A hostile sibling must not redirect writes or partially update the pair."""
    target = tmp_path / "unrelated"
    target.write_bytes(b"outside sentinel")
    surface = tmp_path / "report.odt"
    surface.write_bytes(b"old document")
    plus = tmp_path / "report.odtplus"
    plus.symlink_to(target)
    with pytest.raises(FileExistsError):
        fileext.write_document(b"new document", surface)
    assert surface.read_bytes() == b"old document"
    assert target.read_bytes() == b"outside sentinel"
    assert plus.is_symlink()


def test_paired_replacement_detaches_hardlinks_and_open_inodes(tmp_path):
    """Complete private siblings replace names rather than truncating shared files."""
    import os

    original = tmp_path / "unrelated"
    original.write_bytes(b"old shared bytes")
    original.chmod(0o644)
    surface = tmp_path / "report.docx"
    plus = tmp_path / "report.docxplus"
    os.link(original, surface)
    os.link(original, plus)
    with surface.open("rb") as previous:
        assert fileext.write_document(b"new bytes", surface) == [surface, plus]
        assert previous.read() == b"old shared bytes"
    assert original.read_bytes() == b"old shared bytes"
    assert surface.read_bytes() == plus.read_bytes() == b"new bytes"
    assert surface.stat().st_ino != plus.stat().st_ino
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (surface, plus))


def test_invalid_document_data_preserves_both_outputs(tmp_path):
    """Serialization/type failure must happen before either document replacement."""
    surface, plus = fileext.write_document(b"old", tmp_path / "report.docx")
    with pytest.raises(TypeError):
        fileext.write_document(object(), surface)
    assert surface.read_bytes() == plus.read_bytes() == b"old"
    assert set(tmp_path.iterdir()) == {surface, plus}


def test_document_parent_symlink_is_not_a_publication_route(tmp_path):
    """Directory aliases refuse instead of letting a path swap redirect publication."""
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(NotADirectoryError):
        fileext.write_document(b"new", alias / "report.docx")
    assert list(real.iterdir()) == []

"""Minimal WordprocessingML base document."""

from __future__ import annotations

from defusedxml.ElementTree import fromstring

from docxplus.opc import read_package
from docxplus.wordml import CT_DOCUMENT, build_document_xml, new_base_document


def test_document_xml_is_well_formed():
    xml = build_document_xml(["Hello", "World"])
    root = fromstring(xml)
    assert root.tag.endswith("}document")


def test_document_xml_escapes_text():
    xml = build_document_xml(["<script> & stuff"])
    assert b"&lt;script&gt;" in xml
    fromstring(xml)  # still well-formed


def test_empty_paragraphs_yield_one_empty_paragraph():
    xml = build_document_xml([])
    assert xml.count(b"<w:p>") == 1


def test_base_document_is_valid_opc():
    pkg = new_base_document(["A report."], title="Q3", creator="DAF")
    data = pkg.to_bytes()
    parsed = read_package(data)
    assert parsed.content_type_for("word/document.xml") == CT_DOCUMENT
    assert "docProps/core.xml" in parsed.parts
    # Two root relationships: document + core props.
    assert len(parsed.relationships[""]) == 2


def test_core_props_carry_metadata():
    pkg = new_base_document(["x"], title="MyTitle", creator="MyCreator")
    core = pkg.parts["docProps/core.xml"]
    assert b"MyTitle" in core
    assert b"MyCreator" in core

"""Tests for the MCE AlternateContent channel."""

import pytest

from docxplus.channels.mce import NS_DXP_MCE, NS_MC, MceChannel
from docxplus.container import DocxPlusBuilder, DocxPlusReader
from docxplus.wordml import new_base_document


def test_mce_channel_embed_and_extract_direct():
    pkg = new_base_document(["Hello from base document."])
    chan = MceChannel()
    payload = b"secret payload in MCE Choice branch"
    rec = chan.embed(pkg, payload, slot="mce_slot")

    assert rec.channel == "mce"
    assert rec.slot == "mce_slot"
    assert rec.size == len(payload)
    assert chan.capacity(pkg) is None

    extracted = chan.extract(pkg, rec)
    assert extracted == payload


def test_mce_channel_in_container_roundtrip():
    b = DocxPlusBuilder(paragraphs=["Testing MCE channel in full container."])
    b.add_module("intel", "mce", "Confidential Strategy Document", payload_type="text")
    b.add_module("cfg", "mce", {"key": "val", "count": 42}, payload_type="json")
    b.add_module("sec", "mce", b"Encrypted MCE Payload", password="pass")

    docx_bytes = b.build()
    reader = DocxPlusReader.from_bytes(docx_bytes)

    assert set(reader.list_modules()) == {"intel", "cfg", "sec"}
    assert reader.extract("intel", as_object=True) == "Confidential Strategy Document"
    assert reader.extract("cfg", as_object=True) == {"key": "val", "count": 42}
    assert reader.extract("sec", password="pass") == b"Encrypted MCE Payload"


def test_mce_markup_preserves_ignorable_choice():
    pkg = new_base_document(["Main text."])
    chan = MceChannel()
    chan.embed(pkg, b"data", slot="s1")
    doc_xml = pkg.parts["word/document.xml"].decode("utf-8")
    assert f'xmlns:mc="{NS_MC}"' in doc_xml
    assert f'xmlns:dxm="{NS_DXP_MCE}"' in doc_xml
    assert 'mc:Ignorable="dxm"' in doc_xml or 'mc:Ignorable=' in doc_xml
    assert "<mc:AlternateContent" in doc_xml
    assert '<mc:Choice Requires="dxm">' in doc_xml
    # Self-closing: an empty fallback adds no visible paragraph, so concealing a
    # module leaves the rendered surface unchanged.
    assert "<mc:Fallback/>" in doc_xml


def test_mce_missing_part_or_slot_raises():
    pkg = new_base_document(["Main text."])
    chan = MceChannel()
    rec = chan.embed(pkg, b"data", slot="s1")

    # Tamper with slot in record
    rec_tampered = type(rec)(**{**rec.to_dict(), "slot": "nonexistent"})
    with pytest.raises(ValueError, match="not found"):
        chan.extract(pkg, rec_tampered)

    # Empty parts
    pkg_empty = new_base_document()
    pkg_empty.parts.clear()
    with pytest.raises(ValueError, match="missing from package"):
        chan.embed(pkg_empty, b"data", slot="s1")


# -- CT_Body ordering ---------------------------------------------------------


def _body_children(docx_bytes: bytes) -> list[str]:
    import re

    from docxplus.opc import read_package

    doc = read_package(docx_bytes).parts["word/document.xml"].decode("utf-8")
    body = doc[doc.index("<w:body>"):doc.index("</w:body>")]
    return re.findall(r"<(?:w:|mc:)(p|tbl|sectPr|AlternateContent)\b", body)


def test_sectpr_remains_the_last_body_child():
    """`CT_Body` is `(EG_BlockLevelElts*, sectPr?)`.

    Appending at `</w:body>` put the AlternateContent after the body-level sectPr and
    produced schema-invalid markup on the one channel that writes into the main story
    part. Word validates document.xml on load and offers repair, which is the loudest
    possible way to break the surface contract.
    """
    from docxplus.container import DocxPlusBuilder

    builder = DocxPlusBuilder(paragraphs=["visible"])
    builder.add_module("a", "mce", b"payload-a")
    builder.add_module("b", "mce", b"payload-b")
    children = _body_children(builder.build())

    assert children[-1] == "sectPr", children
    assert children.count("sectPr") == 1
    assert children.count("AlternateContent") == 2


def test_concealing_a_module_adds_no_visible_paragraph():
    """Dual-contract independence: the rendered surface must not change."""
    from docxplus.container import DocxPlusBuilder

    plain = _body_children(DocxPlusBuilder(paragraphs=["visible"]).build())
    with_mce = _body_children(
        DocxPlusBuilder(paragraphs=["visible"]).add_module("a", "mce", b"x").build()
    )
    assert [c for c in with_mce if c == "p"] == [c for c in plain if c == "p"]


def test_a_section_break_inside_a_paragraph_is_not_mistaken_for_the_body_sectpr():
    """Only a body-level sectPr terminates the body; a `w:pPr` one is a section break."""
    from docxplus.channels.mce import _body_insertion_point

    doc = (
        "<w:body><w:p><w:pPr><w:sectPr><w:type/></w:sectPr></w:pPr></w:p>"
        "<w:p>tail</w:p></w:body>"
    )
    # No body-level sectPr here, so content belongs immediately before </w:body>.
    assert _body_insertion_point(doc) == doc.rfind("</w:body>")


def test_mce_varied_prefixes_and_namespaces():
    """Verify extraction resilience when MCE XML is loaded with alternative prefix aliases."""
    pkg = new_base_document(["Main text."])
    chan = MceChannel()
    rec = chan.embed(pkg, b"flexible-mce-data", slot="flex_slot")

    # Manually rewrite namespace prefix in document.xml from dxm to alt
    doc_xml = pkg.parts["word/document.xml"].decode("utf-8")
    doc_xml = doc_xml.replace("xmlns:dxm=", "xmlns:alt=").replace("<dxm:payload", "<alt:payload").replace("</dxm:payload>", "</alt:payload>")
    pkg.parts["word/document.xml"] = doc_xml.encode("utf-8")

    # Extraction must still find it
    extracted = chan.extract(pkg, rec)
    assert extracted == b"flexible-mce-data"


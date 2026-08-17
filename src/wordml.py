"""Minimal, spec-valid WordprocessingML document builder.

Produces the smallest conforming DOCX body the standards report documents (§2.1,
§3.1): a package with ``[Content_Types].xml``, ``_rels/.rels`` pointing at the
main document, and ``word/document.xml`` whose root is ``<w:document>``. The
resulting bytes open in Word / LibreOffice / Google Docs as an ordinary document.

Keeping this in-repo (rather than depending on python-docx) makes the base
carrier deterministic and avoids the ``docx`` import-name collision, while
staying faithful to the "standards-first" framing.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from opc import OpcPackage, Relationship

NS_WORDML = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS_OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

CT_DOCUMENT = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
)
CT_CORE_PROPS = "application/vnd.openxmlformats-package.core-properties+xml"
CT_RELATIONSHIPS = "application/vnd.openxmlformats-package.relationships+xml"
CT_XML = "application/xml"

REL_OFFICE_DOCUMENT = f"{NS_OFFICE_REL}/officeDocument"
REL_CORE_PROPS = (
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
)


def build_document_xml(paragraphs: list[str]) -> bytes:
    """Render a minimal ``word/document.xml`` from a list of paragraph strings."""
    body_parts: list[str] = []
    for text in paragraphs or [""]:
        body_parts.append(
            f"<w:p><w:r><w:t xml:space=\"preserve\">{escape(text)}</w:t></w:r></w:p>"
        )
    body = "".join(body_parts)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{NS_WORDML}"><w:body>{body}'
        # A sectPr keeps Word happy about page geometry.
        '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr>'
        "</w:body></w:document>"
    ).encode()


def build_core_props(title: str, creator: str, keywords: str = "") -> bytes:
    """Render OPC core properties (Dublin-Core based; report §9)."""
    ns = (
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/"'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f"<cp:coreProperties {ns}>"
        f"<dc:title>{escape(title)}</dc:title>"
        f"<dc:creator>{escape(creator)}</dc:creator>"
        f"<cp:keywords>{escape(keywords)}</cp:keywords>"
        "</cp:coreProperties>"
    ).encode()


def new_base_document(
    paragraphs: list[str] | None = None,
    *,
    title: str = "Document",
    creator: str = "docxplus",
) -> OpcPackage:
    """Construct a fresh, valid base DOCX as an :class:`OpcPackage`.

    This is the *surface* document — the ordinary content a reader sees. The
    intelligence layer is composed on top of it by :mod:`container`.
    """
    pkg = OpcPackage()
    pkg.set_default_type("rels", CT_RELATIONSHIPS)
    pkg.set_default_type("xml", CT_XML)

    pkg.add_part("word/document.xml", build_document_xml(paragraphs or []), CT_DOCUMENT)
    pkg.add_part("docProps/core.xml", build_core_props(title, creator), CT_CORE_PROPS)

    pkg.add_relationship(
        Relationship("rId1", REL_OFFICE_DOCUMENT, "word/document.xml"), source_part=""
    )
    pkg.add_relationship(
        Relationship("rId2", REL_CORE_PROPS, "docProps/core.xml"), source_part=""
    )
    return pkg

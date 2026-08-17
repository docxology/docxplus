"""Custom-XML-part channel.

Word stores mapped content-control data as "flat Open XML markup" inside a custom
XML part (report §3.1). Such parts are fully in-spec, reachable via a package
relationship, and invisible in the rendered document — an ideal structured
payload channel. We base64-wrap arbitrary bytes inside a tiny XML envelope so the
part is always well-formed XML.
"""

from __future__ import annotations

import base64

from xml.sax.saxutils import quoteattr

from defusedxml.ElementTree import fromstring as _safe_fromstring

from channels.base import ChannelRecord
from crypto import digest as _digest
from opc import OpcPackage, Relationship

CT_CUSTOM_XML = "application/xml"
REL_CUSTOM_XML = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml"
)
NS_DXPLUS = "urn:docxplus:intelligence:1.0"


class CustomXmlChannel:
    id = "custom_xml"

    def embed(self, pkg: OpcPackage, payload: bytes, *, slot: str) -> ChannelRecord:
        index = _next_item_index(pkg)
        part_name = f"customXml/item{index}.xml"
        encoded = base64.b64encode(payload).decode("ascii")
        xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<dx:payload xmlns:dx="{NS_DXPLUS}" slot={quoteattr(slot)} encoding="base64">'
            f"{encoded}</dx:payload>"
        ).encode()
        pkg.add_part(part_name, xml, CT_CUSTOM_XML)
        rid = pkg.next_rel_id("word/document.xml")
        pkg.add_relationship(
            Relationship(rid, REL_CUSTOM_XML, f"../{part_name}"),
            source_part="word/document.xml",
        )
        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type=CT_CUSTOM_XML,
            location={"part": part_name},
        )

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes:
        part = record.location["part"]
        blob = pkg.parts[part]
        root = _safe_fromstring(blob)
        return base64.b64decode((root.text or "").strip())

    def capacity(self, pkg: OpcPackage) -> int | None:
        return None


def _next_item_index(pkg: OpcPackage) -> int:
    n = 1
    while f"customXml/item{n}.xml" in pkg.parts:
        n += 1
    return n

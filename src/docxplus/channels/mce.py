"""Markup Compatibility and Extensibility (MCE) channel.

Standardized as ISO/IEC 29500-3 (ECMA-376 Part 3), MCE defines conventions for
forward compatibility via `<mc:AlternateContent>`, `<mc:Choice>`, and `<mc:Fallback>`.

In this channel, payloads are embedded inside `<mc:Choice>` under an ignorable
extension namespace (`urn:docxplus:mce:1.0`), above an empty `<mc:Fallback/>`.
MCE-aware consumers that do not understand the extension namespace process the
Fallback. Consumer compatibility requires actual interoperability evidence; this
channel alone does not certify every Office implementation.

The fallback is empty on purpose. A fallback carrying a placeholder paragraph makes
every concealed module add a visible paragraph, which contradicts the independence
of the two contracts — the property this whole channel exists to demonstrate.
"""

from __future__ import annotations

import base64
from xml.sax.saxutils import quoteattr

from defusedxml.ElementTree import fromstring as _safe_fromstring

from ..crypto import digest as _digest
from ..opc import OpcPackage, _insert_xml_fragment
from .base import ChannelRecord

NS_MC = "http://schemas.openxmlformats.org/markup-compatibility/2006"
NS_DXP_MCE = "urn:docxplus:mce:1.0"
NS_WORDML = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"




class MceChannel:
    id = "mce"

    def embed(self, pkg: OpcPackage, payload: bytes, *, slot: str) -> ChannelRecord:
        doc_part = "word/document.xml"
        if doc_part not in pkg.parts:
            raise ValueError(f"cannot embed MCE payload: {doc_part} missing from package")

        encoded = base64.b64encode(payload).decode("ascii")
        mce_xml = (
            f'<mc:AlternateContent xmlns:mc="{NS_MC}" xmlns:dxm="{NS_DXP_MCE}" mc:Ignorable="dxm">'
            f'<mc:Choice Requires="dxm">'
            f'<dxm:payload slot={quoteattr(slot)} encoding="base64">{encoded}</dxm:payload>'
            f'</mc:Choice>'
            f'<mc:Fallback/>'
            f'</mc:AlternateContent>'
        )

        doc_xml = pkg.parts[doc_part].decode("utf-8")

        pkg.parts[doc_part] = _insert_xml_fragment(
            doc_xml, (f"{{{NS_WORDML}}}document", f"{{{NS_WORDML}}}body"), mce_xml,
            terminal_tag=f"{{{NS_WORDML}}}sectPr",
        ).encode("utf-8")

        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type="application/xml",
            location={"part": doc_part, "slot": slot},
        )

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes:
        doc_part = record.location.get("part")
        blob = pkg.parts.get(doc_part)
        if not blob:
            raise ValueError(f"part {doc_part} not found")

        root = _safe_fromstring(blob)
        slot = record.slot

        for elem in root.iter():
            tag = elem.tag
            if tag == f"{{{NS_DXP_MCE}}}payload" and elem.get("slot") == slot:
                return base64.b64decode((elem.text or "").strip())

        raise ValueError(f"MCE payload for slot {slot!r} not found in {doc_part}")

    def capacity(self, pkg: OpcPackage) -> int | None:
        return None


__all__ = [
    "NS_DXP_MCE",
    "NS_MC",
    "NS_WORDML",
    "MceChannel",
]


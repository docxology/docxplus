"""Markup Compatibility and Extensibility (MCE) channel.

Standardized as ISO/IEC 29500-3 (ECMA-376 Part 3), MCE defines conventions for
forward compatibility via `<mc:AlternateContent>`, `<mc:Choice>`, and `<mc:Fallback>`.

In this channel, payloads are embedded inside `<mc:Choice>` under an ignorable
extension namespace (`urn:docxplus:mce:1.0`), while `<mc:Fallback>` carries a
benign visible placeholder or is empty. Standard-conforming OOXML consumers that do
not understand the namespace ignore the Choice branch and process the Fallback,
leaving the document completely valid and openable without warnings.
"""

from __future__ import annotations

import base64
from xml.sax.saxutils import escape

from defusedxml.ElementTree import fromstring as _safe_fromstring

from channels.base import ChannelRecord
from crypto import digest as _digest
from opc import OpcPackage

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
            f'<dxm:payload slot="{escape(slot)}" encoding="base64">{encoded}</dxm:payload>'
            f'</mc:Choice>'
            f'<mc:Fallback>'
            f'<w:p xmlns:w="{NS_WORDML}"><w:r><w:t xml:space="preserve"></w:t></w:r></w:p>'
            f'</mc:Fallback>'
            f'</mc:AlternateContent>'
        )

        doc_xml = pkg.parts[doc_part].decode("utf-8")
        # Ensure root element declares mc namespace if not present
        if f'xmlns:mc="{NS_MC}"' not in doc_xml:
            doc_xml = doc_xml.replace(
                f'<w:document xmlns:w="{NS_WORDML}"',
                f'<w:document xmlns:w="{NS_WORDML}" xmlns:mc="{NS_MC}" mc:Ignorable="dxm" xmlns:dxm="{NS_DXP_MCE}"',
                1,
            )
        pos = doc_xml.rfind("</w:body>")
        if pos == -1:
            raise ValueError("invalid document.xml: missing </w:body>")

        new_doc_xml = doc_xml[:pos] + mce_xml + doc_xml[pos:]
        pkg.parts[doc_part] = new_doc_xml.encode("utf-8")

        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type="application/xml",
            location={"part": doc_part, "slot": slot},
        )

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes:
        doc_part = record.location.get("part", "word/document.xml")
        blob = pkg.parts.get(doc_part)
        if not blob:
            raise ValueError(f"part {doc_part} not found")

        root = _safe_fromstring(blob)
        slot = record.slot

        for elem in root.iter(f"{{{NS_DXP_MCE}}}payload"):
            if elem.get("slot") == slot:
                return base64.b64decode((elem.text or "").strip())

        raise ValueError(f"MCE payload for slot {slot!r} not found in {doc_part}")

    def capacity(self, pkg: OpcPackage) -> int | None:
        return None

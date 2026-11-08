"""Custom-document-properties channel.

DOCX carries a custom-properties part (``docProps/custom.xml``) alongside core and
app properties (report §9). Named custom properties are a structured, in-spec
metadata channel: small, human-inspectable, and retained by library serialization.
Suited to short payloads (identifiers, routing tags, digests) rather than bulk
data. We base64-encode the payload into a single named ``lpwstr`` property.
"""

from __future__ import annotations

import base64
from xml.etree.ElementTree import Element, SubElement, tostring

from defusedxml.ElementTree import fromstring as _safe_fromstring

from ..crypto import digest as _digest
from ..opc import OpcPackage, Relationship
from .base import ChannelRecord

CT_CUSTOM_PROPS = (
    "application/vnd.openxmlformats-officedocument.custom-properties+xml"
)
REL_CUSTOM_PROPS = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties"
)
CUSTOM_PART = "docProps/custom.xml"
NS_CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
NS_VT = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
_FMTID = "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}"

# Office rejects properties smaller/larger constraints vary; keep a conservative
# per-property ceiling (lpwstr is practically bounded). Report treats metadata as
# a leakage/short-string channel, not bulk storage.
MAX_PAYLOAD = 8_000


class MetadataChannel:
    id = "metadata"

    def embed(self, pkg: OpcPackage, payload: bytes, *, slot: str) -> ChannelRecord:
        if len(payload) > MAX_PAYLOAD:
            raise ValueError(
                f"metadata channel holds at most {MAX_PAYLOAD} bytes; got {len(payload)}"
            )
        root = _load_props(pkg)
        prop_name = f"dxplus_{slot}"
        if any(prop.get("name") == prop_name for prop in root):
            raise ValueError(f"metadata property collision for slot {slot!r}: {prop_name!r} already exists")
        try:
            used_pids = {int(prop.attrib["pid"]) for prop in root}
        except (KeyError, ValueError) as exc:
            raise ValueError("existing custom property has no valid integer PID") from exc
        pid = 2
        while pid in used_pids:
            pid += 1
        prop = SubElement(root, f"{{{NS_CUSTOM}}}property", {
            "fmtid": _FMTID, "pid": str(pid), "name": prop_name,
        })
        SubElement(prop, f"{{{NS_VT}}}lpwstr").text = base64.b64encode(payload).decode("ascii")
        _store_props(pkg, root)
        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type=CT_CUSTOM_PROPS,
            location={"property": prop_name},
        )

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes:
        root = _load_props(pkg)
        for prop in root:
            if prop.get("name") == record.location["property"]:
                value = prop.find(f"{{{NS_VT}}}lpwstr")
                if value is None:
                    raise ValueError("module metadata is not an lpwstr property")
                return base64.b64decode(value.text or "", validate=True)
        raise KeyError(record.location["property"])

    def capacity(self, pkg: OpcPackage) -> int | None:
        return MAX_PAYLOAD


def _load_props(pkg: OpcPackage) -> Element:
    """Retain existing property types, attributes, IDs and compound values."""
    if CUSTOM_PART not in pkg.parts:
        return Element(f"{{{NS_CUSTOM}}}Properties")
    return _safe_fromstring(pkg.parts[CUSTOM_PART])


def _store_props(pkg: OpcPackage, root: Element) -> None:
    xml = tostring(root, encoding="utf-8", xml_declaration=True)

    if CUSTOM_PART in pkg.parts:
        pkg.parts[CUSTOM_PART] = xml
    else:
        pkg.add_part(CUSTOM_PART, xml, CT_CUSTOM_PROPS)
        rid = pkg.next_rel_id("")
        pkg.add_relationship(
            Relationship(rid, REL_CUSTOM_PROPS, CUSTOM_PART), source_part=""
        )


__all__ = [
    "CT_CUSTOM_PROPS",
    "CUSTOM_PART",
    "MAX_PAYLOAD",
    "NS_CUSTOM",
    "NS_VT",
    "REL_CUSTOM_PROPS",
    "MetadataChannel",
]


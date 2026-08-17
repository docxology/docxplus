"""Custom-document-properties channel.

DOCX carries a custom-properties part (``docProps/custom.xml``) alongside core and
app properties (report §9). Named custom properties are a structured, in-spec
metadata channel: small, human-inspectable, and preserved across round-trips.
Suited to short payloads (identifiers, routing tags, digests) rather than bulk
data. We base64-encode the payload into a single named ``lpwstr`` property.
"""

from __future__ import annotations

import base64

from xml.sax.saxutils import escape, quoteattr
from defusedxml.ElementTree import fromstring as _safe_fromstring

from .base import ChannelRecord
from ..crypto import digest as _digest
from ..opc import OpcPackage, Relationship

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
        props = _load_props(pkg)
        prop_name = f"dxplus_{slot}"
        props[prop_name] = base64.b64encode(payload).decode("ascii")
        _store_props(pkg, props)
        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type=CT_CUSTOM_PROPS,
            location={"property": prop_name},
        )

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes:
        props = _load_props(pkg)
        return base64.b64decode(props[record.location["property"]])

    def capacity(self, pkg: OpcPackage) -> int | None:
        return MAX_PAYLOAD


def _load_props(pkg: OpcPackage) -> dict[str, str]:
    if CUSTOM_PART not in pkg.parts:
        return {}
    root = _safe_fromstring(pkg.parts[CUSTOM_PART])
    props: dict[str, str] = {}
    for prop in root:
        name = prop.attrib.get("name")
        value_el = list(prop)
        if name and value_el:
            props[name] = value_el[0].text or ""
    return props


def _store_props(pkg: OpcPackage, props: dict[str, str]) -> None:
    entries = []
    for pid, (name, value) in enumerate(sorted(props.items()), start=2):
        entries.append(
            f'<property fmtid="{_FMTID}" pid="{pid}" name={quoteattr(name)}>'
            f'<vt:lpwstr>{escape(value)}</vt:lpwstr></property>'
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Properties xmlns="{NS_CUSTOM}" xmlns:vt="{NS_VT}">'
        f'{"".join(entries)}</Properties>'
    ).encode()

    if CUSTOM_PART in pkg.parts:
        pkg.parts[CUSTOM_PART] = xml
    else:
        pkg.add_part(CUSTOM_PART, xml, CT_CUSTOM_PROPS)
        rid = pkg.next_rel_id("")
        pkg.add_relationship(
            Relationship(rid, REL_CUSTOM_PROPS, CUSTOM_PART), source_part=""
        )

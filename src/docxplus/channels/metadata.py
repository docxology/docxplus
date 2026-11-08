"""Custom-document-properties channel.

DOCX carries a custom-properties part (``docProps/custom.xml``) alongside core and
app properties (report §9). Named custom properties are a structured, in-spec
metadata channel: small, human-inspectable, and retained by library serialization.
Suited to short payloads (identifiers, routing tags, digests) rather than bulk
data. We base64-encode the payload into a single named ``lpwstr`` property.
"""

from __future__ import annotations

import base64
from xml.etree.ElementTree import Element, SubElement, register_namespace, tostring

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


# -- ODF profile ---------------------------------------------------------------
#
# ODF has no custom-properties part. The in-spec analogue is a user-defined
# field in ``meta.xml`` (ODF 1.3 §3.4.2): the same short-string contract, the
# same ``dxplus_<slot>`` naming and the same 8 kB ceiling, carried as base64 in
# the field's text. The channel id differs from the OOXML one because the
# extraction path and package type differ; a manifest record names exactly one.

ODT_META_PART = "meta.xml"
NS_ODF_META = "urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
NS_ODF_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
NS_DC = "http://purl.org/dc/elements/1.1/"


class OdtMetadataChannel:
    """The ``metadata`` contract over ODF: ``meta.xml`` user-defined fields."""

    id = "odt_metadata"

    def embed(self, pkg, payload: bytes, *, slot: str) -> ChannelRecord:
        if len(payload) > MAX_PAYLOAD:
            raise ValueError(
                f"metadata channel holds at most {MAX_PAYLOAD} bytes; got {len(payload)}"
            )
        root = _load_odt_meta(pkg)
        meta = root.find(f"{{{NS_ODF_OFFICE}}}meta")
        if meta is None:
            raise ValueError("meta.xml has no office:meta element")
        name = f"dxplus_{slot}"
        field = f"{{{NS_ODF_META}}}user-defined"
        for node in meta.iter(field):
            if node.get(f"{{{NS_ODF_META}}}name") == name:
                raise ValueError(
                    f"metadata field collision for slot {slot!r}: {name!r} already exists"
                )
        node = SubElement(meta, field, {f"{{{NS_ODF_META}}}name": name})
        node.text = base64.b64encode(payload).decode("ascii")
        _store_odt_meta(pkg, root)
        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type="text/xml",
            location={"property": name},
        )

    def extract(self, pkg, record: ChannelRecord) -> bytes:
        root = _load_odt_meta(pkg)
        name = record.location["property"]
        for node in root.iter(f"{{{NS_ODF_META}}}user-defined"):
            if node.get(f"{{{NS_ODF_META}}}name") == name:
                return base64.b64decode(node.text or "", validate=True)
        raise KeyError(name)

    def capacity(self, pkg) -> int | None:
        return MAX_PAYLOAD


def _load_odt_meta(pkg) -> Element:
    raw = pkg.parts.get(ODT_META_PART)
    if raw is None:
        raise ValueError("ODT package has no meta.xml part")
    return _safe_fromstring(raw)


def _store_odt_meta(pkg, root: Element) -> None:
    # Register the ODF prefixes so re-serialisation keeps ``office:``/``meta:``
    # rather than emitting ns0/ns1 prefixes that are valid but unreadable.
    for prefix, uri in (("office", NS_ODF_OFFICE), ("meta", NS_ODF_META), ("dc", NS_DC)):
        register_namespace(prefix, uri)
    pkg.parts[ODT_META_PART] = tostring(root, encoding="utf-8", xml_declaration=True)
    pkg.media_types[ODT_META_PART] = "text/xml"


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
    "NS_DC",
    "NS_ODF_META",
    "NS_ODF_OFFICE",
    "NS_VT",
    "ODT_META_PART",
    "REL_CUSTOM_PROPS",
    "MetadataChannel",
    "OdtMetadataChannel",
]


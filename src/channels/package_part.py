"""Additional-package-part channel.

Both OPC and ODF permit extra parts beyond the mandated set ("A package may
contain additional files", report §2.2, §4.1). This channel stores a payload as
a raw binary part under ``intelligence/`` with its own Default content type and a
package-level relationship, so the bytes travel with the document and remain
discoverable by following relationships (report §14.1) yet are ignored by word
processors. This is the natural home for encrypted or steganography-bound blobs.
"""

from __future__ import annotations

from channels.base import ChannelRecord
from crypto import digest as _digest
from opc import OpcPackage, Relationship

CT_INTELLIGENCE_BLOB = "application/vnd.docxplus.payload"
REL_INTELLIGENCE = "urn:docxplus:intelligence:1.0/payload"
EXTENSION = "dxp"


class PackagePartChannel:
    id = "package_part"

    def embed(self, pkg: OpcPackage, payload: bytes, *, slot: str) -> ChannelRecord:
        index = _next_index(pkg)
        part_name = f"intelligence/payload{index}.{EXTENSION}"
        pkg.set_default_type(EXTENSION, CT_INTELLIGENCE_BLOB)
        pkg.add_part(part_name, payload)
        rid = pkg.next_rel_id("")
        pkg.add_relationship(Relationship(rid, REL_INTELLIGENCE, part_name), source_part="")
        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type=CT_INTELLIGENCE_BLOB,
            location={"part": part_name},
        )

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes:
        return pkg.parts[record.location["part"]]

    def capacity(self, pkg: OpcPackage) -> int | None:
        return None


def _next_index(pkg: OpcPackage) -> int:
    n = 1
    while f"intelligence/payload{n}.{EXTENSION}" in pkg.parts:
        n += 1
    return n

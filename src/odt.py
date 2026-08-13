"""OpenDocument Text (ODT) sibling container implementation.

Grounded in OASIS OpenDocument v1.3/v1.4 Part 2 (Packages) and Part 3 (Schema).
An ODF package is a ZIP containing:
- `mimetype`: uncompressed (ZIP STORED), first entry in package, text `application/vnd.oasis.opendocument.text`
- `META-INF/manifest.xml`: root `<manifest:manifest>` listing all files and media-types
- `content.xml`: root `<office:document-content>` carrying visible text
- `meta.xml`, `styles.xml`, etc.
- `intelligence/manifest.json` and side-channel payload entries conforming to ODF manifest file-entries.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

from defusedxml.ElementTree import fromstring as _safe_fromstring

MIMETYPE_ODT = b"application/vnd.oasis.opendocument.text"
NS_MANIFEST = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
NS_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
NS_TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"


def build_content_xml(paragraphs: list[str]) -> bytes:
    p_xml = "".join(f"<text:p>{escape(p)}</text:p>" for p in (paragraphs or [""]))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<office:document-content xmlns:office="{NS_OFFICE}" xmlns:text="{NS_TEXT}" office:version="1.3">'
        f'<office:body><office:text>{p_xml}</office:text></office:body>'
        '</office:document-content>'
    ).encode()


def build_meta_xml(title: str, creator: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<office:document-meta xmlns:office="{NS_OFFICE}" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3">'
        f'<office:meta><dc:title>{escape(title)}</dc:title><dc:creator>{escape(creator)}</dc:creator></office:meta>'
        '</office:document-meta>'
    ).encode()


def build_manifest_xml(entries: list[tuple[str, str]]) -> bytes:
    """Build META-INF/manifest.xml containing file-entry elements."""
    entries_xml = ['<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>']
    for path, media_type in entries:
        if path != "/":
            entries_xml.append(
                f'<manifest:file-entry manifest:full-path="{escape(path)}" manifest:media-type="{escape(media_type)}"/>'
            )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<manifest:manifest xmlns:manifest="{NS_MANIFEST}" manifest:version="1.3">'
        f'{"".join(entries_xml)}'
        '</manifest:manifest>'
    ).encode()


@dataclass
class OdtPackage:
    parts: dict[str, bytes] = field(default_factory=dict)
    media_types: dict[str, str] = field(default_factory=dict)

    def add_part(self, path: str, data: bytes, media_type: str = "application/octet-stream") -> None:
        self.parts[path] = data
        self.media_types[path] = media_type

    def to_bytes(self) -> bytes:
        """Produce a deterministic, spec-conforming ODT zip archive.
        mimetype must be the first entry, uncompressed.
        """
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            # 1. mimetype first, uncompressed (ZIP_STORED)
            zinfo = zipfile.ZipInfo("mimetype")
            zinfo.compress_type = zipfile.ZIP_STORED
            zinfo.date_time = (2026, 1, 1, 0, 0, 0)
            zf.writestr(zinfo, MIMETYPE_ODT)

            # Ensure META-INF/manifest.xml is present and accurate
            manifest_entries = [(p, self.media_types.get(p, "application/octet-stream")) for p in sorted(self.parts)]
            manifest_xml = build_manifest_xml(manifest_entries)

            zinfo_m = zipfile.ZipInfo("META-INF/manifest.xml")
            zinfo_m.compress_type = zipfile.ZIP_DEFLATED
            zinfo_m.date_time = (2026, 1, 1, 0, 0, 0)
            zf.writestr(zinfo_m, manifest_xml)

            # 2. Write other parts sorted
            for path in sorted(self.parts):
                if path in ("mimetype", "META-INF/manifest.xml"):
                    continue
                zinfo_p = zipfile.ZipInfo(path)
                zinfo_p.compress_type = zipfile.ZIP_DEFLATED
                zinfo_p.date_time = (2026, 1, 1, 0, 0, 0)
                zf.writestr(zinfo_p, self.parts[path])
        return buf.getvalue()

    @classmethod
    def from_bytes(cls, data: bytes) -> OdtPackage:
        pkg = cls()
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            for name in zf.namelist():
                pkg.parts[name] = zf.read(name)
        # Parse META-INF/manifest.xml if present
        if "META-INF/manifest.xml" in pkg.parts:
            root = _safe_fromstring(pkg.parts["META-INF/manifest.xml"])
            for elem in root.iter(f"{{{NS_MANIFEST}}}file-entry"):
                path = elem.get(f"{{{NS_MANIFEST}}}full-path") or elem.get("manifest:full-path")
                mtype = elem.get(f"{{{NS_MANIFEST}}}media-type") or elem.get("manifest:media-type")
                if path and mtype:
                    pkg.media_types[path] = mtype
        return pkg


def new_base_odt(paragraphs: list[str] | None = None, *, title: str = "Document", creator: str = "DOCX+") -> OdtPackage:
    pkg = OdtPackage()
    pkg.add_part("content.xml", build_content_xml(paragraphs or [""]), "text/xml")
    pkg.add_part("meta.xml", build_meta_xml(title, creator), "text/xml")
    return pkg

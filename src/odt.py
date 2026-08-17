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
from xml.sax.saxutils import escape, quoteattr

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


# Files that must never appear as manifest file-entries: the manifest cannot list
# itself, and the mimetype stream is located positionally (first, STORED) rather
# than through the manifest — LibreOffice omits both.
_UNLISTED_IN_MANIFEST = frozenset({"/", "mimetype", "META-INF/manifest.xml"})


def build_manifest_xml(entries: list[tuple[str, str]]) -> bytes:
    """Build META-INF/manifest.xml containing file-entry elements."""
    entries_xml = ['<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>']
    for path, media_type in entries:
        if path not in _UNLISTED_IN_MANIFEST:
            entries_xml.append(
                f'<manifest:file-entry manifest:full-path={quoteattr(path)} manifest:media-type={quoteattr(media_type)}/>'
            )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<manifest:manifest xmlns:manifest="{NS_MANIFEST}" manifest:version="1.3">'
        f'{"".join(entries_xml)}'
        '</manifest:manifest>'
    ).encode()


def _reject_unsafe_entry(name: str) -> None:
    """Refuse ZIP entry names that escape the package root or are absolute.

    Backslashes are normalised first so a Windows-style ``..\\..\\x`` cannot slip
    past a check that only looks for forward slashes.
    """
    import posixpath

    from opc import OpcError

    if not name or name.endswith("/"):
        return  # directory marker: carries no bytes
    candidate = name.replace("\\", "/")
    if candidate.startswith("/") or (len(candidate) > 1 and candidate[1] == ":"):
        raise OpcError(f"absolute ODT entry name rejected: {name!r}")
    normalised = posixpath.normpath(candidate)
    if normalised.startswith("../") or normalised == ".." or normalised.startswith("/"):
        raise OpcError(f"path-traversal ODT entry name rejected: {name!r}")


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
        from opc import _FIXED_ZIP_TIME

        def _info(name: str, compress: int) -> zipfile.ZipInfo:
            # Same determinism contract as the OPC path: the 1980-01-01 DOS epoch
            # and an explicit permission mask, so archives are byte-identical
            # across machines and carry no inherited mode or symlink bits.
            info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
            info.compress_type = compress
            info.external_attr = 0o600 << 16
            return info

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            # 1. mimetype first, uncompressed (ZIP_STORED)
            zf.writestr(_info("mimetype", zipfile.ZIP_STORED), MIMETYPE_ODT)

            # Ensure META-INF/manifest.xml is present and accurate
            manifest_entries = [(p, self.media_types.get(p, "application/octet-stream")) for p in sorted(self.parts)]
            manifest_xml = build_manifest_xml(manifest_entries)
            zf.writestr(_info("META-INF/manifest.xml", zipfile.ZIP_DEFLATED), manifest_xml)

            # 2. Write other parts sorted
            for path in sorted(self.parts):
                if path in ("mimetype", "META-INF/manifest.xml"):
                    continue
                zf.writestr(_info(path, zipfile.ZIP_DEFLATED), self.parts[path])
        return buf.getvalue()

    @classmethod
    def from_bytes(cls, data: bytes) -> OdtPackage:
        """Parse an ODT package under the same intake caps the OPC reader enforces.

        The ODT sibling is a second front door into the same container, so it has
        to fail closed on the same inputs: a pathological entry count, a
        decompression bomb, and entry names that escape the package root. Names
        are rejected even though parts are only held in memory here — a reader
        that later materialises them to disk must not be the thing that discovers
        the package was hostile.
        """
        from opc import MAX_ENTRIES, OpcError, _guard_zip_bomb

        pkg = cls()
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = zf.namelist()
            if len(names) > MAX_ENTRIES:
                raise OpcError(f"ODT package has too many entries ({len(names)} > {MAX_ENTRIES})")
            # Two entries under one name — or two names that normalise to one key,
            # like `content.xml` and `./content.xml` — let a signed package carry a
            # second stream. Which one a consumer renders depends on whether it reads
            # local headers or the central directory, so refusing to choose is the
            # only safe answer. The OPC reader rejects both; the ODF door must too.
            if len(names) != len(set(names)):
                raise OpcError("ODT package contains duplicate ZIP entry names")
            import posixpath as _pp

            normalised: dict[str, str] = {}
            for name in names:
                key = _pp.normpath(name.replace("\\", "/")).lstrip("./")
                if key in normalised:
                    raise OpcError(
                        f"colliding ODT entry names: {normalised[key]!r} and {name!r}"
                    )
                normalised[key] = name
            _guard_zip_bomb(zf.infolist(), len(data))
            for name in names:
                _reject_unsafe_entry(name)
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


def new_base_odt(paragraphs: list[str] | None = None, *, title: str = "Document", creator: str = "docxplus") -> OdtPackage:
    pkg = OdtPackage()
    pkg.add_part("content.xml", build_content_xml(paragraphs or [""]), "text/xml")
    pkg.add_part("meta.xml", build_meta_xml(title, creator), "text/xml")
    return pkg

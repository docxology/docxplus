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
import re
import zipfile
from dataclasses import dataclass, field
from xml.sax.saxutils import escape, quoteattr

from defusedxml.ElementTree import fromstring as _safe_fromstring

MIMETYPE_ODT = b"application/vnd.oasis.opendocument.text"
NS_MANIFEST = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
NS_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
NS_TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"
NS_META = "urn:oasis:names:tc:opendocument:xmlns:meta:1.0"


def build_content_xml(paragraphs: list[str]) -> bytes:
    p_xml = "".join(f"<text:p>{escape(p)}</text:p>" for p in (paragraphs or [""]))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<office:document-content xmlns:office="{NS_OFFICE}" xmlns:text="{NS_TEXT}" office:version="1.3">'
        f'<office:body><office:text>{p_xml}</office:text></office:body>'
        '</office:document-content>'
    ).encode()


def build_meta_xml(title: str, creator: str, custom_properties: dict[str, str] | None = None) -> bytes:
    custom_xml = ""
    if custom_properties:
        custom_xml = "".join(
            f'<meta:user-defined meta:name={quoteattr(k)}>{escape(v)}</meta:user-defined>'
            for k, v in sorted(custom_properties.items())
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<office:document-meta xmlns:office="{NS_OFFICE}" xmlns:meta="{NS_META}" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3">'
        f'<office:meta><dc:title>{escape(title)}</dc:title><dc:creator>{escape(creator)}</dc:creator>{custom_xml}</office:meta>'
        '</office:document-meta>'
    ).encode()


# Files that must never appear as manifest file-entries: the manifest cannot list
# itself, and the mimetype stream is located positionally (first, STORED) rather
# than through the manifest — LibreOffice omits both.
_UNLISTED_IN_MANIFEST = frozenset({"/", "mimetype", "META-INF/manifest.xml"})
_ENTRY_ATTRIBUTES = frozenset({"version", "size", "preferred-view-mode"})


def _validate_entry_attributes(path: str, values: dict[str, str]) -> None:
    from .opc import OpcError

    if set(values) - _ENTRY_ATTRIBUTES or any(not isinstance(value, str) for value in values.values()):
        raise OpcError("unsupported ODF file-entry attributes")
    if "size" in values and re.fullmatch(r"(?:\+?[0-9]+|-0+)", values["size"].strip(" \t\r\n")) is None:
        raise OpcError("invalid ODF file-entry size")
    if "preferred-view-mode" in values and (
        path != "/" or values["preferred-view-mode"] not in {"edit", "presentation-slide-show", "read-only"}
    ):
        # QName modes depend on namespace context, which this model cannot
        # preserve. Refuse them rather than authenticate a lossy projection.
        raise OpcError("unsupported ODF preferred view mode")


def build_manifest_xml(
    entries: list[tuple[str, str]], *, version: str | None = "1.3",
    entry_attributes: dict[str, dict[str, str]] | None = None,
) -> bytes:
    """Build an index without dropping supported file-entry authority metadata."""
    listed = [("/", MIMETYPE_ODT.decode("ascii"))] + [
        (path, media_type) for path, media_type in entries if path not in _UNLISTED_IN_MANIFEST
    ]
    attributes = entry_attributes or {}
    if set(attributes) - {path for path, _ in listed}:
        from .opc import OpcError

        raise OpcError("ODF attributes refer to an unlisted file-entry")
    entries_xml = []
    for path, media_type in listed:
        values = attributes.get(path, {})
        _validate_entry_attributes(path, values)
        extra = "".join(f" manifest:{key}={quoteattr(value)}" for key, value in sorted(values.items()))
        entries_xml.append(
            f'<manifest:file-entry manifest:full-path={quoteattr(path)} manifest:media-type={quoteattr(media_type)}{extra}/>'
        )
    version_attribute = "" if version is None else f" manifest:version={quoteattr(version)}"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<manifest:manifest xmlns:manifest="{NS_MANIFEST}"{version_attribute}>'
        f'{"".join(entries_xml)}'
        '</manifest:manifest>'
    ).encode()


def _reject_unsafe_entry(name: str) -> None:
    """Require an already-canonical file entry, never a ZIP directory alias."""
    from .opc import _reject_noncanonical_entry_name

    _reject_noncanonical_entry_name(name)


@dataclass
class OdtPackage:
    parts: dict[str, bytes] = field(default_factory=dict)
    media_types: dict[str, str] = field(default_factory=dict)
    manifest_version: str | None = "1.3"
    entry_attributes: dict[str, dict[str, str]] = field(default_factory=dict)

    def add_part(self, path: str, data: bytes, media_type: str = "application/octet-stream") -> None:
        from .opc import OpcError

        _reject_unsafe_entry(path)
        if path in self.parts:
            raise OpcError(f"duplicate ODT part name: {path!r}")
        self.parts[path] = data
        self.media_types[path] = media_type

    def to_bytes(self) -> bytes:
        """Produce a deterministic, spec-conforming ODT zip archive.
        mimetype must be the first entry, uncompressed.
        """
        from .opc import _FIXED_ZIP_TIME, _compression_for, _guard_writer_entries

        def _info(name: str, compress: int) -> zipfile.ZipInfo:
            # Same determinism contract as the OPC path: the 1980-01-01 DOS epoch
            # and an explicit permission mask, so archives are byte-identical
            # across machines and carry no inherited mode or symlink bits.
            info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
            info.compress_type = compress
            info.external_attr = 0o600 << 16
            return info

        if self.media_types.get("/", MIMETYPE_ODT.decode()) != MIMETYPE_ODT.decode():
            from .opc import OpcError

            raise OpcError("ODT root media type disagrees with mimetype")
        for path in self.media_types:
            if path == "/":
                continue
            _reject_unsafe_entry(path.removesuffix("/"))
            if path in _UNLISTED_IN_MANIFEST:
                from .opc import OpcError

                raise OpcError(f"reserved ODF file-entry: {path!r}")
        manifest_entries = [(p, self.media_types.get(p, "application/octet-stream"))
                            for p in sorted(self.parts.keys() | self.media_types.keys())]
        manifest_xml = build_manifest_xml(
            manifest_entries, version=self.manifest_version, entry_attributes=self.entry_attributes
        )
        rendered = {p: data for p, data in self.parts.items()
                    if p not in ("mimetype", "META-INF/manifest.xml")}
        rendered["mimetype"] = MIMETYPE_ODT
        rendered["META-INF/manifest.xml"] = manifest_xml
        _guard_writer_entries(rendered, case_sensitive=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            # 1. mimetype first, uncompressed (ZIP_STORED)
            zf.writestr(_info("mimetype", zipfile.ZIP_STORED), MIMETYPE_ODT)

            # Ensure META-INF/manifest.xml is present and accurate
            zf.writestr(_info("META-INF/manifest.xml", _compression_for(manifest_xml)), manifest_xml)

            # 2. Write other parts sorted
            for path in sorted(self.parts):
                if path in ("mimetype", "META-INF/manifest.xml"):
                    continue
                zf.writestr(_info(path, _compression_for(self.parts[path])), self.parts[path])
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
        from .opc import OpcError, _guard_zip_bomb, _preflight_zip

        pkg = cls()
        expected_entries = _preflight_zip(data)
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            _guard_zip_bomb(zf.infolist(), expected_entries)
            names = zf.namelist()
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
            _guard_mimetype(zf)
            for name in names:
                if name.endswith("/"):
                    continue  # validated empty directory markers are not package parts
                pkg.parts[name] = zf.read(name)
        # Parse META-INF/manifest.xml if present
        if "META-INF/manifest.xml" in pkg.parts:
            root = _safe_fromstring(pkg.parts["META-INF/manifest.xml"])
            if root.tag != f"{{{NS_MANIFEST}}}manifest" or set(root.attrib) - {
                f"{{{NS_MANIFEST}}}version"
            }:
                raise OpcError("invalid ODF manifest namespace or attributes")
            pkg.manifest_version = root.get(f"{{{NS_MANIFEST}}}version")
            for elem in root:
                if elem.tag != f"{{{NS_MANIFEST}}}file-entry" or len(elem):
                    raise OpcError("unsupported ODF manifest element or namespace")
                required = {f"{{{NS_MANIFEST}}}full-path", f"{{{NS_MANIFEST}}}media-type"}
                optional = {f"{{{NS_MANIFEST}}}{key}" for key in _ENTRY_ATTRIBUTES}
                if not required <= set(elem.attrib) or set(elem.attrib) - required - optional:
                    raise OpcError("invalid ODF file-entry attributes")
                path = elem.attrib[f"{{{NS_MANIFEST}}}full-path"]
                mtype = elem.attrib[f"{{{NS_MANIFEST}}}media-type"]
                if path in _UNLISTED_IN_MANIFEST and path != "/":
                    raise OpcError(f"reserved ODF file-entry: {path!r}")
                if path != "/":
                    _reject_unsafe_entry(path.removesuffix("/"))
                if path in pkg.media_types:
                    raise OpcError(f"duplicate ODF file-entry: {path!r}")
                pkg.media_types[path] = mtype
                attributes = {
                    key: elem.attrib[f"{{{NS_MANIFEST}}}{key}"] for key in _ENTRY_ATTRIBUTES
                    if f"{{{NS_MANIFEST}}}{key}" in elem.attrib
                }
                _validate_entry_attributes(path, attributes)
                if attributes:
                    pkg.entry_attributes[path] = attributes
        if pkg.media_types.get("/") != MIMETYPE_ODT.decode():
            raise OpcError("ODT root media type disagrees with mimetype")
        return pkg


def _guard_mimetype(zf: zipfile.ZipFile) -> None:
    """Admit the positional fixed-size STORED ODT marker before reading it."""
    from .opc import OpcError

    infos = zf.infolist()
    if not infos or infos[0].filename != "mimetype" or infos[0].header_offset != 0:
        raise OpcError("ODT first ZIP entry must be mimetype")
    info = infos[0]
    if (info.compress_type != zipfile.ZIP_STORED
            or info.file_size != len(MIMETYPE_ODT)
            or info.compress_size != len(MIMETYPE_ODT)):
        raise OpcError("ODT mimetype must be fixed-size and STORED")
    with zf.open(info) as stream:
        if stream.read(len(MIMETYPE_ODT) + 1) != MIMETYPE_ODT:
            raise OpcError("not an OpenDocument Text mimetype")


def new_base_odt(
    paragraphs: list[str] | None = None,
    *,
    title: str = "Document",
    creator: str = "docxplus",
    custom_properties: dict[str, str] | None = None,
) -> OdtPackage:
    pkg = OdtPackage()
    pkg.add_part("content.xml", build_content_xml(paragraphs or [""]), "text/xml")
    pkg.add_part("meta.xml", build_meta_xml(title, creator, custom_properties=custom_properties), "text/xml")
    return pkg


__all__ = [
    "MIMETYPE_ODT",
    "NS_MANIFEST",
    "NS_META",
    "NS_OFFICE",
    "NS_TEXT",
    "OdtPackage",
    "build_content_xml",
    "build_manifest_xml",
    "build_meta_xml",
    "new_base_odt",
]


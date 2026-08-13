"""Open Packaging Conventions (OPC) primitives for DOCX+ containers.

Grounded in ISO/IEC 29500-2 / ECMA-376 Part 2 as summarised in the DOCX/ODT
standards report (§2.1): an OPC package is a ZIP whose mandatory index parts are
``[Content_Types].xml`` and ``_rels/.rels``; every part must be reachable by
following relationships; duplicate ZIP entry names are a corruption class.

This module is deliberately dependency-free (stdlib ``zipfile`` only) so a DOCX+
package can be produced and inspected without any Office toolchain. Output is
*deterministic*: entries are written with a fixed timestamp and stable order, per
the Reproducible Builds guidance the report cites (§2.3, §10).
"""

from __future__ import annotations

import posixpath
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field

from defusedxml.ElementTree import fromstring as _safe_fromstring

# Fixed DOS timestamp (1980-01-01 00:00:00) for reproducible archives.
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

CONTENT_TYPES_PART = "[Content_Types].xml"
ROOT_RELS_PART = "_rels/.rels"

# Well-known OPC namespaces (report §2.1, §4.1).
NS_CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
NS_RELATIONSHIPS = "http://schemas.openxmlformats.org/package/2006/relationships"


class OpcError(ValueError):
    """Raised when a package violates a documented OPC invariant."""


@dataclass(frozen=True)
class Relationship:
    """A single OPC relationship edge (report §2.1: parts form a directed graph)."""

    id: str
    type: str
    target: str
    mode: str = "Internal"  # "Internal" | "External"


@dataclass
class OpcPackage:
    """An in-memory OPC package: named parts, per-extension/part content types,
    and relationship sets keyed by the owning part (``""`` = package root).
    """

    parts: dict[str, bytes] = field(default_factory=dict)
    default_types: dict[str, str] = field(default_factory=dict)  # extension -> content type
    override_types: dict[str, str] = field(default_factory=dict)  # part name -> content type
    relationships: dict[str, list[Relationship]] = field(default_factory=dict)

    # -- part management ---------------------------------------------------
    def add_part(self, name: str, data: bytes, content_type: str | None = None) -> None:
        """Add a part. ``name`` is a package-absolute path without a leading slash.

        A ``content_type`` registers an Override entry; when omitted the caller is
        expected to have registered a Default for the extension.
        """
        norm = _normalize_part_name(name)
        if norm in self.parts:
            # Duplicate entry names are a documented corruption/ambiguity class
            # (report §2.3; Apache POI 5.4.0+ rejects them). Fail loudly.
            raise OpcError(f"duplicate part name: {norm}")
        self.parts[norm] = data
        if content_type is not None:
            self.override_types[norm] = content_type

    def set_default_type(self, extension: str, content_type: str) -> None:
        """Register a Default content type for a file extension (no leading dot)."""
        self.default_types[extension.lower().lstrip(".")] = content_type

    def add_relationship(self, rel: Relationship, source_part: str = "") -> None:
        """Attach a relationship to ``source_part`` (``""`` = package-level)."""
        source = "" if source_part == "" else _normalize_part_name(source_part)
        self.relationships.setdefault(source, []).append(rel)

    def next_rel_id(self, source_part: str = "") -> str:
        """Return an unused ``rIdN`` for the given source part."""
        source = "" if source_part == "" else _normalize_part_name(source_part)
        existing = {r.id for r in self.relationships.get(source, [])}
        n = 1
        while f"rId{n}" in existing:
            n += 1
        return f"rId{n}"

    def content_type_for(self, part_name: str) -> str | None:
        """Resolve the effective content type for a part (Override wins over Default)."""
        norm = _normalize_part_name(part_name)
        if norm in self.override_types:
            return self.override_types[norm]
        ext = posixpath.splitext(norm)[1].lower().lstrip(".")
        return self.default_types.get(ext)

    # -- serialization -----------------------------------------------------
    def to_bytes(self) -> bytes:
        """Serialise to a deterministic OPC ZIP byte string."""
        import io

        self._assert_index_parts()
        rendered: dict[str, bytes] = dict(self.parts)
        rendered[CONTENT_TYPES_PART] = self._render_content_types()
        for source, rels in self.relationships.items():
            if not rels:
                continue
            rendered[_rels_part_for(source)] = _render_relationships(rels)

        buf = io.BytesIO()
        # Stable ordering: content types first (OPC readers expect it early), then
        # every other entry sorted by name in the C locale (report §2.3).
        ordered = [CONTENT_TYPES_PART] + sorted(k for k in rendered if k != CONTENT_TYPES_PART)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in ordered:
                info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                zf.writestr(info, rendered[name])
        return buf.getvalue()

    def _assert_index_parts(self) -> None:
        if not self.relationships.get(""):
            raise OpcError("package has no root relationships (_rels/.rels)")
        for part in self.parts:
            if self.content_type_for(part) is None:
                raise OpcError(f"no content type registered for part: {part}")

    def _render_content_types(self) -> bytes:
        lines = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            f'<Types xmlns="{NS_CONTENT_TYPES}">',
        ]
        for ext in sorted(self.default_types):
            lines.append(f'<Default Extension="{ext}" ContentType="{self.default_types[ext]}"/>')
        for part in sorted(self.override_types):
            ct = self.override_types[part]
            lines.append(f'<Override PartName="/{part}" ContentType="{ct}"/>')
        lines.append("</Types>")
        return "".join(lines).encode("utf-8")


def _normalize_part_name(name: str) -> str:
    norm = name.replace("\\", "/").lstrip("/")
    norm = posixpath.normpath(norm)
    if norm.startswith("..") or norm == ".":
        raise OpcError(f"illegal part name: {name!r}")
    return norm


def _rels_part_for(source_part: str) -> str:
    if source_part == "":
        return ROOT_RELS_PART
    directory, base = posixpath.split(source_part)
    return posixpath.join(directory, "_rels", base + ".rels") if directory else f"_rels/{base}.rels"


def _render_relationships(rels: Iterable[Relationship]) -> bytes:
    lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        f'<Relationships xmlns="{NS_RELATIONSHIPS}">',
    ]
    for r in sorted(rels, key=lambda x: x.id):
        mode = ' TargetMode="External"' if r.mode == "External" else ""
        lines.append(
            f'<Relationship Id="{r.id}" Type="{r.type}" Target="{r.target}"{mode}/>'
        )
    lines.append("</Relationships>")
    return "".join(lines).encode("utf-8")


def read_package(data: bytes) -> OpcPackage:
    """Parse OPC bytes back into an :class:`OpcPackage`.

    Enforces the two documented invariants on intake: ``[Content_Types].xml`` must
    exist, and duplicate ZIP entry names are rejected (report §2.3, §14.3).
    """
    import io

    pkg = OpcPackage()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        if len(names) != len(set(names)):
            raise OpcError("package contains duplicate ZIP entry names")
        if CONTENT_TYPES_PART not in names:
            raise OpcError("missing mandatory [Content_Types].xml")
        raw = {name: zf.read(name) for name in names}

    _parse_content_types(pkg, raw.pop(CONTENT_TYPES_PART))
    for name, blob in raw.items():
        if name.endswith(".rels") and (name == ROOT_RELS_PART or "/_rels/" in name):
            _parse_relationships(pkg, name, blob)
        else:
            pkg.parts[_normalize_part_name(name)] = blob
    return pkg


def _parse_content_types(pkg: OpcPackage, blob: bytes) -> None:
    root = _safe_fromstring(blob)
    for child in root:
        tag = child.tag.split("}")[-1]
        if tag == "Default":
            pkg.default_types[child.attrib["Extension"].lower()] = child.attrib["ContentType"]
        elif tag == "Override":
            part = _normalize_part_name(child.attrib["PartName"])
            pkg.override_types[part] = child.attrib["ContentType"]


def _parse_relationships(pkg: OpcPackage, rels_name: str, blob: bytes) -> None:
    if rels_name == ROOT_RELS_PART:
        source = ""
    else:
        directory = posixpath.dirname(posixpath.dirname(rels_name))
        base = posixpath.basename(rels_name)[: -len(".rels")]
        source = _normalize_part_name(posixpath.join(directory, base) if directory else base)
    root = _safe_fromstring(blob)
    for child in root:
        if child.tag.split("}")[-1] != "Relationship":
            continue
        pkg.relationships.setdefault(source, []).append(
            Relationship(
                id=child.attrib["Id"],
                type=child.attrib["Type"],
                target=child.attrib["Target"],
                mode=child.attrib.get("TargetMode", "Internal"),
            )
        )

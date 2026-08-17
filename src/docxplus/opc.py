"""Open Packaging Conventions (OPC) primitives for docxplus containers.

Grounded in ISO/IEC 29500-2 / ECMA-376 Part 2 as summarised in the DOCX/ODT
standards report (§2.1): an OPC package is a ZIP whose mandatory index parts are
``[Content_Types].xml`` and ``_rels/.rels``; every part must be reachable by
following relationships; duplicate ZIP entry names are a corruption class.

This module is deliberately dependency-free (stdlib ``zipfile`` only) so a docxplus
package can be produced and inspected without any Office toolchain. Output is
*deterministic*: entries are written with a fixed timestamp and stable order, per
the Reproducible Builds guidance the report cites (§2.3, §10).
"""

from __future__ import annotations

import posixpath
import re
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field

from xml.sax.saxutils import quoteattr

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
                info.compress_type = _compression_for(rendered[name])
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
            lines.append(f'<Default Extension={quoteattr(ext)} ContentType={quoteattr(self.default_types[ext])}/>')
        for part in sorted(self.override_types):
            ct = self.override_types[part]
            lines.append(f'<Override PartName={quoteattr("/" + part)} ContentType={quoteattr(ct)}/>')
        lines.append("</Types>")
        return "".join(lines).encode("utf-8")


_DRIVE_LETTER = re.compile(r"^[A-Za-z]:")


def _normalize_part_name(name: str) -> str:
    norm = name.replace("\\", "/").lstrip("/")
    norm = posixpath.normpath(norm)
    if norm.startswith("..") or norm == ".":
        raise OpcError(f"illegal part name: {name!r}")
    return norm


def _reject_noncanonical_entry_name(name: str) -> None:
    """Refuse a ZIP entry name that is not already the part name it denotes.

    ``_normalize_part_name`` exists to canonicalise names this library constructs.
    Applying it to *untrusted* entry names turns it into a silent rewriter, and a
    rewriter is a smuggling vector: this reader stored ``/abs/x.xml`` as
    ``abs/x.xml`` and ``a/../b.xml`` as ``b.xml``, so the part it operated on had a
    different name from the one any other consumer — a word processor, a scanner,
    an archive lister — reads off the entry. Disagreement about *which part this is*
    is the same class of defect as the case-folding collision already closed above.

    The rule is canonical-form-or-refuse rather than a list of bad prefixes,
    deliberately. A check that named ``/`` and ``..`` would still have admitted the
    drive-letter and NUL forms below, and would admit whatever the next variant is.
    """
    if not name or name.endswith("/"):
        return
    if "\\" in name or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        raise OpcError(f"illegal characters in entry name: {name!r}")
    if _DRIVE_LETTER.match(name):
        raise OpcError(f"drive-qualified entry name: {name!r}")
    try:
        canonical = _normalize_part_name(name)
    except OpcError:
        raise OpcError(f"illegal part name: {name!r}") from None
    if canonical != name:
        raise OpcError(
            f"non-canonical entry name {name!r} (denotes {canonical!r}); OPC entry "
            "names must be relative and already normalised"
        )


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
            f'<Relationship Id={quoteattr(r.id)} Type={quoteattr(r.type)} Target={quoteattr(r.target)}{mode}/>'
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
        if len(names) > MAX_ENTRIES:
            raise OpcError(f"package has too many entries ({len(names)} > {MAX_ENTRIES})")
        if len(names) != len(set(names)):
            raise OpcError("package contains duplicate ZIP entry names")
        # OPC part names are equivalent under path normalization and case folding;
        # two raw entries that collapse to the same part are a smuggling vector
        # (a reader that takes the first entry sees different bytes than the scanner).
        seen: dict[str, str] = {}
        for name in names:
            if name.endswith("/"):
                continue
            _reject_noncanonical_entry_name(name)
            key = _normalize_part_name(name).casefold()
            if key in seen and seen[key] != name:
                raise OpcError(f"colliding part names: {seen[key]!r} and {name!r}")
            seen[key] = name
        if CONTENT_TYPES_PART not in names:
            raise OpcError("missing mandatory [Content_Types].xml")
        _guard_zip_bomb(zf.infolist(), len(data))
        raw = {name: zf.read(name) for name in names}

    _parse_content_types(pkg, raw.pop(CONTENT_TYPES_PART))
    for name, blob in raw.items():
        if name.endswith(".rels") and (name == ROOT_RELS_PART or "/_rels/" in name):
            _parse_relationships(pkg, name, blob)
        else:
            pkg.parts[_normalize_part_name(name)] = blob
    return pkg


# Untrusted-intake caps for read_package (standards-report §14.3, §6.1).
MAX_ENTRY_BYTES = 256 * 1024 * 1024        # per-part inflated size
MAX_TOTAL_BYTES = 1024 * 1024 * 1024       # whole-package inflated size
MAX_INFLATE_RATIO = 200                     # inflated/compressed per entry
MAX_ENTRIES = 4096                          # pathological part-graph cap (checked pre-read)


def _compression_for(data: bytes) -> int:
    """Choose a compression method the *reader's* bomb guard will accept.

    A writer must never emit a package its own reader refuses. Deflating a highly
    compressible payload — a sparse buffer, a zero-filled block — trips the
    inflate-ratio heuristic, and the tool produced documents that then failed
    `validate` and could not be extracted through the public API at all.

    The ratio test is a hostile-input heuristic, not a size bound: memory is already
    bounded by the absolute per-entry and total caps, which apply either way. Storing
    such an entry uncompressed keeps the ratio at 1 and costs space only for payloads
    that would have compressed suspiciously well. The choice is a pure function of
    the bytes, so determinism is unaffected.
    """
    import zlib

    if len(data) <= 1_000_000:
        return zipfile.ZIP_DEFLATED
    compressed = max(len(zlib.compress(data, 9)), 1)
    if len(data) / compressed > MAX_INFLATE_RATIO:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


def _guard_zip_bomb(infos, compressed_len: int) -> None:
    """Reject a package whose entries inflate past sane caps (zip-bomb defence)."""
    total = 0
    for info in infos:
        size = info.file_size
        if size > MAX_ENTRY_BYTES:
            raise OpcError(f"zip entry too large ({info.filename}): {size} bytes")
        comp = max(info.compress_size, 1)
        if size / comp > MAX_INFLATE_RATIO and size > 1_000_000:
            raise OpcError(f"suspicious inflate ratio for {info.filename} (possible zip bomb)")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise OpcError("package inflates past the total-size cap (possible zip bomb)")


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

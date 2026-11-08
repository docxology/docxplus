"""Open Packaging Conventions (OPC) primitives for docxplus containers.

Grounded in ISO/IEC 29500-2 / ECMA-376 Part 2 as summarised in the DOCX/ODT
standards report (§2.1): an OPC package is a ZIP whose mandatory index parts are
``[Content_Types].xml`` and ``_rels/.rels``; every part must be reachable by
following relationships; duplicate ZIP entry names are a corruption class.

Packaging and shared XML primitives need no Office toolchain. Archive composition
fixes timestamps and ordering for the same parts; cryptographic entropy and author
attestations are separate inputs, not a whole-file bit-reproducibility promise.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from xml.parsers import expat
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


def _insert_xml_fragment(doc_xml: str, container_path: tuple[str, ...], fragment: str,
                         *, terminal_tag: str | None = None) -> str:
    """Insert into UTF-8 XML without rewriting existing namespaces or QName values.

    Expat supplies byte offsets and expanded names. MCE-wrapped terminal section
    properties count as terminal too; paragraph-level section breaks do not.
    """
    data = doc_xml.encode("utf-8")
    path = [name[1:] for name in container_path]
    terminal = terminal_tag[1:] if terminal_tag else None
    wrappers = {"http://schemas.openxmlformats.org/markup-compatibility/2006}" + name
                for name in ("AlternateContent", "Choice", "Fallback")}
    stack = []
    start = end = child = insertion = None
    has_content = False
    parser = expat.ParserCreate(namespace_separator="}")

    def opened(name, _attributes):
        nonlocal start, child, insertion, has_content
        if stack == path[:-1] and name == path[-1]:
            if start is not None:
                raise ValueError("duplicate XML insertion container")
            start = parser.CurrentByteIndex
        elif stack == path:
            child = parser.CurrentByteIndex
            has_content = True
        if (name == terminal and stack[:len(path)] == path
                and all(parent in wrappers for parent in stack[len(path):])):
            insertion = child if insertion is None else min(insertion, child)
        stack.append(name)

    def closed(_name):
        nonlocal end
        if stack == path:
            end = parser.CurrentByteIndex
        stack.pop()

    def text(value):
        nonlocal has_content
        if stack == path and value:
            has_content = True

    def doctype(*_args):
        raise ValueError("DTD-bearing XML cannot be modified")

    parser.StartElementHandler = opened
    parser.EndElementHandler = closed
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = doctype
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ValueError("invalid XML insertion source") from exc
    if start is None or end is None:
        raise ValueError("missing XML insertion container")
    encoded = fragment.encode("utf-8")
    if not has_content and data[end - 2:end] == b"/>":
        # The parser has already validated this start tag; retain its original QName.
        match = re.compile(rb"<([^\s/>]+)").match(data, start)
        if match is None:
            raise ValueError("invalid XML insertion container")
        return b"".join((data[:end - 2], b">", encoded, b"</", match[1], b">", data[end:])).decode("utf-8")
    position = insertion if insertion is not None else end
    return b"".join((data[:position], encoded, data[position:])).decode("utf-8")


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

        _guard_writer_entries(rendered, case_sensitive=False)
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
        raise OpcError(f"directory or empty ZIP entry rejected: {name!r}")
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
    expected_entries = _preflight_zip(data)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        _guard_zip_bomb(zf.infolist(), expected_entries)
        names = zf.namelist()
        if len(names) != len(set(names)):
            raise OpcError("package contains duplicate ZIP entry names")
        # OPC part names are equivalent under path normalization and case folding;
        # two raw entries that collapse to the same part are a smuggling vector
        # (a reader that takes the first entry sees different bytes than the scanner).
        seen: dict[str, str] = {}
        for name in names:
            key = _normalize_part_name(name.removesuffix("/")).casefold()
            if key in seen and seen[key] != name:
                raise OpcError(f"colliding part names: {seen[key]!r} and {name!r}")
            seen[key] = name
        if CONTENT_TYPES_PART not in names:
            raise OpcError("missing mandatory [Content_Types].xml")
        raw = {name: zf.read(name) for name in names if not name.endswith("/")}

    _parse_content_types(pkg, raw.pop(CONTENT_TYPES_PART))
    for name, blob in raw.items():
        if name.endswith(".rels") and (name == ROOT_RELS_PART or name.startswith("_rels/") or "/_rels/" in name):
            _parse_relationships(pkg, name, blob)
        else:
            pkg.parts[_normalize_part_name(name)] = blob
    return pkg


# Untrusted-intake caps for read_package (standards-report §14.3, §6.1).
MAX_ENTRY_BYTES = 256 * 1024 * 1024        # per-part inflated size
MAX_TOTAL_BYTES = 1024 * 1024 * 1024       # whole-package inflated size
MAX_INFLATE_RATIO = 200                     # inflated/compressed per entry
MAX_ENTRIES = 4096                          # pathological part-graph cap (checked pre-read)


def _surface_hasher(profile: bytes):
    """Start a profile-separated format-3 surface transcript."""
    h = hashlib.blake2b(digest_size=32)
    h.update(b"docxplus:surface:3.0\x00" + profile + b"\x00")
    return h


def _surface_record(h, kind: bytes, *fields: bytes) -> None:
    """Hash a typed record with counted, length-delimited fields."""
    h.update(kind)
    h.update(len(fields).to_bytes(4, "big"))
    for value in fields:
        h.update(len(value).to_bytes(8, "big"))
        h.update(value)


def _guard_writer_entries(entries: dict[str, bytes], *, case_sensitive: bool) -> None:
    """Apply reader byte/name/metadata limits under the profile's name equivalence."""
    from .archive_limits import MAX_ZIP_DIRECTORY_BYTES
    if len(entries) > MAX_ENTRIES:
        raise OpcError(f"package has too many entries ({len(entries)} > {MAX_ENTRIES})")
    total = directory_bytes = 0
    seen: set[str] = set()
    for name, data in entries.items():
        _reject_noncanonical_entry_name(name)
        folded = name if case_sensitive else name.casefold()
        if folded in seen:
            raise OpcError(f"colliding part name: {name!r}")
        seen.add(folded)
        directory_bytes += 46 + len(name.encode("utf-8"))
        if directory_bytes > MAX_ZIP_DIRECTORY_BYTES:
            raise OpcError("ZIP central-directory metadata exceeds byte cap")
        if len(data) > MAX_ENTRY_BYTES:
            raise OpcError(f"zip entry too large ({name}): {len(data)} bytes")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise OpcError("package inflates past the total-size cap (possible zip bomb)")


def _preflight_zip(data: bytes) -> int:
    from .archive_limits import ArchiveLimitError, guard_zip_directory

    try:
        return guard_zip_directory(data, max_data_bytes=MAX_TOTAL_BYTES, max_members=MAX_ENTRIES)
    except ArchiveLimitError as exc:
        raise OpcError(str(exc)) from exc

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


def _guard_zip_bomb(infos, expected_entries: int) -> None:
    """Reject ambiguous directories and over-budget/unsupported compressed parts."""
    if len(infos) > MAX_ENTRIES or len(infos) != expected_entries:
        raise OpcError("ZIP directory entry count is inconsistent or exceeds cap")
    total = 0
    for info in infos:
        if info.filename.endswith("/"):
            _reject_noncanonical_entry_name(info.filename[:-1])
            if info.file_size:
                raise OpcError("ZIP directory entry has a payload")
        else:
            _reject_noncanonical_entry_name(info.filename)
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise OpcError(f"unsupported package compression method: {info.compress_type}")
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
    if root.tag != f"{{{NS_CONTENT_TYPES}}}Types" or root.attrib:
        raise OpcError("invalid content-types index namespace or attributes")
    for child in root:
        if child.tag == f"{{{NS_CONTENT_TYPES}}}Default":
            if set(child.attrib) != {"Extension", "ContentType"} or len(child):
                raise OpcError("invalid Default content-type declaration")
            ext = child.attrib["Extension"].lower()
            if not ext or ext in pkg.default_types:
                raise OpcError(f"duplicate or empty Default extension: {ext!r}")
            pkg.default_types[ext] = child.attrib["ContentType"]
        elif child.tag == f"{{{NS_CONTENT_TYPES}}}Override":
            if set(child.attrib) != {"PartName", "ContentType"} or len(child):
                raise OpcError("invalid Override content-type declaration")
            name = child.attrib["PartName"]
            if not name.startswith("/"):
                raise OpcError("Override PartName must be package-absolute")
            _reject_noncanonical_entry_name(name[1:])
            part = name[1:]
            if any(p.casefold() == part.casefold() for p in pkg.override_types):
                raise OpcError(f"duplicate Override part: {part!r}")
            pkg.override_types[part] = child.attrib["ContentType"]
        else:
            raise OpcError("unknown content-types index element or namespace")


def _parse_relationships(pkg: OpcPackage, rels_name: str, blob: bytes) -> None:
    if rels_name == ROOT_RELS_PART:
        source = ""
    else:
        directory = posixpath.dirname(posixpath.dirname(rels_name))
        base = posixpath.basename(rels_name)[: -len(".rels")]
        source = _normalize_part_name(posixpath.join(directory, base) if directory else base)
        if rels_name != _rels_part_for(source):
            raise OpcError(f"noncanonical relationships index: {rels_name!r}")
    root = _safe_fromstring(blob)
    if root.tag != f"{{{NS_RELATIONSHIPS}}}Relationships" or root.attrib:
        raise OpcError("invalid relationships index namespace or attributes")
    seen: set[str] = set()
    for child in root:
        if child.tag != f"{{{NS_RELATIONSHIPS}}}Relationship":
            raise OpcError("unknown relationship element or namespace")
        if not {"Id", "Type", "Target"} <= set(child.attrib) or set(child.attrib) - {
            "Id", "Type", "Target", "TargetMode"
        } or len(child):
            raise OpcError("invalid relationship declaration")
        rid = child.attrib["Id"]
        if not rid or rid in seen:
            raise OpcError(f"duplicate or empty relationship Id: {rid!r}")
        seen.add(rid)
        if child.attrib.get("TargetMode", "Internal") not in ("Internal", "External"):
            raise OpcError("invalid relationship TargetMode")
        pkg.relationships.setdefault(source, []).append(
            Relationship(
                id=child.attrib["Id"],
                type=child.attrib["Type"],
                target=child.attrib["Target"],
                mode=child.attrib.get("TargetMode", "Internal"),
            )
        )


__all__ = [
    "CONTENT_TYPES_PART",
    "MAX_ENTRIES",
    "MAX_ENTRY_BYTES",
    "MAX_INFLATE_RATIO",
    "MAX_TOTAL_BYTES",
    "NS_CONTENT_TYPES",
    "NS_RELATIONSHIPS",
    "ROOT_RELS_PART",
    "OpcError",
    "OpcPackage",
    "Relationship",
    "read_package",
]



"""Hardened untrusted-input intake for `.docx` bytes.

Operationalises the standards report's untrusted-input checklist (§14.3, §6): open
an unknown `.docx` under caps and surface a threat report *without executing
anything*. `read_package` already enforces zip-bomb / duplicate-entry / size caps
and parses XML through `defusedxml` (DTDs disabled); this layer adds the
package-level threat surface a defender must triage:

* **External relationships** — parts or the package linking to off-package URIs
  (SSRF / dial-home; report §6.1).
* **Macro parts** — VBA (`word/vbaProject.bin`, macro-enabled content types).
* **`altChunk` imports** — a WordprocessingML foreign-content import (RTF/HTML/…)
  the consumer would parse (report §3.1, §6.1).
* **Part-count blow-up** — a cap against pathological package graphs.

`safe_open` returns the report plus a reader (when the file is a DOCX+), and raises
under a strict policy when threats are present. Nothing here runs carried code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from defusedxml.ElementTree import fromstring as _safe_fromstring

from manifest import read_manifest
from opc import OpcPackage, read_package

_MACRO_MARKERS = ("vbaproject.bin",)  # compared case-folded
_MACRO_CT_HINTS = ("macroenabled", "ms-word.vbaproject", "ms-office.vbaproject")
_VBA_REL_HINT = "vbaproject"
_ALTCHUNK_TAG = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}altChunk"


class IntakeError(RuntimeError):
    """Raised by ``safe_open`` under a strict policy when threats are present."""


@dataclass
class IntakePolicy:
    """What to tolerate on intake. ``strict`` raises when any disallowed threat is found."""

    max_parts: int = 2048
    strict: bool = False
    allow_external_relationships: bool = False
    allow_macros: bool = False
    allow_altchunk: bool = False


DEFAULT_POLICY = IntakePolicy()


@dataclass
class ThreatReport:
    external_relationships: list[str] = field(default_factory=list)
    macro_parts: list[str] = field(default_factory=list)
    altchunk_imports: list[str] = field(default_factory=list)
    part_count: int = 0
    oversized: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (
            self.external_relationships
            or self.macro_parts
            or self.altchunk_imports
            or self.oversized
        )

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "external_relationships": list(self.external_relationships),
            "macro_parts": list(self.macro_parts),
            "altchunk_imports": list(self.altchunk_imports),
            "part_count": self.part_count,
            "oversized": self.oversized,
            "notes": list(self.notes),
        }


def scan(pkg: OpcPackage, policy: IntakePolicy = DEFAULT_POLICY) -> ThreatReport:
    """Inspect an in-memory package for intake threats (no execution)."""
    report = ThreatReport(part_count=len(pkg.parts))
    if report.part_count > policy.max_parts:
        report.oversized = True
        report.notes.append(f"part count {report.part_count} exceeds cap {policy.max_parts}")

    macro_targets: set[str] = set()
    for _source, rels in pkg.relationships.items():
        for rel in rels:
            if not policy.allow_external_relationships and rel.mode.casefold() == "external":
                where = _source or "(package)"
                report.external_relationships.append(f"{where} -> {rel.target}")
            if _VBA_REL_HINT in rel.type.lower():
                macro_targets.add(rel.target.split("/")[-1].casefold())

    if not policy.allow_macros:
        for part in pkg.parts:
            ct = (pkg.content_type_for(part) or "").lower()
            base = part.casefold()
            if (
                any(m in base for m in _MACRO_MARKERS)
                or any(h in ct for h in _MACRO_CT_HINTS)
                or base.split("/")[-1] in macro_targets
            ):
                report.macro_parts.append(part)

    if not policy.allow_altchunk:
        # Detect the altChunk *element* in any XML part (by resolved content type,
        # not filename extension), parsing rather than substring-matching so a
        # non-.xml part name cannot evade and benign prose cannot false-positive.
        for part in pkg.parts:
            ct = (pkg.content_type_for(part) or "").lower()
            if "xml" not in ct and not part.lower().endswith(".xml"):
                continue
            if _has_altchunk(pkg.parts[part]):
                report.altchunk_imports.append(part)

    return report


def _has_altchunk(data: bytes) -> bool:
    if b"altChunk" not in data:  # cheap pre-filter; then confirm by parsing
        return False
    try:
        root = _safe_fromstring(data)
    except Exception:  # noqa: BLE001 - unparseable part is not an altChunk import
        return False
    return root.tag == _ALTCHUNK_TAG or any(el.tag == _ALTCHUNK_TAG for el in root.iter())


def safe_open(data: bytes, *, policy: IntakePolicy = DEFAULT_POLICY):
    """Open untrusted `.docx` bytes under ``policy``; return ``(report, reader|None)``.

    ``read_package`` applies the zip-bomb / size / duplicate caps. Under a strict
    policy, a non-clean report raises :class:`IntakeError`. The returned reader is a
    ``DocxPlusReader`` when the file carries an intelligence manifest, else ``None``.
    """
    from container import DocxPlusReader  # local import to avoid a cycle

    pkg = read_package(data)  # caps + defused XML; may raise OpcError
    report = scan(pkg, policy)
    if policy.strict and not report.ok:
        raise IntakeError(f"intake rejected: {report.to_dict()}")
    manifest = read_manifest(pkg)
    reader = DocxPlusReader(package=pkg, manifest=manifest) if manifest is not None else None
    return report, reader

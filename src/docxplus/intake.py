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

`safe_open` returns the report plus a reader (when the file is a docxplus), and raises
under a strict policy when threats are present. Nothing here runs carried code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from defusedxml.ElementTree import fromstring as _safe_fromstring

from .manifest import read_manifest
from .opc import OpcPackage, read_package

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
    from .container import DocxPlusReader  # local import to avoid a cycle

    pkg = read_package(data)  # caps + defused XML; may raise OpcError
    report = scan(pkg, policy)
    if policy.strict and not report.ok:
        raise IntakeError(f"intake rejected: {report.to_dict()}")
    manifest = read_manifest(pkg)
    reader = DocxPlusReader(package=pkg, manifest=manifest) if manifest is not None else None
    return report, reader


# -- ODF intake ----------------------------------------------------------------
#
# ODF's threat surface is not OOXML's, so it gets its own scan rather than a
# borrowed one. The shapes that matter here are macro/script containers, links to
# off-package resources, and embedded objects — the ODF analogues of the OOXML
# triad above. Running the OPC scan against an ODF package would pass vacuously,
# which is worse than not scanning at all because it would report "clean".

#: ODF stores Basic macros under this directory, and scripts are declared here.
_ODF_SCRIPT_MARKERS = ("basic/", "scripts/")
_ODF_SCRIPT_PARTS = ("content.xml", "styles.xml", "meta.xml", "settings.xml")
#: `xlink:href` values that leave the package. Same-document (`#…`) and relative
#: in-package targets are ordinary; a scheme means it dials out.
_ODF_EXTERNAL_SCHEMES = ("http://", "https://", "ftp://", "file://", "smb://", "\\\\")
_XLINK_HREF = "{http://www.w3.org/1999/xlink}href"
_ODF_OBJECT_HINTS = ("object", "ole")


def scan_odt(pkg, policy: IntakePolicy = DEFAULT_POLICY) -> ThreatReport:
    """Threat-scan a parsed ODF package. Executes nothing.

    Reuses :class:`ThreatReport` so a caller triaging documents of both kinds reads
    one shape: ``macro_parts`` collects ODF script/Basic containers, and
    ``external_relationships`` collects off-package ``xlink:href`` targets.
    """
    report = ThreatReport()
    report.part_count = len(pkg.parts)
    if report.part_count > policy.max_parts:
        report.oversized = True
        report.notes.append(f"part count {report.part_count} exceeds cap {policy.max_parts}")

    for name in sorted(pkg.parts):
        folded = name.casefold()
        if any(folded.startswith(marker) for marker in _ODF_SCRIPT_MARKERS):
            report.macro_parts.append(name)
        elif "objectreplacements" in folded or folded.startswith("object "):
            report.notes.append(f"embedded object: {name}")

    for part in _ODF_SCRIPT_PARTS:
        blob = pkg.parts.get(part)
        if not blob:
            continue
        report.external_relationships.extend(
            f"{part} -> {href}" for href in _odf_external_hrefs(blob)
        )
        if _odf_declares_scripts(blob):
            report.macro_parts.append(f"{part} (script declarations)")

    manifest = pkg.parts.get("META-INF/manifest.xml")
    if manifest and b"application/binary" in manifest:
        report.notes.append("manifest declares an opaque binary media type")
    return report


def _odf_external_hrefs(blob: bytes) -> list[str]:
    try:
        root = _safe_fromstring(blob)
    except Exception:  # noqa: BLE001 - unparseable content is the caller's problem
        return []
    out = []
    for elem in root.iter():
        href = elem.get(_XLINK_HREF) or elem.get("xlink:href")
        if href and any(href.lower().startswith(s) for s in _ODF_EXTERNAL_SCHEMES):
            out.append(href)
    return out


def _odf_declares_scripts(blob: bytes) -> bool:
    try:
        root = _safe_fromstring(blob)
    except Exception:  # noqa: BLE001
        return False
    return any(
        elem.tag.rsplit("}", 1)[-1] in {"scripts", "script", "event-listeners"}
        for elem in root.iter()
    )


def safe_open_odt(data: bytes, *, policy: IntakePolicy = DEFAULT_POLICY):
    """Open untrusted `.odt` bytes under ``policy``; return ``(report, reader|None)``.

    The ODF counterpart of :func:`safe_open`. The reader is returned only when the
    package actually carries an intelligence layer; a plain `.odt` yields ``None``,
    which is a fact about the document rather than a failure.
    """
    from .odt import OdtPackage
    from .odt_container import ODT_MANIFEST_PART, OdtPlusReader

    pkg = OdtPackage.from_bytes(data)  # enforces entry, bomb, and traversal caps
    report = scan_odt(pkg, policy)
    if policy.strict and not report.ok:
        raise IntakeError(f"intake rejected: {report.to_dict()}")
    reader = OdtPlusReader.from_bytes(data) if ODT_MANIFEST_PART in pkg.parts else None
    return report, reader

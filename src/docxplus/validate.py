"""Conformance validation for docxplus packages.

Two layers, matching the report's producer/intake checklists (§14.1, §14.3):

1. **OPC conformance** — the surface .docx must be a valid Office package:
   mandatory ``[Content_Types].xml`` and root relationships, a main document
   part, every part reachable by following relationships, no duplicate entries,
   every part typed.
2. **Intelligence conformance** — if a manifest is present, every module it lists
   must resolve to real bytes with a matching digest, and the signature (when
   present) must validate.

The validator returns a structured report rather than raising, so a pipeline can
record findings; :func:`assert_valid` is the strict wrapper.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field

from .manifest import read_manifest
from .opc import CONTENT_TYPES_PART, OpcError, OpcPackage, read_package
from .wordml import CT_DOCUMENT


@dataclass
class ValidationReport:
    ok: bool = True
    opc_errors: list[str] = field(default_factory=list)
    intelligence_errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fail(self, bucket: list[str], message: str) -> None:
        bucket.append(message)
        self.ok = False

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "opc_errors": list(self.opc_errors),
            "intelligence_errors": list(self.intelligence_errors),
            "notes": list(self.notes),
        }


def validate_bytes(data: bytes) -> ValidationReport:
    """Validate raw .docx bytes."""
    report = ValidationReport()
    try:
        pkg = read_package(data)
    except (OpcError, zipfile.BadZipFile) as exc:
        report.fail(report.opc_errors, f"unreadable package: {exc}")
        return report
    return validate_package(pkg, report)


def validate_package(pkg: OpcPackage, report: ValidationReport | None = None) -> ValidationReport:
    """Validate an in-memory :class:`OpcPackage`."""
    report = report or ValidationReport()
    _check_opc(pkg, report)
    _check_intelligence(pkg, report)
    check_opc_signature_coverage(pkg, report)
    return report


def _check_opc(pkg: OpcPackage, report: ValidationReport) -> None:
    if not pkg.relationships.get(""):
        report.fail(report.opc_errors, "missing root relationships (_rels/.rels)")

    # A main WordprocessingML document part must exist and be typed as such.
    main_parts = [p for p in pkg.parts if pkg.content_type_for(p) == CT_DOCUMENT]
    if not main_parts:
        report.fail(report.opc_errors, "no main document part (word/document.xml)")

    for part in pkg.parts:
        if part == CONTENT_TYPES_PART:
            continue
        if pkg.content_type_for(part) is None:
            report.fail(report.opc_errors, f"part has no content type: {part}")

    if not _all_parts_reachable(pkg):
        report.fail(
            report.opc_errors,
            "not every part is reachable by following relationships",
        )


def _all_parts_reachable(pkg: OpcPackage) -> bool:
    """Root-anchored OPC reachability (report §14.1): walk relationships starting
    from the package root, following only sources already proven reachable. A part
    referenced solely by another *orphan* part must NOT count as reachable — a plain
    "is any relationship a target" check would wrongly pass such orphan chains."""
    import posixpath

    def targets_of(source: str) -> set[str]:
        base_dir = "" if source == "" else posixpath.dirname(source)
        out: set[str] = set()
        for rel in pkg.relationships.get(source, []):
            if rel.mode == "External":
                continue
            resolved = posixpath.normpath(
                posixpath.join(base_dir, rel.target) if base_dir else rel.target
            )
            out.add(resolved.lstrip("/"))
        return out

    reachable: set[str] = set()
    frontier = list(targets_of(""))  # package-root relationships
    while frontier:
        part = frontier.pop()
        if part in reachable:
            continue
        reachable.add(part)
        frontier.extend(targets_of(part))

    for part in pkg.parts:
        if part.endswith(".rels"):
            continue
        if part not in reachable:
            return False
    return True


def _check_intelligence(pkg: OpcPackage, report: ValidationReport) -> None:
    manifest = read_manifest(pkg)
    if manifest is None:
        report.notes.append("no intelligence manifest (plain document)")
        return

    from . import channels as channel_registry
    from .crypto import digest as _digest

    report.notes.append(f"intelligence modules: {len(manifest.records)}")
    for record in manifest.records:
        try:
            channel = channel_registry.get_channel(record.channel)
        except ValueError as exc:
            report.fail(report.intelligence_errors, f"{record.slot}: {exc}")
            continue
        try:
            raw = channel.extract(pkg, record)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the validator
            report.fail(report.intelligence_errors, f"{record.slot}: extract failed: {exc}")
            continue
        # The manifest digest binds the STORED bytes uniformly (plaintext or sealed);
        # plaintext integrity for sealed modules is the AEAD tag, checked on decrypt.
        if _digest(raw) != record.digest:
            report.fail(report.intelligence_errors, f"{record.slot}: digest mismatch")

    # Make the stored Merkle root live: it must equal the root recomputed from the
    # module set, or the manifest is internally inconsistent.
    import json as _json

    from .manifest import MANIFEST_PART

    stored_root = _json.loads(pkg.parts[MANIFEST_PART]).get("merkle_root", "")
    if stored_root != manifest.merkle_root():
        report.fail(report.intelligence_errors, "stored merkle_root does not match the module set")

    # The surface digest has to be recomputed for the same reason the Merkle root
    # does. Checking only that the signature is self-consistent leaves the most
    # visible tamper of all undetected: editing the text of word/document.xml
    # changes nothing the signature covers *as stored*, so a package whose visible
    # prose had been rewritten passed `docxplus validate` with no findings at all.
    # `verify` caught it, but validate is the command a release process runs.
    if manifest.surface_digest:
        from .container import _compute_surface_digest

        if manifest.surface_digest != _compute_surface_digest(pkg):
            report.fail(
                report.intelligence_errors,
                "stored surface_digest does not match the package — the visible "
                "document or its part graph has been altered since signing",
            )

    if manifest.is_signed():
        if not manifest.verify_signature():
            report.fail(report.intelligence_errors, "manifest signature is invalid")
    else:
        # Unsigned manifests carry no cryptographic provenance: an attacker who
        # rewrites a module can also rewrite its digest. Loudly note it.
        report.notes.append(
            "WARNING: manifest is unsigned — module digests are not tamper-evident "
            "without a signature (see docs/security-model.md)"
        )


def assert_valid(data: bytes) -> None:
    """Raise :class:`AssertionError` with the joined findings if invalid."""
    report = validate_bytes(data)
    if not report.ok:
        problems = report.opc_errors + report.intelligence_errors
        raise AssertionError("docxplus validation failed: " + "; ".join(problems))


# -- ODT profile ---------------------------------------------------------------
#
# The sibling profile gets its own validator rather than borrowing the OPC one:
# ODF locates parts through META-INF/manifest.xml and positionally (mimetype
# first, stored), where OPC uses [Content_Types].xml and a relationship graph.
# Checking an ODF package against OPC rules would either pass vacuously or fail
# for the wrong reason.

def validate_odt_bytes(data: bytes) -> ValidationReport:
    """Validate raw .odt bytes across both contracts."""
    report = ValidationReport()
    try:
        from .odt import OdtPackage

        pkg = OdtPackage.from_bytes(data)
    except Exception as exc:  # noqa: BLE001 - report, don't crash the validator
        report.fail(report.opc_errors, f"unreadable ODT package: {exc}")
        return report
    _check_odf(data, pkg, report)
    _check_odt_intelligence(pkg, report)
    return report


def _check_odf(data: bytes, pkg, report: ValidationReport) -> None:
    """Surface contract: the positional mimetype rule and manifest completeness."""
    import io
    import zipfile as _zip

    from .odt import MIMETYPE_ODT

    with _zip.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
    if not infos:
        report.fail(report.opc_errors, "empty ODT package")
        return
    # ODF requires the mimetype stream first and uncompressed so a consumer can
    # identify the format from the archive's opening bytes alone.
    if infos[0].filename != "mimetype":
        report.fail(report.opc_errors, f"first ZIP entry is {infos[0].filename!r}, not 'mimetype'")
    elif infos[0].compress_type != _zip.ZIP_STORED:
        report.fail(report.opc_errors, "mimetype entry is compressed (must be STORED)")
    if pkg.parts.get("mimetype") != MIMETYPE_ODT:
        report.fail(report.opc_errors, "mimetype content is not the OpenDocument Text media type")
    if "META-INF/manifest.xml" not in pkg.parts:
        report.fail(report.opc_errors, "missing META-INF/manifest.xml")
    if "content.xml" not in pkg.parts:
        report.fail(report.opc_errors, "missing content.xml")

    # Every carried part must be declared, or a reader following the manifest
    # would never find it — the ODF analogue of OPC reachability.
    positional = {"mimetype", "META-INF/manifest.xml"}
    for part in pkg.parts:
        if part in positional or part.endswith("/"):
            continue
        if part not in pkg.media_types:
            report.fail(report.opc_errors, f"part not declared in META-INF/manifest.xml: {part}")


def _check_odt_intelligence(pkg, report: ValidationReport) -> None:
    import json as _json

    from .crypto import digest as _digest
    from .manifest import Manifest
    from .odt_container import ODT_MANIFEST_PART

    blob = pkg.parts.get(ODT_MANIFEST_PART)
    if blob is None:
        report.notes.append("no intelligence manifest (plain ODT document)")
        return
    manifest = Manifest.from_bytes(blob)
    report.notes.append(f"intelligence modules: {len(manifest.records)}")

    for record in manifest.records:
        part = record.location.get("part")
        raw = pkg.parts.get(part)
        if raw is None:
            report.fail(report.intelligence_errors, f"{record.slot}: missing part {part}")
            continue
        if _digest(raw) != record.digest:
            report.fail(report.intelligence_errors, f"{record.slot}: digest mismatch")

    if _json.loads(blob).get("merkle_root", "") != manifest.merkle_root():
        report.fail(report.intelligence_errors, "stored merkle_root does not match the module set")

    # Same recomputation for the ODF profile. Parity here is the whole point of the
    # shared code path: a check present on one profile and absent on the other makes
    # the weaker profile the one an attacker chooses to present.
    if manifest.surface_digest:
        from .odt_container import compute_odt_surface_digest

        if manifest.surface_digest != compute_odt_surface_digest(pkg):
            report.fail(
                report.intelligence_errors,
                "stored surface_digest does not match the package — the visible "
                "document or its part graph has been altered since signing",
            )

    if manifest.is_signed():
        if not manifest.verify_signature():
            report.fail(report.intelligence_errors, "manifest signature is invalid")
    else:
        report.notes.append(
            "WARNING: manifest is unsigned — module digests are not tamper-evident "
            "without a signature (see docs/security-model.md)"
        )


# -- OPC whole-package signatures ---------------------------------------------

#: Where an OPC digital-signature origin part lives, per ISO/IEC 29500-2.
OPC_SIGNATURE_ORIGIN = "_xmlsignatures/origin.sigs"


def check_opc_signature_coverage(pkg: OpcPackage, report: ValidationReport) -> None:
    """Fail closed when an OPC package signature does not cover the payloads.

    An OPC signature enumerates the parts it covers. A signature listing only the
    conventional Word parts would display as valid in a desktop office suite over
    a package whose intelligence layer had been stripped or swapped — the trust
    indicator would then be attesting the absence of the thing a reader assumes it
    covers. That is strictly worse than carrying no signature at all, so the rule
    is written before any signing support exists: if a package carries OPC
    signatures, their combined reference set must include every part the
    intelligence manifest names, plus the manifest itself.

    See ``docs/opc-signatures.md``. Packages with no OPC signature are unaffected.
    """
    signature_parts = [p for p in pkg.parts if p.startswith("_xmlsignatures/") and p.endswith(".xml")]
    if OPC_SIGNATURE_ORIGIN not in pkg.parts and not signature_parts:
        return  # no OPC signature: nothing to over-claim

    from .manifest import MANIFEST_PART, read_manifest

    manifest = read_manifest(pkg)
    if manifest is None:
        return  # a plain signed document is the office suite's business, not ours

    covered: set[str] = set()
    for sig_part in signature_parts:
        covered |= _signed_part_names(pkg.parts[sig_part])

    required = {MANIFEST_PART} | {
        part for r in manifest.records if (part := r.location.get("part"))
    }
    missing = sorted(required - covered)
    if missing:
        report.fail(
            report.intelligence_errors,
            "OPC signature does not cover intelligence parts "
            f"({', '.join(missing)}) — a validating signature over a stripped "
            "payload set is worse than none; see docs/opc-signatures.md",
        )


def _signed_part_names(blob: bytes) -> set[str]:
    """Part names referenced by an XML-DSig signature part.

    OPC references a part as a URI with an optional ``?ContentType=`` query, so
    the query is stripped before comparison.
    """
    from urllib.parse import unquote

    from defusedxml.ElementTree import fromstring as _safe_fromstring

    names: set[str] = set()
    try:
        root = _safe_fromstring(blob)
    except Exception:  # noqa: BLE001 - a malformed signature covers nothing
        return names
    for elem in root.iter():
        if not elem.tag.endswith("}Reference") and not elem.tag.endswith("Reference"):
            continue
        uri = elem.get("URI")
        if not uri:
            continue
        names.add(unquote(uri.split("?", 1)[0]).lstrip("/"))
    return names


__all__ = [
    "ValidationReport",
    "assert_valid",
    "check_opc_signature_coverage",
    "validate_bytes",
    "validate_odt_bytes",
    "validate_package",
]


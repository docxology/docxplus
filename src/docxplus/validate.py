"""Structural validation for docxplus packages.

Check the OPC/ODF surface structure and intelligence-layer consistency, not full
Office/ODF schemas or XML-DSig/X.509 authenticity. Manifest signatures establish
self-consistency only, unless a separate authenticity API pins the signing key.

The validator returns a structured report rather than raising, so a pipeline can
record findings; :func:`assert_valid` is the strict wrapper.
"""

from __future__ import annotations

import posixpath
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring as _safe_fromstring

from .manifest import read_manifest
from .opc import CONTENT_TYPES_PART, OpcPackage, read_package
from .wordml import CT_DOCUMENT, NS_WORDML, REL_OFFICE_DOCUMENT

# Expected failures decoding untrusted package, XML, JSON, and manifest fields.
_MALFORMED_INPUT = (
    ValueError, TypeError, LookupError, UnicodeError, ParseError, DefusedXmlException,
    zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, OSError, struct.error, zlib.error,
    NotImplementedError,  # unsupported ZIP compression
    RuntimeError,  # encrypted ZIP entries without a password
)


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
    except _MALFORMED_INPUT as exc:
        report.fail(report.opc_errors, f"unreadable package: {exc}")
        return report
    return validate_package(pkg, report)


def validate_package(pkg: OpcPackage, report: ValidationReport | None = None) -> ValidationReport:
    """Check package structure and manifest consistency, returning all findings."""
    report = report or ValidationReport()
    try:
        _check_opc(pkg, report)
    except _MALFORMED_INPUT as exc:
        report.fail(report.opc_errors, f"malformed package surface: {exc}")
    try:
        _check_intelligence(pkg, report)
    except _MALFORMED_INPUT as exc:
        report.fail(report.intelligence_errors, f"malformed intelligence manifest: {exc}")
    check_opc_signature_coverage(pkg, report)
    return report


def _check_opc(pkg: OpcPackage, report: ValidationReport) -> None:
    if not pkg.relationships.get(""):
        report.fail(report.opc_errors, "missing root relationships (_rels/.rels)")

    main_edges = [r for r in pkg.relationships.get("", []) if r.type == REL_OFFICE_DOCUMENT]
    if len(main_edges) != 1:
        report.fail(report.opc_errors, "expected one root officeDocument relationship to the main document")
    else:
        edge = main_edges[0]
        main = _root_target(edge.target) if edge.mode == "Internal" else None
        if main not in pkg.parts or pkg.content_type_for(main) != CT_DOCUMENT:
            report.fail(report.opc_errors, "root officeDocument relationship has no correctly typed main document")
        else:
            _check_xml_root(pkg.parts[main], f"{{{NS_WORDML}}}document", main, report)

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


def _root_target(target: str) -> str | None:
    """Resolve an internal package-root edge without treating external URIs as parts."""
    uri = urlsplit(target)
    if uri.scheme or uri.netloc or uri.query or uri.fragment:
        return None
    path = posixpath.normpath(unquote(uri.path, errors="strict").lstrip("/"))
    return path if path not in (".", "..") and not path.startswith("../") else None


def _check_xml_root(blob: bytes, expected: str, part: str, report: ValidationReport) -> None:
    try:
        root = _safe_fromstring(blob)
    except (ParseError, DefusedXmlException, ValueError, LookupError) as exc:
        report.fail(report.opc_errors, f"{part}: malformed surface XML: {exc}")
        return
    if root.tag != expected:
        report.fail(report.opc_errors, f"{part}: unexpected surface XML root {root.tag!r}; expected {expected}")


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
    from .manifest import CT_MANIFEST, MANIFEST_PART, REL_MANIFEST

    edges = [r for r in pkg.relationships.get("", []) if r.type == REL_MANIFEST]
    if MANIFEST_PART in pkg.parts or edges:
        if pkg.content_type_for(MANIFEST_PART) != CT_MANIFEST:
            report.fail(report.intelligence_errors, "intelligence manifest has the wrong content type")
        if (len(edges) != 1 or edges[0].mode != "Internal"
                or _root_target(edges[0].target) != MANIFEST_PART):
            report.fail(report.intelligence_errors, "intelligence manifest requires its root authority relationship")
        if MANIFEST_PART not in pkg.parts:
            report.fail(report.intelligence_errors, "intelligence manifest authority names a missing part")
            return
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

    if manifest.signature or manifest.public_key:
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
    except _MALFORMED_INPUT as exc:
        report.fail(report.opc_errors, f"unreadable ODT package: {exc}")
        return report
    _check_odf(data, pkg, report)
    try:
        _check_odt_intelligence(pkg, report)
    except _MALFORMED_INPUT as exc:
        report.fail(report.intelligence_errors, f"malformed intelligence manifest: {exc}")
    return report


def _check_odf(data: bytes, pkg, report: ValidationReport) -> None:
    """Surface contract: the positional mimetype rule and manifest completeness."""
    import io
    import zipfile as _zip

    from .odt import MIMETYPE_ODT, NS_OFFICE

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
    else:
        _check_xml_root(pkg.parts["content.xml"], f"{{{NS_OFFICE}}}document-content", "content.xml", report)

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
    from .odt_container import CT_MANIFEST, ODT_MANIFEST_PART

    blob = pkg.parts.get(ODT_MANIFEST_PART)
    if blob is None:
        report.notes.append("no intelligence manifest (plain ODT document)")
        return
    if pkg.media_types.get(ODT_MANIFEST_PART) != CT_MANIFEST:
        report.fail(report.intelligence_errors, "intelligence manifest has the wrong ODF media-type declaration")
    manifest = Manifest.from_bytes(blob)
    report.notes.append(f"intelligence modules: {len(manifest.records)}")

    from .channels.metadata import OdtMetadataChannel
    from .channels.stego_media import OdtStegMediaChannel

    for record in manifest.records:
        if record.channel not in ("odt_package_part", "stego_media", "odt_metadata"):
            report.fail(report.intelligence_errors, f"{record.slot}: unsupported ODT channel: {record.channel}")
            continue
        if record.channel == "stego_media":
            # A concealed module travels inside its carrier's pixels, not as a
            # standalone part; the channel's extract verifies against the record
            # digest itself, including the replica-selection rule.
            try:
                backend = record.location.get("backend", "python_lsb")
                OdtStegMediaChannel(backend=backend).extract(pkg, record)
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                report.fail(report.intelligence_errors, f"{record.slot}: {exc}")
            continue
        if record.channel == "odt_metadata":
            # A user-defined meta.xml field; the record digest binds the stored
            # (possibly sealed) bytes exactly as the package-part path does.
            try:
                raw = OdtMetadataChannel().extract(pkg, record)
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                report.fail(report.intelligence_errors, f"{record.slot}: {exc}")
                continue
            if _digest(raw) != record.digest:
                report.fail(report.intelligence_errors, f"{record.slot}: digest mismatch")
            continue
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

    if manifest.signature or manifest.public_key:
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
    """Check syntactic coverage of every intelligence carrier, not XML-DSig validity.

    Only namespace-qualified references reachable from SignedInfo and referenced
    Manifest/Object nodes count. No cryptographic XML-DSig or X.509 check occurs.
    Packages without an OPC signature are unaffected.
    """
    signature_parts = [p for p in pkg.parts if p.startswith("_xmlsignatures/") and p.endswith(".xml")]
    if OPC_SIGNATURE_ORIGIN not in pkg.parts and not signature_parts:
        return  # no OPC signature: nothing to over-claim

    from .manifest import MANIFEST_PART, read_manifest

    covered: set[str] = set()
    for sig_part in signature_parts:
        try:
            covered |= _signed_part_names(pkg.parts[sig_part])
        except _MALFORMED_INPUT as exc:
            report.fail(report.intelligence_errors, f"{sig_part}: malformed OPC signature XML: {exc}")
    report.notes.append("OPC signature coverage is syntactic only; XML-DSig and X.509 are not verified")
    try:
        manifest = read_manifest(pkg)
    except _MALFORMED_INPUT as exc:
        report.fail(report.intelligence_errors, f"cannot check OPC coverage: malformed manifest: {exc}")
        return
    if manifest is None:
        return


    from .channels.metadata import CUSTOM_PART

    required = {MANIFEST_PART}
    for record in manifest.records:
        carriers = []
        if record.channel == "metadata":
            carriers.append(CUSTOM_PART)
        if record.channel == "mce":
            carriers.append(record.location.get("part", "word/document.xml"))
        if "part" in record.location:
            carriers.append(record.location["part"])
        replicas = record.location.get("parts", [])
        if not isinstance(replicas, list):
            report.fail(report.intelligence_errors, f"{record.slot}: carrier parts must be a list")
            continue
        carriers.extend(replicas)
        if any(not isinstance(part, str) or not part for part in carriers):
            report.fail(report.intelligence_errors, f"{record.slot}: carrier names must be nonempty strings")
            continue
        required.update(carriers)
    missing = sorted(required - covered)
    if missing:
        report.fail(
            report.intelligence_errors,
            "OPC signature does not cover intelligence parts "
            f"({', '.join(missing)}) — syntactic coverage only; see docs/opc-signatures.md",
        )


def _signed_part_names(blob: bytes) -> set[str]:
    """Collect package references reachable through the XML-DSig signed topology.

    A signed Object may contain a Manifest, which in turn references package parts
    or another Manifest. Unsigned Objects and unrelated extension nodes do not
    contribute. This examines topology only, not digests, transforms or signatures.
    """
    ds = "{http://www.w3.org/2000/09/xmldsig#}"
    root = _safe_fromstring(blob)
    if root.tag != ds + "Signature":
        raise ValueError("expected an XML-DSig Signature root")
    signed_info = root.findall(ds + "SignedInfo")
    if len(signed_info) != 1:
        raise ValueError("expected exactly one XML-DSig SignedInfo")
    ids = {}
    for elem in root.iter():
        if ident := elem.get("Id"):
            if ident in ids:
                raise ValueError(f"duplicate signature Id: {ident}")
            ids[ident] = elem

    names: set[str] = set()
    pending = list(signed_info[0].findall(ds + "Reference"))
    visited: set[str] = set()
    while pending:
        reference = pending.pop()
        uri = reference.get("URI", "")
        if uri.startswith("#"):
            ident = unquote(uri[1:], errors="strict")
            if ident in visited:
                continue
            visited.add(ident)
            target = ids.get(ident)
            if target is None:
                raise ValueError(f"unresolved signature reference: {uri}")
            if target.tag == ds + "Manifest":
                pending.extend(target.findall(ds + "Reference"))
            elif target.tag == ds + "Object":
                for manifest in target.findall(ds + "Manifest"):
                    pending.extend(manifest.findall(ds + "Reference"))
            continue
        parsed = urlsplit(uri)
        if (not parsed.scheme and not parsed.netloc and not parsed.fragment
                and parsed.path.startswith("/")):
            part = _root_target(parsed.path)
            if part is not None:
                names.add(part)
    return names


__all__ = [
    "ValidationReport",
    "assert_valid",
    "check_opc_signature_coverage",
    "validate_bytes",
    "validate_odt_bytes",
    "validate_package",
]


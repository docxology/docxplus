"""Conformance validation for DOCX+ packages.

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

from manifest import read_manifest
from opc import CONTENT_TYPES_PART, OpcError, OpcPackage, read_package
from wordml import CT_DOCUMENT


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
    """Approximate OPC reachability: every non-rels part is a relationship target
    from the package root or from another reachable part (report §14.1)."""
    targets: set[str] = set()
    import posixpath

    for source, rels in pkg.relationships.items():
        base_dir = "" if source == "" else posixpath.dirname(source)
        for rel in rels:
            if rel.mode == "External":
                continue
            resolved = posixpath.normpath(
                posixpath.join(base_dir, rel.target) if base_dir else rel.target
            )
            targets.add(resolved.lstrip("/"))

    for part in pkg.parts:
        if part.endswith(".rels"):
            continue
        if part not in targets:
            return False
    return True


def _check_intelligence(pkg: OpcPackage, report: ValidationReport) -> None:
    manifest = read_manifest(pkg)
    if manifest is None:
        report.notes.append("no intelligence manifest (plain document)")
        return

    import channels as channel_registry

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
        from crypto import digest as _digest

        # For encrypted modules the stored bytes are the envelope; the manifest
        # digest is over the *plaintext*, so we can only length-check here.
        if record.encrypted:
            if len(raw) < record.size:
                report.fail(
                    report.intelligence_errors,
                    f"{record.slot}: ciphertext shorter than declared plaintext size",
                )
        elif _digest(raw) != record.digest:
            report.fail(report.intelligence_errors, f"{record.slot}: digest mismatch")

    if manifest.is_signed() and not manifest.verify_signature():
        report.fail(report.intelligence_errors, "manifest signature is invalid")


def assert_valid(data: bytes) -> None:
    """Raise :class:`AssertionError` with the joined findings if invalid."""
    report = validate_bytes(data)
    if not report.ok:
        problems = report.opc_errors + report.intelligence_errors
        raise AssertionError("DOCX+ validation failed: " + "; ".join(problems))

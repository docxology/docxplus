"""Independent structural, provenance and threat reports for document intake.

Auditing never extracts payloads, decodes carriers or executes carried recipes.
Self-consistency is not authenticity: only a complete caller-pinned signing key
can authenticate the inspected intelligence layer.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException

from .inspection import (
    inspect_document,
    read_document_file,
    validate_inspection_policy,
)
from .intake import IntakeError, IntakePolicy, scan, scan_odt
from .odt import OdtPackage
from .opc import OpcPackage

MAX_AUDIT_DOCUMENTS = 256


def _audit_policy(policy: IntakePolicy | None) -> IntakePolicy:
    """Snapshot caller policy and reject configuration errors before intake."""
    if policy is None:
        return IntakePolicy()
    if not isinstance(policy, IntakePolicy):
        raise TypeError("policy must be an IntakePolicy or None")
    if type(policy.max_parts) is not int or policy.max_parts <= 0:
        raise ValueError("policy.max_parts must be a positive integer")
    fields = ("strict", "allow_external_relationships", "allow_macros", "allow_altchunk")
    if any(type(getattr(policy, name)) is not bool for name in fields):
        raise ValueError("intake policy flags must be booleans")
    return IntakePolicy(max_parts=policy.max_parts, **{
        name: getattr(policy, name) for name in fields
    })


def _audit_document(
    data: bytes,
    *,
    expected_public_key: bytes | None,
    require_cosigners: Sequence[bytes],
    policy: IntakePolicy,
) -> dict:
    """Keep independently available diagnostics, including on rejected inputs."""
    inspection = inspect_document(
        data, expected_public_key=expected_public_key, require_cosigners=require_cosigners,
    )
    errors = list(inspection.report["errors"])
    if not inspection.ok and not errors:
        errors.append("document inspection failed")
    threats = None
    if inspection.package is None:
        errors.append("threat scan unavailable: package could not be parsed")
    else:
        try:
            # scan/scan_odt, unlike safe_open, retain a report under strict policy.
            if isinstance(inspection.package, OdtPackage):
                threats = scan_odt(inspection.package, policy).to_dict()
            elif isinstance(inspection.package, OpcPackage):
                threats = scan(inspection.package, policy).to_dict()
            else:
                raise TypeError("inspection returned an unsupported package type")
        except (IntakeError, ValueError, ParseError, DefusedXmlException) as exc:
            errors.append(f"threat scan failed: {type(exc).__name__}: {exc}")
        if threats is not None and not threats["ok"]:
            errors.append("document intake threats detected")
    return {
        "schema": "docxplus.audit.v1",
        "ok": inspection.ok and threats is not None and threats["ok"],
        "inspection": inspection.report,
        "threats": threats,
        "errors": errors,
    }


def audit_document(
    data: bytes,
    *,
    expected_public_key: bytes | None = None,
    require_cosigners: Sequence[bytes] = (),
    policy: IntakePolicy | None = None,
) -> dict:
    """Inspect bytes and independently triage the parsed DOCX or ODT package.

    ``ok`` requires both inspection and threat triage to pass. A strict policy
    does not raise for document threats or discard their diagnostics. Malformed
    documents produce failed reports; invalid caller policy raises ``TypeError``
    or ``ValueError``.
    Payload integrity and successful execution are not conclusions of this API.
    """
    cosigners = validate_inspection_policy(expected_public_key, require_cosigners)
    return _audit_document(
        data, expected_public_key=expected_public_key, require_cosigners=cosigners,
        policy=_audit_policy(policy),
    )


def audit_files(
    paths: Sequence[str | Path],
    *,
    expected_public_key: bytes | None = None,
    require_cosigners: Sequence[bytes] = (),
    policy: IntakePolicy | None = None,
    max_bytes: int = 64 * 1024 * 1024,
    max_documents: int = MAX_AUDIT_DOCUMENTS,
) -> dict:
    """Audit regular files sequentially, retaining input order and duplicates.

    Read/admission failures belong to their own rows and cannot discard peers.
    Empty inputs, invalid limits or invalid policy raise ``TypeError`` or
    ``ValueError`` before opening inputs. Oversized batches reject all inputs.
    The count bound is not a process-memory bound. Reports
    never imply unpinned identity.
    """
    if type(max_documents) is not int or max_documents <= 0:
        raise ValueError("max_documents must be a positive integer")
    if len(paths) > max_documents:
        raise ValueError("document count exceeds max_documents")
    if not paths:
        raise ValueError("at least one document path is required")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    cosigners = validate_inspection_policy(expected_public_key, require_cosigners)
    intake_policy = _audit_policy(policy)
    results = []
    for path in paths:
        label = str(path)
        try:
            data = read_document_file(path, max_bytes=max_bytes)
        except (NotImplementedError, OSError, ValueError) as exc:
            results.append({
                "path": label, "ok": False, "inspection": None, "threats": None,
                "errors": [f"document read failed: {type(exc).__name__}: {exc}"],
            })
            continue
        row = _audit_document(
            data, expected_public_key=expected_public_key, require_cosigners=cosigners,
            policy=intake_policy,
        )
        results.append({"path": label, **{
            name: value for name, value in row.items() if name != "schema"
        }})
    return {
        "schema": "docxplus.audit-batch.v1",
        "ok": all(row["ok"] for row in results),
        "results": results,
    }


__all__ = ["MAX_AUDIT_DOCUMENTS", "audit_document", "audit_files"]

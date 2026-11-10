"""Logical, declaration-aware comparison without extracting carried payloads."""

from __future__ import annotations

import json
from collections.abc import Sequence

from .inspection import Inspection, inspect_document


def _signing_identities(inspection: Inspection) -> tuple | None:
    """Retain declared identities/schemes, not randomized signature values."""
    if inspection.package is None:
        return None
    if inspection.reader is None:
        return None if inspection.manifest_present else (None, ())
    manifest = inspection.reader.manifest
    primary = (bytes.fromhex(manifest.public_key), manifest.algorithm) if manifest.public_key else None
    cosigners = tuple(sorted(
        (bytes.fromhex(entry["public_key"]), entry["algorithm"]) for entry in manifest.cosignatures
    ))
    return primary, cosigners


def _json_value(value: object) -> str:
    """Compare JSON types exactly while retaining nested array order."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def compare_documents(
    left: bytes,
    right: bytes,
    *,
    expected_public_key: bytes | None = None,
    require_cosigners: Sequence[bytes] = (),
) -> dict:
    """Compare validated package surfaces, complete module records and signers.

    Changes are directed from ``left`` to ``right``. ``equal`` is ``None`` if
    either inspection fails; otherwise it describes stored logical equality,
    ignoring ZIP representation and valid signature value differences. It does
    not assert plaintext/rendered equivalence or authenticity. Authenticity needs
    a complete caller-pinned key; the same optional policy applies to both sides.
    No payload extraction, media decoding, nested traversal or execution occurs.
    Unavailable package/signer comparisons are reported as ``None``.
    """
    before = inspect_document(
        left, expected_public_key=expected_public_key, require_cosigners=require_cosigners
    )
    after = inspect_document(
        right, expected_public_key=expected_public_key, require_cosigners=require_cosigners
    )
    left_modules = {record["slot"]: record for record in before.report["intelligence"]["modules"]}
    right_modules = {record["slot"]: record for record in after.report["intelligence"]["modules"]}
    added = sorted(right_modules.keys() - left_modules.keys())
    removed = sorted(left_modules.keys() - right_modules.keys())
    changed = []
    unchanged = []
    for slot in sorted(left_modules.keys() & right_modules.keys()):
        old, new = left_modules[slot], right_modules[slot]
        fields = sorted(
            field for field in old.keys() | new.keys()
            if field not in old or field not in new or _json_value(old[field]) != _json_value(new[field])
        )
        if fields:
            changed.append({"slot": slot, "fields": fields, "before": old, "after": new})
        else:
            unchanged.append(slot)

    profile_equal = before.profile is not None and before.profile == after.profile
    left_digest, right_digest = before.report["surface_digest"], after.report["surface_digest"]
    package_equal = (
        left_digest == right_digest if left_digest is not None and right_digest is not None else None
    )
    left_signers, right_signers = _signing_identities(before), _signing_identities(after)
    signers_equal = (
        left_signers == right_signers if left_signers is not None and right_signers is not None else None
    )
    ok = before.ok and after.ok
    equal = (
        bool(profile_equal and package_equal and signers_equal
             and before.manifest_present == after.manifest_present
             and not added and not removed and not changed)
        if ok else None
    )
    return {
        "schema": "docxplus.comparison.v1",
        "ok": ok,
        "equal": equal,
        "left": before.report,
        "right": after.report,
        "byte_equal": left == right,
        "profile_equal": profile_equal,
        "package_equal": package_equal,
        "signers_equal": signers_equal,
        "modules": {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged},
    }

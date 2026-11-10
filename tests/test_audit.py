"""Real serialized documents pin independent audit and ordered batch diagnostics."""

from __future__ import annotations

import io
import json
import sys
import zipfile

import pytest

from docxplus import crypto
from docxplus.audit import audit_document, audit_files
from docxplus.container import DocxPlusBuilder
from docxplus.intake import IntakePolicy
from docxplus.manifest import MANIFEST_PART
from docxplus.odt import OdtPackage, new_base_odt
from docxplus.odt_container import OdtPlusBuilder
from docxplus.opc import read_package
from docxplus.wordml import new_base_document

_PRIVATE = bytes([1]) * 32
_PUBLIC = crypto.signing_public_key(_PRIVATE)
_COSIGNER_PRIVATE = bytes([2]) * 32
_COSIGNER_PUBLIC = crypto.signing_public_key(_COSIGNER_PRIVATE)
_STRANGER = crypto.signing_public_key(bytes([3]) * 32)


@pytest.fixture(params=["docx", "odt"])
def profile(request):
    return request.param


def _document(profile: str, *, signed: bool = True, cosigned: bool = False) -> bytes:
    builder = (
        DocxPlusBuilder(paragraphs=["original surface"])
        if profile == "docx" else OdtPlusBuilder(paragraphs=["original surface"])
    )
    if profile == "docx":
        builder.add_module("brief", "package_part", b"carried bytes", payload_type="bytes")
    else:
        builder.add_module("brief", b"carried bytes", payload_type="bytes")
    if signed:
        builder.sign(_PRIVATE)
    if cosigned:
        builder.add_cosigner(_COSIGNER_PRIVATE)
    return builder.build()


def _replace(data: bytes, replacements: dict[str, bytes]) -> bytes:
    """Retain ODF mimetype ordering/compression while changing serialized evidence."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, "w") as target:
        for info in source.infolist():
            target.writestr(info, replacements.get(info.filename, source.read(info)))
    return out.getvalue()


def _manifest(data: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return json.loads(archive.read(MANIFEST_PART))


def _threat_document(profile: str, data: bytes) -> bytes:
    if profile == "docx":
        package = read_package(data)
        package.add_part("word/vbaProject.bin", b"inert macro marker", "application/vnd.ms-office.vbaProject")
    else:
        package = OdtPackage.from_bytes(data)
        package.add_part("Basic/Module1.bin", b"inert macro marker", "application/octet-stream")
    return package.to_bytes()


def test_ordinary_documents_are_not_fictitious_intelligence(profile):
    """Ordinary package acceptance cannot invent modules, signatures or identity."""
    data = (
        new_base_document(["ordinary"]).to_bytes()
        if profile == "docx" else new_base_odt(["ordinary"]).to_bytes()
    )
    row = audit_document(data)
    assert row["schema"] == "docxplus.audit.v1"
    assert row["ok"], row
    assert row["threats"]["ok"]
    inspection = row["inspection"]
    assert inspection["profile"] == profile
    assert not inspection["intelligence"]["present"]
    assert inspection["intelligence"]["declaration_valid"] is None
    assert inspection["intelligence"]["modules"] == []
    assert inspection["signature"]["authentic"] is None
    assert not inspection["signature"]["self_consistent"]
    assert not inspection["payloads_verified"]
    assert not audit_document(data, expected_public_key=_PUBLIC)["ok"]


def test_signed_unpinned_trusted_and_stranger_are_distinct(profile):
    """A successful unpinned signature is self-consistency, never authenticity."""
    data = _document(profile)
    unpinned = audit_document(data)
    assert unpinned["ok"], unpinned
    assert unpinned["inspection"]["signature"]["self_consistent"]
    assert unpinned["inspection"]["signature"]["authentic"] is None
    trusted = audit_document(data, expected_public_key=_PUBLIC)
    assert trusted["ok"], trusted
    assert trusted["inspection"]["signature"]["authentic"] is True
    stranger = audit_document(data, expected_public_key=_STRANGER)
    assert not stranger["ok"]
    assert stranger["inspection"]["signature"]["authentic"] is False
    assert stranger["threats"]["ok"]


def test_unsigned_intelligence_never_authenticates(profile):
    """Unsigned declarations remain auditable without implying a trusted author."""
    data = _document(profile, signed=False)
    unpinned = audit_document(data)
    assert unpinned["ok"], unpinned
    assert unpinned["inspection"]["signature"]["status"] == "unsigned"
    assert unpinned["inspection"]["signature"]["authentic"] is None
    assert not audit_document(data, expected_public_key=_PUBLIC)["ok"]


def test_required_cosigners_are_and_policy(profile):
    """A required institution does not replace authentication of the primary author."""
    data = _document(profile, cosigned=True)
    trusted = audit_document(
        data, expected_public_key=_PUBLIC, require_cosigners=[_COSIGNER_PUBLIC],
    )
    assert trusted["ok"], trusted
    assert trusted["inspection"]["signature"]["required_cosigners_verified"] is True
    assert not audit_document(
        data, expected_public_key=_PUBLIC, require_cosigners=[_STRANGER],
    )["ok"]
    assert not audit_document(
        data, expected_public_key=_STRANGER, require_cosigners=[_COSIGNER_PUBLIC],
    )["ok"]


@pytest.mark.parametrize("tamper", ["surface", "root"])
def test_tampering_preserves_original_inspection_evidence(profile, tamper):
    """Serialized roots cannot be repaired by reconstructing a parsed manifest."""
    data = _document(profile)
    if tamper == "surface":
        part = "word/document.xml" if profile == "docx" else "content.xml"
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            replacement = archive.read(part).replace(b"original surface", b"altered surface")
        data = _replace(data, {part: replacement})
    else:
        declaration = _manifest(data)
        declaration["merkle_root"] = "0" * 64
        data = _replace(data, {MANIFEST_PART: json.dumps(declaration).encode()})
    row = audit_document(data, expected_public_key=_PUBLIC)
    assert not row["ok"]
    assert not row["inspection"]["ok"]
    assert row["threats"]["ok"]
    assert row["errors"]


@pytest.mark.parametrize("manifest", [b"{", b'{"modules":null}'])
def test_malformed_manifest_does_not_erase_threats(profile, manifest):
    """A broken intelligence layer must not conceal independent macro triage."""
    data = _threat_document(profile, _document(profile))
    row = audit_document(_replace(data, {MANIFEST_PART: manifest}))
    assert not row["ok"]
    assert row["inspection"] is not None
    assert not row["inspection"]["ok"]
    assert row["threats"]["macro_parts"]
    assert not row["threats"]["ok"]


def test_strict_triage_retains_inspection_and_report(profile):
    """Strict intake rejects without safe_open's diagnostic-discarding exception."""
    data = _threat_document(profile, _document(profile, signed=False))
    strict = audit_document(data, policy=IntakePolicy(strict=True))
    ordinary = audit_document(data, policy=IntakePolicy(strict=False))
    assert strict == ordinary
    assert not strict["ok"]
    assert strict["inspection"] is not None
    assert strict["threats"]["macro_parts"]
    allowed = audit_document(data, policy=IntakePolicy(strict=True, allow_macros=True))
    assert allowed["threats"]["ok"]


def test_triage_failure_is_independent_of_successful_inspection(profile):
    """A structurally authentic package still fails an independent part-count cap."""
    row = audit_document(
        _document(profile), expected_public_key=_PUBLIC,
        policy=IntakePolicy(strict=True, max_parts=1),
    )
    assert not row["ok"]
    assert row["inspection"]["ok"]
    assert row["inspection"]["signature"]["authentic"] is True
    assert not row["threats"]["ok"]
    assert row["threats"]["oversized"]


def test_incomplete_xml_triage_keeps_inspection(profile):
    """Unscannable XML is a failed threat stage rather than a false clean result."""
    data = _document(profile)
    part = "word/document.xml" if profile == "docx" else "content.xml"
    row = audit_document(_replace(data, {part: b"<broken"}))
    assert not row["ok"]
    assert row["inspection"] is not None
    assert part in row["threats"]["parse_errors"]
    assert not row["threats"]["ok"]


def test_batch_preserves_mixed_peers_and_order(profile, tmp_path):
    """Read, archive and schema failures never discard distinct valid peers."""
    good = tmp_path / f"good.{profile}"
    second = tmp_path / f"cosigned.{profile}"
    bad = tmp_path / f"bad.{profile}"
    malformed = tmp_path / f"manifest.{profile}"
    missing = tmp_path / f"missing.{profile}"
    good.write_bytes(_document(profile))
    second.write_bytes(_document(profile, cosigned=True))
    bad.write_bytes(b"not a ZIP")
    malformed.write_bytes(_replace(_document(profile), {MANIFEST_PART: b"{"}))
    paths = [good, missing, bad, malformed, str(second)]
    report = audit_files(paths, expected_public_key=_PUBLIC)
    assert report["schema"] == "docxplus.audit-batch.v1"
    assert not report["ok"]
    rows = report["results"]
    assert [row["path"] for row in rows] == [str(path) for path in paths]
    assert [row["ok"] for row in rows] == [True, False, False, False, True]
    assert rows[1]["inspection"] is None and rows[1]["threats"] is None
    assert rows[2]["inspection"] is not None and rows[2]["threats"] is None
    assert rows[3]["inspection"] is not None and rows[3]["threats"] is not None
    assert all(row["errors"] for row in rows[1:4])
    assert all("schema" not in row for row in rows)


def test_batch_read_admission_failures_are_individual(profile, tmp_path):
    """Oversize, directory and symlink inputs fail separately from regular peers."""
    good = tmp_path / f"good.{profile}"
    good.write_bytes(_document(profile))
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"x" * (good.stat().st_size + 1))
    link = tmp_path / "link"
    link.symlink_to(good)
    rows = audit_files(
        [oversized, tmp_path, link, good], max_bytes=good.stat().st_size,
    )["results"]
    assert [row["ok"] for row in rows] == [False, False, False, True]
    assert all(row["inspection"] is None and row["threats"] is None for row in rows[:3])


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, None])
def test_invalid_limits_raise_before_processing(limit, tmp_path):
    """A bad caller limit is not downgraded to a per-file admission failure."""
    with pytest.raises(ValueError):
        audit_files([tmp_path / "missing"], max_bytes=limit)


@pytest.mark.parametrize("kwargs,error", [
    ({"expected_public_key": b"short"}, ValueError),
    ({"expected_public_key": "not bytes"}, TypeError),
    ({"expected_public_key": _PUBLIC + b"trailing"}, ValueError),
    ({"require_cosigners": [_COSIGNER_PUBLIC]}, ValueError),
    ({"expected_public_key": _PUBLIC, "require_cosigners": [b"short"]}, ValueError),
    ({"expected_public_key": _PUBLIC, "require_cosigners": [_COSIGNER_PUBLIC] * 2}, ValueError),
    ({"policy": IntakePolicy(max_parts=0)}, ValueError),
    ({"policy": IntakePolicy(max_parts=True)}, ValueError),
    ({"policy": IntakePolicy(strict="yes")}, ValueError),
    ({"policy": "strict"}, TypeError),
])
def test_invalid_configuration_is_not_an_input_error(kwargs, error, tmp_path):
    """Invalid trust/intake configuration fails before missing-file processing."""
    with pytest.raises(error):
        audit_files([tmp_path / "missing"], **kwargs)
    with pytest.raises(error):
        audit_document(b"not a package", **kwargs)


def test_empty_batch_is_not_vacuously_successful():
    """An accidental empty intake request cannot report that all documents passed."""
    with pytest.raises(ValueError):
        audit_files([])


def test_audit_never_decodes_carriers_or_runs_recipes(profile, tmp_path):
    """Unsupported carrier declarations remain metadata, not decoder invocations."""
    data = _document(profile, signed=False)
    declaration = _manifest(data)
    module = declaration["modules"][0]
    module["channel"] = "stego_media"
    module["location"] = {
        "part": "intelligence/unsupported-carrier.unknown",
        "backend": "nonexistent-audit-backend",
    }
    sentinel = tmp_path / "executed"
    module["reproduction"] = {
        "commands": [[sys.executable, "-c", f"from pathlib import Path; Path({str(sentinel)!r}).touch()"]],
    }
    row = audit_document(_replace(data, {MANIFEST_PART: json.dumps(declaration).encode()}))
    assert row['ok'], row
    assert row["inspection"] is not None
    assert row["threats"] is not None
    assert not row["inspection"]["payloads_verified"]
    assert not sentinel.exists()


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, None])
def test_invalid_document_limits_raise_before_processing(limit, tmp_path):
    """Invalid batch-count configuration is never an individual input error."""
    with pytest.raises(ValueError):
        audit_files([tmp_path / "missing"], max_documents=limit)


def test_document_count_bound_rejects_instead_of_truncating(profile, tmp_path):
    """A count boundary accepts all distinct peers or rejects the whole request."""
    first = tmp_path / f"first.{profile}"
    second = tmp_path / f"second.{profile}"
    first.write_bytes(_document(profile))
    second.write_bytes(_document(profile, cosigned=True))
    accepted = audit_files([first, second], max_documents=2, expected_public_key=_PUBLIC)
    assert accepted["ok"], accepted
    assert [row["path"] for row in accepted["results"]] == [str(first), str(second)]
    with pytest.raises(ValueError):
        audit_files([first, second], max_documents=1, expected_public_key=_PUBLIC)

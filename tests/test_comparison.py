"""Real-byte cross-profile logical comparison and fail-closed declaration tests."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from docxplus.comparison import compare_documents
from docxplus.container import DocxPlusBuilder
from docxplus.crypto import (
    generate_hybrid_signing_key,
    generate_recipient_key,
    generate_signing_key,
    sign,
)
from docxplus.manifest import MANIFEST_PART, Manifest
from docxplus.odt import new_base_odt
from docxplus.odt_container import OdtPlusBuilder
from docxplus.wordml import new_base_document


@pytest.fixture(params=["docx", "odt"])
def profile(request):
    return request.param


@pytest.fixture
def roundtrip(tmp_path):
    """Put every consumer input through a real file, not an in-memory reader."""
    count = 0

    def persist(data):
        nonlocal count
        count += 1
        path = tmp_path / f"document-{count}.zip"
        path.write_bytes(data)
        return path.read_bytes()

    return persist


def _document(profile, modules=(("brief", b"payload"),), *, key=None, cosigners=(), **options):
    builder = (DocxPlusBuilder(paragraphs=["comparison sentinel"]) if profile == "docx"
               else OdtPlusBuilder(paragraphs=["comparison sentinel"]))
    for slot, payload in modules:
        if profile == "docx":
            builder.add_module(slot, "package_part", payload, **options)
        else:
            builder.add_module(slot, payload, **options)
    if key is not None:
        builder.sign(key)
    for cosigner in cosigners:
        builder.add_cosigner(cosigner)
    return builder.build()


def _ordinary(profile, text="ordinary surface"):
    builder = new_base_document if profile == "docx" else new_base_odt
    return builder([text]).to_bytes()


def _replace_entries(data, replacements):
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, "w") as target:
        for info in source.infolist():
            blob = replacements.get(info.filename, source.read(info))
            if blob is not None:
                target.writestr(info, blob)
    return out.getvalue()


def _manifest(data):
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        return json.loads(package.read(MANIFEST_PART))


def _change_record(data, changes, *, key=None):
    document = _manifest(data)
    document["modules"][0].update(changes)
    manifest = Manifest.from_bytes(json.dumps(document).encode())
    if key is not None:
        manifest.signature = sign(manifest.canonical_body(), key).hex()
    return _replace_entries(data, {MANIFEST_PART: manifest.to_bytes()})


def _repack(data):
    """Vary physical ZIP order/time/compression, preserving ODT's mimetype rule."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, "w") as target:
        names = sorted(source.namelist(), reverse=True)
        if "mimetype" in names:
            names.remove("mimetype")
            names.insert(0, "mimetype")
        for name in names:
            info = zipfile.ZipInfo(name, date_time=(2020, 2, 3, 4, 5, 6))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o600 << 16
            target.writestr(info, source.read(name))
    return out.getvalue()


def test_same_document_is_logically_equal_without_claiming_authenticity(profile, roundtrip):
    """Self-consistency remains distinct from complete-key pinned authenticity."""
    private, public = generate_signing_key()
    data = roundtrip(_document(profile, key=private))
    report = compare_documents(data, data)
    assert report["schema"] == "docxplus.comparison.v1"
    assert report["ok"] and report["equal"] is True
    assert report["byte_equal"] and report["profile_equal"]
    assert report["package_equal"] and report["signers_equal"]
    assert report["modules"] == {"added": [], "removed": [], "changed": [], "unchanged": ["brief"]}
    assert report["left"]["signature"]["authentic"] is None
    assert report["left"]["payloads_verified"] is False
    pinned = compare_documents(data, data, expected_public_key=public)
    assert pinned["equal"] is True
    assert pinned["left"]["signature"]["authentic"] is True
    assert pinned["right"]["signature"]["authentic"] is True


def test_untrusted_complete_pin_invalidates_even_identical_bytes(profile, roundtrip):
    """Raw equality cannot turn a rejected trust policy into logical equality."""
    private, _ = generate_signing_key()
    _, stranger = generate_signing_key()
    data = roundtrip(_document(profile, key=private))
    report = compare_documents(data, data, expected_public_key=stranger)
    assert report["byte_equal"] is True
    assert report["ok"] is False and report["equal"] is None
    with pytest.raises(ValueError):
        compare_documents(data, data, expected_public_key=b"short")


def test_ordinary_documents_have_no_modules(profile, roundtrip):
    """Ordinary documents compare without inventing an intelligence declaration."""
    data = roundtrip(_ordinary(profile))
    report = compare_documents(data, data)
    assert report["ok"] and report["equal"] is True
    assert report["modules"] == {"added": [], "removed": [], "changed": [], "unchanged": []}
    assert report["left"]["intelligence"]["present"] is False
    other = roundtrip(_ordinary(profile, "different visible surface"))
    changed = compare_documents(data, other)
    assert changed["ok"] and changed["equal"] is False
    assert changed["package_equal"] is False


def test_valid_different_profiles_are_unequal(roundtrip):
    """A profile change is a valid comparison, never an incomparable input error."""
    for intelligent in (False, True):
        build = _document if intelligent else _ordinary
        report = compare_documents(roundtrip(build("docx")), roundtrip(build("odt")))
        assert report["ok"] and report["equal"] is False
        assert report["profile_equal"] is False
        assert report["package_equal"] is False


def test_module_diff_direction_and_sorting(profile, roundtrip):
    """Slots and changed field names are sorted, with complete directional records."""
    left = roundtrip(_document(profile, (
        ("z_removed", b"x"), ("a_removed", b"x"), ("keep", b"same"),
        ("z_change", b"old"), ("a_change", b"old"),
    )))
    right = roundtrip(_document(profile, (
        ("z_added", b"x"), ("a_added", b"x"), ("keep", b"same"),
        ("z_change", b"new-longer"), ("a_change", b"new-longer"),
    )))
    report = compare_documents(left, right)
    assert report["ok"] and report["equal"] is False
    modules = report["modules"]
    assert modules["added"] == ["a_added", "z_added"]
    assert modules["removed"] == ["a_removed", "z_removed"]
    assert modules["unchanged"] == ["keep"]
    assert [item["slot"] for item in modules["changed"]] == ["a_change", "z_change"]
    for item in modules["changed"]:
        assert item["fields"] == ["digest", "size"]
        assert item["before"]["size"] == 3 and item["after"]["size"] == 10
        assert set(item["before"]) == set(item["after"]) == set(_manifest(left)["modules"][0])
    reverse = compare_documents(right, left)["modules"]
    assert reverse["added"] == modules["removed"]
    assert reverse["removed"] == modules["added"]
    assert reverse["changed"][0]["before"] == modules["changed"][0]["after"]


@pytest.mark.parametrize("field,value", [
    ("content_type", "application/x-review-payload"),
    ("payload_type", "text"),
    ("location", {"part": "intelligence/payload1.dxp", "note": "reviewed"}),
    ("reproduction", {"steps": ["prepare", "run"], "result": {"approved": True}}),
])
def test_metadata_changes_with_identical_stored_digest_are_not_equal(profile, roundtrip, field, value):
    """Merkle roots alone must not hide any signed record metadata change."""
    private, public = generate_signing_key()
    left = roundtrip(_document(profile, key=private))
    right = roundtrip(_change_record(left, {field: value}, key=private))
    assert _manifest(left)["merkle_root"] == _manifest(right)["merkle_root"]
    report = compare_documents(left, right, expected_public_key=public)
    assert report["ok"] and report["equal"] is False
    assert report["package_equal"] and report["signers_equal"]
    item, = report["modules"]["changed"]
    assert item["fields"] == [field]
    assert item["before"]["digest"] == item["after"]["digest"]
    assert item["after"][field] == value


@pytest.mark.parametrize("before,after", [
    ({"steps": ["first", "second"]}, {"steps": ["second", "first"]}),
    ({"approval": True}, {"approval": 1}),
])
def test_nested_record_lists_and_json_types_are_meaningful(profile, roundtrip, before, after):
    """Metadata arrays retain order and JSON booleans never collapse into integers."""
    original = _document(profile)
    left = roundtrip(_change_record(original, {"reproduction": before}))
    right = roundtrip(_change_record(original, {"reproduction": after}))
    report = compare_documents(left, right)
    assert report["ok"] and report["equal"] is False
    assert report["modules"]["changed"][0]["fields"] == ["reproduction"]


def test_archive_representation_does_not_change_logical_equality(profile, roundtrip):
    """ZIP timestamps, ordering and compression are not stored logical differences."""
    private, public = generate_signing_key()
    original = roundtrip(_document(profile, key=private))
    repacked = roundtrip(_repack(original))
    report = compare_documents(original, repacked, expected_public_key=public)
    assert report["ok"] and report["equal"] is True
    assert report["byte_equal"] is False
    assert report["package_equal"] and report["signers_equal"]


@pytest.mark.parametrize("mutation", ["visible", "carrier", "root", "missing", "malformed"])
def test_tampered_input_never_equals_itself(profile, roundtrip, mutation):
    """Preserve raw root and declaration evidence; identical corruption is not equality."""
    original = _document(profile)
    document = _manifest(original)
    if mutation == "visible":
        part = "word/document.xml" if profile == "docx" else "content.xml"
        with zipfile.ZipFile(io.BytesIO(original)) as source:
            replacement = source.read(part).replace(b"comparison sentinel", b"altered surface")
        replacements = {part: replacement}
    elif mutation == "carrier":
        replacements = {document["modules"][0]["location"]["part"]: b"changed carrier"}
    elif mutation == "root":
        document["merkle_root"] = "0" * 64
        replacements = {MANIFEST_PART: json.dumps(document).encode()}
    elif mutation == "missing":
        replacements = {MANIFEST_PART: None}
    else:
        replacements = {MANIFEST_PART: b"not JSON"}
    tampered = roundtrip(_replace_entries(original, replacements))
    report = compare_documents(tampered, tampered)
    assert report["byte_equal"] is True
    assert report["ok"] is False and report["equal"] is None
    assert report["left"]["ok"] is False and report["right"]["ok"] is False


def test_signer_identity_changes_are_logical_changes(profile, roundtrip):
    """The same package and modules signed by a different primary are unequal."""
    first, _ = generate_signing_key()
    second, _ = generate_signing_key()
    report = compare_documents(
        roundtrip(_document(profile, key=first)), roundtrip(_document(profile, key=second))
    )
    assert report["ok"] and report["equal"] is False
    assert report["package_equal"] and report["signers_equal"] is False
    assert report["modules"]["unchanged"] == ["brief"]


def test_cosigner_order_is_ignored_but_identity_and_policy_are_not(profile, roundtrip):
    """Declared co-signer descriptors are a sorted set, verified under an AND policy."""
    author, public = generate_signing_key()
    first, first_public = generate_signing_key()
    second, second_public = generate_signing_key()
    stranger, stranger_public = generate_signing_key()
    left = roundtrip(_document(profile, key=author, cosigners=(first, second)))
    reordered = roundtrip(_document(profile, key=author, cosigners=(second, first)))
    report = compare_documents(left, reordered, expected_public_key=public,
                               require_cosigners=(first_public, second_public))
    assert report["ok"] and report["equal"] is True
    assert report["byte_equal"] is False
    assert report["signers_equal"] is True
    changed = roundtrip(_document(profile, key=author, cosigners=(first, stranger)))
    report = compare_documents(left, changed)
    assert report["ok"] and report["equal"] is False and report["signers_equal"] is False
    assert report["package_equal"] is True
    rejected = compare_documents(left, left, expected_public_key=public,
                                 require_cosigners=(first_public, stranger_public))
    assert rejected["ok"] is False and rejected["equal"] is None
    with pytest.raises(ValueError):
        compare_documents(left, left, require_cosigners=(first_public,))


@pytest.mark.parametrize("field,value", [("value", "00" * 64), ("algorithm", "unsupported")])
def test_corrupt_declared_cosignature_invalidates_comparison(profile, roundtrip, field, value):
    """An invalid declared co-signature is not ignored when no pin was requested."""
    author, _ = generate_signing_key()
    cosigner, _ = generate_signing_key()
    data = _document(profile, key=author, cosigners=(cosigner,))
    declaration = _manifest(data)
    declaration["cosignatures"][0][field] = value
    corrupt = roundtrip(_replace_entries(data, {MANIFEST_PART: json.dumps(declaration).encode()}))
    report = compare_documents(corrupt, corrupt)
    assert report["ok"] is False and report["equal"] is None


def test_randomized_valid_signature_values_are_ignored(profile, roundtrip):
    """Hybrid signature entropy changes bytes but not the verified signer identities."""
    author = generate_hybrid_signing_key()
    cosigner = generate_hybrid_signing_key()
    options = {"key": author.private_bytes, "cosigners": (cosigner.private_bytes,)}
    left = roundtrip(_document(profile, **options))
    right = roundtrip(_document(profile, **options))
    report = compare_documents(left, right, expected_public_key=author.public_bytes,
                               require_cosigners=(cosigner.public_bytes,))
    assert report["ok"] and report["equal"] is True
    assert report["byte_equal"] is False and report["signers_equal"] is True
    incomplete = compare_documents(left, right, expected_public_key=author.classical_pub)
    assert incomplete["ok"] is False and incomplete["equal"] is None
    assert incomplete["left"]["signature"]["authentic"] is False


def test_encrypted_same_plaintext_reports_stored_differences_without_decryption(profile, roundtrip):
    """No credentials are needed to compare stored ciphertext; plaintext stays unclaimed."""
    _, recipient = generate_recipient_key()
    plain = roundtrip(_document(profile))
    left = roundtrip(_document(profile, recipients=[recipient]))
    right = roundtrip(_document(profile, recipients=[recipient]))
    report = compare_documents(left, right)
    assert report["ok"] and report["equal"] is False
    assert report["package_equal"] is False
    item, = report["modules"]["changed"]
    assert "digest" in item["fields"]
    assert item["before"]["encrypted"] and item["after"]["encrypted"]
    assert report["left"]["payloads_verified"] is False
    assert report["right"]["payloads_verified"] is False
    transition = compare_documents(plain, left)["modules"]["changed"][0]
    assert {"digest", "encrypted", "sealing", "size"} <= set(transition["fields"])


def test_unreadable_bytes_are_failed_inspections_not_equal_documents(roundtrip):
    """Two unparseable inputs cannot compare equal merely because bytes match."""
    data = roundtrip(b"not an office package")
    report = compare_documents(data, data)
    assert report["ok"] is False and report["equal"] is None
    assert report["byte_equal"] is True and report["package_equal"] is None

def test_channel_transport_is_part_of_the_complete_record(profile, roundtrip):
    """Identical stored payload digests do not hide a changed transport channel."""
    left = roundtrip(_document(profile))
    if profile == "docx":
        right = DocxPlusBuilder().add_module("brief", "custom_xml", b"payload").build()
    else:
        right = OdtPlusBuilder().add_module("brief", b"payload", channel_id="odt_metadata").build()
    report = compare_documents(left, roundtrip(right))
    assert report["ok"] and report["equal"] is False
    item, = report["modules"]["changed"]
    assert {"channel", "location"} <= set(item["fields"])
    assert item["before"]["digest"] == item["after"]["digest"]


def test_primary_key_hex_representation_is_not_a_different_identity(profile, roundtrip):
    """Signing identity comparison uses complete key bytes, not hex letter case."""
    private, public = generate_signing_key()
    left = roundtrip(_document(profile, key=private))
    declaration = _manifest(left)
    declaration["signature"]["public_key"] = declaration["signature"]["public_key"].upper()
    right = roundtrip(_replace_entries(left, {MANIFEST_PART: json.dumps(declaration).encode()}))
    report = compare_documents(left, right, expected_public_key=public)
    assert report["ok"] and report["equal"] is True
    assert report["byte_equal"] is False and report["signers_equal"] is True


@pytest.mark.parametrize("field,value", [("value", "00" * 64), ("algorithm", "unsupported")])
def test_corrupt_primary_signature_invalidates_comparison(profile, roundtrip, field, value):
    """Invalid primary signatures cannot pass by comparison with identical corruption."""
    private, _ = generate_signing_key()
    original = _document(profile, key=private)
    declaration = _manifest(original)
    declaration["signature"][field] = value
    corrupt = roundtrip(_replace_entries(original, {MANIFEST_PART: json.dumps(declaration).encode()}))
    report = compare_documents(corrupt, corrupt)
    assert report["ok"] is False and report["equal"] is None

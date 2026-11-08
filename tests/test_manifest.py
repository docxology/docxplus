"""Intelligence manifest: canonicalisation, signing, part I/O."""

from __future__ import annotations

import pytest

from docxplus.channels.base import ChannelRecord
from docxplus.crypto import generate_signing_key, sign
from docxplus.manifest import Manifest, read_manifest, write_manifest
from docxplus.wordml import new_base_document


def _record(slot: str) -> ChannelRecord:
    return ChannelRecord(channel="custom_xml", slot=slot, size=3, digest="ab" * 32)


def test_add_and_lookup_slot():
    m = Manifest()
    m.add(_record("a"))
    assert m.slot("a").slot == "a"
    with pytest.raises(KeyError):
        m.slot("missing")


def test_duplicate_slot_rejected():
    m = Manifest()
    m.add(_record("a"))
    with pytest.raises(ValueError, match="duplicate manifest slot"):
        m.add(_record("a"))


def test_canonical_body_is_order_independent():
    m1 = Manifest()
    m1.add(_record("b"))
    m1.add(_record("a"))
    m2 = Manifest()
    m2.add(_record("a"))
    m2.add(_record("b"))
    assert m1.canonical_body() == m2.canonical_body()


def test_bytes_roundtrip():
    m = Manifest()
    m.add(_record("a"))
    parsed = Manifest.from_bytes(m.to_bytes())
    assert parsed.records[0].slot == "a"
    assert parsed.version == m.version


def test_sign_and_verify_manifest():
    priv, pub = generate_signing_key()
    m = Manifest()
    m.add(_record("a"))
    m.public_key = pub.hex()
    m.signature = sign(m.canonical_body(), priv).hex()
    assert m.is_signed()
    assert m.verify_signature() is True


def test_tampered_signed_manifest_fails_verify():
    priv, pub = generate_signing_key()
    m = Manifest()
    m.add(_record("a"))
    m.public_key = pub.hex()
    m.signature = sign(m.canonical_body(), priv).hex()
    m.add(_record("b"))  # body changed after signing
    assert m.verify_signature() is False


def test_unsigned_manifest_reports_unsigned():
    m = Manifest()
    m.add(_record("a"))
    assert m.is_signed() is False
    assert m.verify_signature() is False


def test_write_and_read_manifest_in_package():
    pkg = new_base_document(["x"])
    m = Manifest()
    m.add(_record("a"))
    write_manifest(pkg, m)
    # Idempotent replace.
    write_manifest(pkg, m)
    from docxplus.opc import read_package

    reparsed = read_package(pkg.to_bytes())
    loaded = read_manifest(reparsed)
    assert loaded is not None
    assert loaded.records[0].slot == "a"


def test_read_manifest_absent_returns_none():
    pkg = new_base_document(["x"])
    from docxplus.opc import read_package

    assert read_manifest(read_package(pkg.to_bytes())) is None


def test_duplicate_json_keys_are_rejected_at_every_object_depth():
    m = Manifest(records=[_record("a")])
    blob = m.to_bytes()
    for original, repeated in (
        (b'"version": "3.0"', b'"version": "3.0", "version": "3.0"'),
        (b'"slot": "a"', b'"slot": "a", "slot": "a"'),
        (b'"mode": "plain"', b'"mode": "plain", "mode": "plain"'),
    ):
        with pytest.raises(ValueError, match="duplicate manifest JSON key"):
            Manifest.from_bytes(blob.replace(original, repeated))


@pytest.mark.parametrize("mutation", [
    "extra_top", "missing_top", "extra_module", "missing_module",
    "wrong_encrypted", "unknown_mode", "extra_plain_metadata", "boolean_size",
    "bad_location", "extra_signature", "missing_algorithm", "duplicate_cosigner",
])
def test_exact_format3_schema_refuses_ambiguous_documents(mutation):
    import json

    doc = json.loads(Manifest(records=[_record("a")]).to_bytes())
    module = doc["modules"][0]
    if mutation == "extra_top":
        doc["unknown"] = 1
    elif mutation == "missing_top":
        del doc["surface_digest"]
    elif mutation == "extra_module":
        module["unknown"] = 1
    elif mutation == "missing_module":
        del module["payload_type"]
    elif mutation == "wrong_encrypted":
        module["encrypted"] = True
    elif mutation == "unknown_mode":
        module["sealing"] = {"mode": "decoy"}
    elif mutation == "extra_plain_metadata":
        module["sealing"]["k"] = 1
    elif mutation == "boolean_size":
        module["size"] = True
    elif mutation == "bad_location":
        module["location"] = {"parts": "part.xml"}
    elif mutation == "extra_signature":
        doc["signature"]["unknown"] = ""
    elif mutation == "missing_algorithm":
        del doc["signature"]["algorithm"]
    else:
        _, public = generate_signing_key()
        entry = {"public_key": public.hex(), "algorithm": "ed25519", "value": "00"}
        doc["cosignatures"] = [entry, dict(entry)]
    with pytest.raises(ValueError):
        Manifest.from_bytes(json.dumps(doc).encode())


@pytest.mark.parametrize("mutation", [
    "missing_commitments", "missing_checksum", "false_checksum", "boolean_k",
    "zero_k", "excess_n", "wrong_count", "duplicate_digest", "bad_digest", "old_vss",
])
def test_threshold_schema_requires_exact_signed_commitments(mutation):
    import json

    record = _record("a")
    record.encrypted = True
    record.sealing = {
        "mode": "threshold", "k": 2, "n": 3, "checksummed_shares": True,
        "share_digests": ["01" * 32, "02" * 32, "03" * 32],
    }
    doc = json.loads(Manifest(records=[record]).to_bytes())
    sealing = doc["modules"][0]["sealing"]
    if mutation == "missing_commitments":
        del sealing["share_digests"]
    elif mutation == "missing_checksum":
        del sealing["checksummed_shares"]
    elif mutation == "false_checksum":
        sealing["checksummed_shares"] = False
    elif mutation == "boolean_k":
        sealing["k"] = True
    elif mutation == "zero_k":
        sealing["k"] = 0
    elif mutation == "excess_n":
        sealing["n"] = 255
    elif mutation == "wrong_count":
        sealing["share_digests"].pop()
    elif mutation == "duplicate_digest":
        sealing["share_digests"][1] = sealing["share_digests"][0]
    elif mutation == "bad_digest":
        sealing["share_digests"][0] = "zz" * 32
    else:
        sealing["vss"] = True
    with pytest.raises(ValueError):
        Manifest.from_bytes(json.dumps(doc).encode())


def test_threshold_commitments_roundtrip_and_bind_signature():
    record = _record("a")
    record.encrypted = True
    record.sealing = {
        "mode": "threshold", "k": 2, "n": 3, "checksummed_shares": True,
        "share_digests": ["01" * 32, "02" * 32, "03" * 32],
    }
    private, public = generate_signing_key()
    manifest = Manifest(records=[record], public_key=public.hex())
    manifest.signature = sign(manifest.canonical_body(), private).hex()
    loaded = Manifest.from_bytes(manifest.to_bytes())
    assert loaded.verify_signature()
    loaded.records[0].sealing["share_digests"][0] = "04" * 32
    assert not loaded.verify_signature()

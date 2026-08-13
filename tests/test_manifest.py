"""Intelligence manifest: canonicalisation, signing, part I/O."""

from __future__ import annotations

import pytest

from channels.base import ChannelRecord
from crypto import generate_signing_key, sign
from manifest import Manifest, read_manifest, write_manifest
from wordml import new_base_document


def _record(slot: str) -> ChannelRecord:
    return ChannelRecord(channel="custom_xml", slot=slot, size=3, digest="abc")


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
    from opc import read_package

    reparsed = read_package(pkg.to_bytes())
    loaded = read_manifest(reparsed)
    assert loaded is not None
    assert loaded.records[0].slot == "a"


def test_read_manifest_absent_returns_none():
    pkg = new_base_document(["x"])
    from opc import read_package

    assert read_manifest(read_package(pkg.to_bytes())) is None

"""Tests for the cryptographic transparency log."""

import pytest

from provenance import verify_inclusion
from transparency import TransparencyLog


def test_transparency_log_append_and_verify_chain():
    log = TransparencyLog()
    att1 = {"output_digest": "abcdef123456", "toolchain": {"python": "3.12.0"}}
    att2 = {"output_digest": "789012fedcba", "toolchain": {"python": "3.12.1"}}

    e1 = log.append(att1, {"author": "Alice"})
    e2 = log.append(att2, {"author": "Bob"})

    assert e1.index == 0
    assert e2.index == 1
    assert e2.prev_hash == e1.entry_hash()
    assert log.verify_chain() is True


def test_transparency_merkle_inclusion_proof():
    log = TransparencyLog()
    for i in range(5):
        log.append({"output_digest": f"digest_{i}", "toolchain": {}})

    root = log.merkle_tree_root()
    assert root != ""

    # Test inclusion proof for entry 2
    proof = log.inclusion_proof(2)
    assert proof["root"] == root
    assert verify_inclusion(proof) is True


def test_transparency_log_tamper_detection():
    log = TransparencyLog()
    log.append({"output_digest": "orig1", "toolchain": {}})
    log.append({"output_digest": "orig2", "toolchain": {}})

    serialized = log.to_json()
    # Tamper with the first entry's attestation_digest
    tampered_json = serialized.replace("orig1", "tampered1")

    with pytest.raises(ValueError, match="chain integrity"):
        TransparencyLog.from_json(tampered_json)

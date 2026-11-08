"""Tests for the cryptographic transparency log."""

import json

import pytest

from docxplus import transparency as transparency_module
from docxplus.provenance import verify_inclusion
from docxplus.transparency import LogEntry, TransparencyLog


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
    assert verify_inclusion(proof, log.merkle_tree_root()) is True


def test_transparency_log_tamper_detection():
    log = TransparencyLog()
    log.append({"output_digest": "orig1", "toolchain": {}})
    log.append({"output_digest": "orig2", "toolchain": {}})

    serialized = json.loads(log.to_json())
    serialized[0]["attestation_digest"] = "0" * 64
    tampered_json = json.dumps(serialized)

    with pytest.raises(ValueError, match="chain integrity"):
        TransparencyLog.from_json(tampered_json)


# -- signed tree head: the trust anchor over the chain ------------------------


def _log_with(n: int) -> TransparencyLog:
    log = TransparencyLog()
    for i in range(n):
        log.append({"output_digest": f"digest_{i}", "toolchain": {"python": "3.12"}}, timestamp=1000 + i)
    return log


def test_signed_tree_head_verifies_against_its_own_log():
    from docxplus import crypto

    log = _log_with(4)
    priv, pub = crypto.generate_signing_key()
    sth = log.signed_tree_head(priv, timestamp=5000)

    assert sth["log_size"] == 4
    assert sth["root_hash"] == log.merkle_tree_root()
    assert log.verify_signed_tree_head(sth) is True
    assert log.verify_signed_tree_head(sth, expected_public_key=pub) is True


def test_signed_tree_head_rejects_a_different_signer():
    """Pinning is the whole point: an authentic-but-unexpected signer must fail."""
    from docxplus import crypto

    log = _log_with(3)
    priv, _pub = crypto.generate_signing_key()
    _other_priv, other_pub = crypto.generate_signing_key()
    sth = log.signed_tree_head(priv, timestamp=1)

    assert log.verify_signed_tree_head(sth) is True
    assert log.verify_signed_tree_head(sth, expected_public_key=other_pub) is False


def test_signed_tree_head_does_not_validate_a_longer_log():
    """An old STH must not describe a log that has since grown (truncation replay)."""
    from docxplus import crypto

    log = _log_with(3)
    priv, pub = crypto.generate_signing_key()
    sth = log.signed_tree_head(priv, timestamp=1)
    assert log.verify_signed_tree_head(sth, expected_public_key=pub) is True

    log.append({"output_digest": "digest_new", "toolchain": {}}, timestamp=2)
    assert log.verify_signed_tree_head(sth, expected_public_key=pub) is False


def test_signed_tree_head_detects_in_place_tip_edit():
    """verify_chain cannot see a tampered tip; the STH must.

    Nothing in the chain references the last entry's hash, so editing it in place
    leaves the chain perfectly self-consistent. Only the root commitment catches it.
    """
    from docxplus import crypto

    log = _log_with(3)
    priv, pub = crypto.generate_signing_key()
    sth = log.signed_tree_head(priv, timestamp=1)

    tampered = TransparencyLog(list(log.entries[:-1]))
    tip = log.entries[-1]
    tampered.entries.append(
        LogEntry(
            index=tip.index,
            timestamp=tip.timestamp,
            attestation_digest="forged_result",
            toolchain_hash=tip.toolchain_hash,
            prev_hash=tip.prev_hash,
            metadata=dict(tip.metadata),
        )
    )
    # The chain check is blind to this edit ...
    assert tampered.verify_chain() is True
    # ... and the signed root is not.
    assert tampered.verify_signed_tree_head(sth, expected_public_key=pub) is False


def test_signed_tree_head_rejects_malformed_input():
    from docxplus import crypto

    log = _log_with(2)
    priv, _pub = crypto.generate_signing_key()
    sth = log.signed_tree_head(priv, timestamp=1)

    for bad in (
        {},
        {**sth, "signature": "not-hex"},
        {**sth, "public_key": "zz"},
        {**sth, "log_size": "many"},
        {k: v for k, v in sth.items() if k != "signature"},
    ):
        assert log.verify_signed_tree_head(bad) is False


def test_signed_tree_head_signature_is_domain_separated():
    """An STH signature must not be replayable as a bare-body signature."""
    from docxplus import crypto

    log = _log_with(2)
    priv, pub = crypto.generate_signing_key()
    sth = log.signed_tree_head(priv, timestamp=7)

    undomained = json.dumps(
        {"log_size": 2, "root_hash": sth["root_hash"], "timestamp": 7},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert crypto.verify(undomained, bytes.fromhex(sth["signature"]), pub) is False
    assert crypto.verify(
        transparency_module.STH_DOMAIN + undomained, bytes.fromhex(sth["signature"]), pub
    ) is True


def test_from_json_rejects_a_published_hash_that_lies():
    """`to_dict` publishes a `hash`; a log whose published hash disagrees is invalid."""
    log = _log_with(2)
    raw = json.loads(log.to_json())
    raw[-1]["hash"] = "0" * 64  # tip hash nothing else references
    with pytest.raises(ValueError, match="does not match its contents"):
        TransparencyLog.from_json(json.dumps(raw))


def test_from_json_roundtrips_a_well_formed_log():
    log = _log_with(4)
    restored = TransparencyLog.from_json(log.to_json())
    assert len(restored.entries) == 4
    assert restored.verify_chain() is True
    assert restored.merkle_tree_root() == log.merkle_tree_root()


def test_transparency_empty_log_and_errors():
    """Cover empty TransparencyLog methods and error conditions."""
    from docxplus import crypto

    log = TransparencyLog()
    assert log.verify_chain() is True
    assert log.merkle_tree_root() == ""
    proof = log.consistency_proof()
    assert proof["old_size"] == 0
    assert proof["prefix_hashes"] == []

    priv, pub = crypto.generate_signing_key()
    sth = log.signed_tree_head(priv, timestamp=10)
    assert log.verify_signed_tree_head(sth, expected_public_key=pub) is True

    # Bad proof in verify_consistency
    assert log.verify_consistency({"bad": "proof"}) is False




# -- append-only consistency --------------------------------------------------
#
# A signed tree head proves a log is authentic at one moment; it cannot show that
# yesterday's log and today's are the same log. An operator who drops an entry and
# re-signs produces a perfectly valid newer head, so "append-only" was a promise
# rather than a property until this existed.


def _log(n, start=0):
    log = TransparencyLog()
    for i in range(start, start + n):
        log.append({"output_digest": f"d{i}", "toolchain": {}}, timestamp=i)
    return log


def test_an_honest_extension_verifies():
    old = _log(3)
    proof = old.consistency_proof()
    new = TransparencyLog(list(old.entries))
    for i in range(3, 6):
        new.append({"output_digest": f"d{i}", "toolchain": {}}, timestamp=i)
    assert new.verify_consistency(proof) is True


def test_a_log_is_consistent_with_itself():
    log = _log(4)
    assert log.verify_consistency(log.consistency_proof()) is True


def test_rewriting_a_retained_entry_is_caught():
    old = _log(3)
    proof = old.consistency_proof()
    tampered = TransparencyLog(list(old.entries))
    e = tampered.entries[1]
    tampered.entries[1] = LogEntry(
        e.index, e.timestamp, "FORGED", e.toolchain_hash, e.prev_hash, e.metadata
    )
    assert tampered.verify_consistency(proof) is False


def test_truncation_is_caught():
    """The event the check exists for: an operator silently dropping an entry."""
    old = _log(5)
    proof = old.consistency_proof()
    assert TransparencyLog(list(old.entries[:3])).verify_consistency(proof) is False


def test_an_unrelated_log_is_not_an_extension():
    proof = _log(3).consistency_proof()
    assert _log(3, start=100).verify_consistency(proof) is False
    assert TransparencyLog().verify_consistency(proof) is False


def test_malformed_proofs_fail_closed():
    log = _log(3)
    good = log.consistency_proof()
    for bad in ({}, {**good, "old_size": "many"}, {**good, "prefix_hashes": []},
                {**good, "old_root": "00" * 32}):
        assert log.verify_consistency(bad) is False


def test_consistency_proof_rejects_an_out_of_range_size():
    log = _log(2)
    with pytest.raises(ValueError, match="outside"):
        log.consistency_proof(5)


def test_proof_does_not_commit_to_a_future_size():
    """The proof describes the state committed to, not the log that verifies it."""
    proof = _log(3).consistency_proof()
    assert "new_size" not in proof
    assert proof["old_size"] == 3


def test_signed_tree_head_uses_the_portable_hybrid_identity():
    """An STH made with a portable key requires the full pinned hybrid signer."""
    from docxplus import crypto

    log = _log_with(3)
    key = crypto.generate_hybrid_signing_key()
    loaded = crypto.HybridKeyPair.from_private_bytes(key.private_bytes)
    sth = log.signed_tree_head(loaded.private_bytes, timestamp=123)
    sth = json.loads(json.dumps(sth))
    assert bytes.fromhex(sth["public_key"]) == key.public_bytes
    assert log.verify_signed_tree_head(sth, expected_public_key=key.public_bytes)
    assert not log.verify_signed_tree_head(sth, expected_public_key=key.classical_pub)
    other = crypto.generate_hybrid_signing_key()
    assert not log.verify_signed_tree_head(sth, expected_public_key=other.public_bytes)
    # A valid classical half cannot launder a damaged ML-DSA signature.
    signature = bytearray.fromhex(sth["signature"])
    signature[68] ^= 1
    assert not log.verify_signed_tree_head(
        {**sth, "signature": signature.hex()}, expected_public_key=key.public_bytes
    )
    assert not log.verify_signed_tree_head({**sth, "timestamp": 124}, expected_public_key=key.public_bytes)
    assert not log.verify_signed_tree_head(
        {**sth, "public_key": (key.public_bytes + b"x").hex()},
        expected_public_key=key.public_bytes,
    )


def test_tree_head_refuses_recipient_or_legacy_simulated_private_keys():
    """Signing never synthesizes an identity from a wrong-family key file."""
    from docxplus import crypto

    log = _log_with(1)
    recipient = crypto.generate_hybrid_recipient_key()
    with pytest.raises(ValueError):
        log.signed_tree_head(recipient.private_bytes, timestamp=1)
    with pytest.raises(ValueError):
        log.signed_tree_head(recipient.classical_priv + b"x" * 32, timestamp=1)


def test_log_commits_the_complete_recipe_and_source_not_only_its_output():
    """An unchanged result cannot launder a different recipe under an old signed head."""
    from docxplus import crypto

    claim = {"output_digest": "same-output", "command": ["{python}", "original.py"],
             "source_digest": "original-source", "outputs": ["result"], "toolchain": {}}
    original = TransparencyLog()
    original.append(claim, timestamp=1)
    private, public = crypto.generate_signing_key()
    head = original.signed_tree_head(private, timestamp=2)
    for altered in ({**claim, "command": ["{python}", "other.py"]},
                    {**claim, "source_digest": "other-source"}):
        replacement = TransparencyLog()
        replacement.append(altered, timestamp=1)
        assert not replacement.verify_signed_tree_head(head, expected_public_key=public)
    reordered = dict(reversed(list(claim.items())))
    assert transparency_module.attestation_digest(reordered) == transparency_module.attestation_digest(claim)

"""Portable genuine hybrid keys, strict family dispatch and envelope boundaries."""

from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from docxplus import crypto


@pytest.mark.parametrize("factory,suite,pq_seed_size,pq_public_size", [
    (crypto.generate_hybrid_recipient_key, 1, 64, 1184),
    (crypto.generate_hybrid_signing_key, 2, 32, 1952),
])
def test_portable_private_key_roundtrip_and_checked_halves(factory, suite, pq_seed_size, pq_public_size):
    """Each native seed family survives serialization with its complete identity."""
    original = factory()
    encoded = original.private_bytes
    assert encoded[:6] == b"DXHK\x01" + bytes([suite])
    assert len(encoded) == 6 + 32 + 32 + pq_seed_size + pq_public_size
    loaded = crypto.HybridKeyPair.from_private_bytes(encoded)
    assert loaded == original
    assert loaded.private_bytes == encoded
    assert loaded.public_bytes == original.public_bytes
    provider = MLKEM768PrivateKey if suite == 1 else MLDSA65PrivateKey
    assert provider.from_seed_bytes(loaded.pq_priv).public_key().public_bytes_raw() == loaded.pq_pub

    # Corrupt non-clamped classical seed bits, each public half, or the PQ seed.
    for index in (14, 38, 70, 70 + pq_seed_size, len(encoded) - 1):
        changed = bytearray(encoded)
        changed[index] ^= 1
        with pytest.raises(ValueError):
            crypto.HybridKeyPair.from_private_bytes(bytes(changed))
    for malformed in (
        b"", encoded[:5], encoded[:-1], encoded + b"trailing",
        b"DXHK\x02" + encoded[5:], encoded[:5] + b"\0" + encoded[6:],
        encoded[:5] + bytes([3 - suite]) + encoded[6:],
        original.classical_priv + original.pq_priv,
        original.classical_priv + b"x" * 32,
    ):
        with pytest.raises(ValueError):
            crypto.HybridKeyPair.from_private_bytes(malformed)
    other = factory()
    with pytest.raises(ValueError, match="mismatch"):
        _ = replace(original, pq_pub=other.pq_pub).private_bytes
    with pytest.raises(ValueError, match="mismatch"):
        _ = replace(original, classical_pub=other.classical_pub).private_bytes


def test_existing_signing_api_dispatches_without_classical_fallback():
    """Portable key files sign with both native algorithms, not just Ed25519."""
    data = b"portable signing identity"
    classical_private, classical_public = crypto.generate_signing_key()
    assert crypto.signing_public_key(classical_private) == classical_public
    assert crypto.signing_algorithm(classical_public) == "ed25519"
    assert crypto.verify(data, crypto.sign(data, classical_private), classical_public)

    key = crypto.generate_hybrid_signing_key()
    private = crypto.HybridKeyPair.from_private_bytes(key.private_bytes).private_bytes
    assert crypto.signing_public_key(private) == key.public_bytes
    assert crypto.signing_algorithm(key.public_bytes) == "ed25519+ml-dsa-65"
    signature = crypto.sign(data, private)
    assert crypto.verify(data, signature, key.public_bytes)
    # Verify both halves independently with the provider.
    message = b"docxplus/hybrid-signature/v1\0" + data
    Ed25519PublicKey.from_public_bytes(key.classical_pub).verify(signature[2:66], message)
    MLDSA65PublicKey.from_public_bytes(key.pq_pub).verify(signature[68:], message)
    with pytest.raises(InvalidSignature):
        MLDSA65PublicKey.from_public_bytes(key.pq_pub).verify(signature[68:], data)
    assert not crypto.verify(data, signature[2:66], key.public_bytes)
    assert not crypto.verify(message, signature, key.classical_pub)
    assert not crypto.verify(data, crypto.sign(data, key.classical_priv), key.public_bytes)
    # The old simulation's valid classical half and arbitrary PQ binding refuse.
    old = b"\0@" + crypto.sign(data, key.classical_priv) + b"\0@" + b"x" * 64
    simulated_public = key.classical_pub + b"\0 " + b"x" * 32
    assert not crypto.verify(data, old, key.public_bytes)
    assert not crypto.verify(data, old, simulated_public)
    for public in (b"", key.public_bytes + b"x", key.public_bytes[:-1], simulated_public):
        with pytest.raises(ValueError):
            crypto.signing_algorithm(public)
        assert not crypto.verify(data, signature, public)
    recipient = crypto.generate_hybrid_recipient_key()
    with pytest.raises(ValueError, match="family"):
        crypto.sign(data, recipient.private_bytes)
    with pytest.raises(ValueError, match="family"):
        crypto.signing_public_key(recipient.private_bytes)
    with pytest.raises(ValueError):
        crypto.signing_algorithm(recipient.public_bytes)
    with pytest.raises(ValueError):
        crypto.sign(data, key.classical_priv + key.pq_priv)


def test_hybrid_signature_rejects_a_valid_pq_signature_for_another_message():
    """A correctly sized provider-valid PQ signature must bind this exact message."""
    key = crypto.generate_hybrid_signing_key()
    signature = crypto.sign(b"one", key.private_bytes)
    other_pq = MLDSA65PrivateKey.from_seed_bytes(key.pq_priv).sign(
        b"docxplus/hybrid-signature/v1\0two"
    )
    assert not crypto.verify(b"one", signature[:68] + other_pq, key.public_bytes)
    for malformed in (signature[:66] + b"\0\0", signature + b"x", signature[:-1]):
        assert not crypto.verify(b"one", malformed, key.public_bytes)


def test_multi_recipient_api_dispatches_portable_hybrid_keys_and_padding():
    """The ordinary recipient APIs actually consume portable hybrid key files."""
    keys = [crypto.generate_hybrid_recipient_key() for _ in range(2)]
    payload, aad = b"portable recipient payload", b"slot"
    envelope = crypto.seal_multi(payload, [key.public_bytes for key in keys], aad=aad, pad_to=4)
    assert envelope[:4] == b"DXE3"
    count_offset = 8 + int.from_bytes(envelope[4:8], "big")
    assert int.from_bytes(envelope[count_offset:count_offset + 2], "big") == 4
    for key in keys:
        loaded = crypto.HybridKeyPair.from_private_bytes(key.private_bytes)
        assert crypto.unseal_multi(envelope, loaded.private_bytes, aad=aad) == payload
        with pytest.raises(ValueError):
            crypto.unseal_multi(envelope, loaded.private_bytes, aad=b"other-slot")
    stranger = crypto.generate_hybrid_recipient_key()
    with pytest.raises(ValueError):
        crypto.unseal_multi(envelope, stranger.private_bytes, aad=aad)
    with pytest.raises(ValueError):
        crypto.unseal_multi(envelope, keys[0].classical_priv, aad=aad)
    signing = crypto.generate_hybrid_signing_key()
    with pytest.raises(ValueError, match="family"):
        crypto.unseal_multi(envelope, signing.private_bytes, aad=aad)
    with pytest.raises(ValueError, match="family"):
        crypto.unseal_hybrid(envelope, signing, aad=aad)
    classical_private, classical_public = crypto.generate_recipient_key()
    classical = crypto.seal_multi(payload, [classical_public], aad=aad)
    assert classical[:4] == b"DXE2"
    assert crypto.unseal_multi(classical, classical_private, aad=aad) == payload
    with pytest.raises(ValueError):
        crypto.unseal_multi(classical, keys[0].private_bytes, aad=aad)


@pytest.mark.parametrize("pad_to", [-1, 65536, 1.5, True])
def test_recipient_padding_bounds_are_checked(pad_to):
    """Impossible padding is rejected as a parameter error for both key families."""
    for public in (crypto.generate_recipient_key()[1], crypto.generate_hybrid_recipient_key().public_bytes):
        with pytest.raises(ValueError):
            crypto.seal_multi(b"payload", [public], pad_to=pad_to)


def test_multi_recipient_rejects_mixed_malformed_and_simulated_families():
    classical = crypto.generate_recipient_key()[1]
    hybrid = crypto.generate_hybrid_recipient_key()
    signing = crypto.generate_hybrid_signing_key()
    simulated = hybrid.classical_pub + b"\0 " + b"p" * 32
    for recipients in (
        [classical, hybrid.public_bytes], [hybrid.public_bytes, classical],
        [hybrid.public_bytes, signing.public_bytes], [signing.public_bytes],
        [hybrid.public_bytes + b"x"], [hybrid.public_bytes[:-1]], [simulated],
    ):
        with pytest.raises(ValueError):
            crypto.seal_multi(b"payload", recipients)
    # Provider refuses a low-order classical recipient, not a success-shaped wrap.
    with pytest.raises(ValueError):
        crypto.seal_multi(b"payload", [b"\0" * 32])
    with pytest.raises(ValueError):
        crypto.seal_multi(b"payload", [b"\0" * 32 + hybrid.public_bytes[32:]])


@pytest.mark.parametrize("hybrid", [False, True])
def test_recipient_reader_validates_every_slot_and_exact_envelope(hybrid):
    """A valid first recipient cannot conceal malformed later bytes or slots."""
    if hybrid:
        key = crypto.generate_hybrid_recipient_key()
        private, public = key.private_bytes, key.public_bytes
    else:
        private, public = crypto.generate_recipient_key()
    envelope = crypto.seal_multi(b"payload", [public])
    body_size = int.from_bytes(envelope[4:8], "big")
    count_offset = 8 + body_size
    for malformed in (
        envelope + b"trailing", envelope[:count_offset] + b"\0\0",
        envelope[:4] + b"\0" * 4 + envelope[8:],
        envelope[:count_offset] + b"\0\2" + envelope[count_offset + 2:] + b"\0" * 4,
    ):
        with pytest.raises(ValueError):
            crypto.unseal_multi(malformed, private)
    for cut in (0, 3, 4, 7, 8, count_offset - 1, count_offset + 1, len(envelope) - 1):
        with pytest.raises(ValueError):
            crypto.unseal_multi(envelope[:cut], private)
    if hybrid:
        # Exact framing is also required inside every nested DXE3 slot.
        slot_offset = count_offset + 2
        slot_size = int.from_bytes(envelope[slot_offset:slot_offset + 4], "big")
        for offset in (slot_offset, slot_offset + 4, slot_offset + 4 + 2 + 32):
            malformed = bytearray(envelope)
            malformed[offset] ^= 1
            with pytest.raises(ValueError):
                crypto.unseal_multi(bytes(malformed), private)
        assert slot_size > 1088
    else:
        # Valid X25519 point parsing remains independent of envelope acceptance.
        X25519PublicKey.from_public_bytes(public)


def test_real_kem_ciphertext_is_required_even_with_unchanged_classical_exchange():
    """ML-KEM implicit rejection yields a different key and cannot open GCM."""
    key = crypto.generate_hybrid_recipient_key()
    envelope = crypto.seal_multi(b"both private agreements", [key.public_bytes], aad=b"slot")
    body_size = int.from_bytes(envelope[4:8], "big")
    # body, count(2), slot-size(4), header-size(2), X25519 point(32), PQ-size(2)
    pq_offset = 8 + body_size + 2 + 4 + 2 + 32 + 2
    for index in (pq_offset, pq_offset + 1087):
        damaged = bytearray(envelope)
        damaged[index] ^= 1
        with pytest.raises(ValueError):
            crypto.unseal_multi(bytes(damaged), key.private_bytes, aad=b"slot")

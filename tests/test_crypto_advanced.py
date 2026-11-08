"""X25519 multi-recipient sealing and the content-key symmetric layer."""

from __future__ import annotations

import pytest

from docxplus import crypto
from docxplus.crypto import (
    KEY_BYTES,
    decrypt_with_key,
    encrypt_with_key,
    generate_recipient_key,
    seal_multi,
    unseal_multi,
)


def test_content_key_roundtrip():
    key = b"k" * KEY_BYTES
    blob = encrypt_with_key(b"payload", key)
    assert decrypt_with_key(blob, key) == b"payload"


def test_content_key_wrong_length():
    with pytest.raises(ValueError):
        encrypt_with_key(b"x", b"short")


def test_multi_recipient_each_can_open():
    priv_a, pub_a = generate_recipient_key()
    priv_b, pub_b = generate_recipient_key()
    envelope = seal_multi(b"referee packet", [pub_a, pub_b])
    assert unseal_multi(envelope, priv_a) == b"referee packet"
    assert unseal_multi(envelope, priv_b) == b"referee packet"


def test_multi_recipient_stranger_cannot_open():
    _, pub_a = generate_recipient_key()
    priv_x, _ = generate_recipient_key()
    envelope = seal_multi(b"secret", [pub_a])
    with pytest.raises(ValueError, match="no recipient slot"):
        unseal_multi(envelope, priv_x)


def test_seal_requires_recipient():
    with pytest.raises(ValueError, match="at least one recipient"):
        seal_multi(b"x", [])


def test_bad_envelope_magic():
    with pytest.raises(ValueError, match="DXE2"):
        unseal_multi(b"nope" + b"\x00" * 40, generate_recipient_key()[0])


def test_single_content_encryption_shared_across_recipients():
    # Three recipients, one document; body encrypted once, key wrapped thrice.
    keys = [generate_recipient_key() for _ in range(3)]
    envelope = seal_multi(b"one body many keys", [pub for _, pub in keys])
    for priv, _ in keys:
        assert unseal_multi(envelope, priv) == b"one body many keys"


# -- v0.6.2: envelope parsing and KDF work-factor ceilings --------------------


def test_truncated_envelopes_raise_valueerror_not_indexerror():
    """A malformed envelope must fail as a typed parse error, not an IndexError."""
    for blob in (
        b"DXE1",                       # magic only
        b"DXE1\x02",                   # kdf id, nothing more
        b"DXE1\x02\x10",               # declares a 16-byte salt that is not there
        b"DXE1\x02\x10" + b"A" * 16,   # salt present, nonce length missing
    ):
        with pytest.raises(ValueError, match="truncated|bad magic"):
            crypto.EncryptedPayload.from_bytes(blob)


def test_envelope_rejects_a_length_field_that_overruns_the_buffer():
    """A header declaring 200 bytes of salt over 4 bytes must not parse."""
    blob = (
        b"DXE1" + bytes([crypto.KDF_SCRYPT]) + bytes([200]) + b"A" * 4
        + b"\x0c" + b"B" * 4 + b"\x03" + bytes([15, 8, 1])
    )
    with pytest.raises(ValueError, match="truncated"):
        crypto.EncryptedPayload.from_bytes(blob)


def _envelope(kdf_id: int, params: bytes) -> bytes:
    return (
        b"DXE1" + bytes([kdf_id]) + bytes([16]) + b"S" * 16
        + bytes([12]) + b"N" * 12 + bytes([len(params)]) + params + b"c" * 16
    )


def test_scrypt_memory_ceiling_bounds_the_product_not_just_n():
    """N=2^21,r=2 needs512MiB but stays within the separate CPU-work ceiling."""
    hostile = _envelope(crypto.KDF_SCRYPT, bytes([crypto.MAX_SCRYPT_N_LOG2, 2, 1]))
    with pytest.raises(ValueError):
        crypto.validate_password_envelope(hostile)
    with pytest.raises(ValueError):
        crypto.decrypt(hostile, "password")


def test_hybrid_post_quantum_crypto_suite():
    """Verify hybrid dual-signing and hybrid KEM multi-recipient sealing (DXE3)."""
    # Signing
    sign_kp = crypto.generate_hybrid_signing_key()
    data = b"evidence and reproducibility"
    sig = crypto.hybrid_sign(data, sign_kp)
    assert crypto.hybrid_verify(data, sig, sign_kp.public_bytes)
    assert not crypto.hybrid_verify(b"tampered", sig, sign_kp.public_bytes)
    assert not crypto.hybrid_verify(data, sig, b"short_pub")
    assert not crypto.hybrid_verify(data, b"short_sig", sign_kp.public_bytes)

    # Multi-recipient hybrid KEM (DXE3)
    recip_kp1 = crypto.generate_hybrid_recipient_key()
    recip_kp2 = crypto.generate_hybrid_recipient_key()
    stranger = crypto.generate_hybrid_recipient_key()

    plaintext = b"top secret quantum-resistant payload"
    envelope = crypto.seal_hybrid(plaintext, [recip_kp1.public_bytes, recip_kp2.public_bytes], aad=b"pq_slot", pad_to=4)
    assert envelope.startswith(b"DXE3")

    # Both recipients can open
    assert crypto.unseal_hybrid(envelope, recip_kp1, aad=b"pq_slot") == plaintext
    assert crypto.unseal_hybrid(envelope, recip_kp2, aad=b"pq_slot") == plaintext

    # Stranger cannot open
    with pytest.raises(ValueError, match="no hybrid recipient slot"):
        crypto.unseal_hybrid(envelope, stranger, aad=b"pq_slot")

    # Error branches on seal/unseal hybrid
    with pytest.raises(ValueError, match="at least one recipient"):
        crypto.seal_hybrid(plaintext, [])
    with pytest.raises(ValueError, match="below recipient count"):
        crypto.seal_hybrid(plaintext, [recip_kp1.public_bytes, recip_kp2.public_bytes], pad_to=1)
    with pytest.raises(ValueError, match="bad magic|not a DXE3"):
        crypto.unseal_hybrid(b"DXE2" + envelope[4:], recip_kp1)
    with pytest.raises(ValueError, match="truncated"):
        crypto.unseal_hybrid(envelope[:12], recip_kp1)


def test_crypto_direct_error_branches():
    """Cover edge-case parameter checks and error paths in crypto module."""
    with pytest.raises(ValueError, match="password must be non-empty"):
        crypto.derive_key("", b"salt")
    with pytest.raises(ValueError, match="password must be non-empty"):
        crypto._derive("", b"salt", crypto.KDF_SCRYPT, bytes([15, 8, 1]))
    with pytest.raises(ValueError, match="unknown KDF id"):
        crypto._derive("pw", b"salt", 999, b"params")
    with pytest.raises(ValueError, match="unknown KDF"):
        crypto._kdf_params("invalid_kdf")
    with pytest.raises(ValueError, match="content key must be 32 bytes"):
        crypto.encrypt_with_key(b"data", b"short_key")


def test_hybrid_signature_requires_both_real_signatures():
    """A valid Ed25519 signature must not launder a damaged or replaced PQ signature."""
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

    key = crypto.generate_hybrid_signing_key()
    other = crypto.generate_hybrid_signing_key()
    data = b"two independent signing keys"
    signature = crypto.hybrid_sign(data, key)
    classical_size = int.from_bytes(signature[:2], "big")
    pq_offset = 2 + classical_size + 2
    # Independent provider verification, not just a round trip through our verifier.
    MLDSA65PublicKey.from_public_bytes(key.pq_pub).verify(
        signature[pq_offset:], b"docxplus/hybrid-signature/v1\0" + data
    )
    for index in (2, pq_offset, len(signature) - 1):
        damaged = bytearray(signature)
        damaged[index] ^= 1
        assert not crypto.hybrid_verify(data, bytes(damaged), key.public_bytes)
    substituted = crypto.HybridKeyPair(
        key.classical_priv, key.classical_pub, other.pq_priv, other.pq_pub
    )
    assert not crypto.hybrid_verify(data, signature, substituted.public_bytes)
    for malformed in (signature[:pq_offset], signature + b"trailing"):
        assert not crypto.hybrid_verify(data, malformed, key.public_bytes)
    assert not crypto.hybrid_verify(data, signature, key.public_bytes + b"trailing")


def test_hybrid_kem_requires_both_private_keys_and_exact_framing():
    """Public PQ material or the wrong private seed cannot open a genuine DXE3 slot."""
    key = crypto.generate_hybrid_recipient_key()
    other = crypto.generate_hybrid_recipient_key()
    payload = b"both key agreements are necessary"
    envelope = crypto.seal_hybrid(payload, [key.public_bytes], aad=b"slot")
    assert crypto.unseal_hybrid(envelope, key, aad=b"slot") == payload
    for substituted in (
        crypto.HybridKeyPair(key.classical_priv, key.classical_pub, other.pq_priv, key.pq_pub),
        crypto.HybridKeyPair(key.classical_priv, key.classical_pub, other.pq_priv, other.pq_pub),
        crypto.HybridKeyPair(other.classical_priv, other.classical_pub, key.pq_priv, key.pq_pub),
    ):
        with pytest.raises(ValueError):
            crypto.unseal_hybrid(envelope, substituted, aad=b"slot")
    with pytest.raises(ValueError):
        crypto.unseal_hybrid(envelope, key, aad=b"wrong-slot")
    with pytest.raises(ValueError, match="trailing"):
        crypto.unseal_hybrid(envelope + b"trailing", key, aad=b"slot")
    simulated = key.classical_pub + (32).to_bytes(2, "big") + b"x" * 32
    with pytest.raises(ValueError, match="malformed hybrid public key"):
        crypto.seal_hybrid(payload, [simulated])



def test_hybrid_kem_interoperates_with_independent_native_provider_operations():
    """Both directions must use native ML-KEM secrets and the documented HKDF transcript."""
    import os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.mlkem import (
        MLKEM768PrivateKey,
        MLKEM768PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    key = crypto.generate_hybrid_recipient_key()
    plaintext, aad = b"independent native KEM interoperability", b"context"
    envelope = crypto.seal_hybrid(plaintext, [key.public_bytes], aad=aad)
    body_size = int.from_bytes(envelope[4:8], "big")
    body = envelope[8:8 + body_size]
    slot = envelope[8 + body_size + 2 + 4:]
    header_size = int.from_bytes(slot[:2], "big")
    header = slot[2:2 + header_size]
    wrapped = slot[2 + header_size + 2:]
    private = X25519PrivateKey.from_private_bytes(key.classical_priv)
    shared_classical = private.exchange(X25519PublicKey.from_public_bytes(header[:32]))
    shared_pq = MLKEM768PrivateKey.from_seed_bytes(key.pq_priv).decapsulate(header[34:])
    kek = HKDF(hashes.SHA384(), 32, salt=None, info=b"docxplus/dxe3-hybrid").derive(
        header[:32] + key.classical_pub + shared_classical + shared_pq
    )
    content_key = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], None)
    assert AESGCM(content_key).decrypt(body[:12], body[12:], aad) == plaintext

    ephemeral = X25519PrivateKey.generate()
    public = ephemeral.public_key().public_bytes_raw()
    pq_secret, pq_ciphertext = MLKEM768PublicKey.from_public_bytes(key.pq_pub).encapsulate()
    classical = ephemeral.exchange(X25519PublicKey.from_public_bytes(key.classical_pub))
    kek = HKDF(hashes.SHA384(), 32, salt=None, info=b"docxplus/dxe3-hybrid").derive(
        public + key.classical_pub + classical + pq_secret
    )
    content_key, nonce, wrap_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
    body = nonce + AESGCM(content_key).encrypt(nonce, plaintext, aad)
    wrapped = wrap_nonce + AESGCM(kek).encrypt(wrap_nonce, content_key, None)
    header = public + len(pq_ciphertext).to_bytes(2, "big") + pq_ciphertext
    slot = len(header).to_bytes(2, "big") + header + len(wrapped).to_bytes(2, "big") + wrapped
    native = (b"DXE3" + len(body).to_bytes(4, "big") + body + b"\0\1"
              + len(slot).to_bytes(4, "big") + slot)
    assert crypto.unseal_hybrid(native, key, aad=aad) == plaintext
    damaged = bytearray(native)
    damaged[-1] ^= 1
    with pytest.raises(ValueError):
        crypto.unseal_hybrid(bytes(damaged), key, aad=aad)


def test_hybrid_reader_rejects_a_malformed_slot_after_a_successful_recipient():
    """Early recipient success must not bypass canonical validation of later slots."""
    key = crypto.generate_hybrid_recipient_key()
    envelope = bytearray(crypto.seal_hybrid(b"data", [key.public_bytes]))
    count_offset = 8 + int.from_bytes(envelope[4:8], "big")
    envelope[count_offset:count_offset + 2] = b"\0\2"
    envelope += (4).to_bytes(4, "big") + b"\0" * 4
    with pytest.raises(ValueError):
        crypto.unseal_hybrid(bytes(envelope), key)


def test_hostile_scrypt_work_is_refused_before_derivation():
    """A memory-admissible parameter set must not multiply CPU work by unbounded p."""
    envelope = crypto.EncryptedPayload(
        crypto.KDF_SCRYPT, b"s" * 16, b"n" * 12, bytes([18, 8, 64]), b"t" * 16
    ).to_bytes()
    with pytest.raises(ValueError):
        crypto.validate_password_envelope(envelope)



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
        + bytes([12]) + b"N" * 12 + bytes([len(params)]) + params + b"ciphertext"
    )


def test_scrypt_memory_ceiling_bounds_the_product_not_just_n():
    """N=2^21 with r=64 is 16 GiB; capping N alone would let it through."""
    hostile = _envelope(crypto.KDF_SCRYPT, bytes([crypto.MAX_SCRYPT_N_LOG2, 64, 1]))
    with pytest.raises(ValueError, match="more memory than the reader allows"):
        crypto.decrypt(hostile, "password")

    # The ceiling is a real bound, not a rounding: right at it, r=1 is admissible.
    assert 128 * (1 << crypto.MAX_SCRYPT_N_LOG2) * 1 <= crypto.MAX_SCRYPT_MEMORY_BYTES
    assert 128 * (1 << crypto.MAX_SCRYPT_N_LOG2) * 2 > crypto.MAX_SCRYPT_MEMORY_BYTES


def test_scrypt_defaults_sit_comfortably_under_the_ceiling():
    default_bytes = 128 * (1 << crypto.SCRYPT_N_LOG2) * crypto.SCRYPT_R
    assert default_bytes <= crypto.MAX_SCRYPT_MEMORY_BYTES
    roundtrip = crypto.encrypt(b"payload", "pw", aad=b"slot")
    assert crypto.decrypt(roundtrip, "pw", aad=b"slot") == b"payload"


def test_scrypt_ceiling_is_aligned_with_the_argon2_ceiling():
    """Two memory-hard KDFs on the same reader should not differ 64-fold."""
    assert crypto.MAX_SCRYPT_MEMORY_BYTES == crypto.MAX_ARGON2_MEMORY_COST_KIB * 1024


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



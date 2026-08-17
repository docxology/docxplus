"""Crypto primitives: KDF, AEAD envelope, hashing, Ed25519 signing."""

from __future__ import annotations

import os

import pytest

from docxplus.crypto import (
    KDF_ARGON2ID,
    EncryptedPayload,
    decrypt,
    derive_key,
    digest,
    encrypt,
    generate_signing_key,
    sign,
    verify,
)


def test_derive_key_is_deterministic():
    salt = b"0123456789abcdef"
    assert derive_key("pw", salt, spin_count=1000) == derive_key("pw", salt, spin_count=1000)


def test_derive_key_varies_with_salt_and_password():
    a = derive_key("pw", b"a" * 16, spin_count=1000)
    b = derive_key("pw", b"b" * 16, spin_count=1000)
    c = derive_key("other", b"a" * 16, spin_count=1000)
    assert len({a, b, c}) == 3
    assert len(a) == 32


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        derive_key("", b"a" * 16)


def test_encrypt_decrypt_roundtrip():
    data = b"exceptional intelligence content"
    envelope = encrypt(data, "hunter2")
    assert envelope != data
    assert decrypt(envelope, "hunter2") == data


def test_decrypt_wrong_password_fails():
    envelope = encrypt(b"secret", "right")
    with pytest.raises(Exception):
        decrypt(envelope, "wrong")


def test_tampered_ciphertext_fails_gcm_tag():
    envelope = bytearray(encrypt(b"secret", "pw"))
    envelope[-1] ^= 0xFF
    with pytest.raises(Exception):
        decrypt(bytes(envelope), "pw")


def test_envelope_bytes_roundtrip():
    env = encrypt(b"x", "pw")
    parsed = EncryptedPayload.from_bytes(env)
    assert parsed.to_bytes() == env
    assert parsed.kdf_id in (1, 2)
    assert len(parsed.params) > 0


def test_envelope_bad_magic():
    with pytest.raises(ValueError, match="magic"):
        EncryptedPayload.from_bytes(b"XXXXnope")


def test_digest_algorithms():
    assert digest(b"a", "blake2b") != digest(b"b", "blake2b")
    assert len(digest(b"a", "sha256")) == 64
    assert digest(b"a", "sha3-256") != digest(b"a", "sha256")


def test_digest_unknown_algorithm():
    with pytest.raises(ValueError):
        digest(b"a", "md5")


def test_sign_and_verify():
    priv, pub = generate_signing_key()
    sig = sign(b"manifest", priv)
    assert verify(b"manifest", sig, pub) is True
    assert verify(b"tampered", sig, pub) is False


def test_verify_never_raises_on_garbage():
    assert verify(b"data", b"not-a-signature", b"not-a-key") is False

def test_argon2id_encryption_roundtrip():
    plaintext = b"sensitive payload with memory-hard argon2id"
    password = "correct_horse_battery_staple"

    # Encrypt with argon2id
    envelope = encrypt(plaintext, password, kdf="argon2id", aad=b"slot1")
    parsed = EncryptedPayload.from_bytes(envelope)
    assert parsed.kdf_id == KDF_ARGON2ID

    # Decrypt with correct password
    decrypted = decrypt(envelope, password, aad=b"slot1")
    assert decrypted == plaintext

    # Decrypt with wrong password fails
    with pytest.raises(Exception):
        decrypt(envelope, "wrong_password", aad=b"slot1")


def test_argon2id_work_factor_caps():
    # Construct malicious envelope with excessive memory_cost or time_cost
    bad_params = (
        (1024 * 1024 * 1024).to_bytes(4, "big")  # 1 TiB memory cost
        + (3).to_bytes(2, "big")
        + (4).to_bytes(2, "big")
    )
    env = EncryptedPayload(
        kdf_id=KDF_ARGON2ID,
        salt=os.urandom(16),
        nonce=os.urandom(12),
        params=bad_params,
        ciphertext=b"dummy",
    ).to_bytes()
    with pytest.raises(ValueError, match="outside accepted range"):
        decrypt(env, "pw")

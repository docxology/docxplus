"""X25519 multi-recipient sealing and the content-key symmetric layer."""

from __future__ import annotations

import pytest
from crypto import (
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

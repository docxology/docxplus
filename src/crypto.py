"""Cryptographic primitives for the DOCX+ intelligence layer.

Design mirrors the mechanisms the standards report documents so the intelligence
layer is *recognisably* an Office-crypto lineage without breaking openability:

* Key derivation follows the MS-OFFCRYPTO agile shape (report §7.1): a random
  salt, an iterated hash (``spinCount``), SHA-512 preferred over the deprecated
  MD/SHA-1 families. We use PBKDF2-HMAC-SHA512.
* Payload confidentiality uses AES-256-GCM (authenticated encryption) rather than
  the report's legacy AES-CBC-without-corruption-detection standard mode — GCM
  gives the integrity the report flags as missing from ECMA-376 *standard*
  encryption while staying in the AES family.
* Signing uses Ed25519, matching the docxology/steganographer signing backend.

Crucially, this encrypts the *payload*, not the whole OPC package, so the .docx
stays a valid, openable Office document (report §6.3, §14.3).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_SPIN_COUNT = 100_000  # PBKDF2 iterations; report §7.1 calls the count agile.
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32  # AES-256

_HASHERS = {
    "blake2b": lambda: hashlib.blake2b(digest_size=32),
    "sha256": hashlib.sha256,
    "sha3-256": hashlib.sha3_256,
}


def digest(data: bytes, algorithm: str = "blake2b") -> str:
    """Return a hex digest, defaulting to BLAKE2b (steganographer uses BLAKE3;
    BLAKE2b is the closest stdlib member and keeps this dependency-free)."""
    if algorithm not in _HASHERS:
        raise ValueError(f"unsupported hash algorithm: {algorithm}")
    h = _HASHERS[algorithm]()
    h.update(data)
    return h.hexdigest()


def derive_key(password: str, salt: bytes, spin_count: int = DEFAULT_SPIN_COUNT) -> bytes:
    """PBKDF2-HMAC-SHA512 key derivation (MS-OFFCRYPTO agile lineage, report §7.1)."""
    if not password:
        raise ValueError("password must be non-empty")
    return hashlib.pbkdf2_hmac(
        "sha512", password.encode("utf-8"), salt, spin_count, dklen=KEY_BYTES
    )


@dataclass(frozen=True)
class EncryptedPayload:
    """Self-describing ciphertext envelope for a package part."""

    salt: bytes
    nonce: bytes
    spin_count: int
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        header = (
            b"DXE1"
            + len(self.salt).to_bytes(1, "big")
            + self.salt
            + len(self.nonce).to_bytes(1, "big")
            + self.nonce
            + self.spin_count.to_bytes(4, "big")
        )
        return header + self.ciphertext

    @classmethod
    def from_bytes(cls, blob: bytes) -> "EncryptedPayload":
        if blob[:4] != b"DXE1":
            raise ValueError("not a DOCX+ encrypted payload (bad magic)")
        i = 4
        slen = blob[i]
        i += 1
        salt = blob[i : i + slen]
        i += slen
        nlen = blob[i]
        i += 1
        nonce = blob[i : i + nlen]
        i += nlen
        spin = int.from_bytes(blob[i : i + 4], "big")
        i += 4
        return cls(salt=salt, nonce=nonce, spin_count=spin, ciphertext=blob[i:])


def encrypt(plaintext: bytes, password: str, spin_count: int = DEFAULT_SPIN_COUNT) -> bytes:
    """Encrypt ``plaintext`` under ``password`` → self-describing envelope bytes."""
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = derive_key(password, salt, spin_count)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return EncryptedPayload(salt, nonce, spin_count, ciphertext).to_bytes()


def decrypt(envelope: bytes, password: str) -> bytes:
    """Reverse :func:`encrypt`. Raises on wrong password / tampering (GCM tag)."""
    payload = EncryptedPayload.from_bytes(envelope)
    key = derive_key(password, payload.salt, payload.spin_count)
    return AESGCM(key).decrypt(payload.nonce, payload.ciphertext, None)


# -- signing (Ed25519, steganographer-compatible curve) --------------------
def generate_signing_key() -> tuple[bytes, bytes]:
    """Return ``(private_key_32, public_key_32)`` raw bytes."""
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    priv_raw = priv.private_bytes_raw()
    pub_raw = priv.public_key().public_bytes_raw()
    del serialization
    return priv_raw, pub_raw


def sign(data: bytes, private_key: bytes) -> bytes:
    """Ed25519-sign ``data`` with a raw 32-byte private key."""
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(data)


def verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature; return ``True``/``False`` (never raises)."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False

"""Cryptographic primitives for the docxplus intelligence layer.

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
import random
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_SPIN_COUNT = 100_000  # legacy PBKDF2 count kept for the derive_key() compat API.
#: Cryptographically secure shuffling for recipient-slot ordering.
_SYSTEM_RANDOM = random.SystemRandom()

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32  # AES-256

# KDF identifiers recorded in the DXE1 envelope so a reader derives the same key.
KDF_PBKDF2 = 1
KDF_SCRYPT = 2
KDF_ARGON2ID = 3

# Argon2id parameters (RFC 9106 recommended first-line memory-hard KDF):
# memory_cost=65536 (64 MiB), time_cost=3, parallelism=4
ARGON2_MEMORY_COST_KIB = 65536
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4
MAX_ARGON2_MEMORY_COST_KIB = 256 * 1024  # 256 MiB ceiling
MAX_ARGON2_TIME_COST = 10
MAX_ARGON2_PARALLELISM = 16
# PBKDF2 compat mode raised to OWASP-2023 guidance for HMAC-SHA512.
PBKDF2_ITERATIONS = 600_000
# Scrypt is the default: memory-hard (~32 MiB), resisting the GPU/ASIC attacks
# that make a fixed PBKDF2 count weak. N=2^15, r=8, p=1.
SCRYPT_N_LOG2 = 15
SCRYPT_R = 8
SCRYPT_P = 1

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
    """PBKDF2-HMAC-SHA512 key derivation (compat helper; new code uses :func:`encrypt`)."""
    if not password:
        raise ValueError("password must be non-empty")
    return hashlib.pbkdf2_hmac(
        "sha512", password.encode("utf-8"), salt, spin_count, dklen=KEY_BYTES
    )


# Ceilings on attacker-supplied KDF work factors. Without these, a hostile
# envelope could set an enormous iteration count / scrypt N and turn any attempt
# to open it into a CPU/memory denial-of-service on the reader.
MAX_PBKDF2_ITERATIONS = 5_000_000
MAX_SCRYPT_N_LOG2 = 21  # N ≤ 2^21; the memory ceiling below is the binding constraint
# Scrypt's footprint is 128 * N * r bytes, so capping N alone bounds nothing: at the
# permitted r=64 an N of 2^21 demands 16 GiB and hands a hostile envelope a
# memory-exhaustion DoS. Bound the product instead, at the same 256 MiB ceiling
# Argon2id already enforces. The default (N=2^15, r=8) needs 32 MiB.
MAX_SCRYPT_MEMORY_BYTES = 256 * 1024 * 1024


def _derive(password: str, salt: bytes, kdf_id: int, params: bytes) -> bytes:
    """Derive a 32-byte key for the KDF recorded in an envelope (work-factor capped)."""
    if not password:
        raise ValueError("password must be non-empty")
    pw = password.encode("utf-8")
    if kdf_id == KDF_PBKDF2:
        if len(params) != 4:
            raise ValueError("malformed PBKDF2 parameters")
        iterations = int.from_bytes(params, "big")
        if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
            raise ValueError("PBKDF2 iteration count outside accepted range")
        return hashlib.pbkdf2_hmac("sha512", pw, salt, iterations, dklen=KEY_BYTES)
    if kdf_id == KDF_SCRYPT:
        if len(params) < 3:
            raise ValueError("malformed scrypt parameters")
        n_log2, r, p = params[0], params[1], params[2]
        if not 1 <= n_log2 <= MAX_SCRYPT_N_LOG2 or not 1 <= r <= 64 or not 1 <= p <= 64:
            raise ValueError("scrypt parameters outside accepted range")
        # The parameters are individually plausible but jointly hostile unless the
        # resulting allocation is bounded too.
        if 128 * (1 << n_log2) * r > MAX_SCRYPT_MEMORY_BYTES:
            raise ValueError("scrypt parameters demand more memory than the reader allows")
        return Scrypt(salt=salt, length=KEY_BYTES, n=1 << n_log2, r=r, p=p).derive(pw)
    if kdf_id == KDF_ARGON2ID:
        # params layout: memory_cost_kib(4) || time_cost(2) || parallelism(2)
        if len(params) < 8:
            raise ValueError("malformed Argon2id parameters")
        memory_cost = int.from_bytes(params[0:4], "big")
        time_cost = int.from_bytes(params[4:6], "big")
        parallelism = int.from_bytes(params[6:8], "big")
        if not (1024 <= memory_cost <= MAX_ARGON2_MEMORY_COST_KIB):
            raise ValueError("Argon2id memory_cost outside accepted range")
        if not (1 <= time_cost <= MAX_ARGON2_TIME_COST):
            raise ValueError("Argon2id time_cost outside accepted range")
        if not (1 <= parallelism <= MAX_ARGON2_PARALLELISM):
            raise ValueError("Argon2id parallelism outside accepted range")
        return Argon2id(
            salt=salt,
            length=KEY_BYTES,
            iterations=time_cost,
            lanes=parallelism,
            memory_cost=memory_cost,
        ).derive(pw)
    raise ValueError(f"unknown KDF id: {kdf_id}")


@dataclass(frozen=True)
class EncryptedPayload:
    """Self-describing ciphertext envelope (``DXE1``) recording its KDF + params.

    Layout: ``"DXE1" | kdf_id(1) | salt_len(1) | salt | nonce_len(1) | nonce |
    params_len(1) | params | ciphertext``. AAD is *not* stored — it is contextual
    (the module slot), so a spliced ciphertext fails its GCM tag.
    """

    kdf_id: int
    salt: bytes
    nonce: bytes
    params: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        return (
            b"DXE1"
            + bytes([self.kdf_id])
            + bytes([len(self.salt)]) + self.salt
            + bytes([len(self.nonce)]) + self.nonce
            + bytes([len(self.params)]) + self.params
            + self.ciphertext
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> EncryptedPayload:
        """Parse an envelope, rejecting anything truncated or self-inconsistent.

        Every field is bounds-checked before it is read. Slicing blindly would let
        a header that declares a 200-byte salt over a 4-byte remainder parse
        "successfully" into a short salt, and would surface truncation as
        ``IndexError`` — a type callers filtering on ``ValueError`` do not expect.
        """
        if blob[:4] != b"DXE1":
            raise ValueError("not a docxplus encrypted payload (bad magic)")
        i = 4

        def take(count: int, what: str) -> bytes:
            nonlocal i
            if count < 0 or i + count > len(blob):
                raise ValueError(f"truncated DXE1 envelope: incomplete {what}")
            chunk = blob[i : i + count]
            i += count
            return chunk

        kdf_id = take(1, "KDF id")[0]
        salt = take(take(1, "salt length")[0], "salt")
        nonce = take(take(1, "nonce length")[0], "nonce")
        params = take(take(1, "parameter length")[0], "parameters")
        return cls(kdf_id=kdf_id, salt=salt, nonce=nonce, params=params, ciphertext=blob[i:])


def _kdf_params(kdf: str) -> tuple[int, bytes]:
    if kdf == "scrypt":
        return KDF_SCRYPT, bytes([SCRYPT_N_LOG2, SCRYPT_R, SCRYPT_P])
    if kdf == "argon2id" or kdf == "argon2":
        params = (
            ARGON2_MEMORY_COST_KIB.to_bytes(4, "big")
            + ARGON2_TIME_COST.to_bytes(2, "big")
            + ARGON2_PARALLELISM.to_bytes(2, "big")
        )
        return KDF_ARGON2ID, params
    if kdf == "pbkdf2":
        return KDF_PBKDF2, PBKDF2_ITERATIONS.to_bytes(4, "big")
    raise ValueError(f"unknown KDF: {kdf}")


def encrypt(plaintext: bytes, password: str, *, aad: bytes = b"", kdf: str = "scrypt") -> bytes:
    """Encrypt ``plaintext`` under ``password`` → self-describing envelope bytes.

    ``aad`` binds the ciphertext to a context (the module slot); default KDF is the
    memory-hard Scrypt.
    """
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    kdf_id, params = _kdf_params(kdf)
    key = _derive(password, salt, kdf_id, params)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return EncryptedPayload(kdf_id, salt, nonce, params, ciphertext).to_bytes()


def decrypt(envelope: bytes, password: str, *, aad: bytes = b"") -> bytes:
    """Reverse :func:`encrypt`. Raises on wrong password / tampering (GCM tag)."""
    payload = EncryptedPayload.from_bytes(envelope)
    key = _derive(password, payload.salt, payload.kdf_id, payload.params)
    return AESGCM(key).decrypt(payload.nonce, payload.ciphertext, aad or None)


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


# -- content-key symmetric layer -------------------------------------------
def encrypt_with_key(plaintext: bytes, key: bytes, *, aad: bytes = b"") -> bytes:
    """AES-256-GCM under a raw 32-byte key → ``nonce || ciphertext``."""
    if len(key) != KEY_BYTES:
        raise ValueError("content key must be 32 bytes")
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad or None)


def decrypt_with_key(blob: bytes, key: bytes, *, aad: bytes = b"") -> bytes:
    """Reverse :func:`encrypt_with_key`."""
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad or None)


# -- X25519 multi-recipient hybrid sealing (DXE2) --------------------------
def generate_recipient_key() -> tuple[bytes, bytes]:
    """Return ``(x25519_private_32, x25519_public_32)`` raw bytes."""
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _wrap_key(content_key: bytes, recipient_pub: bytes) -> tuple[bytes, bytes]:
    """Wrap ``content_key`` for one recipient via X25519 + HKDF + AES-GCM.

    Returns ``(ephemeral_pub, wrapped)`` where ``wrapped = nonce || ct``.
    """
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    eph_pub = eph.public_key().public_bytes_raw()
    kek = HKDF(hashes.SHA256(), KEY_BYTES, salt=None, info=b"docxplus/dxe2").derive(
        eph_pub + recipient_pub + shared
    )
    return eph_pub, encrypt_with_key(content_key, kek)


def _unwrap_key(eph_pub: bytes, wrapped: bytes, recipient_priv: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(recipient_priv)
    recipient_pub = priv.public_key().public_bytes_raw()
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    kek = HKDF(hashes.SHA256(), KEY_BYTES, salt=None, info=b"docxplus/dxe2").derive(
        eph_pub + recipient_pub + shared
    )
    return decrypt_with_key(wrapped, kek)


def seal_multi(
    plaintext: bytes,
    recipients: list[bytes],
    *,
    aad: bytes = b"",
    pad_to: int = 0,
) -> bytes:
    """Encrypt ``plaintext`` once, wrapping the content key for each recipient.

    Envelope layout::

        "DXE2" | body_len(4) | body | recip_count(2) | [ eph(32) wrap_len(2) wrap ]...

    body = encrypt_with_key(plaintext, content_key, aad). ``aad`` binds the body to
    its module context. The envelope does not embed recipient public keys, so it does
    not leak recipient *identities* — a reader trial-decrypts each wrap slot.

    It does leak the recipient **count**, which is a field of the format and is also
    recoverable from the envelope length at a fixed cost per slot. The manifest goes
    to some trouble to record neither identities nor count, and that intent is only
    half achieved without addressing this: for the blind-review packet the format is
    meant to serve, "sealed to three people" is itself information about the review.

    ``pad_to`` raises the apparent recipient count to a fixed bucket by wrapping the
    content key to freshly generated public keys whose private halves are discarded
    before this function returns. A padded slot is a genuine X25519 wrap and is
    therefore indistinguishable from a real one; it is simply undecryptable, by
    anyone, forever. This is the same move the password lineage already makes with
    its chaff frame — the observer sees a slot and cannot tell whether it is a
    recipient or an absence.
    """
    if not recipients:
        raise ValueError("at least one recipient required")
    if pad_to and pad_to < len(recipients):
        raise ValueError(
            f"pad_to={pad_to} is below the actual recipient count {len(recipients)}; "
            "padding may only ever add slots"
        )
    slots = list(recipients)
    for _ in range(max(0, pad_to - len(slots))):
        # The private half is never bound to a name and goes out of scope here.
        _discarded, decoy_pub = generate_recipient_key()
        slots.append(decoy_pub)

    content_key = os.urandom(KEY_BYTES)
    body = encrypt_with_key(plaintext, content_key, aad=aad)
    out = bytearray(b"DXE2" + len(body).to_bytes(4, "big") + body)
    out += len(slots).to_bytes(2, "big")
    # Shuffle so a padded slot cannot be identified by position: appending decoys
    # would put every real recipient first and defeat the point.
    _SYSTEM_RANDOM.shuffle(slots)
    for pub in slots:
        eph_pub, wrapped = _wrap_key(content_key, pub)
        out += eph_pub + len(wrapped).to_bytes(2, "big") + wrapped
    return bytes(out)


def unseal_multi(envelope: bytes, recipient_priv: bytes, *, aad: bytes = b"") -> bytes:
    """Open a :func: envelope with one recipient's private key."""
    if envelope[:4] != b"DXE2":
        raise ValueError("not a DXE2 multi-recipient envelope")
    i = 4
    if len(envelope) < i + 4:
        raise ValueError("truncated DXE2 envelope (missing body length)")
    body_len = int.from_bytes(envelope[i : i + 4], "big")
    i += 4
    if len(envelope) < i + body_len + 2:
        raise ValueError("truncated DXE2 envelope (missing body or count)")
    body = envelope[i : i + body_len]
    i += body_len
    count = int.from_bytes(envelope[i : i + 2], "big")
    i += 2
    last_error: Exception | None = None
    for _ in range(count):
        if len(envelope) < i + 34:
            raise ValueError("truncated DXE2 recipient slot")
        eph_pub = envelope[i : i + 32]
        i += 32
        wrap_len = int.from_bytes(envelope[i : i + 2], "big")
        i += 2
        if len(envelope) < i + wrap_len:
            raise ValueError("truncated DXE2 wrapped key")
        wrapped = envelope[i : i + wrap_len]
        i += wrap_len
        try:
            content_key = _unwrap_key(eph_pub, wrapped, recipient_priv)
            return decrypt_with_key(body, content_key, aad=aad)
        except Exception as exc:
            last_error = exc
    raise ValueError("no recipient slot could be opened with this key") from last_error

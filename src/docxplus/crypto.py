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

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
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
MAX_SCRYPT_WORK = 1 << 22  # N * r * p; bound CPU independently of main memory.


def _validate_kdf_params(kdf_id: int, params: bytes) -> tuple[int, ...]:
    """Validate attacker-declared work without performing a derivation."""
    if kdf_id == KDF_PBKDF2:
        if len(params) != 4:
            raise ValueError("malformed PBKDF2 parameters")
        iterations = int.from_bytes(params, "big")
        if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
            raise ValueError("PBKDF2 iteration count outside accepted range")
        return (iterations,)
    if kdf_id == KDF_SCRYPT:
        if len(params) != 3:
            raise ValueError("malformed scrypt parameters")
        n_log2, r, p = params
        if not 1 <= n_log2 <= MAX_SCRYPT_N_LOG2 or not 1 <= r <= 64 or not 1 <= p <= 64:
            raise ValueError("scrypt parameters outside accepted range")
        n = 1 << n_log2
        if 128 * n * r > MAX_SCRYPT_MEMORY_BYTES:
            raise ValueError("scrypt parameters demand more memory than the reader allows")
        if n * r * p > MAX_SCRYPT_WORK:
            raise ValueError("scrypt parameters exceed the reader work budget")
        return n, r, p
    if kdf_id == KDF_ARGON2ID:
        if len(params) != 8:
            raise ValueError("malformed Argon2id parameters")
        memory = int.from_bytes(params[:4], "big")
        iterations = int.from_bytes(params[4:6], "big")
        lanes = int.from_bytes(params[6:8], "big")
        if not 1024 <= memory <= MAX_ARGON2_MEMORY_COST_KIB:
            raise ValueError("Argon2id memory_cost outside accepted range")
        if not 1 <= iterations <= MAX_ARGON2_TIME_COST:
            raise ValueError("Argon2id time_cost outside accepted range")
        if not 1 <= lanes <= MAX_ARGON2_PARALLELISM:
            raise ValueError("Argon2id parallelism outside accepted range")
        return memory, iterations, lanes
    raise ValueError(f"unknown KDF id: {kdf_id}")


def _derive(password: str, salt: bytes, kdf_id: int, params: bytes) -> bytes:
    """Derive a 32-byte key for the KDF recorded in an envelope (work-factor capped)."""
    if not password:
        raise ValueError("password must be non-empty")
    pw = password.encode("utf-8")
    parameters = _validate_kdf_params(kdf_id, params)
    if kdf_id == KDF_PBKDF2:
        return hashlib.pbkdf2_hmac("sha512", pw, salt, parameters[0], dklen=KEY_BYTES)
    if kdf_id == KDF_SCRYPT:
        n, r, p = parameters
        return Scrypt(salt=salt, length=KEY_BYTES, n=n, r=r, p=p).derive(pw)
    memory, iterations, lanes = parameters
    return Argon2id(salt=salt, length=KEY_BYTES, iterations=iterations,
                    lanes=lanes, memory_cost=memory).derive(pw)


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
def validate_password_envelope(envelope: bytes) -> EncryptedPayload:
    """Parse a supported DXE1 envelope and bound its KDF, executing no derivation."""
    payload = EncryptedPayload.from_bytes(envelope)
    if (len(payload.salt) != SALT_BYTES or len(payload.nonce) != NONCE_BYTES
            or len(payload.ciphertext) < 16):
        raise ValueError("malformed DXE1 salt, nonce, or authentication tag")
    _validate_kdf_params(payload.kdf_id, payload.params)
    return payload


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
    payload = validate_password_envelope(envelope)
    key = _derive(password, payload.salt, payload.kdf_id, payload.params)
    try:
        return AESGCM(key).decrypt(payload.nonce, payload.ciphertext, aad or None)
    except Exception as exc:
        raise ValueError(f"decryption failed: {exc}") from exc


# -- signing (Ed25519, steganographer-compatible curve) --------------------
def generate_signing_key() -> tuple[bytes, bytes]:
    """Return ``(private_key_32, public_key_32)`` raw bytes."""
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    priv_raw = priv.private_bytes_raw()
    pub_raw = priv.public_key().public_bytes_raw()
    del serialization
    return priv_raw, pub_raw


def signing_public_key(private_key: bytes) -> bytes:
    """Derive the exact raw Ed25519 or portable hybrid signing identity."""
    if len(private_key) == 32:
        return Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
    keypair = HybridKeyPair.from_private_bytes(private_key)
    keypair._private_keys(_HYBRID_SIGNING)
    return keypair.public_bytes


def signing_algorithm(public_key: bytes) -> str:
    """Return the signing scheme selected by strict public-key framing."""
    if len(public_key) == 32:
        Ed25519PublicKey.from_public_bytes(public_key)
        return "ed25519"
    classical, pq = _hybrid_public_key(public_key, _MLDSA_PUBLIC_BYTES)
    Ed25519PublicKey.from_public_bytes(classical)
    MLDSA65PublicKey.from_public_bytes(pq)
    return "ed25519+ml-dsa-65"


def sign(data: bytes, private_key: bytes) -> bytes:
    """Sign using raw Ed25519 or an explicitly serialized hybrid signing key."""
    if len(private_key) == 32:
        return Ed25519PrivateKey.from_private_bytes(private_key).sign(data)
    return hybrid_sign(data, HybridKeyPair.from_private_bytes(private_key))


def verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify the key's actual family, never falling back to its classical half."""
    try:
        if signing_algorithm(public_key) == "ed25519+ml-dsa-65":
            return hybrid_verify(data, signature, public_key)
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
    if len(key) != KEY_BYTES:
        raise ValueError("content key must be 32 bytes")
    if len(blob) < NONCE_BYTES + 16:
        raise ValueError("truncated AES-256-GCM payload")
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad or None)


# -- X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65 ---------------------------

_MLKEM_PUBLIC_BYTES = 1184
_MLKEM_CIPHERTEXT_BYTES = 1088
_MLDSA_PUBLIC_BYTES = 1952
_HYBRID_SIGN_DOMAIN = b"docxplus/hybrid-signature/v1\0"
_HYBRID_PRIVATE_MAGIC = b"DXHK"
_HYBRID_PRIVATE_VERSION = 1
_HYBRID_RECIPIENT = 1
_HYBRID_SIGNING = 2
_MLDSA_SIGNATURE_BYTES = 3309

@dataclass(frozen=True)
class HybridKeyPair:
    """Raw classical keys plus genuine ML-KEM-768 or ML-DSA-65 keys.

    ``pq_priv`` is the provider's seed serialization, not an expanded private key.
    Simulated keys from earlier releases are not supported.
    """
    classical_priv: bytes
    classical_pub: bytes
    pq_priv: bytes
    pq_pub: bytes

    @property
    def public_bytes(self) -> bytes:
        """Combined public key: classical(32) || pq_pub_len(2) || pq_pub."""
        return self.classical_pub + len(self.pq_pub).to_bytes(2, "big") + self.pq_pub

    def _private_keys(self, expected_suite: int | None = None):
        """Derive and check both halves, refusing wrong-family or simulated keys."""
        if len(self.pq_pub) == _MLKEM_PUBLIC_BYTES:
            suite, seed_size = _HYBRID_RECIPIENT, 64
            classical_type, pq_type = X25519PrivateKey, MLKEM768PrivateKey
        elif len(self.pq_pub) == _MLDSA_PUBLIC_BYTES:
            suite, seed_size = _HYBRID_SIGNING, 32
            classical_type, pq_type = Ed25519PrivateKey, MLDSA65PrivateKey
        else:
            raise ValueError("unsupported hybrid key family")
        if expected_suite is not None and suite != expected_suite:
            raise ValueError("wrong hybrid key family")
        if len(self.classical_priv) != 32 or len(self.pq_priv) != seed_size:
            raise ValueError("malformed hybrid private seed")
        classical = classical_type.from_private_bytes(self.classical_priv)
        pq = pq_type.from_seed_bytes(self.pq_priv)
        if classical.public_key().public_bytes_raw() != self.classical_pub:
            raise ValueError("classical private/public key mismatch")
        if pq.public_key().public_bytes_raw() != self.pq_pub:
            raise ValueError("post-quantum private/public key mismatch")
        return suite, classical, pq

    @property
    def private_bytes(self) -> bytes:
        """Export checked DXHK v1, with suite-fixed seed and public-half sizes.

        Layout: DXHK | version(1) | suite(1) | classical_seed(32) |
        classical_public(32) | pq_seed | pq_public. Suite 1 is
        X25519/ML-KEM-768 (64/1184 bytes); suite 2 is Ed25519/ML-DSA-65
        (32/1952 bytes). Legacy simulated keys are never accepted.
        """
        suite, _, _ = self._private_keys()
        return (
            _HYBRID_PRIVATE_MAGIC + bytes([_HYBRID_PRIVATE_VERSION, suite])
            + self.classical_priv + self.classical_pub + self.pq_priv + self.pq_pub
        )

    @classmethod
    def from_private_bytes(cls, blob: bytes) -> HybridKeyPair:
        """Import exactly one typed v1 key, checking derived public halves."""
        if (len(blob) < 6 or blob[:4] != _HYBRID_PRIVATE_MAGIC
                or blob[4] != _HYBRID_PRIVATE_VERSION):
            raise ValueError("unsupported hybrid private key format")
        suite = blob[5]
        if suite == _HYBRID_RECIPIENT:
            seed_size, public_size = 64, _MLKEM_PUBLIC_BYTES
        elif suite == _HYBRID_SIGNING:
            seed_size, public_size = 32, _MLDSA_PUBLIC_BYTES
        else:
            raise ValueError("unsupported hybrid private key suite")
        if len(blob) != 6 + 64 + seed_size + public_size:
            raise ValueError("truncated or trailing hybrid private key")
        keypair = cls(blob[6:38], blob[38:70], blob[70:70 + seed_size], blob[70 + seed_size:])
        keypair._private_keys(suite)
        return keypair


def generate_hybrid_recipient_key() -> HybridKeyPair:
    """Generate an X25519 + ML-KEM-768 recipient keypair."""
    c_priv, c_pub = generate_recipient_key()
    pq = MLKEM768PrivateKey.generate()
    return HybridKeyPair(c_priv, c_pub, pq.private_bytes_raw(), pq.public_key().public_bytes_raw())


def generate_hybrid_signing_key() -> HybridKeyPair:
    """Generate an Ed25519 + ML-DSA-65 signing keypair."""
    c_priv, c_pub = generate_signing_key()
    pq = MLDSA65PrivateKey.generate()
    return HybridKeyPair(c_priv, c_pub, pq.private_bytes_raw(), pq.public_key().public_bytes_raw())


def hybrid_sign(data: bytes, keypair: HybridKeyPair) -> bytes:
    """Sign a domain-separated message with both Ed25519 and ML-DSA-65."""
    message = _HYBRID_SIGN_DOMAIN + data
    _, classical, pq = keypair._private_keys(_HYBRID_SIGNING)
    c_sig = classical.sign(message)
    pq_sig = pq.sign(message)
    return len(c_sig).to_bytes(2, "big") + c_sig + len(pq_sig).to_bytes(2, "big") + pq_sig


def _hybrid_public_key(combined_pub: bytes, pq_size: int) -> tuple[bytes, bytes]:
    """Parse exactly one supported combined key; reject simulated/ambiguous keys."""
    if (len(combined_pub) != 34 + pq_size
            or int.from_bytes(combined_pub[32:34], "big") != pq_size):
        raise ValueError("malformed hybrid public key")
    return combined_pub[:32], combined_pub[34:]


def hybrid_verify(data: bytes, signature: bytes, combined_pub: bytes) -> bool:
    """Require both signatures under the caller's exact combined public key."""
    try:
        c_pub, pq_pub = _hybrid_public_key(combined_pub, _MLDSA_PUBLIC_BYTES)
        if len(signature) < 4:
            return False
        c_len = int.from_bytes(signature[:2], "big")
        end = 2 + c_len
        if c_len != 64 or len(signature) < end + 2:
            return False
        pq_len = int.from_bytes(signature[end:end + 2], "big")
        if pq_len != _MLDSA_SIGNATURE_BYTES or len(signature) != end + 2 + pq_len:
            return False
        message = _HYBRID_SIGN_DOMAIN + data
        if not verify(message, signature[2:end], c_pub):
            return False
        MLDSA65PublicKey.from_public_bytes(pq_pub).verify(signature[end + 2:], message)
    except (ValueError, InvalidSignature):
        return False
    return True


def _wrap_hybrid_key(content_key: bytes, combined_pub: bytes) -> tuple[bytes, bytes]:
    """Wrap a content key using independent X25519 and ML-KEM-768 secrets."""
    c_pub, pq_pub = _hybrid_public_key(combined_pub, _MLKEM_PUBLIC_BYTES)
    eph = X25519PrivateKey.generate()
    shared_c = eph.exchange(X25519PublicKey.from_public_bytes(c_pub))
    eph_pub_c = eph.public_key().public_bytes_raw()
    shared_pq, pq_ct = MLKEM768PublicKey.from_public_bytes(pq_pub).encapsulate()

    # Dual-combiner KDF: combines classical + post-quantum shared secrets
    kek = HKDF(hashes.SHA384(), KEY_BYTES, salt=None, info=b"docxplus/dxe3-hybrid").derive(
        eph_pub_c + c_pub + shared_c + shared_pq
    )
    wrapped = encrypt_with_key(content_key, kek)
    # Header: eph_pub_c(32) || pq_ct_len(2) || pq_ct
    eph_header = eph_pub_c + len(pq_ct).to_bytes(2, "big") + pq_ct
    return eph_header, wrapped


def _unwrap_hybrid_key(eph_header: bytes, wrapped: bytes, keypair: HybridKeyPair) -> bytes:
    """Decapsulate with the genuine ML-KEM private seed, never public material."""
    if (len(eph_header) != 34 + _MLKEM_CIPHERTEXT_BYTES
            or int.from_bytes(eph_header[32:34], "big") != _MLKEM_CIPHERTEXT_BYTES):
        raise ValueError("malformed hybrid ephemeral header")
    eph_pub_c, pq_ct = eph_header[:32], eph_header[34:]
    priv_c = X25519PrivateKey.from_private_bytes(keypair.classical_priv)
    c_pub = priv_c.public_key().public_bytes_raw()
    if c_pub != keypair.classical_pub:
        raise ValueError("X25519 private/public key mismatch")
    shared_c = priv_c.exchange(X25519PublicKey.from_public_bytes(eph_pub_c))
    pq = MLKEM768PrivateKey.from_seed_bytes(keypair.pq_priv)
    if pq.public_key().public_bytes_raw() != keypair.pq_pub:
        raise ValueError("ML-KEM private/public key mismatch")
    shared_pq = pq.decapsulate(pq_ct)
    kek = HKDF(hashes.SHA384(), KEY_BYTES, salt=None, info=b"docxplus/dxe3-hybrid").derive(
        eph_pub_c + c_pub + shared_c + shared_pq
    )
    return decrypt_with_key(wrapped, kek)


def seal_hybrid(
    plaintext: bytes,
    recipients: list[bytes],
    *,
    aad: bytes = b"",
    pad_to: int = 0,
) -> bytes:
    """Encrypt using X25519 + ML-KEM-768 (DXE3); no simulated-key fallback."""
    _validate_recipient_count(recipients, pad_to)
    for public_key in recipients:
        classical, pq = _hybrid_public_key(public_key, _MLKEM_PUBLIC_BYTES)
        X25519PublicKey.from_public_bytes(classical)
        MLKEM768PublicKey.from_public_bytes(pq)
    slots = list(recipients)
    for _ in range(max(0, pad_to - len(slots))):
        decoy = generate_hybrid_recipient_key()
        slots.append(decoy.public_bytes)

    content_key = os.urandom(KEY_BYTES)
    body = encrypt_with_key(plaintext, content_key, aad=aad)
    out = bytearray(b"DXE3" + len(body).to_bytes(4, "big") + body)
    out += len(slots).to_bytes(2, "big")
    _SYSTEM_RANDOM.shuffle(slots)
    for pub in slots:
        eph_header, wrapped = _wrap_hybrid_key(content_key, pub)
        slot_data = len(eph_header).to_bytes(2, "big") + eph_header + len(wrapped).to_bytes(2, "big") + wrapped
        out += len(slot_data).to_bytes(4, "big") + slot_data
    return bytes(out)


def unseal_hybrid(envelope: bytes, keypair: HybridKeyPair, *, aad: bytes = b"") -> bytes:
    """Open a DXE3 hybrid envelope using a recipient's hybrid keypair."""
    keypair._private_keys(_HYBRID_RECIPIENT)
    if len(envelope) < 4:
        raise ValueError("truncated DXE3 envelope (missing magic)")
    if envelope[:4] != b"DXE3":
        raise ValueError("not a DXE3 hybrid multi-recipient envelope")
    i = 4
    if len(envelope) < i + 4:
        raise ValueError("truncated DXE3 envelope (missing body length)")
    body_len = int.from_bytes(envelope[i : i + 4], "big")
    if body_len < NONCE_BYTES + 16:
        raise ValueError("truncated DXE3 encrypted body")
    i += 4
    if len(envelope) < i + body_len + 2:
        raise ValueError("truncated DXE3 envelope (missing body or count)")
    body = envelope[i : i + body_len]
    i += body_len
    count = int.from_bytes(envelope[i : i + 2], "big")
    if count == 0:
        raise ValueError("DXE3 requires at least one recipient")
    i += 2
    slots: list[tuple[bytes, bytes]] = []
    last_error: Exception | None = None
    for _ in range(count):
        if len(envelope) < i + 4:
            raise ValueError("truncated DXE3 slot length")
        slot_len = int.from_bytes(envelope[i : i + 4], "big")
        if slot_len != 4 + 34 + _MLKEM_CIPHERTEXT_BYTES + NONCE_BYTES + KEY_BYTES + 16:
            raise ValueError("malformed DXE3 recipient slot size")
        i += 4
        if len(envelope) < i + slot_len:
            raise ValueError("truncated DXE3 slot data")
        slot_bytes = envelope[i : i + slot_len]
        i += slot_len
        if len(slot_bytes) < 2:
            raise ValueError("truncated DXE3 slot header")
        eph_len = int.from_bytes(slot_bytes[:2], "big")
        if eph_len != 34 + _MLKEM_CIPHERTEXT_BYTES:
            raise ValueError("malformed DXE3 ephemeral header size")
        idx = 2
        if len(slot_bytes) < idx + eph_len + 2:
            raise ValueError("truncated DXE3 slot ephemeral header")
        eph_header = slot_bytes[idx : idx + eph_len]
        idx += eph_len
        wrap_len = int.from_bytes(slot_bytes[idx : idx + 2], "big")
        if wrap_len != NONCE_BYTES + KEY_BYTES + 16:
            raise ValueError("malformed DXE3 wrapped content key size")
        idx += 2
        if len(slot_bytes) != idx + wrap_len:
            raise ValueError("truncated or trailing DXE3 slot wrapped key")
        if int.from_bytes(eph_header[32:34], "big") != _MLKEM_CIPHERTEXT_BYTES:
            raise ValueError("malformed DXE3 ML-KEM ciphertext size")
        slots.append((eph_header, slot_bytes[idx:]))
    if i != len(envelope):
        raise ValueError("trailing bytes in DXE3 envelope")
    for eph_header, wrapped in slots:
        try:
            content_key = _unwrap_hybrid_key(eph_header, wrapped, keypair)
            return decrypt_with_key(body, content_key, aad=aad)
        except (ValueError, InvalidTag) as exc:
            last_error = exc
    raise ValueError("no hybrid recipient slot could be opened with this key") from last_error

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


def _validate_recipient_count(recipients: list[bytes], pad_to: int) -> None:
    if not recipients:
        raise ValueError("at least one recipient required")
    if type(pad_to) is not int or not 0 <= pad_to <= 65535 or len(recipients) > 65535:
        raise ValueError("recipient count and pad_to must fit unsigned 16-bit fields")
    if pad_to and pad_to < len(recipients):
        raise ValueError(f"pad_to={pad_to} is below recipient count {len(recipients)}")


def seal_multi(
    plaintext: bytes,
    recipients: list[bytes],
    *,
    aad: bytes = b"",
    pad_to: int = 0,
) -> bytes:
    """Seal for one key family: raw X25519 (DXE2) or all-hybrid (DXE3).

    Slot AAD binds the encrypted body to its context. Optional ``pad_to`` adds
    genuine discarded-key slots of the same family and shuffles their order.
    Mixed, malformed or simulated recipient families are refused.
    """
    _validate_recipient_count(recipients, pad_to)
    if all(len(public_key) != 32 for public_key in recipients):
        return seal_hybrid(plaintext, recipients, aad=aad, pad_to=pad_to)
    if any(len(public_key) != 32 for public_key in recipients):
        raise ValueError("mixed recipient key families")
    for public_key in recipients:
        X25519PublicKey.from_public_bytes(public_key)
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
    """Open a strict DXE2/DXE3 envelope with its matching private-key family."""
    if len(recipient_priv) != 32:
        keypair = HybridKeyPair.from_private_bytes(recipient_priv)
        keypair._private_keys(_HYBRID_RECIPIENT)
        return unseal_hybrid(envelope, keypair, aad=aad)
    if len(envelope) < 4:
        raise ValueError("truncated envelope (missing magic)")
    if envelope[:4] != b"DXE2":
        raise ValueError("not a DXE2 multi-recipient envelope")
    i = 4
    if len(envelope) < i + 4:
        raise ValueError("truncated DXE2 envelope (missing body length)")
    body_len = int.from_bytes(envelope[i : i + 4], "big")
    if body_len < NONCE_BYTES + 16:
        raise ValueError("truncated DXE2 encrypted body")
    i += 4
    if len(envelope) < i + body_len + 2:
        raise ValueError("truncated DXE2 envelope (missing body or count)")
    body = envelope[i : i + body_len]
    i += body_len
    count = int.from_bytes(envelope[i : i + 2], "big")
    if count == 0:
        raise ValueError("DXE2 requires at least one recipient")
    i += 2
    slots: list[tuple[bytes, bytes]] = []
    last_error: Exception | None = None
    for _ in range(count):
        if len(envelope) < i + 34:
            raise ValueError("truncated DXE2 recipient slot")
        eph_pub = envelope[i : i + 32]
        i += 32
        wrap_len = int.from_bytes(envelope[i : i + 2], "big")
        if wrap_len != NONCE_BYTES + KEY_BYTES + 16:
            raise ValueError("malformed DXE2 wrapped content key size")
        i += 2
        if len(envelope) < i + wrap_len:
            raise ValueError("truncated DXE2 wrapped key")
        wrapped = envelope[i : i + wrap_len]
        i += wrap_len
        slots.append((eph_pub, wrapped))
    if i != len(envelope):
        raise ValueError("trailing bytes in DXE2 envelope")
    for eph_pub, wrapped in slots:
        try:
            content_key = _unwrap_key(eph_pub, wrapped, recipient_priv)
            return decrypt_with_key(body, content_key, aad=aad)
        except (ValueError, InvalidTag) as exc:
            last_error = exc
    raise ValueError("no recipient slot could be opened with this key") from last_error


__all__ = [
    "DEFAULT_SPIN_COUNT",
    "KDF_ARGON2ID",
    "KDF_PBKDF2",
    "KDF_SCRYPT",
    "KEY_BYTES",
    "NONCE_BYTES",
    "SALT_BYTES",
    "EncryptedPayload",
    "HybridKeyPair",
    "decrypt",
    "decrypt_with_key",
    "derive_key",
    "digest",
    "encrypt",
    "encrypt_with_key",
    "generate_hybrid_recipient_key",
    "generate_hybrid_signing_key",
    "generate_recipient_key",
    "generate_signing_key",
    "hybrid_sign",
    "hybrid_verify",
    "seal_hybrid",
    "seal_multi",
    "sign",
    "signing_algorithm",
    "signing_public_key",
    "unseal_hybrid",
    "unseal_multi",
    "validate_password_envelope",
    "verify",
]


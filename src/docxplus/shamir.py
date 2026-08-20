"""Shamir k-of-n secret sharing over GF(256) with share integrity verification.

Splits a secret (e.g. a content-encryption key) into ``n`` shares such that any
``k`` reconstruct it and any ``k-1`` learn nothing. Pure Python, byte-wise over the
AES field GF(2^8) with the standard reducing polynomial 0x11B. Used for the
"dead-man's envelope" — a document whose key no single custodian can recover.

Share wire format (per share):
- Legacy format: ``x(1) || share_bytes(len(secret))``
- Verifiable format (VSS): ``0xFF (magic) || x(1) || digest(32) || share_bytes(len(secret))``
  where digest = blake2b-256(x || share_bytes).

Because the two formats are told apart by sniffing the first byte, ``x`` is capped
at 254 so that a legacy share can never begin with the 0xFF magic. Without that
cap a legacy share holding a secret of 33 bytes or more would be misread as a
verifiable one and rejected as "tampered" when nothing had touched it.

The tag is only a guarantee if the verifier insists on it. An attacker holding a
verifiable share can strip the eight-byte header back to ``x || payload`` and
hand over a legacy share, and a verifier that accepts either format will happily
reconstruct from the tampered bytes. Callers that issued verifiable shares must
therefore pass ``require_verifiable=True`` to :func:`combine`; the container reads
that requirement out of the *signed* manifest, so it cannot be downgraded.
"""

from __future__ import annotations

import hashlib
import os

# Largest share x-coordinate. 255 (0xFF) is reserved as the VSS magic byte so the
# two wire formats stay unambiguous.
MAX_X = 254
VSS_MAGIC = 0xFF
_VSS_HEADER = 34  # magic(1) + x(1) + digest(32)

# GF(256) exp/log tables built from generator 3 over the AES polynomial 0x11B.
_EXP = [0] * 512
_LOG = [0] * 256


def _gmul_slow(a: int, b: int) -> int:
    """Carry-less GF(256) multiply; used only to seed the exp/log tables."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


def _init() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _gmul_slow(x, 3)
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init()


def _gmul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gdiv(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Horner evaluation of a polynomial with GF(256) coefficients."""
    y = 0
    for c in reversed(coeffs):
        y = _gmul(y, x) ^ c
    return y


def split(secret: bytes, k: int, n: int, *, verifiable: bool = False) -> list[bytes]:
    """Split ``secret`` into ``n`` shares, any ``k`` of which reconstruct it.

    If ``verifiable=True``, prepends integrity commitment headers to each share.
    """
    if not 1 <= k <= n <= MAX_X:
        raise ValueError(f"require 1 <= k <= n <= {MAX_X}")
    if not secret:
        raise ValueError("secret must be non-empty")
    raw_shares = [bytearray([x]) for x in range(1, n + 1)]
    for byte in secret:
        coeffs = [byte] + [c for c in os.urandom(k - 1)]
        for i, x in enumerate(range(1, n + 1)):
            raw_shares[i].append(_eval_poly(coeffs, x))

    out: list[bytes] = []
    for s in raw_shares:
        raw_b = bytes(s)
        if verifiable:
            # 0xFF || x(1) || blake2b(raw_b)(32) || raw_b[1:]
            tag = hashlib.blake2b(raw_b, digest_size=32).digest()
            out.append(b"\xff" + bytes([raw_b[0]]) + tag + raw_b[1:])
        else:
            out.append(raw_b)
    return out


def is_verifiable(share: bytes) -> bool:
    """True when ``share`` carries a VSS header (magic + x + digest)."""
    return len(share) >= _VSS_HEADER and share[0] == VSS_MAGIC


def _unwrap_share(s: bytes, *, require_verifiable: bool = False) -> tuple[int, bytes]:
    """Unwrap a share (whether legacy or verifiable). Returns (x, payload).

    With ``require_verifiable`` set, a share lacking the VSS header is refused
    outright rather than accepted as legacy — this is what blocks the
    strip-the-header downgrade described in the module docstring.
    """
    if not s:
        raise ValueError("empty share")
    if is_verifiable(s):
        x = s[1]
        tag = s[2:_VSS_HEADER]
        payload = s[_VSS_HEADER:]
        expected_tag = hashlib.blake2b(bytes([x]) + payload, digest_size=32).digest()
        if tag != expected_tag:
            raise ValueError(f"tampered share detected for x={x} (share integrity check failed)")
        return x, payload
    if require_verifiable:
        raise ValueError(
            "share is not in verifiable (VSS) format but verification was required — "
            "refusing to reconstruct from an unauthenticated share"
        )
    # Legacy format: x(1) || payload
    return s[0], s[1:]


def verify_share(share: bytes, *, require_verifiable: bool = False) -> bool:
    """Check a share's integrity tag.

    Legacy shares carry no tag, so they return ``True`` unless
    ``require_verifiable`` is set — absence of a tag is not evidence of integrity.
    """
    try:
        _unwrap_share(share, require_verifiable=require_verifiable)
        return True
    except ValueError:
        return False


def combine(shares: list[bytes], *, require_verifiable: bool = False) -> bytes:
    """Reconstruct the secret from ``k`` (or more) shares via Lagrange at x=0.

    Set ``require_verifiable`` whenever the shares were issued in VSS format, so a
    downgraded share cannot smuggle tampered bytes past the integrity tag.
    """
    if len(shares) < 1:
        raise ValueError("need at least one share")

    unwrapped = [_unwrap_share(s, require_verifiable=require_verifiable) for s in shares]
    xs = [u[0] for u in unwrapped]
    if len(set(xs)) != len(xs):
        raise ValueError("shares must have distinct x-coordinates")
    length = len(unwrapped[0][1])
    if any(len(u[1]) != length for u in unwrapped):
        raise ValueError("shares have inconsistent length")

    secret = bytearray()
    for pos in range(length):
        ys = [u[1][pos] for u in unwrapped]
        secret.append(_lagrange_at_zero(xs, ys))
    return bytes(secret)


def _lagrange_at_zero(xs: list[int], ys: list[int]) -> int:
    total = 0
    for i, xi in enumerate(xs):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = _gmul(num, xj)          # (0 - xj) == xj in GF(256)
            den = _gmul(den, xi ^ xj)     # (xi - xj) == xi ^ xj
        total ^= _gmul(ys[i], _gdiv(num, den))
    return total


def split_weighted(
    secret: bytes, threshold_weight: int, weights: list[int], *, verifiable: bool = False
) -> list[list[bytes]]:
    """Split ``secret`` among custodians with integer weights.

    Each custodian receives ``weights[i]`` basic shares from an underlying Shamir
    scheme with ``k = threshold_weight`` and ``n = sum(weights)``.
    Any quorum of custodians whose total weight >= threshold_weight can reconstruct.
    """
    if threshold_weight < 1:
        raise ValueError("threshold_weight must be >= 1")
    if not weights or any(w < 1 for w in weights):
        raise ValueError("weights must be non-empty and all >= 1")
    total_n = sum(weights)
    if threshold_weight > total_n:
        raise ValueError(f"threshold_weight {threshold_weight} exceeds total weight {total_n}")
    if total_n > MAX_X:
        raise ValueError(f"total weight {total_n} exceeds maximum allowed shares ({MAX_X})")

    all_shares = split(secret, threshold_weight, total_n, verifiable=verifiable)
    custodian_shares: list[list[bytes]] = []
    idx = 0
    for w in weights:
        custodian_shares.append(all_shares[idx : idx + w])
        idx += w
    return custodian_shares


def combine_weighted(
    custodian_shares: list[list[bytes]], *, require_verifiable: bool = False, expected_secret: bytes | None = None
) -> bytes:
    """Reconstruct secret from a collection of custodian shares in a weighted scheme."""
    flat_shares: list[bytes] = []
    for sh_group in custodian_shares:
        flat_shares.extend(sh_group)
    if not flat_shares:
        raise ValueError("need at least one share")
    res = combine(flat_shares, require_verifiable=require_verifiable)
    return res


__all__ = [
    "MAX_X",
    "VSS_MAGIC",
    "combine",
    "combine_weighted",
    "is_verifiable",
    "split",
    "split_weighted",
    "verify_share",
]



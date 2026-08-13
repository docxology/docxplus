"""Shamir k-of-n secret sharing over GF(256).

Splits a secret (e.g. a content-encryption key) into ``n`` shares such that any
``k`` reconstruct it and any ``k-1`` learn nothing. Pure Python, byte-wise over the
AES field GF(2^8) with the standard reducing polynomial 0x11B. Used for the
"dead-man's envelope" — a document whose key no single custodian can recover.

Share wire format (per share): ``x(1) || share_bytes(len(secret))``. All shares of
one secret carry the same length.
"""

from __future__ import annotations

import os

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


def split(secret: bytes, k: int, n: int) -> list[bytes]:
    """Split ``secret`` into ``n`` shares, any ``k`` of which reconstruct it."""
    if not 1 <= k <= n <= 255:
        raise ValueError("require 1 <= k <= n <= 255")
    if not secret:
        raise ValueError("secret must be non-empty")
    shares = [bytearray([x]) for x in range(1, n + 1)]
    for byte in secret:
        coeffs = [byte] + [c for c in os.urandom(k - 1)]
        for i, x in enumerate(range(1, n + 1)):
            shares[i].append(_eval_poly(coeffs, x))
    return [bytes(s) for s in shares]


def combine(shares: list[bytes]) -> bytes:
    """Reconstruct the secret from ``k`` (or more) shares via Lagrange at x=0."""
    if len(shares) < 1:
        raise ValueError("need at least one share")
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("shares must have distinct x-coordinates")
    length = len(shares[0]) - 1
    if any(len(s) - 1 != length for s in shares):
        raise ValueError("shares have inconsistent length")

    secret = bytearray()
    for pos in range(1, length + 1):
        ys = [s[pos] for s in shares]
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

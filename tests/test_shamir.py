"""Shamir k-of-n secret sharing over GF(256)."""

from __future__ import annotations

import pytest

import shamir


def test_split_combine_roundtrip():
    secret = b"a 32-byte content encryption key"
    shares = shamir.split(secret, k=3, n=5)
    assert len(shares) == 5
    assert shamir.combine(shares[:3]) == secret


def test_any_k_subset_reconstructs():
    secret = bytes(range(32))
    shares = shamir.split(secret, k=2, n=4)
    from itertools import combinations

    for subset in combinations(shares, 2):
        assert shamir.combine(list(subset)) == secret


def test_more_than_k_shares_also_works():
    secret = b"threshold"
    shares = shamir.split(secret, k=2, n=5)
    assert shamir.combine(shares) == secret


def test_fewer_than_k_shares_does_not_recover():
    secret = b"this must stay hidden below quorum"
    shares = shamir.split(secret, k=3, n=5)
    # Any 2 shares reconstruct *some* value, but not the secret.
    assert shamir.combine(shares[:2]) != secret


def test_distinct_x_required():
    shares = shamir.split(b"x", k=2, n=3)
    with pytest.raises(ValueError, match="distinct"):
        shamir.combine([shares[0], shares[0]])


def test_invalid_parameters():
    with pytest.raises(ValueError):
        shamir.split(b"x", k=3, n=2)
    with pytest.raises(ValueError):
        shamir.split(b"", k=2, n=3)


def test_inconsistent_share_length():
    shares = shamir.split(b"abc", k=2, n=3)
    with pytest.raises(ValueError, match="length"):
        shamir.combine([shares[0], shares[1][:-1]])


def test_gf_multiply_inverse_property():
    # a * (1/a) == 1 for all non-zero a, exercising exp/log tables.
    for a in range(1, 256):
        inv = shamir._gdiv(1, a)
        assert shamir._gmul(a, inv) == 1

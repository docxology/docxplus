"""Shamir k-of-n secret sharing over GF(256)."""

from __future__ import annotations

import pytest

import shamir
from shamir import combine, split, verify_share


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


def test_verifiable_shares_roundtrip():
    secret = b"cryptographic_key_32_bytes_len!!"
    shares = split(secret, 3, 5, verifiable=True)
    assert len(shares) == 5
    for s in shares:
        assert verify_share(s) is True

    # Reconstruct from subset
    recovered = combine([shares[0], shares[2], shares[4]])
    assert recovered == secret


def test_verifiable_share_tamper_detection():
    secret = b"top_secret_data"
    shares = split(secret, 2, 3, verifiable=True)

    # Tamper with share 1 payload byte
    tampered = bytearray(shares[0])
    tampered[-1] ^= 0x01
    tampered_b = bytes(tampered)

    assert verify_share(tampered_b) is False
    with pytest.raises(ValueError, match="tampered share detected"):
        combine([tampered_b, shares[1]])


# -- v0.6.2: VSS downgrade resistance and format disambiguation ---------------


def test_verifiable_share_downgrade_is_refused():
    """Stripping the VSS header must not launder a tampered share into a legacy one.

    Without `require_verifiable` the header can simply be removed, and the
    reconstruction silently returns the wrong secret.
    """
    secret = b"CONTENT-ENCRYPTION-KEY-32-BYTES!"
    shares = shamir.split(secret, 2, 3, verifiable=True)

    tampered = bytearray(shares[0])
    tampered[shamir._VSS_HEADER + 4] ^= 0xFF
    assert shamir.verify_share(bytes(tampered)) is False

    # x || payload — the same tampered bytes wearing the legacy format.
    downgraded = bytes([tampered[1]]) + bytes(tampered[shamir._VSS_HEADER:])
    assert shamir.is_verifiable(downgraded) is False

    # Permissive mode still accepts it (documented legacy behaviour) ...
    assert shamir.verify_share(downgraded) is True
    # ... and produces the wrong secret, which is exactly why the strict mode exists.
    assert shamir.combine([downgraded, shares[1]]) != secret

    # Strict mode refuses to reconstruct at all.
    assert shamir.verify_share(downgraded, require_verifiable=True) is False
    with pytest.raises(ValueError, match="not in verifiable"):
        shamir.combine([downgraded, shares[1]], require_verifiable=True)


def test_require_verifiable_still_reconstructs_genuine_vss_shares():
    secret = b"a real secret worth splitting"
    shares = shamir.split(secret, 3, 5, verifiable=True)
    assert shamir.combine(shares[:3], require_verifiable=True) == secret


def test_x_coordinate_is_capped_below_the_vss_magic():
    """n=255 would mint a legacy share starting with 0xFF and be misread as VSS."""
    with pytest.raises(ValueError, match="254"):
        shamir.split(b"secret", 2, 255)
    shares = shamir.split(b"x" * 40, 2, shamir.MAX_X)
    assert max(s[0] for s in shares) == shamir.MAX_X
    assert all(not shamir.is_verifiable(s) for s in shares)


def test_long_legacy_shares_are_never_misparsed_as_verifiable():
    """A 40-byte secret makes legacy shares long enough to trip the old sniffer."""
    secret = b"K" * 40
    shares = shamir.split(secret, 2, shamir.MAX_X)
    assert shamir.combine([shares[0], shares[-1]]) == secret


def test_container_threshold_shares_are_verifiable_and_required(tmp_path):
    """The shipped path must actually issue VSS shares and demand them on read."""
    from container import ContainerError, DocxPlusBuilder, DocxPlusReader

    builder = DocxPlusBuilder(paragraphs=["threshold"])
    builder.add_threshold("secret", b"classified payload", k=2, n=3)
    docx = builder.build()
    shares = builder.threshold_shares["secret"]

    assert all(shamir.is_verifiable(s) for s in shares)

    reader = DocxPlusReader.from_bytes(docx)
    assert reader.manifest.slot("secret").sealing["vss"] is True
    assert reader.extract("secret", shares=shares[:2]) == b"classified payload"

    # A downgraded share must be refused by the reader, not silently accepted.
    downgraded = bytes([shares[0][1]]) + bytes(shares[0][shamir._VSS_HEADER:])
    with pytest.raises(ContainerError):
        reader.extract("secret", shares=[downgraded, shares[1]])

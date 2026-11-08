"""Shamir k-of-n secret sharing over GF(256)."""

from __future__ import annotations

import pytest

from docxplus import shamir
from docxplus.shamir import combine, split, verify_share_checksum


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


def test_checksummed_shares_roundtrip():
    secret = b"cryptographic_key_32_bytes_len!!"
    shares = split(secret, 3, 5, checksummed=True)
    assert len(shares) == 5
    for s in shares:
        assert verify_share_checksum(s) is True

    # Reconstruct from subset
    recovered = combine([shares[0], shares[2], shares[4]])
    assert recovered == secret


def test_checksummed_share_tamper_detection():
    secret = b"top_secret_data"
    shares = split(secret, 2, 3, checksummed=True)

    # Tamper with share 1 payload byte
    tampered = bytearray(shares[0])
    tampered[-1] ^= 0x01
    tampered_b = bytes(tampered)

    assert verify_share_checksum(tampered_b) is False
    with pytest.raises(ValueError, match="tampered share detected"):
        combine([tampered_b, shares[1]])


# -- v0.6.2: checksum downgrade resistance and format disambiguation ---------------


def test_checksummed_share_downgrade_is_refused():
    """Stripping the checksum header must not launder a tampered share into a legacy one.

    Without `require_checksum` the header can simply be removed, and the
    reconstruction silently returns the wrong secret.
    """
    secret = b"CONTENT-ENCRYPTION-KEY-32-BYTES!"
    shares = shamir.split(secret, 2, 3, checksummed=True)

    tampered = bytearray(shares[0])
    tampered[shamir._CHECKSUM_HEADER + 4] ^= 0xFF
    assert shamir.verify_share_checksum(bytes(tampered)) is False

    # x || payload — the same tampered bytes wearing the legacy format.
    downgraded = bytes([tampered[1]]) + bytes(tampered[shamir._CHECKSUM_HEADER:])
    assert shamir.is_checksummed(downgraded) is False

    # Raw reconstruction remains explicit, but has no checksum to verify.
    assert shamir.verify_share_checksum(downgraded) is False
    # It produces the wrong secret, which is why strict combination exists.
    assert shamir.combine([downgraded, shares[1]]) != secret

    # Strict mode refuses to reconstruct at all.
    assert shamir.verify_share_checksum(downgraded) is False
    with pytest.raises(ValueError, match="not in checksummed"):
        shamir.combine([downgraded, shares[1]], require_checksum=True)


def test_require_checksum_still_reconstructs_genuine_checksummed_shares():
    secret = b"a real secret worth splitting"
    shares = shamir.split(secret, 3, 5, checksummed=True)
    assert shamir.combine(shares[:3], require_checksum=True) == secret


def test_x_coordinate_is_capped_below_the_checksum_magic():
    """n=255 would mint a legacy share starting with 0xFF and be misread as checksum."""
    with pytest.raises(ValueError, match="254"):
        shamir.split(b"secret", 2, 255)
    shares = shamir.split(b"x" * 40, 2, shamir.MAX_X)
    assert max(s[0] for s in shares) == shamir.MAX_X
    assert all(not shamir.is_checksummed(s) for s in shares)


def test_long_legacy_shares_are_never_misparsed_as_checksummed():
    """A 40-byte secret makes legacy shares long enough to trip the old sniffer."""
    secret = b"K" * 40
    shares = shamir.split(secret, 2, shamir.MAX_X)
    assert shamir.combine([shares[0], shares[-1]]) == secret


def test_container_threshold_shares_are_checksummed_and_required(tmp_path):
    """The shipped path must actually issue checksum shares and demand them on read."""
    from docxplus.container import ContainerError, DocxPlusBuilder, DocxPlusReader

    builder = DocxPlusBuilder(paragraphs=["threshold"])
    builder.add_threshold("secret", b"classified payload", k=2, n=3)
    docx = builder.build()
    shares = builder.threshold_shares["secret"]

    assert all(shamir.is_checksummed(s) for s in shares)

    reader = DocxPlusReader.from_bytes(docx)
    assert reader.manifest.slot("secret").sealing["checksummed_shares"] is True
    from docxplus.crypto import digest

    assert reader.manifest.slot("secret").sealing["share_digests"] == [digest(s) for s in shares]
    assert reader.extract("secret", shares=shares[:2]) == b"classified payload"

    # A downgraded share must be refused by the reader, not silently accepted.
    downgraded = bytes([shares[0][1]]) + bytes(shares[0][shamir._CHECKSUM_HEADER:])
    with pytest.raises(ContainerError):
        reader.extract("secret", shares=[downgraded, shares[1]])


def test_weighted_threshold_shares():
    """Verify split_weighted and combine_weighted under various quorum configurations."""
    secret = b"weighted multi-custodian secret"
    # Threshold weight = 4. Custodians: Board (weight 3), Auditor (weight 2), Trustee (weight 1). Total weight = 6.
    weights = [3, 2, 1]
    custodian_shares = shamir.split_weighted(secret, threshold_weight=4, weights=weights, checksummed=True)
    assert len(custodian_shares) == 3
    assert len(custodian_shares[0]) == 3
    assert len(custodian_shares[1]) == 2
    assert len(custodian_shares[2]) == 1

    # Board (3) + Trustee (1) = 4 >= 4 shares -> SUCCESS
    assert shamir.combine_weighted([custodian_shares[0], custodian_shares[2]], require_checksum=True) == secret

    # Board (3) + Auditor (2) = 5 >= 4 shares -> SUCCESS
    assert shamir.combine_weighted([custodian_shares[0], custodian_shares[1]], require_checksum=True) == secret

    # Auditor (2) + Trustee (1) = 3 shares < 4 threshold -> yields incorrect reconstructed secret (as expected with Shamir under-quorum)
    under_quorum_reconstruction = shamir.combine_weighted([custodian_shares[1], custodian_shares[2]], require_checksum=True)
    assert under_quorum_reconstruction != secret

    # Empty shares raises
    with pytest.raises(ValueError, match="need at least one share"):
        shamir.combine_weighted([])


def test_weighted_reconstruction_checks_an_explicit_expected_secret():
    """The expected_secret contract rejects wrong or below-quorum reconstructions."""
    secret = b"trusted expected secret"
    groups = shamir.split_weighted(secret, 3, [2, 1, 1], checksummed=True)
    assert shamir.combine_weighted(
        groups[:2], require_checksum=True, expected_secret=secret
    ) == secret
    with pytest.raises(ValueError):
        shamir.combine_weighted(
            groups[:2], require_checksum=True, expected_secret=b"not the secret"
        )
    with pytest.raises(ValueError):
        shamir.combine_weighted(
            [groups[-1]], require_checksum=True, expected_secret=secret
        )


def test_public_checksums_do_not_claim_issuer_authentication():
    """Anyone can recalculate a checksum; GCM independently rejects a wrong key."""
    import hashlib

    from cryptography.exceptions import InvalidTag

    from docxplus import crypto

    key = bytes(range(32))
    encrypted = crypto.encrypt_with_key(b"threshold confidentiality", key, aad=b"slot")
    shares = shamir.split(key, 2, 3, checksummed=True)
    changed = bytearray(shares[0])
    changed[-1] ^= 1
    changed[2:shamir._CHECKSUM_HEADER] = hashlib.blake2b(
        bytes([changed[1]]) + changed[shamir._CHECKSUM_HEADER:], digest_size=32
    ).digest()
    assert shamir.verify_share_checksum(bytes(changed))
    reconstructed = shamir.combine([bytes(changed), shares[1]], require_checksum=True)
    assert reconstructed != key
    with pytest.raises(InvalidTag):
        crypto.decrypt_with_key(encrypted, reconstructed, aad=b"slot")
    assert crypto.decrypt_with_key(
        encrypted, shamir.combine(shares[:2], require_checksum=True), aad=b"slot"
    ) == b"threshold confidentiality"


@pytest.mark.parametrize("malformed", [
    b"", b"\0x", b"\x01", b"\xff", b"\xff\x01" + b"x" * 32,
    b"\xff\0" + b"x" * 33, b"\xff\xff" + b"x" * 33,
])
def test_malformed_share_shapes_are_never_accepted(malformed):
    """Reserved/zero coordinates and empty payloads must not reconstruct."""
    assert not shamir.verify_share_checksum(malformed)
    for strict in (False, True):
        with pytest.raises(ValueError):
            shamir.combine([malformed], require_checksum=strict)


def test_checksums_are_optional_for_combination_but_required_for_verification():
    raw = shamir.split(b"secret", 2, 3)
    assert not shamir.is_checksummed(raw[0])
    assert not shamir.verify_share_checksum(raw[0])
    assert shamir.combine(raw[:2]) == b"secret"
    with pytest.raises(ValueError, match="checksum"):
        shamir.combine(raw[:2], require_checksum=True)


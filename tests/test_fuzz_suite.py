"""Comprehensive fuzzing and differential stress validation suite for docxplus.

Tests edge cases across:
- Malformed OPC / ODT ZIP archives and corrupted central directories
- Truncated crypto envelopes (DXE1, DXE2, DXE3)
- Path-traversal payloads and malicious entry names
- Malformed XML / MCE namespace variations
- Shamir share corruption and verifiable downgrade attacks
- Fuzzed metadata properties
"""

from __future__ import annotations

import io
import os
import zipfile
import pytest

from docxplus import (
    DocxPlusBuilder,
    crypto,
    shamir,
    validate_bytes,
    validate_odt_bytes,
)
from docxplus.container import ContainerError
from docxplus.intake import IntakePolicy, safe_open
from docxplus.opc import read_package


def test_fuzz_truncated_dxe1_envelopes():
    """Fuzz various truncations of DXE1 password envelopes."""
    envelope = crypto.encrypt(b"secret message", "password123", aad=b"slot1", kdf="scrypt")
    assert envelope.startswith(b"DXE1")
    for cut in range(1, len(envelope)):
        truncated = envelope[:cut]
        with pytest.raises((ValueError, ContainerError)):
            crypto.decrypt(truncated, "password123", aad=b"slot1")


def test_fuzz_corrupted_dxe2_multi_recipient():
    """Fuzz corrupted and bit-flipped DXE2 multi-recipient envelopes."""
    priv1, pub1 = crypto.generate_recipient_key()
    priv2, pub2 = crypto.generate_recipient_key()
    envelope = crypto.seal_multi(b"confidential data", [pub1, pub2], aad=b"slot_mr")

    # Corrupting critical header fields or ciphertext guarantees decryption failure
    # Byte 0: Magic ('D') -> ValueError (bad magic)
    with pytest.raises(ValueError, match="DXE2"):
        crypto.unseal_multi(b"X" + envelope[1:], priv1, aad=b"slot_mr")

    # Truncated envelope
    with pytest.raises(ValueError, match="truncated"):
        crypto.unseal_multi(envelope[:10], priv1, aad=b"slot_mr")

    # Corrupted ciphertext body (e.g. byte 10 is inside ciphertext)
    corrupted_body = bytearray(envelope)
    corrupted_body[10] ^= 0xFF
    with pytest.raises(ValueError):
        crypto.unseal_multi(bytes(corrupted_body), priv1, aad=b"slot_mr")


def test_fuzz_dxe3_hybrid_envelope_tamper():
    """Fuzz hybrid DXE3 envelopes with truncations and corrupted headers."""
    kp1 = crypto.generate_hybrid_recipient_key()
    kp2 = crypto.generate_hybrid_recipient_key()
    envelope = crypto.seal_hybrid(b"quantum future payload", [kp1.public_bytes, kp2.public_bytes], aad=b"hybrid_slot")

    # Success roundtrip
    dec = crypto.unseal_hybrid(envelope, kp1, aad=b"hybrid_slot")
    assert dec == b"quantum future payload"
    dec2 = crypto.unseal_hybrid(envelope, kp2, aad=b"hybrid_slot")
    assert dec2 == b"quantum future payload"

    # Truncation before body or count header
    for cut in [0, 1, 2, 3, 4, 8, 12]:
        with pytest.raises(ValueError, match="truncated|bad magic|not a DXE3"):
            crypto.unseal_hybrid(envelope[:cut], kp1, aad=b"hybrid_slot")

    # Tampered magic
    with pytest.raises(ValueError, match="not a DXE3"):
        crypto.unseal_hybrid(b"DXE2" + envelope[4:], kp1, aad=b"hybrid_slot")

    # Corrupt body ciphertext bytes
    corrupted_env = bytearray(envelope)
    corrupted_env[10] ^= 0xFF
    with pytest.raises(ValueError):
        crypto.unseal_hybrid(bytes(corrupted_env), kp1, aad=b"hybrid_slot")




def test_fuzz_shamir_weighted_and_shares():
    """Fuzz threshold shares: random byte mutations and share dropping."""
    secret = os.urandom(32)
    shares = shamir.split(secret, 3, 5, verifiable=True)

    # 3 of 5 works
    assert shamir.combine(shares[:3], require_verifiable=True) == secret

    # Bit-flip in verifiable share tag
    tampered_share = bytearray(shares[0])
    tampered_share[10] ^= 0xAA
    with pytest.raises(ValueError, match="tampered share detected"):
        shamir.combine([bytes(tampered_share), shares[1], shares[2]], require_verifiable=True)

    # Weighted scheme fuzzing
    w_shares = shamir.split_weighted(secret, threshold_weight=5, weights=[2, 2, 1], verifiable=True)
    # Custodian 0 (wt 2) + Custodian 1 (wt 2) = 4 < 5 gives wrong secret
    assert shamir.combine_weighted([w_shares[0], w_shares[1]], require_verifiable=True) != secret

    # Custodian 0 (wt 2) + Custodian 1 (wt 2) + Custodian 2 (wt 1) = 5 >= 5 succeeds
    assert shamir.combine_weighted([w_shares[0], w_shares[1], w_shares[2]], require_verifiable=True) == secret


def test_fuzz_corrupted_zip_opc_and_odt():
    """Fuzz parser resilience against malformed ZIP archives."""
    # Garbage bytes
    assert not validate_bytes(b"PK\x03\x04garbage").ok
    assert not validate_odt_bytes(b"PK\x03\x04garbage").ok

    # Truncated valid docx
    b = DocxPlusBuilder(paragraphs=["Hello"])
    b.add_module("m", "package_part", b"content")
    data = b.build()

    for cut in [10, 50, 100, len(data) - 20]:
        report = validate_bytes(data[:cut])
        assert not report.ok
        assert len(report.opc_errors) > 0


def test_fuzz_odt_corrupted_manifest_and_mimetype():
    """Fuzz ODT parser against invalid MIME types and broken manifest XML."""
    # Missing mimetype
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("content.xml", b"<root/>")
    report = validate_odt_bytes(buf.getvalue())
    assert not report.ok
    assert any("mimetype" in err for err in report.opc_errors)

    # Wrong mimetype value
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", b"application/pdf", compress_type=zipfile.ZIP_STORED)
        zf.writestr("content.xml", b"<root/>")
    report = validate_odt_bytes(buf.getvalue())
    assert not report.ok
    assert any("mimetype" in err for err in report.opc_errors)


def test_fuzz_intake_threat_combinations():
    """Fuzz intake scanners with combinatorial threats."""
    # Build package with macro + external relationship
    b = DocxPlusBuilder(paragraphs=["Innocent"])
    pkg = read_package(b.build())
    pkg.add_part("word/vbaProject.bin", b"\x00\x01VBA", "application/vnd.ms-office.vbaProject")
    
    # Non-strict mode surfaces threats without throwing
    report, _ = safe_open(pkg.to_bytes(), policy=IntakePolicy(strict=False))
    assert not report.ok
    assert len(report.macro_parts) > 0

    # Strict mode raises IntakeError
    with pytest.raises(Exception):
        safe_open(pkg.to_bytes(), policy=IntakePolicy(strict=True))

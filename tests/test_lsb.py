"""Pure-Python LSB codec: real embed/extract round-trips (needs Pillow)."""

from __future__ import annotations

import pytest

pytest.importorskip("PIL")

from conftest import pixels

from docxplus import lsb


def test_capacity_matches_formula():
    assert lsb.capacity_bytes(100, 100) == (100 * 100 * 3) // 8 - 8


def test_carrier_is_deterministic(tmp_path):
    p1 = lsb.make_carrier(tmp_path / "c1.png", (32, 32))
    p2 = lsb.make_carrier(tmp_path / "c2.png", (32, 32))
    assert p1.read_bytes() == p2.read_bytes()


@pytest.mark.parametrize("payload", [b"x", b"hello world", b'{"k": 1}' * 20])
def test_embed_extract_roundtrip(tmp_path, payload):
    carrier = lsb.make_carrier(tmp_path / "carrier.png", (128, 128))
    out = lsb.embed(carrier, payload, tmp_path / "stego.png")
    assert lsb.extract(out) == payload


def test_carrier_visually_close_to_original(tmp_path):
    from PIL import Image

    carrier = lsb.make_carrier(tmp_path / "carrier.png", (64, 64))
    orig = pixels(Image.open(carrier).convert("RGB"))
    stego = lsb.embed(carrier, b"secret payload", tmp_path / "stego.png")
    changed = pixels(Image.open(stego).convert("RGB"))
    # LSB flips differ by at most 1 per channel.
    assert all(abs(a - b) <= 1 for po, pn in zip(orig, changed) for a, b in zip(po, pn))


def test_payload_too_large_raises(tmp_path):
    carrier = lsb.make_carrier(tmp_path / "carrier.png", (16, 16))
    with pytest.raises(ValueError, match="too large"):
        lsb.embed(carrier, b"A" * 10_000, tmp_path / "out.png")


def test_extract_from_non_carrier_raises(tmp_path):
    plain = lsb.make_carrier(tmp_path / "plain.png", (32, 32))
    with pytest.raises(ValueError, match="no DXL1 payload"):
        lsb.extract(plain)


def _raw_header_carrier(path, size, header):
    """Write hostile DXL1 header bits directly, without the validating embedder."""
    from PIL import Image

    image = Image.new("RGB", size, (100, 100, 100))
    samples = [100] * (size[0] * size[1] * 3)
    for i in range(min(len(header) * 8, len(samples))):
        samples[i] |= (header[i // 8] >> (7 - i % 8)) & 1
    image.putdata([tuple(samples[i:i + 3]) for i in range(0, len(samples), 3)])
    image.save(path)
    return path


def test_dxl1_requires_full_header_even_when_magic_fits(tmp_path):
    """C20: a 63-bit image cannot silently supply a truncated uint32 length."""
    path = _raw_header_carrier(tmp_path / "short.png", (7, 3), b"DXL1\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="full DXL1 header"):
        lsb.extract(path)
    with pytest.raises(ValueError, match="too large"):
        lsb.embed(path, b"", tmp_path / "out.png")
    assert not (tmp_path / "out.png").exists()


@pytest.mark.parametrize("declared", [17, 2**32 - 1])
def test_declared_payload_must_fit_carrier_before_reading(tmp_path, declared):
    """C20: a valid magic cannot turn an overlength claim into truncated bytes."""
    path = _raw_header_carrier(
        tmp_path / "overlength.png", (8, 8), b"DXL1" + declared.to_bytes(4, "big")
    )
    with pytest.raises(ValueError, match="declared DXL1 payload exceeds carrier capacity"):
        lsb.extract(path)


def test_exact_capacity_and_one_byte_overflow(tmp_path):
    carrier = lsb.make_carrier(tmp_path / "c.png", (8, 8))
    payload = bytes(range(16))
    assert lsb.capacity_bytes(8, 8) == len(payload)
    assert lsb.extract(lsb.embed(carrier, payload, tmp_path / "exact.png")) == payload
    with pytest.raises(ValueError, match="too large"):
        lsb.embed(carrier, payload + b"x", tmp_path / "overflow.png")
    assert not (tmp_path / "overflow.png").exists()


def test_complete_empty_frame_with_partial_trailing_byte(tmp_path):
    """Only complete carrier bytes count toward the declared payload boundary."""
    carrier = lsb.make_carrier(tmp_path / "c.png", (11, 2))
    assert lsb.extract(lsb.embed(carrier, b"", tmp_path / "empty.png")) == b""
    malformed = _raw_header_carrier(
        tmp_path / "one-byte.png", (11, 2), b"DXL1\x00\x00\x00\x01"
    )
    with pytest.raises(ValueError, match="exceeds carrier capacity"):
        lsb.extract(malformed)


@pytest.mark.parametrize("size", [(0, 1), (1, 0), (-1, 1), (4001, 4000)])
def test_generated_carrier_dimensions_are_admitted_before_allocation(tmp_path, size):
    """The shared decoded-pixel budget also applies to generated carriers."""
    output = tmp_path / "oversized.png"
    with pytest.raises(ValueError, match="carrier pixel count"):
        lsb.make_carrier(output, size)
    assert not output.exists()


def test_oversized_png_header_refuses_before_pixel_decode(tmp_path):
    """Hostile dimensions must fail before converting a truncated pixel stream."""
    import struct
    import zlib

    from docxplus import steg_bridge

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    path = tmp_path / "oversized.png"
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 4001, 4000, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + chunk(b"IEND", b"")
    )
    with pytest.raises(ValueError, match="carrier pixel count"):
        lsb.embed(path, b"", tmp_path / "out.png")
    with pytest.raises(ValueError, match="carrier pixel count"):
        lsb.extract(path)
    with pytest.raises(ValueError, match="carrier pixel count"):
        steg_bridge.chi_square_lsb(path)
    assert not (tmp_path / "out.png").exists()


def test_streaming_byte_reader_requires_every_bit():
    """Even a partial final byte cannot be returned as recovered plaintext."""
    with pytest.raises(ValueError, match="truncated DXL1 payload"):
        lsb._read_bytes(iter([1] * 7), 1)

"""Pure-Python LSB codec: real embed/extract round-trips (needs Pillow)."""

from __future__ import annotations

import pytest

pytest.importorskip("PIL")

import lsb
from conftest import pixels


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

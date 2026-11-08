"""Deterministic statistical limitations and actual PNG carrier boundaries.

Pair equality is compatible with LSB replacement but is not proof of embedding:
an untouched balanced cover has p_value=1, and a supported low-entropy payload
can be compatible too. These controls do not establish natural-cover accuracy.
"""

from __future__ import annotations

import os

import pytest
from conftest import pixels
from PIL import Image

from docxplus import lsb, steg_bridge

#: Small enough to keep the suite fast, large enough that the chi-squared
#: approximation holds over the sample histogram.
CARRIER = (128, 128)


def _carrier(tmp_path, name="carrier.png"):
    return lsb.make_carrier(tmp_path / name, CARRIER)


def _capacity() -> int:
    return lsb.capacity_bytes(*CARRIER)


def _flat_carrier(tmp_path, name="flat.png"):
    path = tmp_path / name
    Image.new("RGB", CARRIER, (100, 100, 100)).save(path)
    return path


def test_untouched_balanced_cover_is_compatible_not_proof_of_embedding(tmp_path):
    """F4: a known cover yields the maximum compatibility p-value."""
    path = tmp_path / "balanced.png"
    image = Image.new("RGB", CARRIER)
    image.putdata([(100, 101, 100), (101, 100, 101)] * (CARRIER[0] * CARRIER[1] // 2))
    image.save(path)
    result = steg_bridge.chi_square_lsb(path)
    assert result["available"] is True
    assert result["chi2"] == 0.0
    assert result["dof"] == 1
    assert result["p_value"] == 1.0
    assert result["suspicious"] is True
    sweep = steg_bridge.chi_square_sweep(path)
    assert sweep["largest_flagged_prefix"] == 1.0
    with pytest.raises(ValueError, match="no DXL1 payload"):
        lsb.extract(path)


def test_tiny_and_sparse_images_are_unavailable(tmp_path):
    """An unsupported approximation must not become a completed negative."""
    for name, size, colour in [
        ("tiny", (1, 1), (100, 101, 100)),
        ("sparse", (16, 16), (100, 100, 100)),
    ]:
        path = tmp_path / f"{name}.png"
        image = Image.new("RGB", size, colour)
        if name == "sparse":
            image.putpixel((0, 0), (2, 100, 100))
        image.save(path)
        result = steg_bridge.chi_square_lsb(path)
        assert result["available"] is False
        assert result["p_value"] is None
        assert result["suspicious"] is False
        sweep = steg_bridge.chi_square_sweep(path)
        assert sweep["available"] is False
        assert sweep["max_p_value"] is None
        assert sweep["largest_flagged_prefix"] == 0.0


def test_asymmetric_cover_and_constant_zero_payload_are_not_compatible(tmp_path):
    """A real extractable payload can fail the pair-equality compatibility test."""
    carrier = _flat_carrier(tmp_path)
    payload = b"\x00" * _capacity()
    stego = lsb.embed(carrier, payload, tmp_path / "zero.png")
    assert lsb.extract(stego) == payload
    for path in (carrier, stego):
        result = steg_bridge.chi_square_lsb(path)
        assert result["available"] is True
        assert result["p_value"] < steg_bridge.SUSPICION_THRESHOLD
        assert result["suspicious"] is False
        sweep = steg_bridge.chi_square_sweep(path)
        assert sweep["largest_flagged_prefix"] == 0.0


def test_low_entropy_alternating_payload_can_be_compatible(tmp_path):
    """Compatibility does not establish encryption or high payload entropy."""
    carrier = _flat_carrier(tmp_path)
    payload = b"\x55" * _capacity()
    stego = lsb.embed(carrier, payload, tmp_path / "alternating.png")
    assert lsb.extract(stego) == payload
    result = steg_bridge.chi_square_lsb(stego)
    assert result["available"] is True
    assert result["p_value"] >= steg_bridge.SUSPICION_THRESHOLD
    assert result["suspicious"] is True


@pytest.mark.parametrize("fill", [0.25, 0.5])
def test_sweep_preserves_largest_flagged_prefix_for_sequential_control(tmp_path, fill):
    """A deterministic embedded prefix is visible before the asymmetric tail."""
    carrier = _flat_carrier(tmp_path)
    payload = b"\x55" * int(_capacity() * fill)
    stego = lsb.embed(carrier, payload, tmp_path / "partial.png")
    assert lsb.extract(stego) == payload
    assert steg_bridge.chi_square_lsb(stego)["suspicious"] is False
    sweep = steg_bridge.chi_square_sweep(stego, steps=20)
    assert sweep["available"] is True
    assert sweep["suspicious"] is True
    assert sweep["largest_flagged_prefix"] == fill
    assert sweep["largest_flagged_prefix"] == max(
        row["fraction"] for row in sweep["steps"] if row["suspicious"]
    )


# -- carrier fragility: what a downstream consumer destroys -------------------


def test_a_lossless_png_resave_preserves_the_payload(tmp_path):
    """Re-compression is not re-encoding: PNG is lossless, so the LSBs survive."""
    carrier = _carrier(tmp_path)
    payload = os.urandom(_capacity() // 2)
    stego = lsb.embed(carrier, payload, tmp_path / "s.png")
    Image.open(stego).save(tmp_path / "resaved.png", format="PNG", compress_level=1)
    assert lsb.extract(tmp_path / "resaved.png") == payload


@pytest.mark.parametrize("transform", ["jpeg", "resize"])
def test_a_lossy_transform_destroys_the_payload_and_fails_closed(tmp_path, transform):
    """Destroyed is acceptable; silently corrupt is not.

    A codec that returned whatever bytes survived would hand a caller a plausible-
    looking payload with no signal that it had been mangled. Refusing is the correct
    behaviour and is the half worth testing.
    """
    carrier = _carrier(tmp_path)
    payload = os.urandom(_capacity() // 2)
    stego = lsb.embed(carrier, payload, tmp_path / "s.png")
    image = Image.open(stego).convert("RGB")
    if transform == "jpeg":
        image.save(tmp_path / "t.jpg", format="JPEG", quality=95)
        Image.open(tmp_path / "t.jpg").save(tmp_path / "t.png", format="PNG")
    else:
        image.resize((64, 64)).resize(CARRIER).save(tmp_path / "t.png")
    with pytest.raises(ValueError):
        lsb.extract(tmp_path / "t.png")


# -- the embedding itself stays within one bit --------------------------------


def test_embedding_moves_only_the_least_significant_bit(tmp_path):
    """Anything above bit 0 is visible distortion, and the carrier is on display."""
    carrier = _carrier(tmp_path)
    stego = lsb.embed(carrier, os.urandom(_capacity()), tmp_path / "s.png")
    before = pixels(Image.open(carrier).convert("RGB"))
    after = pixels(Image.open(stego).convert("RGB"))
    assert all(
        (x >> 1) == (y >> 1)
        for pixel_a, pixel_b in zip(before, after)
        for x, y in zip(pixel_a, pixel_b)
    ), "embedding disturbed a bit above the LSB"

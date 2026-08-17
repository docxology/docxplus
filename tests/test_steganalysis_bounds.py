"""What the shipped steganalysis finds, what it misses, and what breaks a carrier.

The security model claims concealment is obfuscation rather than secrecy and offers
`analyze-carrier` as the way to check. A claim like that is only worth what its
boundary is worth, and the boundary here is sharp and counter-intuitive: the
chi-squared pairs-of-values attack keys on the histogram flattening that a **uniform**
bit stream causes, so it finds the sealed payloads that are already protected and
misses the unsealed low-entropy ones that are not.

That asymmetry is easy to state and easy to lose. Someone tuning the detector, or
swapping in a different one, could improve the average case and silently erase the
documented regime. These tests pin the regime itself, so the documentation and the
code cannot drift apart: if the detector ever does catch a constant-fill payload, the
test that says it does not will fail, and the docs must be rewritten deliberately.

Everything here embeds into a real PNG and reads it back. No mocks, no fixtures
standing in for a carrier.
"""

from __future__ import annotations

import os

import pytest
from PIL import Image

from docxplus import lsb
from docxplus import steg_bridge
from conftest import pixels

#: Small enough to keep the suite fast, large enough that the chi-squared
#: approximation holds over the sample histogram.
CARRIER = (128, 128)


def _carrier(tmp_path, name="carrier.png"):
    return lsb.make_carrier(tmp_path / name, CARRIER)


def _capacity() -> int:
    return lsb.capacity_bytes(*CARRIER)


# -- the detector finds what it is supposed to find ---------------------------


def test_a_clean_carrier_is_not_flagged(tmp_path):
    result = steg_bridge.chi_square_lsb(_carrier(tmp_path))
    assert not result["suspicious"], f"false positive on an untouched carrier: {result}"


def test_a_fully_embedded_random_payload_is_flagged(tmp_path):
    """The default path: docxplus seals modules, and ciphertext is uniform."""
    carrier = _carrier(tmp_path)
    stego = lsb.embed(carrier, os.urandom(_capacity()), tmp_path / "full.png")
    result = steg_bridge.chi_square_lsb(stego)
    assert result["suspicious"], f"missed a fully embedded random payload: {result}"


@pytest.mark.parametrize("fill", [0.25, 0.5])
def test_the_sweep_catches_partial_fills_the_whole_image_statistic_misses(tmp_path, fill):
    """A sequentially filled carrier hides in aggregate; the untouched tail dominates.

    Both halves of this are asserted, because the sweep only earns its place if the
    whole-image statistic genuinely fails on the same carrier.
    """
    carrier = _carrier(tmp_path)
    stego = lsb.embed(carrier, os.urandom(int(_capacity() * fill)), tmp_path / "part.png")
    assert not steg_bridge.chi_square_lsb(stego)["suspicious"], (
        "whole-image analysis caught a partial fill; the sweep's justification is gone "
        "and the manuscript's explanation of it is now wrong"
    )
    assert steg_bridge.chi_square_sweep(stego)["suspicious"], (
        f"the prefix sweep missed a {fill:.0%} fill"
    )


# -- and does not find what it cannot find ------------------------------------


@pytest.mark.parametrize(
    "name,payload_for",
    [
        ("ascii text", lambda n: (b"the quick brown fox jumps over the lazy dog. " * (n // 45 + 1))[:n]),
        ("constant fill", lambda n: b"\xA5" * n),
        ("zero fill", lambda n: b"\x00" * n),
    ],
)
def test_a_low_entropy_payload_is_not_detected_even_at_full_fill(tmp_path, name, payload_for):
    """The documented false-negative regime, pinned as measured behaviour.

    This is not the detector failing at its job; PoV analysis has no signal to read
    when the embedded bits are structured. It is pinned so the `security-model.md`
    statement that a clean verdict proves nothing stays true of the shipped code.
    """
    carrier = _carrier(tmp_path)
    stego = lsb.embed(carrier, payload_for(_capacity()), tmp_path / "low.png")
    whole = steg_bridge.chi_square_lsb(stego)
    sweep = steg_bridge.chi_square_sweep(stego)
    assert not whole["suspicious"] and not sweep["suspicious"], (
        f"the detector now catches a {name} payload. That is an improvement, but "
        f"docs/security-model.md, docs/channels.md, docs/cli.md and the manuscript all "
        f"state it does not. Update them, then update this test."
    )


def test_sealing_a_module_makes_it_more_detectable_not_less(tmp_path):
    """The trade the channel actually offers, stated as a comparison.

    Worth asserting because the intuition runs the other way: encrypting a payload
    protects its contents while making its *presence* maximally visible to this test.
    """
    carrier = _carrier(tmp_path)
    n = _capacity()
    sealed = lsb.embed(carrier, os.urandom(n), tmp_path / "sealed.png")
    plain = lsb.embed(carrier, b"\x00" * n, tmp_path / "plain.png")
    assert (
        steg_bridge.chi_square_lsb(sealed)["p_embedding"]
        > steg_bridge.chi_square_lsb(plain)["p_embedding"]
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

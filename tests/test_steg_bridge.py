"""Real CLI bridge interoperability and statistical tests over actual carriers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from docxplus import steg_bridge


def test_run_reports_nonzero_exit():
    """A real failed subprocess must raise rather than become success or absence."""
    tool = steg_bridge.StegTool(argv_prefix=(sys.executable,), cwd=None, kind="binary")
    with pytest.raises(steg_bridge.StegError):
        steg_bridge._run(tool, ["-c", "raise SystemExit(3)"])


@pytest.mark.requires_steganographer
def test_real_tool_roundtrip(tmp_path):
    if not steg_bridge.available():
        pytest.skip("steganographer CLI not built")
    pytest.importorskip("PIL")
    from docxplus import lsb

    carrier = lsb.make_carrier(tmp_path / "c.png", (128, 128))
    out = tmp_path / "s.png"
    steg_bridge.embed_payload(carrier, b"real packet", out)
    assert steg_bridge.extract_payload(out, tmp_path / "o.bin") == b"real packet"


@pytest.mark.requires_steganographer
def test_real_tool_analyze(tmp_path):
    """Real CLI envelopes must not leak into the public analysis dictionary."""
    if not steg_bridge.available():
        pytest.skip("steganographer CLI not built")
    pytest.importorskip("PIL")
    from docxplus import lsb

    carrier = lsb.make_carrier(tmp_path / "c.png", (128, 128))
    out = tmp_path / "s.png"
    steg_bridge.embed_payload(carrier, b"payload for steganalysis", out)

    res = steg_bridge.analyze_carrier(out)
    assert isinstance(res["detected"], bool)
    assert isinstance(res["analysis_type"], str)


@pytest.mark.requires_steganographer
def test_real_tool_analyze_failure_propagates(tmp_path):
    """A present CLI rejecting a missing carrier must never become a report."""
    if not steg_bridge.available():
        pytest.skip("steganographer CLI not built")
    with pytest.raises(steg_bridge.StegError):
        steg_bridge.analyze_carrier(tmp_path / "missing.png")


# -- statistical steganalysis (pure Python, always available) -----------------
#
# Every test below runs the real detector over real PNG carriers produced by the
# real `lsb` backend at known embedding rates. Nothing is stubbed: the ground
# truth is the payload actually written into the pixels.


def _textured_carrier(path: Path, size: tuple[int, int] = (96, 96)) -> Path:
    """A smooth analytic carrier whose LSBs carry structure, not noise.

    A per-pixel-random image would already have flat pairs-of-values histograms
    and so would look "embedded" before anything was embedded; the detector must
    be exercised against a carrier with genuine PoV asymmetry.
    """
    import math

    from PIL import Image

    width, height = size
    img = Image.new("RGB", size)
    px = img.load()
    for y in range(height):
        for x in range(width):
            px[x, y] = (
                max(0, min(255, int(127 + 100 * math.sin(x / 23.0) * math.cos(y / 31.0)))),
                max(0, min(255, int(127 + 90 * math.sin((x + y) / 19.0)))),
                max(0, min(255, int(127 + 80 * math.cos((x - y) / 27.0)))),
            )
    img.save(path, format="PNG")
    return path


def test_chi_square_sf_matches_known_critical_values():
    # The textbook 0.05 critical points; if the incomplete-gamma implementation
    # drifts, every p_embedding derived from it is silently wrong.
    assert steg_bridge.chi_square_sf(3.841, 1) == pytest.approx(0.05, abs=1e-3)
    assert steg_bridge.chi_square_sf(5.991, 2) == pytest.approx(0.05, abs=1e-3)
    assert steg_bridge.chi_square_sf(0.0, 5) == 1.0
    assert steg_bridge.chi_square_sf(-1.0, 5) == 1.0


def test_chi_square_sf_rejects_bad_dof():
    with pytest.raises(ValueError, match="dof"):
        steg_bridge.chi_square_sf(1.0, 0)


def test_clean_carrier_is_not_flagged(tmp_path):
    pytest.importorskip("PIL")
    carrier = _textured_carrier(tmp_path / "clean.png")
    result = steg_bridge.chi_square_lsb(carrier)
    assert result["suspicious"] is False
    assert result["p_embedding"] < 0.5
    assert result["dof"] > 1


def test_fully_embedded_carrier_is_flagged(tmp_path):
    pytest.importorskip("PIL")
    import os

    from docxplus import lsb

    carrier = _textured_carrier(tmp_path / "clean.png")
    payload = os.urandom(lsb.capacity_bytes(96, 96))
    stego = lsb.embed(carrier, payload, tmp_path / "stego.png")

    result = steg_bridge.chi_square_lsb(stego)
    assert result["suspicious"] is True
    assert result["p_embedding"] > steg_bridge.SUSPICION_THRESHOLD


def test_sweep_localizes_partial_sequential_embedding(tmp_path):
    """A half-filled carrier hides from whole-image analysis but not from the sweep."""
    pytest.importorskip("PIL")
    import os

    from docxplus import lsb

    carrier = _textured_carrier(tmp_path / "clean.png")
    payload = os.urandom(lsb.capacity_bytes(96, 96) // 2)
    stego = lsb.embed(carrier, payload, tmp_path / "half.png")

    # The untouched tail dominates the aggregate histogram, so the whole-image
    # test alone would miss this payload entirely.
    assert steg_bridge.chi_square_lsb(stego)["suspicious"] is False

    sweep = steg_bridge.chi_square_sweep(stego, steps=10)
    assert sweep["suspicious"] is True
    # ~half the carrier is occupied; the estimate should land near that, and must
    # not claim the whole carrier is full.
    assert 0.3 <= sweep["embedded_fraction_estimate"] <= 0.7


def test_sweep_is_quiet_on_a_clean_carrier(tmp_path):
    pytest.importorskip("PIL")
    carrier = _textured_carrier(tmp_path / "clean.png")
    sweep = steg_bridge.chi_square_sweep(carrier, steps=8)
    assert sweep["suspicious"] is False
    assert sweep["embedded_fraction_estimate"] == 0.0
    assert len(sweep["steps"]) == 8


def test_sweep_detection_grows_with_payload_size(tmp_path):
    """More payload must never read as *less* occupancy."""
    pytest.importorskip("PIL")
    import os

    from docxplus import lsb

    capacity = lsb.capacity_bytes(96, 96)
    estimates = []
    for fraction in (0.25, 0.5, 1.0):
        carrier = _textured_carrier(tmp_path / f"c{fraction}.png")
        stego = lsb.embed(
            carrier, os.urandom(int(capacity * fraction)), tmp_path / f"s{fraction}.png"
        )
        estimates.append(steg_bridge.chi_square_sweep(stego)["embedded_fraction_estimate"])
    assert estimates == sorted(estimates), estimates
    assert estimates[-1] > estimates[0]


def test_chi_square_rejects_invalid_prefix(tmp_path):
    pytest.importorskip("PIL")
    carrier = _textured_carrier(tmp_path / "c.png")
    for bad in (0.0, -0.1, 1.5):
        with pytest.raises(ValueError, match="prefix"):
            steg_bridge.chi_square_lsb(carrier, prefix=bad)
    with pytest.raises(ValueError, match="steps"):
        steg_bridge.chi_square_sweep(carrier, steps=1)


def test_steganalysis_report_runs_without_the_rust_toolchain(tmp_path, monkeypatch):
    """The verdict must not depend on an optional binary being installed."""
    pytest.importorskip("PIL")
    import os

    from docxplus import lsb

    monkeypatch.setattr(steg_bridge, "locate", lambda repo=None: None)
    carrier = _textured_carrier(tmp_path / "c.png")
    stego = lsb.embed(carrier, os.urandom(lsb.capacity_bytes(96, 96)), tmp_path / "s.png")

    report = steg_bridge.steganalysis_report(stego)
    assert report["external_available"] is False
    assert report["external_analysis"] is None
    assert report["suspicious"] is True
    assert report["chi_square"]["p_embedding"] > steg_bridge.SUSPICION_THRESHOLD


def test_steg_bridge_gamma_and_tool_not_found(tmp_path):
    """Cover incomplete gamma edge cases and missing tool branches."""
    # Test lower gamma and upper gamma evaluation directly
    assert steg_bridge._lower_gamma_series(1.0, 0.5) > 0.0
    assert steg_bridge._upper_gamma_cf(1.0, 100.0) >= 0.0

    # Test StegTool run failure when executable doesn't exist
    fake_tool = steg_bridge.StegTool(argv_prefix=("/nonexistent/steganographer-cli",), cwd=None, kind="binary")
    with pytest.raises(steg_bridge.StegError, match="cannot execute"):
        steg_bridge._run(fake_tool, ["analyze", str(tmp_path / "c.png")])


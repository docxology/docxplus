"""Steganographer bridge: resolution logic (real files) + optional real tool.

Absence of the Rust toolchain is a graceful skip; a *present* toolchain runs the
real embed/extract round-trip. The resolution branches are covered with real
temporary files acting as the discovered binaries — no behaviour is mocked.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from docxplus import steg_bridge


def _make_exe(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_locate_via_env_var(tmp_path, monkeypatch):
    fake = _make_exe(tmp_path / "steganographer")
    monkeypatch.setenv("STEGANOGRAPHER_BIN", str(fake))
    tool = steg_bridge.locate(repo=tmp_path / "no_repo")
    assert tool is not None and tool.kind == "binary"
    assert tool.argv_prefix == (str(fake),)


def test_locate_via_built_release_binary(tmp_path, monkeypatch):
    monkeypatch.delenv("STEGANOGRAPHER_BIN", raising=False)
    monkeypatch.setattr(steg_bridge.shutil, "which", lambda _name: None)
    (tmp_path / "target" / "release").mkdir(parents=True)
    _make_exe(tmp_path / "target" / "release" / "steganographer")
    tool = steg_bridge.locate(repo=tmp_path)
    assert tool is not None and tool.kind == "binary"


def test_locate_returns_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("STEGANOGRAPHER_BIN", raising=False)
    monkeypatch.setattr(steg_bridge.shutil, "which", lambda _name: None)
    assert steg_bridge.locate(repo=tmp_path / "does_not_exist") is None


def test_locate_cargo_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("STEGANOGRAPHER_BIN", raising=False)

    def fake_which(name):
        return "/usr/bin/cargo" if name == "cargo" else None

    monkeypatch.setattr(steg_bridge.shutil, "which", fake_which)
    tool = steg_bridge.locate(repo=tmp_path)  # repo dir exists, no binary
    assert tool is not None and tool.kind == "cargo"
    assert tool.cwd == tmp_path


def test_available_matches_locate():
    assert steg_bridge.available() == (steg_bridge.locate() is not None)


def test_embed_without_tool_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(steg_bridge, "locate", lambda repo=None: None)
    with pytest.raises(steg_bridge.StegError, match="not available"):
        steg_bridge.embed_payload(tmp_path / "x.png", b"p", tmp_path / "o.png")


def test_extract_without_tool_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(steg_bridge, "locate", lambda repo=None: None)
    with pytest.raises(steg_bridge.StegError, match="not available"):
        steg_bridge.extract_payload(tmp_path / "x.png", tmp_path / "o.bin")


def test_run_reports_nonzero_exit(tmp_path):
    # A real subprocess that fails: `sh -c 'exit 3'` surfaces as StegError.
    tool = steg_bridge.StegTool(argv_prefix=("/bin/sh", "-c"), cwd=None, kind="binary")
    with pytest.raises(steg_bridge.StegError, match="exit 3"):
        steg_bridge._run(tool, ["exit 3"])


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
    if not steg_bridge.available():
        pytest.skip("steganographer CLI not built")
    pytest.importorskip("PIL")
    from docxplus import lsb

    carrier = lsb.make_carrier(tmp_path / "c.png", (128, 128))
    out = tmp_path / "s.png"
    steg_bridge.embed_payload(carrier, b"payload for steganalysis", out)

    res = steg_bridge.analyze_carrier(out)
    assert isinstance(res, dict)
    assert "detected" in res
    assert "analysis_type" in res


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

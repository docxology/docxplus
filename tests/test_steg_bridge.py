"""Real subprocess, Rust packet-capacity and RGB statistical contracts."""

from __future__ import annotations

import subprocess
import sys

import pytest

from docxplus import steg_bridge


def test_run_reports_nonzero_exit():
    """A failed subprocess must not become success or backend absence."""
    tool = steg_bridge.StegTool((sys.executable,), None, "binary")
    with pytest.raises(steg_bridge.StegError, match="exit 3"):
        steg_bridge._run(tool, ["-c", "raise SystemExit(3)"])


def test_run_normalizes_real_timeout():
    """BRIDGE001: preserve the actual TimeoutExpired as the chained cause."""
    tool = steg_bridge.StegTool((sys.executable,), None, "binary")
    with pytest.raises(steg_bridge.StegError, match="timed out") as caught:
        steg_bridge._run(tool, ["-c", "import time; time.sleep(60)"], timeout=0.05)
    assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)


def test_run_missing_executable(tmp_path):
    tool = steg_bridge.StegTool((str(tmp_path / "missing"),), None, "binary")
    with pytest.raises(steg_bridge.StegError, match="cannot execute") as caught:
        steg_bridge._run(tool, ["analyze"])
    assert isinstance(caught.value.__cause__, FileNotFoundError)


def _real_tool():
    tool = steg_bridge.locate()
    if tool is None:
        pytest.skip("steganographer CLI not built")
    return tool


@pytest.mark.requires_steganographer
@pytest.mark.parametrize("signed", [False, True])
def test_real_capacity_exact_embedding_boundary(tmp_path, signed):
    """C22: Rust sizing and encode agree despite random temporary payload names."""
    pytest.importorskip("PIL")
    from docxplus import lsb

    tool = _real_tool()
    key = None
    if signed:
        steg_bridge._run(tool, ["keygen", "--output", str(tmp_path / "signer")])
        key = tmp_path / "signer.key"
    carrier = lsb.make_carrier(tmp_path / "cover.png", (64, 48))
    result = steg_bridge.capacity(64 * 48 * 3, signing_key=key, tool=tool)
    assert result["signed"] is signed
    assert result["filename"] == "payload.bin"
    assert result["mime_type"] == "application/octet-stream"
    assert result["bits"] == 1
    assert result["max_packet_bytes"] == 64 * 48 * 3 // 8
    payload = bytes(range(256)) * (result["max_payload_bytes"] // 256 + 1)
    payload = payload[:result["max_payload_bytes"]]
    out = tmp_path / "stego.png"
    steg_bridge.embed_payload(carrier, payload, out, signing_key=key, tool=tool)
    assert steg_bridge.extract_payload(out, tmp_path / "decoded.bin", tool=tool) == payload
    with pytest.raises(steg_bridge.StegError):
        steg_bridge.embed_payload(
            carrier, payload + b"x", tmp_path / "too-large.png", signing_key=key, tool=tool
        )
    assert not (tmp_path / "too-large.png").exists()


@pytest.mark.requires_steganographer
def test_real_capacity_rejects_framing_shortfall_and_bad_key(tmp_path):
    """Framing failure is not a success-shaped zero-byte capacity."""
    tool = _real_tool()
    with pytest.raises(steg_bridge.StegError):
        steg_bridge.capacity(3, tool=tool)
    bad_key = tmp_path / "bad.key"
    bad_key.write_bytes(b"not a signing key")
    with pytest.raises(steg_bridge.StegError):
        steg_bridge.capacity(100_000, signing_key=bad_key, tool=tool)


@pytest.mark.requires_steganographer
def test_real_optional_signing_is_separate_from_identity_pinning(tmp_path):
    """Signed packets round-trip, but only the actual pinned identity is trusted."""
    pytest.importorskip("PIL")
    from docxplus import lsb

    tool = _real_tool()
    for name in ("alice", "bob"):
        steg_bridge._run(tool, ["keygen", "--output", str(tmp_path / name)])
    carrier = lsb.make_carrier(tmp_path / "c.png", (64, 64))
    stego = tmp_path / "signed.png"
    steg_bridge.embed_payload(
        carrier, b"signed packet", stego, signing_key=tmp_path / "alice.key", tool=tool
    )
    def pinned_decode(image, key, output):
        return steg_bridge._run(tool, [
            "decode", "--input", str(image), "--output", str(output),
            "--stego-type", "lsb_video", "--input-format", "png",
            "--trusted-signer", key.read_text().strip(),
        ])
    with pytest.raises(steg_bridge.StegError):
        pinned_decode(stego, tmp_path / "bob.pub", tmp_path / "wrong.bin")
    assert not (tmp_path / "wrong.bin").exists()
    pinned_decode(stego, tmp_path / "alice.pub", tmp_path / "trusted.bin")
    assert (tmp_path / "trusted.bin").read_bytes() == b"signed packet"
    unsigned = tmp_path / "unsigned.png"
    steg_bridge.embed_payload(carrier, b"unsigned packet", unsigned, tool=tool)
    with pytest.raises(steg_bridge.StegError):
        pinned_decode(unsigned, tmp_path / "alice.pub", tmp_path / "untrusted.bin")
    assert not (tmp_path / "untrusted.bin").exists()


@pytest.mark.requires_steganographer
def test_real_tool_analyze(tmp_path):
    """The public dictionary unwraps the actual CLI analysis envelope."""
    pytest.importorskip("PIL")
    from docxplus import lsb

    tool = _real_tool()
    carrier = lsb.make_carrier(tmp_path / "c.png", (128, 128))
    result = steg_bridge.analyze_carrier(carrier, tool=tool)
    assert isinstance(result["detected"], bool)
    assert isinstance(result["analysis_type"], str)
    with pytest.raises(steg_bridge.StegError):
        steg_bridge.analyze_carrier(tmp_path / "missing.png", tool=tool)


def test_chi_square_sf_matches_known_critical_values():
    assert steg_bridge.chi_square_sf(3.841, 1) == pytest.approx(0.05, abs=1e-3)
    assert steg_bridge.chi_square_sf(5.991, 2) == pytest.approx(0.05, abs=1e-3)
    assert steg_bridge.chi_square_sf(0.0, 5) == 1.0
    assert steg_bridge._lower_gamma_series(1.0, 0.5) > 0.0
    assert steg_bridge._upper_gamma_cf(1.0, 100.0) >= 0.0
    with pytest.raises(ValueError, match="dof"):
        steg_bridge.chi_square_sf(1.0, 0)


def test_paired_pearson_statistic_has_one_dof_per_populated_pair():
    """Both cells contribute: (30-20)^2/20 + (10-20)^2/20 = 10."""
    hist = [30, 10, 20, 20] + [0] * 252
    chi2, dof, p_value = steg_bridge._chi_square_from_histogram(hist)
    assert chi2 == 10.0
    assert dof == 2
    # Chi-square with two degrees of freedom has survival exp(-x/2).
    import math

    assert p_value == pytest.approx(math.exp(-5.0))


@pytest.mark.parametrize("hist", [
    [0] * 256,
    [30, 30] + [0] * 254,
    [100, 100, 1, 0] + [0] * 252,
])
def test_unsupported_histogram_is_unavailable(hist):
    assert steg_bridge._chi_square_from_histogram(hist) == (0.0, 0, None)


def test_steganalysis_report_without_toolchain(tmp_path, monkeypatch):
    """Environment isolation exercises real lookup; no dependency is mocked."""
    pytest.importorskip("PIL")
    from PIL import Image

    monkeypatch.delenv("STEGANOGRAPHER_BIN", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    carrier = tmp_path / "balanced.png"
    image = Image.new("RGB", (16, 16))
    image.putdata([(100, 101, 100), (101, 100, 101)] * 128)
    image.save(carrier)
    report = steg_bridge.steganalysis_report(carrier)
    assert report["external_available"] is False
    assert report["external_analysis"] is None
    assert report["available"] is True
    assert report["chi_square"]["p_value"] == 1.0
    assert report["suspicious"] is True  # Untouched cover, not proof of embedding.


def test_chi_square_rejects_invalid_prefix(tmp_path):
    for bad in (0.0, -0.1, 1.5):
        with pytest.raises(ValueError, match="prefix"):
            steg_bridge.chi_square_lsb(tmp_path / "unused.png", prefix=bad)
    with pytest.raises(ValueError, match="steps"):
        steg_bridge.chi_square_sweep(tmp_path / "unused.png", steps=1)



def test_run_has_no_inherited_standard_input():
    """A media helper must not consume interactive or carried stdin."""
    tool = steg_bridge.StegTool((sys.executable,), None, "binary")
    proc = steg_bridge._run(
        tool, ["-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"]
    )
    assert proc.stdout == b""


@pytest.mark.parametrize("kind", ["empty", "missing", "directory", "nonexecutable"])
def test_invalid_explicit_binary_refuses_without_discovery_fallback(tmp_path, monkeypatch, kind):
    """Explicit invalid configuration is failure, not optional-tool absence."""
    candidate = tmp_path / "tool"
    if kind == "directory":
        candidate.mkdir()
    elif kind == "nonexecutable":
        candidate.write_bytes(b"not executable")
        candidate.chmod(0o600)
    monkeypatch.setenv("STEGANOGRAPHER_BIN", "" if kind == "empty" else str(candidate))
    with pytest.raises(steg_bridge.StegError, match="invalid STEGANOGRAPHER_BIN"):
        steg_bridge.locate()


def test_discovery_resolves_explicit_executable(tmp_path, monkeypatch):
    from pathlib import Path

    monkeypatch.setenv("STEGANOGRAPHER_BIN", sys.executable)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    tool = steg_bridge.locate()
    assert tool == steg_bridge.StegTool((str(Path(sys.executable).resolve()),), None, "binary")


def test_explicit_repo_requires_built_executable_without_cargo_fallback(tmp_path, monkeypatch):
    """A source checkout never grants permission to build or run dependency code."""
    from pathlib import Path

    monkeypatch.delenv("STEGANOGRAPHER_BIN", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    repo = tmp_path / "source"
    repo.mkdir()
    (repo / "Cargo.toml").write_text("[workspace]\n")
    assert steg_bridge.locate() is None
    with pytest.raises(steg_bridge.StegError, match="no built steganographer"):
        steg_bridge.locate(repo)
    candidate = repo / "target" / "release" / "steganographer"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"not executable")
    candidate.chmod(0o600)
    with pytest.raises(steg_bridge.StegError, match="invalid steganographer executable"):
        steg_bridge.locate(repo)
    candidate.unlink()
    candidate.symlink_to(Path(sys.executable).resolve())
    assert steg_bridge.locate(repo) == steg_bridge.StegTool(
        (str(Path(sys.executable).resolve()),), None, "binary"
    )
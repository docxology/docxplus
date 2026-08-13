"""Steganographer bridge: resolution logic (real files) + optional real tool.

Absence of the Rust toolchain is a graceful skip; a *present* toolchain runs the
real embed/extract round-trip. The resolution branches are covered with real
temporary files acting as the discovered binaries — no behaviour is mocked.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

import steg_bridge


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
    import lsb

    carrier = lsb.make_carrier(tmp_path / "c.png", (128, 128))
    out = tmp_path / "s.png"
    steg_bridge.embed_payload(carrier, b"real packet", out)
    assert steg_bridge.extract_payload(out, tmp_path / "o.bin") == b"real packet"

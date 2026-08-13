"""CLI v0.2 commands: project pack/unpack, graph, x25519 keygen, threshold."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "docxplus_cli.py"


def _run(args, **kw):
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, **kw)


def test_project_build_and_unpack(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.py").write_text("X = 1\n")
    docx = tmp_path / "out.docx"

    built = _run(["build", str(docx), "--project", f"source:{proj}", "--password", "pw"])
    assert built.returncode == 0, built.stderr

    graph = _run(["graph", str(docx)])
    assert graph.returncode == 0
    assert "source" in graph.stdout and "project" in graph.stdout

    dest = tmp_path / "unpacked"
    up = _run(["unpack-project", str(docx), "source", str(dest), "--password", "pw"])
    assert up.returncode == 0, up.stderr
    assert (dest / "src" / "m.py").read_text() == "X = 1\n"


def test_keygen_x25519_and_multi_recipient(tmp_path):
    key = tmp_path / "rk.hex"
    assert _run(["keygen", str(key), "--type", "x25519"]).returncode == 0
    pub = (tmp_path / "rk.hex.pub").read_text().strip()

    payload = tmp_path / "p.bin"
    payload.write_bytes(b"referee draft")
    docx = tmp_path / "r.docx"
    built = _run(["build", str(docx), "--module", f"m:package_part:{payload}", "--recipient", pub])
    assert built.returncode == 0, built.stderr

    out = tmp_path / "got.bin"
    got = _run(["extract", str(docx), "m", "--private-key", str(key), "--out", str(out)])
    assert got.returncode == 0, got.stderr
    assert out.read_bytes() == b"referee draft"


def test_threshold_build_writes_shares_and_extracts(tmp_path):
    payload = tmp_path / "s.bin"
    payload.write_bytes(b"vault code")
    docx = tmp_path / "t.docx"
    shares_dir = tmp_path / "shares"
    built = _run([
        "build", str(docx), "--module", f"vault:package_part:{payload}",
        "--threshold", "2:3", "--shares-dir", str(shares_dir),
    ])
    assert built.returncode == 0, built.stderr
    shares = sorted(shares_dir.glob("vault.share*.bin"))
    assert len(shares) == 3

    out = tmp_path / "v.bin"
    got = _run([
        "extract", str(docx), "vault", "--out", str(out),
        "--share", str(shares[0]), "--share", str(shares[1]),
    ])
    assert got.returncode == 0, got.stderr
    assert out.read_bytes() == b"vault code"


def test_graph_shows_signature_and_merkle(tmp_path):
    key = tmp_path / "sk.hex"
    _run(["keygen", str(key)])
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    docx = tmp_path / "g.docx"
    _run(["build", str(docx), "--module", f"a:custom_xml:{payload}", "--signing-key", str(key)])
    graph = _run(["graph", str(docx)])
    assert "signature: valid" in graph.stdout
    assert "merkle_root" in graph.stdout

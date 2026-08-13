"""CLI smoke tests via subprocess (no mocks; real files)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "docxplus_cli.py"


def _run(args, **kw):
    return subprocess.run(
        [sys.executable, str(CLI), *args], capture_output=True, text=True, **kw
    )


def test_build_inspect_extract_validate(tmp_path):
    payload = tmp_path / "brief.json"
    payload.write_text('{"priority": 1}')
    docx = tmp_path / "out.docx"

    built = _run(["build", str(docx), "--text", "Hello", "--module", f"brief:custom_xml:{payload}"])
    assert built.returncode == 0, built.stderr
    assert docx.exists()

    inspected = _run(["inspect", str(docx)])
    assert inspected.returncode == 0
    assert "brief" in inspected.stdout

    out = tmp_path / "extracted.json"
    extracted = _run(["extract", str(docx), "brief", "--out", str(out)])
    assert extracted.returncode == 0
    assert out.read_text() == '{"priority": 1}'

    validated = _run(["validate", str(docx)])
    assert validated.returncode == 0
    assert '"ok": true' in validated.stdout


def test_keygen_and_signed_build(tmp_path):
    key = tmp_path / "key.hex"
    assert _run(["keygen", str(key)]).returncode == 0
    assert key.exists() and (tmp_path / "key.hex.pub").exists()

    payload = tmp_path / "p.bin"
    payload.write_bytes(b"data")
    docx = tmp_path / "signed.docx"
    built = _run(
        [
            "build",
            str(docx),
            "--module",
            f"m:package_part:{payload}",
            "--signing-key",
            str(key),
        ]
    )
    assert built.returncode == 0, built.stderr
    inspected = _run(["inspect", str(docx)])
    assert '"signature": "valid"' in inspected.stdout


def test_encrypted_build_and_extract(tmp_path):
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"top secret")
    docx = tmp_path / "enc.docx"
    _run(
        [
            "build",
            str(docx),
            "--module",
            f"s:package_part:{payload}",
            "--password",
            "pw",
        ]
    )
    out = tmp_path / "dec.bin"
    ok = _run(["extract", str(docx), "s", "--out", str(out), "--password", "pw"])
    assert ok.returncode == 0
    assert out.read_bytes() == b"top secret"

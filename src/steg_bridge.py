"""Bridge to the docxology/steganographer Rust CLI.

The steganographer embeds a signed (BLAKE3 + Ed25519) payload into the
least-significant bits of a PNG carrier via its opt-in *generic packet* channel
(``encode --payload-file`` / ``decode``). DOCX+ uses it as the media-stego
channel: the intelligence rides inside the LSBs of an image that is *itself* a
visible part of the document (``word/media/``).

Availability is optional and best-effort. Per the operational rule against
masking a failing external tool, we never swallow a real error into a silent
no-op: :func:`available` reports honestly, and a genuine encode/decode failure
raises :class:`StegError`. Only *absence* of the toolchain is a graceful skip.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Sibling checkout produced by `git clone` into projects/ongoing/DAF/steganographer.
_DEFAULT_REPO = Path(__file__).resolve().parents[2] / "steganographer"


class StegError(RuntimeError):
    """A real failure of the steganographer toolchain (not mere absence)."""


@dataclass(frozen=True)
class StegTool:
    """A resolved way to invoke the steganographer CLI."""

    argv_prefix: tuple[str, ...]
    cwd: Path | None
    kind: str  # "binary" | "cargo"


def locate(repo: Path | None = None) -> StegTool | None:
    """Find a runnable steganographer CLI, or ``None`` if unavailable.

    Resolution order: an explicit ``STEGANOGRAPHER_BIN`` env var, a
    ``steganographer`` binary on ``PATH``, a built ``target/release`` binary in
    the sibling repo, then ``cargo run`` in the repo if Cargo is present.
    """
    env_bin = os.environ.get("STEGANOGRAPHER_BIN")
    if env_bin and Path(env_bin).exists():
        return StegTool((env_bin,), None, "binary")

    on_path = shutil.which("steganographer")
    if on_path:
        return StegTool((on_path,), None, "binary")

    root = repo or _DEFAULT_REPO
    for profile in ("release", "debug"):
        candidate = root / "target" / profile / "steganographer"
        if candidate.exists():
            return StegTool((str(candidate),), None, "binary")

    if root.exists() and shutil.which("cargo"):
        return StegTool(
            ("cargo", "run", "--quiet", "--release", "-p", "steganographer-cli", "--"),
            root,
            "cargo",
        )
    return None


def available(repo: Path | None = None) -> bool:
    """True when a steganographer CLI can be invoked."""
    return locate(repo) is not None


def _run(tool: StegTool, args: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    proc = subprocess.run(  # noqa: S603 - argv is fully constructed, no shell
        [*tool.argv_prefix, *args],
        cwd=str(tool.cwd) if tool.cwd else None,
        capture_output=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise StegError(
            f"steganographer {args[0]} failed (exit {proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace')[:2000]}"
        )
    return proc


def embed_payload(
    carrier_png: Path,
    payload: bytes,
    out_png: Path,
    *,
    signing_key: Path | None = None,
    tool: StegTool | None = None,
) -> Path:
    """Embed ``payload`` bytes into ``carrier_png`` LSBs → ``out_png``."""
    resolved = tool or locate()
    if resolved is None:
        raise StegError("steganographer CLI not available")
    import tempfile

    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as tmp:
        tmp.write(payload)
        payload_path = Path(tmp.name)
    try:
        args = [
            "encode",
            "--input",
            str(carrier_png),
            "--output",
            str(out_png),
            "--stego-type",
            "lsb_video",
            "--input-format",
            "png",
            "--payload-file",
            str(payload_path),
        ]
        if signing_key is not None:
            args += ["--signing-key", str(signing_key)]
        _run(resolved, args)
    finally:
        payload_path.unlink(missing_ok=True)
    return out_png


def extract_payload(
    stego_png: Path, out_path: Path, *, tool: StegTool | None = None
) -> bytes:
    """Extract a generic-packet payload from ``stego_png`` → ``out_path`` bytes."""
    resolved = tool or locate()
    if resolved is None:
        raise StegError("steganographer CLI not available")
    _run(
        resolved,
        [
            "decode",
            "--input",
            str(stego_png),
            "--output",
            str(out_path),
            "--stego-type",
            "lsb_video",
            "--input-format",
            "png",
            "--force",
        ],
    )
    return out_path.read_bytes()

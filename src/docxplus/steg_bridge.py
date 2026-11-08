"""Bridge to the docxology/steganographer Rust CLI.

The steganographer embeds a BLAKE3-checked payload into the least-significant bits
of a PNG carrier via its opt-in *generic packet* channel. Packets are unsigned and
non-ECC by default; a supplied signing key enables Ed25519 signing. The media
channel's intelligence rides inside the LSBs of an image that is *itself* a
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
from itertools import islice
from pathlib import Path


class StegError(RuntimeError):
    """A real failure of the steganographer toolchain (not mere absence)."""


@dataclass(frozen=True)
class StegTool:
    """A resolved way to invoke the steganographer CLI."""

    argv_prefix: tuple[str, ...]
    cwd: Path | None
    kind: str  # "binary"


def locate(repo: Path | None = None) -> StegTool | None:
    """Resolve only an explicitly configured binary, PATH, or explicit repo.

    A repository argument permits already-built release/debug binaries only;
    dependency source is never compiled or executed through Cargo. Missing
    default discovery returns ``None``; invalid explicit configuration raises.
    """
    env_bin = os.environ.get("STEGANOGRAPHER_BIN")
    if env_bin is not None:
        candidate = Path(env_bin)
        if not env_bin or not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise StegError(f"invalid STEGANOGRAPHER_BIN executable: {env_bin!r}")
        return StegTool((str(candidate.resolve()),), None, "binary")

    on_path = shutil.which("steganographer")
    if on_path:
        return StegTool((str(Path(on_path).resolve()),), None, "binary")

    if repo is not None:
        for profile in ("release", "debug"):
            candidate = Path(repo) / "target" / profile / "steganographer"
            if candidate.exists():
                if not candidate.is_file() or not os.access(candidate, os.X_OK):
                    raise StegError(f"invalid steganographer executable: {candidate}")
                return StegTool((str(candidate.resolve()),), None, "binary")
        raise StegError(f"no built steganographer executable in explicit repo: {repo}")
    return None


def available(repo: Path | None = None) -> bool:
    """True when a steganographer CLI can be invoked."""
    return locate(repo) is not None


def _run(tool: StegTool, args: list[str], timeout: float = 600) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(
            [*tool.argv_prefix, *args],
            cwd=str(tool.cwd) if tool.cwd else None,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise StegError(
            f"steganographer {args[0]} timed out after {timeout} seconds"
        ) from exc
    except OSError as exc:
        raise StegError(f"cannot execute steganographer tool {tool.argv_prefix!r}: {exc}") from exc
    if proc.returncode != 0:
        raise StegError(
            f"steganographer {args[0]} failed (exit {proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace')[:2000]}"
        )
    return proc


def capacity(
    carrier_units: int,
    *,
    signing_key: Path | None = None,
    tool: StegTool | None = None,
) -> dict:
    """Ask Rust for exact sequential RGB capacity, including packet overhead.

    Metadata and signing policy match :func:`embed_payload`. A carrier too small
    for framing, an absent backend, or an invalid response raises ``StegError``.
    """
    import json

    resolved = tool or locate()
    if resolved is None:
        raise StegError("steganographer CLI not available")
    args = [
        "capacity", "--carrier-units", str(carrier_units),
        "--stego-type", "lsb_video", "--bits", "1",
        "--filename", "payload.bin", "--mime-type", "application/octet-stream",
        "--format", "json",
    ]
    if signing_key is not None:
        args += ["--signing-key", str(signing_key)]
    proc = _run(resolved, args)
    try:
        envelope = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StegError(f"failed to parse capacity output: {exc}") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != "steganographer.cli/v1"
        or envelope.get("command") != "capacity"
        or envelope.get("status") != "success"
    ):
        raise StegError("invalid steganographer capacity success envelope")
    result = envelope.get("result")
    if not isinstance(result, dict):
        raise StegError("invalid steganographer capacity result")
    for name in ("max_payload_bytes", "max_packet_bytes", "packet_overhead_bytes",
                 "carrier_units", "bits"):
        if type(result.get(name)) is not int or result[name] < 0:
            raise StegError(f"invalid steganographer capacity field: {name}")
    if (
        result["carrier_units"] != carrier_units
        or result["bits"] != 1
        or result.get("signed") is not (signing_key is not None)
        or result.get("filename") != "payload.bin"
        or result.get("mime_type") != "application/octet-stream"
        or result["max_packet_bytes"] > carrier_units // 8
        or result["max_payload_bytes"] + result["packet_overhead_bytes"]
        != result["max_packet_bytes"]
    ):
        raise StegError("inconsistent steganographer capacity result")
    return result



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
            "--filename",
            "payload.bin",
            "--mime-type",
            "application/octet-stream",
            "--bits",
            "1",
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


# -- statistical steganalysis (pure Python, no external toolchain) -----------
#
# The Rust CLI's `analyze` command is optional, so a docxplus carrier could ship
# with no steganalysis at all whenever the binary is absent. These functions
# close that gap with the classic chi-squared attack on LSB replacement, which
# needs nothing beyond Pillow and therefore always runs.

# Populated pairs below this expected count cannot support the approximation.
MIN_EXPECTED_COUNT = 5
# Upper-tail compatibility cutoff for equal-frequency adjacent value pairs.
SUSPICION_THRESHOLD = 0.05


def _lower_gamma_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a, x) by series expansion (x < a+1)."""
    import math

    ap = a
    total = delta = 1.0 / a
    for _ in range(1000):
        ap += 1
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-14:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _upper_gamma_cf(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) by continued fraction (x >= a+1)."""
    import math

    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi_square_sf(chi2: float, dof: int) -> float:
    """Upper-tail probability P(X² > ``chi2``) for ``dof`` degrees of freedom.

    Implemented directly (no SciPy dependency) as the regularized upper incomplete
    gamma Q(dof/2, chi2/2). Verified against the standard critical values: the
    0.05 points 3.841 at 1 dof and 5.991 at 2 dof both return 0.050.
    """
    if dof < 1:
        raise ValueError("dof must be >= 1")
    if chi2 <= 0:
        return 1.0
    a, x = dof / 2.0, chi2 / 2.0
    return 1.0 - _lower_gamma_series(a, x) if x < a + 1.0 else _upper_gamma_cf(a, x)


def _samples(carrier_png: Path) -> bytes:
    """Return bounded RGB samples in the exact order :mod:`lsb` writes bits."""
    from .lsb import _open_rgb

    with _open_rgb(carrier_png) as img:
        return img.tobytes()


def _chi_square_from_histogram(hist: list[int]) -> tuple[float, int, float | None]:
    """Pearson equal-frequency statistic over adjacent pairs (2i, 2i+1).

    Each populated pair contributes one degree of freedom. An expected count
    below five makes the approximation unavailable, not a negative observation.
    High p-values mean compatibility with pair equalization, not embedding.
    """
    if sum(hist) < 64:
        return 0.0, 0, None
    chi2 = 0.0
    pairs = 0
    for i in range(128):
        observed, partner = hist[2 * i], hist[2 * i + 1]
        total = observed + partner
        if total == 0:
            continue
        if total / 2.0 < MIN_EXPECTED_COUNT:
            return 0.0, 0, None
        chi2 += (observed - partner) ** 2 / total
        pairs += 1
    if pairs == 0:
        return 0.0, 0, None
    return chi2, pairs, chi_square_sf(chi2, pairs)


def chi_square_lsb(carrier_png: Path, *, prefix: float = 1.0) -> dict:
    """Report pair-equality compatibility over the first carrier ``prefix``.

    ``p_value`` is an upper-tail reference probability, not an embedding
    probability. ``available=False`` and ``p_value=None`` mean the histogram
    cannot support the chi-square approximation. Balanced untouched covers can
    be flagged; neither a flag nor its absence proves payload presence/absence.
    """
    if not 0.0 < prefix <= 1.0:
        raise ValueError("prefix must be in (0, 1]")
    values = _samples(carrier_png)
    count = max(1, int(len(values) * prefix))
    hist = [0] * 256
    for v in islice(values, count):
        hist[v] += 1
    chi2, dof, p = _chi_square_from_histogram(hist)
    return {
        "chi2": chi2,
        "dof": dof,
        "p_value": p,
        "available": p is not None,
        "suspicious": p is not None and p >= SUSPICION_THRESHOLD,
        "samples": count,
    }


def chi_square_sweep(carrier_png: Path, *, steps: int = 10) -> dict:
    """Report compatibility over increasing sequential prefixes.

    ``largest_flagged_prefix`` is the largest tested fraction compatible with
    pair equalization. It is heuristic evidence, not a payload-extent estimate:
    untouched covers can have the same histogram, and repeated prefix tests are
    not calibrated as an independent detection procedure.
    """
    if steps < 2:
        raise ValueError("steps must be >= 2")
    values = _samples(carrier_png)
    total = len(values)
    fractions = [(i + 1) / steps for i in range(steps)]

    # One pass over the samples, accumulating the histogram across boundaries,
    # rather than re-reading the image once per prefix.
    hist = [0] * 256
    results: list[dict] = []
    cursor = 0
    samples = iter(values)
    for frac in fractions:
        boundary = max(1, int(total * frac))
        for v in islice(samples, boundary - cursor):
            hist[v] += 1
        cursor = boundary
        chi2, dof, p = _chi_square_from_histogram(hist)
        results.append(
            {"fraction": frac, "chi2": chi2, "dof": dof, "p_value": p,
             "available": p is not None,
             "suspicious": p is not None and p >= SUSPICION_THRESHOLD}
        )

    flagged = [r["fraction"] for r in results if r["suspicious"]]
    return {
        "steps": results,
        "suspicious": bool(flagged),
        "available": any(r["available"] for r in results),
        "max_p_value": max(
            (r["p_value"] for r in results if r["available"]), default=None
        ),
        "largest_flagged_prefix": max(flagged) if flagged else 0.0,
    }


def steganalysis_report(
    carrier_png: Path, *, tool: StegTool | None = None, steps: int = 10
) -> dict:
    """Report Python pair-equality compatibility and optional Rust telemetry.

    ``suspicious`` is a statistical flag, never proof of an embedded payload.
    Availability is explicit; missing tools are unavailable, while a real
    failure of a present tool raises. Rust analyzes encoded PNG file bytes,
    unlike Python's decoded RGB samples, so the observations are not equivalent.
    """
    whole = chi_square_lsb(carrier_png)
    sweep = chi_square_sweep(carrier_png, steps=steps)
    report = {
        "carrier": str(carrier_png),
        "chi_square": whole,
        "chi_square_sweep": sweep,
        "suspicious": whole["suspicious"] or sweep["suspicious"],
        "available": whole["available"] or sweep["available"],
        "external_analysis": None,
        "external_available": False,
    }
    resolved = tool or locate()
    if resolved is not None:
        report["external_available"] = True
        report["external_analysis"] = analyze_carrier(carrier_png, tool=resolved)
    return report


def analyze_carrier(
    carrier_png: Path,
    *,
    analysis_type: str = "combined",
    tool: StegTool | None = None,
) -> dict:
    """Return the analysis result from the versioned steganographer CLI envelope.

    The public dictionary contains ``detected`` and ``analysis_type``, not CLI
    envelope metadata. Invalid contracts and nonzero tool exits raise ``StegError``.
    """
    import json
    resolved = tool or locate()
    if resolved is None:
        raise StegError("steganographer CLI not available")
    proc = _run(
        resolved,
        [
            "analyze",
            "--input",
            str(carrier_png),
            "--analysis-type",
            analysis_type,
            "--format",
            "json",
        ],
    )
    try:
        envelope = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StegError(f"failed to parse analyze output: {exc}") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != "steganographer.cli/v1"
        or envelope.get("command") != "analyze"
        or envelope.get("status") != "success"
    ):
        raise StegError("invalid steganographer analyze success envelope")
    result = envelope.get("result")
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("detected"), bool)
        or not isinstance(result.get("analysis_type"), str)
    ):
        raise StegError("invalid steganographer analyze result")
    return result


__all__ = [
    "SUSPICION_THRESHOLD",
    "StegError",
    "StegTool",
    "analyze_carrier",
    "available",
    "capacity",
    "chi_square_lsb",
    "chi_square_sf",
    "chi_square_sweep",
    "embed_payload",
    "extract_payload",
    "locate",
    "steganalysis_report",
]


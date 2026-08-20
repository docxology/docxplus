"""Bridge to the docxology/steganographer Rust CLI.

The steganographer embeds a signed (BLAKE3 + Ed25519) payload into the
least-significant bits of a PNG carrier via its opt-in *generic packet* channel
(``encode --payload-file`` / ``decode``). docxplus uses it as the media-stego
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
    try:
        proc = subprocess.run(
            [*tool.argv_prefix, *args],
            cwd=str(tool.cwd) if tool.cwd else None,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        raise StegError(f"cannot execute steganographer tool {tool.argv_prefix!r}: {exc}") from exc
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


# -- statistical steganalysis (pure Python, no external toolchain) -----------
#
# The Rust CLI's `analyze` command is optional, so a docxplus carrier could ship
# with no steganalysis at all whenever the binary is absent. These functions
# close that gap with the classic chi-squared attack on LSB replacement, which
# needs nothing beyond Pillow and therefore always runs.

# Below this expected-count the chi-squared approximation stops being valid, so
# the pair is dropped from the statistic rather than inflating it.
MIN_EXPECTED_COUNT = 5
# p(embedding) at or above which a carrier is reported suspicious.
SUSPICION_THRESHOLD = 0.95


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


def _samples(carrier_png: Path) -> list[int]:
    """Flatten an RGB image into the sample order :mod:`lsb` writes bits in."""
    from PIL import Image

    img = Image.open(carrier_png).convert("RGB")
    width, height = img.size
    px = img.load()
    return [c for y in range(height) for x in range(width) for c in px[x, y]]


def _chi_square_from_histogram(hist: list[int]) -> tuple[float, int, float]:
    """Westfeld-Pfitzmann statistic over pairs-of-values (2i, 2i+1).

    LSB replacement drives the counts of each PoV pair together, so a *low* chi²
    (counts nearly equal) is the evidence of embedding — the returned p is the
    probability of embedding, not a conventional significance level.
    """
    chi2 = 0.0
    pairs = 0
    for i in range(128):
        observed, partner = hist[2 * i], hist[2 * i + 1]
        expected = (observed + partner) / 2.0
        if expected < MIN_EXPECTED_COUNT:
            continue
        chi2 += (observed - expected) ** 2 / expected
        pairs += 1
    if pairs < 2:
        # Too few populated pairs to say anything; report "no evidence".
        return chi2, 0, 0.0
    dof = pairs - 1
    return chi2, dof, chi_square_sf(chi2, dof)


def chi_square_lsb(carrier_png: Path, *, prefix: float = 1.0) -> dict:
    """Chi-squared LSB-replacement test over the first ``prefix`` of the carrier.

    Returns ``{chi2, dof, p_embedding, suspicious, samples}``. ``p_embedding``
    near 1.0 means the sample histogram has been flattened the way LSB embedding
    flattens it; near 0.0 means the carrier's natural PoV asymmetry is intact.
    """
    if not 0.0 < prefix <= 1.0:
        raise ValueError("prefix must be in (0, 1]")
    values = _samples(carrier_png)
    count = max(1, int(len(values) * prefix))
    hist = [0] * 256
    for v in values[:count]:
        hist[v] += 1
    chi2, dof, p = _chi_square_from_histogram(hist)
    return {
        "chi2": chi2,
        "dof": dof,
        "p_embedding": p,
        "suspicious": p >= SUSPICION_THRESHOLD,
        "samples": count,
    }


def chi_square_sweep(carrier_png: Path, *, steps: int = 10) -> dict:
    """Sweep increasing prefixes to detect *and localize* sequential embedding.

    :func:`lsb.embed` fills the carrier from the first pixel and stops when the
    payload runs out, so a partially-filled carrier looks clean in aggregate: the
    untouched tail dominates the histogram and hides the payload. Testing growing
    initial fractions is the standard answer — the point where p collapses marks
    the end of the embedded region, which also estimates the payload extent.
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
    for frac in fractions:
        boundary = max(1, int(total * frac))
        for v in values[cursor:boundary]:
            hist[v] += 1
        cursor = boundary
        chi2, dof, p = _chi_square_from_histogram(hist)
        results.append(
            {"fraction": frac, "chi2": chi2, "dof": dof, "p_embedding": p,
             "suspicious": p >= SUSPICION_THRESHOLD}
        )

    flagged = [r["fraction"] for r in results if r["suspicious"]]
    return {
        "steps": results,
        "suspicious": bool(flagged),
        "max_p_embedding": max((r["p_embedding"] for r in results), default=0.0),
        # The largest still-suspicious prefix approximates how much of the
        # carrier the payload occupies; 0.0 when nothing looks embedded.
        "embedded_fraction_estimate": max(flagged) if flagged else 0.0,
    }


def steganalysis_report(
    carrier_png: Path, *, tool: StegTool | None = None, steps: int = 10
) -> dict:
    """Combined carrier verdict: always-available statistics, plus tool telemetry.

    The pure-Python chi-squared results are authoritative for the verdict; the
    external steganographer's ``analyze`` output is attached when the binary is
    present and reported as unavailable when it is not. Absence is a graceful
    skip, but a genuine failure of a *present* tool still raises.
    """
    whole = chi_square_lsb(carrier_png)
    sweep = chi_square_sweep(carrier_png, steps=steps)
    report = {
        "carrier": str(carrier_png),
        "chi_square": whole,
        "chi_square_sweep": sweep,
        "suspicious": whole["suspicious"] or sweep["suspicious"],
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
    """Run steganalysis on ``carrier_png`` via steganographer's ``analyze`` command."""
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
        return json.loads(proc.stdout.decode("utf-8"))
    except Exception as exc:
        raise StegError(f"failed to parse analyze output: {exc}") from exc


__all__ = [
    "SUSPICION_THRESHOLD",
    "StegError",
    "StegTool",
    "analyze_carrier",
    "available",
    "chi_square_lsb",
    "chi_square_sf",
    "chi_square_sweep",
    "embed_payload",
    "extract_payload",
    "locate",
    "steganalysis_report",
]


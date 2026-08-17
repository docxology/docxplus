"""Resolve project root and standard output directories."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def project_root() -> Path:
    return _ROOT


def output_dirs() -> dict[str, Path]:
    """Return the standard output directories (disposable, regeneratable)."""
    output = _ROOT / "output"
    return {
        "output": output,
        "documents": output / "documents",
        "figures": output / "figures",
        "data": output / "data",
        "reports": output / "reports",
    }


def ensure_output_dirs() -> dict[str, Path]:
    dirs = output_dirs()
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs

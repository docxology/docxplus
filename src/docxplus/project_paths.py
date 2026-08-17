"""Resolve project root and standard output directories."""

from __future__ import annotations

from pathlib import Path

# src/docxplus/project_paths.py -> src/docxplus -> src -> repo root.
# Counting parents is brittle across a package move (this file gained a level when
# the modules were namespaced), so the root is identified by what a checkout
# actually contains rather than by depth. An installed copy has no checkout above
# it, and falls back to the working directory, which is the only sane answer there.
def _find_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "pyproject.toml").is_file() and (candidate / "manuscript").is_dir():
            return candidate
    return Path.cwd()


_ROOT = _find_root()


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

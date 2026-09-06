"""The manuscript plate builders, tested where they live now.

These plates were untestable while they lived in ``scripts/build_figures.py`` —
the coverage gate measures ``src/``, not that directory. Extracted to
``docxplus.manuscript_figures``, the contract they must hold is pinned here:
each plate renders from ``manuscript_vars`` values alone, writes a real PNG to
exactly the path it is given, and is byte-deterministic across runs.
"""

from __future__ import annotations

import hashlib

import pytest

pytest.importorskip("matplotlib")

from docxplus import manuscript_figures, manuscript_vars


@pytest.fixture(scope="module")
def v() -> dict:
    return manuscript_vars.variables(include_dossier=False)


def _digest(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_trust_ladder_renders_deterministically(tmp_path, v):
    out = tmp_path / "trust_ladder.png"
    manuscript_figures.build_trust_ladder(out, v)
    first = _digest(out)
    manuscript_figures.build_trust_ladder(out, v)
    assert first == _digest(out)
    assert out.stat().st_size > 1_000


def test_fidelity_figure_renders_without_a_harness_report(tmp_path, v):
    """Absent report -> the figure still renders, visibly empty (its stated contract)."""
    out = tmp_path / "roundtrip_fidelity.png"
    manuscript_figures.build_fidelity_figure(out, v, None)
    assert out.stat().st_size > 1_000


def test_byte_labels_use_binary_prefixes():
    assert manuscript_figures._fmt(512) == "512 B"
    assert manuscript_figures._fmt(2048) == "2.0 KiB"
    assert manuscript_figures._fmt(3 * 1024 * 1024) == "3.0 MiB"

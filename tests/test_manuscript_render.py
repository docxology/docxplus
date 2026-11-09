"""The manuscript gate fails closed when the PDF toolchain is absent."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "render_manuscript", ROOT / "scripts" / "render_manuscript.py"
)
render = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(render)


def test_missing_pdf_tools_names_each_absent_executable(monkeypatch):
    monkeypatch.setattr(render.shutil, "which", lambda name: None)
    assert render.missing_pdf_tools({"pdf_engine": "xelatex"}) == [
        "pandoc", "pandoc-crossref", "xelatex",
    ]


def test_missing_pdf_tools_is_empty_when_the_toolchain_is_present(monkeypatch):
    monkeypatch.setattr(render.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert render.missing_pdf_tools({"pdf_engine": "xelatex"}) == []


def test_missing_pdf_tools_honours_the_configured_engine(monkeypatch):
    monkeypatch.setattr(render.shutil, "which", lambda name: None)
    assert render.missing_pdf_tools({"pdf_engine": "lualatex"})[-1] == "lualatex"

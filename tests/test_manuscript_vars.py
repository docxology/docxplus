"""Actual manuscript sources render without unresolved variable markers."""

from __future__ import annotations

from docxplus import manuscript_vars
from docxplus.project_paths import source_manuscript_dir

_SECTIONS = sorted(
    path
    for path in source_manuscript_dir().glob("*.md")
    if path.name not in {"AGENTS.md", "README.md"}
)


def test_generator_and_renderer_produce_clean_output():
    values = manuscript_vars.variables()
    for path in _SECTIONS:
        rendered, missing = manuscript_vars.render_text(path.read_text(), values)
        assert not missing, f"{path.name}: {missing}"
        assert "{{" not in rendered, path.name

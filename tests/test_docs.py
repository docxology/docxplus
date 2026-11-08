"""Relative links must lead readers to an existing document or artifact."""

from __future__ import annotations

import re

import pytest

from docxplus.project_paths import project_root

ROOT = project_root()
GUIDED_DIRS = (
    "",
    "src",
    "src/docxplus",
    "src/docxplus/channels",
    "scripts",
    "tests",
    "docs",
    "docs/manuscript",
    "output",
    "data",
    ".github",
    ".agents",
)
DOCUMENTS = sorted(
    {
        *(ROOT / "docs").glob("*.md"),
        *(
            path
            for directory in GUIDED_DIRS
            for name in ("README.md", "AGENTS.md")
            if (path := ROOT / directory / name).is_file()
        ),
    }
)


@pytest.mark.parametrize("document", DOCUMENTS, ids=lambda path: str(path.relative_to(ROOT)))
def test_internal_links_resolve(document):
    for target in re.findall(r"\]\((?!https?://|mailto:)([^)#]+)", document.read_text()):
        resolved = (document.parent / target.strip()).resolve()
        assert resolved.exists(), f"{document.relative_to(ROOT)} links a missing target: {target}"

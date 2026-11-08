"""Catch broken manuscript navigation and fatal renderer diagnostics."""

from __future__ import annotations

import re

import pytest

from docxplus.project_paths import project_root, source_manuscript_dir

ROOT = project_root()
MANUSCRIPT = source_manuscript_dir()

#: Sections only. AGENTS.md and README.md are guidance for authors, not content.
NOT_SECTIONS = {"AGENTS.md", "README.md"}


def _sections() -> dict[str, str]:
    return {
        p.name: p.read_text() for p in sorted(MANUSCRIPT.glob("*.md")) if p.name not in NOT_SECTIONS
    }


def _declarations(blob: str) -> dict[str, set[str]]:
    return {
        "formalism": set(re.findall(r"^:::+ \{\.[\w-]+ #([A-Za-z]+:[\w-]+)", blob, re.MULTILINE)),
        "fig": set(re.findall(r"\{#(fig:[\w-]+)", blob)),
        "sec": set(re.findall(r"\{#(sec:[\w-]+)\}", blob)),
        "tbl": set(re.findall(r"\{#(tbl:[\w-]+)", blob)),
        "eq": set(re.findall(r"\{#(eq:[\w-]+)\}", blob)),
    }


def _references(blob: str) -> set[str]:
    """Every ``@kind:label`` reference, case-folded on the kind.

    Pandoc's `[@Fig:x]` capitalises the rendered prefix; it is the same target.
    """
    found = re.findall(r"@([A-Za-z]+):([\w-]+)", blob)
    return {f"{kind[0].lower()}{kind[1:]}:{label}" for kind, label in found}


# -- references and declarations must agree -----------------------------------


def test_every_reference_resolves_to_a_declaration():
    """A reference whose prefix the document uses must name something declared.

    This is the failure that used to ship: `formalism.lua` reports the broken label
    on stderr, pandoc exits 0, and the literal `[@thm:typo]` lands in the PDF.
    """
    blob = "\n".join(_sections().values())
    declared = set().union(*_declarations(blob).values())
    prefixes = {d.split(":", 1)[0] for d in declared}
    dangling = sorted(
        r for r in _references(blob) if r.split(":", 1)[0] in prefixes and r not in declared
    )
    assert not dangling, f"references with no declaration: {dangling}"


def test_no_label_is_declared_twice():
    """formalism.lua reports a duplicate label and keeps going; this stops it."""
    blob = "\n".join(_sections().values())
    all_ids = re.findall(r"^:::+ \{\.[\w-]+ #([A-Za-z]+:[\w-]+)", blob, re.MULTILINE)
    all_ids += re.findall(r"\{#((?:fig|sec|tbl|eq):[\w-]+)", blob)
    seen, duplicated = set(), set()
    for label in all_ids:
        (duplicated if label in seen else seen).add(label)
    assert not duplicated, f"labels declared more than once: {sorted(duplicated)}"


def _diagnose(stderr: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "render_manuscript", ROOT / "scripts" / "render_manuscript.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.diagnose(stderr, module.render_settings(MANUSCRIPT / "config.yaml"))


@pytest.mark.parametrize(
    "line",
    [
        "formalism.lua: reference to undeclared formalism 'thm:nope'",
        "formalism.lua: duplicate label 'def:x'",
        "[WARNING] Could not fetch resource ../output/figures/x.png: replacing image",
        "[ERROR] something the writer could not do",
        "[WARNING] Citeproc: citation smith2020 not found",
    ],
)
def test_each_class_of_diagnostic_fails_the_render(line):
    """Each of these was survivable before: pandoc printed it and exited 0."""
    assert _diagnose(f"some benign chatter\n{line}\nmore chatter") == [line]


def test_a_clean_stderr_passes_the_gate():
    assert _diagnose("") == []
    assert _diagnose("[makeindex] pass 1\nrunning xelatex\n") == []

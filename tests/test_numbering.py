"""Numbering and cross-reference integrity, enforced statically.

Every number that names a figure, section, or formalism in this manuscript is
assigned by a filter at render time and referenced by label, never typed. That is a
property worth having and a property that decays silently: hand-typing "Definition 3"
works perfectly until someone inserts Definition 2, and nothing in a build catches
the drift because the document still compiles and still reads like prose.

These tests need no toolchain. They read the manuscript sources and the render
config, so they run wherever pytest runs, and they fail on the *class* of mistake
rather than on any instance of it — the vocabulary of numbered things is derived
from `manuscript/config.yaml` and `manuscript/formalism.lua`, so adding a kind
extends the guard automatically instead of quietly escaping it.

The complementary runtime check lives in `scripts/render_manuscript.py`: pandoc
reports an unresolved reference on stderr and exits 0, so a clean exit code alone
never established that the PDF says what the manuscript meant.
"""

from __future__ import annotations

import re

import pytest
import yaml

from project_paths import project_root

ROOT = project_root()
MANUSCRIPT = ROOT / "manuscript"

#: Sections only. AGENTS.md and README.md are guidance for authors, not content.
NOT_SECTIONS = {"AGENTS.md", "README.md"}

#: pandoc-crossref owns these; formalism.lua owns whatever config declares.
CROSSREF_KINDS = {
    "fig": ("Figure", "Fig."),
    "sec": ("Section", "Sec."),
    "tbl": ("Table", "Tbl."),
    "eq": ("Equation", "Eq."),
    "lst": ("Listing",),
}


def _sections() -> dict[str, str]:
    return {
        p.name: p.read_text()
        for p in sorted(MANUSCRIPT.glob("*.md"))
        if p.name not in NOT_SECTIONS
    }


def _config() -> dict:
    return yaml.safe_load((MANUSCRIPT / "config.yaml").read_text()) or {}


def _formalism_titles() -> set[str]:
    """Displayed titles of every numbered environment, from config."""
    return {str(v) for v in (_config().get("formalism_kinds") or {}).values()}


def _declarations(blob: str) -> dict[str, set[str]]:
    return {
        "formalism": set(re.findall(r"^:::+ \{\.[\w-]+ #([A-Za-z]+:[\w-]+)", blob, re.M)),
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


# -- the rule the user asked for: no number is ever typed ----------------------


@pytest.mark.parametrize("name", sorted(_sections()))
def test_no_numbered_thing_is_hardcoded_in_the_manuscript(name):
    """Reject a typed number after *any* numbered noun, not one known offender.

    Written against the whole class deliberately. A guard that forbids only
    "Definition 3" re-prints the very string it exists to remove and misses
    "Proposition 4" entirely, so the noun list is derived: pandoc-crossref's own
    prefixes plus whatever kinds config declares to formalism.lua.
    """
    nouns = sorted(
        {n for names in CROSSREF_KINDS.values() for n in names} | _formalism_titles()
    )
    pattern = re.compile(
        r"(?<![\w`])(" + "|".join(re.escape(n) for n in nouns) + r")\s+\d+(?:\.\d+)*\b"
    )
    text = _sections()[name]
    # Fenced code may legitimately contain such strings; it is quoted, not authored.
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    offenders = [m.group(0) for m in pattern.finditer(text)]
    assert not offenders, (
        f"{name} hardcodes numbering: {offenders}. Declare a label and reference it "
        f"with [@kind:label] so the number is assigned at render time."
    )


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


def test_every_formalism_and_figure_is_referenced():
    """A numbered block nobody points at is either dead weight or a lost reference.

    Section labels are deliberately exempt: they are navigation anchors and exist to
    be linkable, whether or not the prose happens to link them.
    """
    blob = "\n".join(_sections().values())
    decls = _declarations(blob)
    refs = _references(blob)
    orphans = sorted((decls["formalism"] | decls["fig"]) - refs)
    assert not orphans, f"declared but never referenced: {orphans}"


def test_no_label_is_declared_twice():
    """formalism.lua reports a duplicate label and keeps going; this stops it."""
    blob = "\n".join(_sections().values())
    all_ids = re.findall(r"^:::+ \{\.[\w-]+ #([A-Za-z]+:[\w-]+)", blob, re.M)
    all_ids += re.findall(r"\{#((?:fig|sec|tbl|eq):[\w-]+)", blob)
    seen, duplicated = set(), set()
    for label in all_ids:
        (duplicated if label in seen else seen).add(label)
    assert not duplicated, f"labels declared more than once: {sorted(duplicated)}"


# -- config must actually reach the filter ------------------------------------


def test_config_declares_every_kind_the_filter_defaults_to():
    """Config may extend the filter's kinds; it must not silently narrow them.

    `formalism.lua` merges `formalism_kinds` over its own defaults, so a config that
    omits a kind still numbers it — but the guard above derives its noun list from
    config, and a kind missing there would be a kind the guard stops checking.
    """
    lua = (MANUSCRIPT / "formalism.lua").read_text()
    block = lua[lua.index("local DEFAULT_KINDS") : lua.index("local kinds = {}")]
    defaults = dict(re.findall(r"(\w+)\s*=\s*\"([^\"]+)\"", block))
    configured = _config().get("formalism_kinds") or {}
    missing = sorted(set(defaults) - set(configured))
    assert not missing, (
        f"manuscript/config.yaml omits formalism kinds the filter defines: {missing}"
    )
    disagreeing = sorted(k for k in defaults if configured.get(k) != defaults[k])
    assert not disagreeing, f"config renames kinds the filter defines: {disagreeing}"


# -- the runtime gate, unit-tested without invoking pandoc --------------------


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


def test_the_gate_is_configured_rather_than_hardcoded():
    """The patterns live in config, so a project can tighten or loosen them."""
    render = _config().get("render") or {}
    assert render.get("fatal_diagnostics"), "config.yaml declares no fatal_diagnostics"
    for pattern in render["fatal_diagnostics"]:
        re.compile(pattern)  # must be a usable regex, not a hopeful string
    for entry in render.get("benign_diagnostics") or []:
        assert isinstance(entry, dict) and entry.get("reason"), (
            "every benign_diagnostics entry must carry a reason; an unexplained "
            "exemption is how a gate stops being a gate"
        )

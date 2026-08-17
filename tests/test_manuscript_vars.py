"""Manuscript variables: derived-not-hard-coded, resolve, and no-drift guards."""

from __future__ import annotations

import re

from docxplus import channels
from docxplus import container
from docxplus import crypto
from docxplus import lsb
from docxplus import manuscript_vars
from docxplus import opc
from docxplus import payloads
from docxplus.channels.metadata import MAX_PAYLOAD
from docxplus.project_paths import project_root

_SECTIONS = sorted(
    p for p in (project_root() / "manuscript").glob("*.md")
    if p.name not in {"AGENTS.md", "README.md"}
)
_TOKEN = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def test_values_derive_from_live_constants():
    v = manuscript_vars.variables(include_dossier=False)
    assert v["KEY_BITS"] == str(crypto.KEY_BYTES * 8)
    assert v["SCRYPT_N"] == str(1 << crypto.SCRYPT_N_LOG2)
    assert v["PBKDF2_ITERATIONS"] == str(crypto.PBKDF2_ITERATIONS)
    assert v["CHANNEL_COUNT"] == str(len(channels.available_channels()))
    assert v["PAYLOAD_TYPE_COUNT"] == str(len(payloads.available_types()))
    assert v["SEALING_COUNT"] == str(len(container.SEALING_LINEAGES))
    assert v["METADATA_MAX_BYTES"] == str(MAX_PAYLOAD)
    assert v["MEDIA_CAP_256"] == str(lsb.capacity_bytes(256, 256))
    assert v["MAX_ENTRIES"] == str(opc.MAX_ENTRIES)
    assert v["MAX_NEST_DEPTH"] == str(container.DocxPlusReader.MAX_NEST_DEPTH)


def test_version_matches_pyproject():
    v = manuscript_vars.variables(include_dossier=False)
    pyproject = (project_root() / "pyproject.toml").read_text()
    assert f'version = "{v["VERSION"]}"' in pyproject


def test_dossier_table_generated_from_a_real_document():
    table, count = manuscript_vars.dossier_table()
    assert count >= 5
    assert table.startswith("| Slot | Channel | Sealing |")
    # Every sealing lineage the dossier uses is a real, registered one.
    for line in table.splitlines()[2:]:
        mode = line.rsplit("|", 2)[1].strip()
        assert mode in (*container.SEALING_LINEAGES, "plain")


def test_every_manuscript_token_resolves():
    known = set(manuscript_vars.variables())
    for path in _SECTIONS:
        for token in _TOKEN.findall(path.read_text()):
            assert token in known, f"{path.name} uses undefined token {token!r}"


def test_manuscript_sources_hardcode_no_drift_prone_values():
    """The point of the token system: a drift-prone value must appear only as a
    token in the sources, never as a literal a future code change would strand."""
    v = manuscript_vars.variables()
    guarded = [
        "TEST_COUNT", "MEDIA_CAP_256", "MEDIA_CAP_512",
        "PBKDF2_ITERATIONS", "METADATA_MAX_BYTES",
    ]
    blob = "\n".join(p.read_text() for p in _SECTIONS)
    for name in guarded:
        literal = v[name]
        assert literal not in blob, (
            f"manuscript hard-codes {name}={literal}; use {{{{{name}}}}} instead"
        )


def test_generator_and_renderer_produce_clean_output():
    # A section rendered with the live values must contain no leftover token braces.
    values = manuscript_vars.variables()
    for path in _SECTIONS:
        rendered, missing = manuscript_vars.render_text(path.read_text(), values)
        assert not missing
        assert "{{" not in rendered


def test_parity_caption_matches_the_figure_it_describes():
    """A caption that counts divergences must agree with the figure's own list.

    The intake-scan gap was closed and its row moved to the parity side, which
    silently made the caption's "four honest divergences" wrong. Counting prose is
    the kind of claim that drifts the moment the thing it counts changes, and the
    two counts are the ones a reader would take at face value: how much of the gap
    is the specification's doing, and how much is ours.
    """
    import ast
    import re

    from docxplus.project_paths import project_root

    root = project_root()
    tree = ast.parse((root / "scripts" / "build_figures.py").read_text())
    ooxml_only = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "build_parity_figure":
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Assign)
                    and getattr(inner.targets[0], "id", "") == "ooxml_only"
                ):
                    ooxml_only = ast.literal_eval(inner.value)
    assert ooxml_only, "parity figure divergence list not found"

    reasons = [r for _, _, r in ooxml_only]
    assert set(reasons) <= {"standard", "unbuilt"}, f"unknown divergence reason in {reasons}"
    by_standard = reasons.count("standard")
    unbuilt = reasons.count("unbuilt")

    caption = (root / "manuscript" / "03_evaluation.md").read_text()
    match = re.search(
        r"(\w+) constructs ODF does not define, and (\w+) analogues that are plausible",
        caption,
    )
    assert match, "parity caption no longer states its divergence counts"
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6}
    assert words[match.group(1)] == by_standard, (
        f"caption says {match.group(1)} spec-forced divergences, figure has {by_standard}"
    )
    assert words[match.group(2)] == unbuilt, (
        f"caption says {match.group(2)} unbuilt analogues, figure has {unbuilt}"
    )


# -- release-metadata guards --------------------------------------------------


def test_release_metadata_versions_all_agree():
    """One version, four files. They had drifted to 0.7.0 / 0.6.0 / 0.6.0 / none.

    A Zenodo record minted from a codemeta that disagrees with the tag is a citation
    that points at the wrong thing forever, so this is checked rather than reviewed.
    """
    import json
    import re

    from docxplus.project_paths import project_root

    root = project_root()
    pyproject = re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M)
    assert pyproject, "pyproject.toml has no version"
    version = pyproject.group(1)

    cff = re.search(r'^version: "([^"]+)"', (root / "CITATION.cff").read_text(), re.M)
    assert cff and cff.group(1) == version, f"CITATION.cff version != {version}"

    for name in ("codemeta.json", ".zenodo.json"):
        path = root / name
        if path.is_file():
            assert json.loads(path.read_text()).get("version") == version, f"{name} version != {version}"


def test_no_absolute_home_paths_in_tracked_sources():
    """An absolute path to one machine breaks the build for everyone else.

    `05_living_manuscript.py` carried one, which also silently made the manuscript's
    "carries its own source" claim false: it packed an unrelated external exemplar.
    """
    import re

    from docxplus.project_paths import project_root

    root = project_root()
    offenders = []
    for pattern in ("*.py", "*.sh", "*.toml", "*.cff", "*.json", "*.yaml", "*.md"):
        for path in root.rglob(pattern):
            parts = set(path.parts)
            if parts & {".venv", "output", "__pycache__", ".git", "node_modules"}:
                continue
            if "egg-info" in str(path):
                continue
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            if re.search(r"/(Users|home)/[a-z0-9_]+/", text):
                offenders.append(str(path.relative_to(root)))
    assert not offenders, f"absolute home paths in tracked files: {offenders}"


def test_living_manuscript_carries_this_repository():
    """The flagship claim must be enforced, not merely asserted in prose."""
    from docxplus.project_paths import project_root

    src = (project_root() / "scripts" / "05_living_manuscript.py").read_text()
    assert "CARRIED_PROJECT = project_root()" in src, (
        "the living manuscript must pack this repository, not an external exemplar"
    )
    assert "template_code_project" not in src


def test_the_test_count_token_is_described_as_what_it_counts():
    """`TEST_COUNT` counts test *functions*; parametrisation expands them further.

    Describing 408 test functions as "408 tests" understates a suite pytest collects
    453 cases from, and a claim that is wrong in the conservative direction is still
    wrong. The token's own derivation is the authority on how prose may word it, so
    the check reads the derivation rather than trusting a comment about it.
    """
    import inspect
    import re

    from docxplus import manuscript_vars
    from docxplus.project_paths import project_root

    source = inspect.getsource(manuscript_vars._count_test_functions)
    assert "def test" in source, (
        "TEST_COUNT no longer counts test functions; update this guard and every "
        "place the manuscript describes it"
    )

    root = project_root()
    sites = list((root / "manuscript").glob("*.md")) + [root / "scripts" / "build_figures.py"]
    offenders = []
    for path in sites:
        # A four-word window: "mock-free test functions" puts the noun third, so a
        # narrower one flags the correct wording it exists to require.
        for match in re.finditer(r"TEST_COUNT[^\w]{0,4}((?:[\w-]+[ ]){0,4})", path.read_text()):
            following = match.group(1).strip()
            if "function" not in following:
                offenders.append(f"{path.name}: '...TEST_COUNT {following}'")
    assert not offenders, (
        "TEST_COUNT is described as something other than a count of test functions: "
        f"{offenders}"
    )


def test_surface_digest_prose_matches_the_package_graph():
    """The digest binds parts, types, and relationships — not a story-part name list.

    Rounds that closed the officeDocument-swap forgery updated the code and the
    figures first. The manuscript kept describing the old prefix list, and the
    conclusion still told readers that styles and the relationship graph sat
    outside the signature. This guard fails on that wording, and requires the
    definition to name the relationship graph so the two cannot drift apart again.
    """
    from docxplus.project_paths import project_root

    blob = "\n".join(
        p.read_text()
        for p in (project_root() / "manuscript").glob("*.md")
        if p.name not in {"AGENTS.md", "README.md"}
    )
    banned = (
        "every visible WordprocessingML story part",
        "styles, numbering, fonts, and the relationship graph sit outside",
        "The signature covers the text, not the package",
    )
    hits = [phrase for phrase in banned if phrase in blob]
    assert not hits, f"manuscript still describes the retired surface digest: {hits}"
    assert "relationship graph" in blob
    assert "#def:composite-surface-digest" in blob

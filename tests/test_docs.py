"""Documentation completeness, enforced rather than asserted.

Docs rot silently: a new module, channel, or subcommand ships and nothing fails. These
tests make the docs tree a checked surface — every module has an architecture entry,
every CLI command a reference entry, every channel a page, and every internal link a
target. A gap fails the build the same way a broken import would.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from docxplus.project_paths import project_root

ROOT = project_root()
DOCS = ROOT / "docs"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text()


# -- every module is placed in the architecture map ---------------------------


def test_every_src_module_appears_in_the_architecture_map():
    """A module nobody documented is a module nobody can find."""
    listed = set(re.findall(r"\|\s*`([a-z_]+\.py)`", _read("docs/architecture.md")))
    on_disk = {p.name for p in (ROOT / "src" / "docxplus").glob("*.py") if p.name != "__init__.py"}
    assert not (on_disk - listed), f"missing from docs/architecture.md: {sorted(on_disk - listed)}"


def test_the_architecture_map_lists_no_module_that_was_removed():
    listed = set(re.findall(r"\|\s*`([a-z_]+\.py)`", _read("docs/architecture.md")))
    on_disk = {p.name for p in (ROOT / "src" / "docxplus").glob("*.py")}
    stale = {m for m in listed if m not in on_disk}
    assert not stale, f"docs/architecture.md lists modules that no longer exist: {sorted(stale)}"


# -- every CLI command is documented ------------------------------------------


def _cli_commands() -> list[str]:
    return sorted(set(re.findall(r'add_parser\(\s*"([a-z-]+)"', _read("src/docxplus/cli.py"))))


def test_every_cli_command_has_a_reference_entry():
    """The CLI reference is the contract; an undocumented command is unusable."""
    reference = _read("docs/cli.md")
    missing = [c for c in _cli_commands() if f"`{c}`" not in reference]
    assert not missing, f"undocumented in docs/cli.md: {missing}"


def test_the_cli_reference_documents_no_command_that_was_removed():
    reference = _read("docs/cli.md")
    documented = set(re.findall(r"^### `([a-z-]+)`", reference, re.M))
    # Headings may group two commands ("`scan` / `odt-scan`"); catch those too.
    documented |= set(re.findall(r"^### `[a-z-]+` / `([a-z-]+)`", reference, re.M))
    stale = documented - set(_cli_commands())
    assert not stale, f"docs/cli.md documents commands that do not exist: {sorted(stale)}"


# -- every channel is documented ----------------------------------------------


def test_every_registered_channel_has_a_channels_entry():
    from docxplus import channels

    reference = _read("docs/channels.md")
    missing = [c for c in channels.available_channels() if f"`{c}`" not in reference]
    assert not missing, f"undocumented in docs/channels.md: {missing}"


def test_every_registered_channel_appears_in_the_format_spec():
    from docxplus import channels

    spec = _read("docs/format-spec.md")
    missing = [c for c in channels.available_channels() if f"`{c}`" not in spec]
    assert not missing, f"undocumented in docs/format-spec.md: {missing}"


# -- the docs tree is navigable ------------------------------------------------


def test_the_docs_index_links_every_document():
    """A document the index omits is one a reader will never open."""
    index = _read("docs/README.md")
    docs = {p.name for p in DOCS.glob("*.md")} - {"README.md", "AGENTS.md"}
    missing = [d for d in sorted(docs) if f"({d})" not in index]
    assert not missing, f"not linked from docs/README.md: {missing}"


def test_the_docs_index_links_nothing_that_is_missing():
    index = _read("docs/README.md")
    for target in re.findall(r"\]\((?!https?://)([^)#]+)\)", index):
        assert (DOCS / target).exists(), f"docs/README.md links a missing file: {target}"


@pytest.mark.parametrize(
    "doc",
    sorted(p.name for p in (project_root() / "docs").glob("*.md")),
)
def test_internal_links_resolve(doc):
    """A broken relative link is a dead end a reader hits, not a warning."""
    path = DOCS / doc
    for target in re.findall(r"\]\((?!https?://|mailto:)([^)#]+)", path.read_text()):
        resolved = (path.parent / target.strip()).resolve()
        assert resolved.exists(), f"{doc} links a missing target: {target}"


@pytest.mark.parametrize(
    "doc",
    sorted(p.name for p in (project_root() / "docs").glob("*.md")),
)
def test_every_doc_opens_with_a_title(doc):
    first = (DOCS / doc).read_text().lstrip().splitlines()[0]
    assert first.startswith("# "), f"{doc} does not open with an H1 title"


def _legacy_pattern() -> "re.Pattern[str]":
    """The retired project name, assembled so this file does not contain it."""
    old = "DOCX" + "\\+"
    slug = "docx" + r"(?!plus|_|-)"
    return re.compile(rf"{old}|docxology/{slug}|ongoing/DAF/{slug}")


#: Files allowed to quote the pre-rename name, each for a stated reason.
_LEGACY_NAME_EXEMPT = {
    "docs/redteam-audit.md": "records the rename as a finding, quoting the old name",
    "CHANGELOG.md": "release history necessarily names what the project used to be",
}


def test_no_tracked_file_still_carries_the_pre_rename_project_name():
    """The project is `docxplus`. Only history may quote the old name.

    Scoped to `docs/*.md` originally, which let a LaTeX preamble keep the old name
    in its header comment through the entire rename and four subsequent review
    rounds. A guard that checks one directory certifies one directory; this one
    walks every tracked text file, so the next stale mention cannot hide in a file
    type nobody thought to include.

    The pattern is assembled from fragments rather than written out. A guard that
    spells the string it exists to eliminate becomes its own last offender, which
    is exactly what happened on the first run of this one.
    """
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    offenders = []
    for rel in tracked:
        if rel in _LEGACY_NAME_EXEMPT or rel.startswith("output/"):
            continue
        path = ROOT / rel
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue  # binary artefact
        if re.search(_legacy_pattern(), text):
            offenders.append(rel)
    assert not offenders, f"pre-rename project name survives in: {offenders}"


# -- the pipeline driver and its own help must agree --------------------------


def _run_sh() -> str:
    return _read("run.sh")


def _run_sh_verbs() -> set[str]:
    """Every verb the case statement dispatches, including aliases."""
    body = _run_sh()
    body = body[body.index("case ") :]
    verbs: set[str] = set()
    for line in body.splitlines():
        match = re.match(r"\s{2}([a-z|_-]+)\)\s", line)
        if match:
            verbs |= set(match.group(1).split("|"))
    return verbs - {"-h", "--help", "help", "*"}


def test_every_run_sh_stage_appears_in_its_own_usage():
    """`./run.sh nonsense` prints the usage; the usage must list what exists.

    A stage nobody can discover is a stage nobody runs. This drifted once already
    when the verbs were renamed and three documents kept describing the old set.
    """
    usage = _run_sh()
    usage = usage[usage.index("usage: ./run.sh") : usage.index("EOF", usage.index("usage: ./run.sh"))]
    documented = set(re.findall(r"^\s{2}([a-z]+)\s{2,}", usage, re.M))
    implemented = _run_sh_verbs()
    # Aliases kept for compatibility need not be advertised, but nothing advertised
    # may be missing, and no primary verb may be undocumented.
    undocumented = implemented - documented - {"manuscript-render", "manuscript"}
    assert not undocumented, f"run.sh stages absent from its usage text: {sorted(undocumented)}"
    phantom = documented - implemented - {"all"}
    assert not phantom, f"run.sh usage advertises stages it does not implement: {sorted(phantom)}"


def test_the_default_pipeline_renders_the_manuscript():
    """`all` must include the render, which is the only stage running the gate.

    pandoc reports an unresolved cross-reference and exits 0, so the render is where
    that is caught. Leaving it out of `all` let a broken reference reach the
    committed PDF with every other stage green — the reason this test exists.
    """
    body = _run_sh()
    block = body[body.index("  all)") : body.index(";;", body.index("  all)"))]
    assert "run_render" in block, "run.sh `all` no longer renders the manuscript"


def test_the_manuscript_readme_lists_every_manuscript_file():
    """An inventory that omits a file is how a reader misses `formalism.lua`."""
    readme = _read("manuscript/README.md")
    present = {p.name for p in (ROOT / "manuscript").glob("*") if p.is_file()}
    missing = sorted(f for f in present - {"README.md", "AGENTS.md"} if f"`{f}`" not in readme)
    assert not missing, f"manuscript/README.md omits: {missing}"


def test_the_readme_review_counts_match_the_audit_record():
    """README numbers cannot be tokens, so they are checked instead.

    `manuscript/*.md` resolves every drift-prone number through
    `manuscript_vars`, and README cannot: it is read on GitHub, not rendered. That
    exemption let it fall to "Eight cycles ... 60 confirmed findings" while the
    audit record had reached fourteen and eighty-eight. A file that states a count
    it does not derive needs the check the derivation would have given it.
    """
    from docxplus import manuscript_vars

    values = manuscript_vars.variables(include_dossier=False)
    readme = _read("README.md")

    words = {
        1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six", 7: "Seven",
        8: "Eight", 9: "Nine", 10: "Ten", 11: "Eleven", 12: "Twelve",
        13: "Thirteen", 14: "Fourteen", 15: "Fifteen", 16: "Sixteen",
        17: "Seventeen", 18: "Eighteen", 19: "Nineteen", 20: "Twenty",
    }
    cycles = int(values["REDTEAM_AUDIT_COUNT"])
    findings = int(values["REDTEAM_FINDING_COUNT"])

    spelled = words.get(cycles, str(cycles))
    assert f"{spelled} cycles of adversarial review" in readme or (
        f"{cycles} cycles of adversarial review" in readme
    ), f"README does not state the current cycle count ({cycles})"
    assert f"{findings} confirmed findings" in readme, (
        f"README does not state the current finding count ({findings})"
    )


def test_the_readme_states_the_shipped_version():
    """The badge is read before anything else, so a stale one mislabels everything.

    Four release-metadata files already agree on the version and are checked for it
    in `test_manuscript_vars.py`; the README badge is the fifth and the most read.
    """
    version = re.search(r'^version = "([^"]+)"', _read("pyproject.toml"), re.M).group(1)
    assert f"**v{version}**" in _read("README.md"), (
        f"README does not carry the shipped version badge (**v{version}**)"
    )


def test_the_readme_links_every_reference_document():
    """The root README is the front door; a doc it omits is one most readers miss."""
    readme = _read("README.md")
    docs = {p.name for p in DOCS.glob("*.md")} - {"AGENTS.md"}
    missing = [d for d in sorted(docs) if f"(docs/{d})" not in readme]
    assert not missing, f"not linked from README.md: {missing}"


# -- every directory carries its own two guides -------------------------------
#
# `docs/` was a checked surface long before the per-directory guides were. The
# exemption is what let `src/docxplus/AGENTS.md` describe sixteen modules while twenty-one
# shipped, hiding the whole ODT profile from anyone who read it, and let
# `scripts/AGENTS.md` list four scripts out of eleven. These tests remove it.

#: Every directory that must carry both a README (what is in here) and an AGENTS
#: (the rules for changing it). "" is the repository root.
GUIDED_DIRS = (
    "",
    "src",
    "src/docxplus",
    "src/docxplus/channels",
    "scripts",
    "tests",
    "docs",
    "manuscript",
    "output",
    "data",
    ".github",
    ".agents",
)

#: Directories that legitimately hold no guides: build/tool state, the virtualenv,
#: and the generated round-trip trees whose contents are diffed byte for byte
#: against an external repository and must not be edited.
_UNGUIDED = {
    ".git", ".venv", ".claude", ".benchmarks", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "docxplus.egg-info",
}


@pytest.mark.parametrize("directory", GUIDED_DIRS)
@pytest.mark.parametrize("guide", ["README.md", "AGENTS.md"])
def test_every_guided_directory_has_both_guides(directory, guide):
    """A README answers "what is in here"; an AGENTS answers "what may I change"."""
    path = ROOT / directory / guide
    assert path.is_file(), f"missing {directory or '.'}/{guide}"


def _is_git_ignored(rel: str) -> bool:
    """True when git would not track this path.

    The guide list describes the repository, so it must be checked against what the
    repository contains rather than against whatever a build happened to leave on
    disk. A wheel build dropped a `build/` tree and failed the guard for a directory
    that is not part of the project at all.
    """
    import subprocess

    result = subprocess.run(
        ["git", "check-ignore", "-q", rel], cwd=ROOT, capture_output=True
    )
    return result.returncode == 0


def test_no_source_directory_escapes_the_guide_list():
    """A new top-level directory must be added to GUIDED_DIRS, not silently skipped."""
    on_disk = {
        p.name
        for p in ROOT.iterdir()
        if p.is_dir() and p.name not in _UNGUIDED and not _is_git_ignored(p.name)
    }
    assert not (on_disk - set(GUIDED_DIRS)), (
        f"top-level directories with no entry in GUIDED_DIRS: {sorted(on_disk - set(GUIDED_DIRS))}"
    )


def _guide_paths() -> list[Path]:
    paths = []
    for directory in GUIDED_DIRS:
        for guide in ("README.md", "AGENTS.md"):
            candidate = ROOT / directory / guide
            if candidate.is_file():
                paths.append(candidate)
    return paths


@pytest.mark.parametrize(
    "guide", _guide_paths(), ids=lambda p: str(p.relative_to(project_root()))
)
def test_guide_links_resolve(guide):
    """A broken relative link is a dead end a reader hits, not a warning."""
    for target in re.findall(r"\]\((?!https?://|mailto:)([^)#]+)", guide.read_text()):
        resolved = (guide.parent / target.strip()).resolve()
        assert resolved.exists(), f"{guide.name} links a missing target: {target}"


@pytest.mark.parametrize(
    "guide", _guide_paths(), ids=lambda p: str(p.relative_to(project_root()))
)
def test_guides_open_with_a_title_and_use_the_current_name(guide):
    text = guide.read_text()
    assert text.lstrip().startswith("# "), f"{guide} does not open with an H1 title"
    # Shares `_legacy_pattern()` with the repository-wide check rather than
    # restating the regex. Two copies of a "never write this string" rule means one
    # of them eventually writes it, which is how this file became its own offender.
    assert not _legacy_pattern().search(text), (
        f"{guide} still carries the pre-rename project name"
    )


# -- the per-directory inventories stay complete ------------------------------


def test_the_src_readme_lists_every_module():
    """`src/docxplus/AGENTS.md` once described sixteen modules while twenty-one shipped."""
    listed = set(re.findall(r"`([a-z_]+\.py)`", _read("src/docxplus/README.md")))
    on_disk = {p.name for p in (ROOT / "src" / "docxplus").glob("*.py") if p.name != "__init__.py"}
    assert not (on_disk - listed), f"missing from src/docxplus/README.md: {sorted(on_disk - listed)}"


def test_the_src_readme_lists_no_module_that_was_removed():
    listed = set(re.findall(r"`([a-z_]+\.py)`", _read("src/docxplus/README.md")))
    on_disk = {p.name for p in (ROOT / "src" / "docxplus").glob("*.py")}
    stale = {m for m in listed if m not in on_disk}
    assert not stale, f"src/docxplus/README.md lists modules that no longer exist: {sorted(stale)}"


def test_the_scripts_readme_lists_every_stage():
    """A stage nobody documented is a stage nobody runs."""
    listed = set(re.findall(r"`([0-9a-z_]+\.py)`", _read("scripts/README.md")))
    on_disk = {p.name for p in (ROOT / "scripts").glob("*.py")}
    assert not (on_disk - listed), f"missing from scripts/README.md: {sorted(on_disk - listed)}"


def test_the_channels_readme_lists_every_registered_channel():
    from docxplus import channels

    readme = _read("src/docxplus/channels/README.md")
    missing = [c for c in channels.available_channels() if f"`{c}`" not in readme]
    assert not missing, f"undocumented in src/docxplus/channels/README.md: {missing}"


def test_the_root_guides_point_at_every_directory_guide():
    """The root AGENTS.md is the map. A directory it omits is one nobody is routed to."""
    agents = _read("AGENTS.md")
    missing = [
        d for d in GUIDED_DIRS if d and f"{d}/AGENTS.md" not in agents
    ]
    assert not missing, f"AGENTS.md does not route to: {missing}"

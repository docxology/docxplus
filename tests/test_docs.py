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

from project_paths import project_root

ROOT = project_root()
DOCS = ROOT / "docs"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text()


# -- every module is placed in the architecture map ---------------------------


def test_every_src_module_appears_in_the_architecture_map():
    """A module nobody documented is a module nobody can find."""
    listed = set(re.findall(r"\|\s*`([a-z_]+\.py)`", _read("docs/architecture.md")))
    on_disk = {p.name for p in (ROOT / "src").glob("*.py") if p.name != "__init__.py"}
    assert not (on_disk - listed), f"missing from docs/architecture.md: {sorted(on_disk - listed)}"


def test_the_architecture_map_lists_no_module_that_was_removed():
    listed = set(re.findall(r"\|\s*`([a-z_]+\.py)`", _read("docs/architecture.md")))
    on_disk = {p.name for p in (ROOT / "src").glob("*.py")}
    stale = {m for m in listed if m not in on_disk}
    assert not stale, f"docs/architecture.md lists modules that no longer exist: {sorted(stale)}"


# -- every CLI command is documented ------------------------------------------


def _cli_commands() -> list[str]:
    return sorted(set(re.findall(r'add_parser\(\s*"([a-z-]+)"', _read("docxplus_cli.py"))))


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
    import channels

    reference = _read("docs/channels.md")
    missing = [c for c in channels.available_channels() if f"`{c}`" not in reference]
    assert not missing, f"undocumented in docs/channels.md: {missing}"


def test_every_registered_channel_appears_in_the_format_spec():
    import channels

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


def test_no_document_still_carries_the_pre_rename_project_name():
    """The project is `docxplus`. Only the audit log may quote the old name, as history."""
    offenders = []
    for path in DOCS.glob("*.md"):
        if path.name == "redteam-audit.md":
            continue  # records the rename as a finding, quoting the old name
        if re.search(r"DOCX\+|docxology/docx\b", path.read_text()):
            offenders.append(path.name)
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

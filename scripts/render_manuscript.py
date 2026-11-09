#!/usr/bin/env python3
"""Render the token-driven manuscript → output/manuscript/ and compile PDF.

Substitutes ``{{TOKEN}}`` in each manuscript source with values generated from the
live system (`manuscript_vars.variables`). Fails loudly on any unresolved token.
Compiles the comprehensive publication-quality PDF using Pandoc, Lua formalism filter,
pandoc-crossref, citeproc, and XeLaTeX.

**A clean exit code is not a clean render.** pandoc reports an unresolved
cross-reference, a missing resource, and a broken citation on stderr and then exits
0, and this script used to discard that stderr whenever the exit code was zero. A
mistyped ``[@thm:label]`` therefore shipped into the PDF as the literal text
``[@thm:label]`` with nothing failing anywhere: not pandoc, not this script, not
``run.sh``. Diagnostics are now gated against patterns declared in
``docs/manuscript/config.yaml`` under ``render.fatal_diagnostics``, so the gate is
configurable and so it names classes of problem rather than the one message that
happened to be found first.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

# Installed, `docxplus` is a real package and this is a no-op. Run out of a checkout
# the package lives under src/ and nothing has put it on the path yet. Importing
# first keeps an installed copy authoritative instead of being shadowed.
try:  # pragma: no cover - one branch or the other, trivially
    import docxplus as _docxplus  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from docxplus.manuscript_vars import render_text, variables
from docxplus.project_paths import ensure_output_dirs, project_root, source_manuscript_dir

#: Used only when config.yaml carries no ``render:`` block, so a stripped-down
#: config still gets a gate rather than silently getting none.
DEFAULT_RENDER = {
    "pdf_engine": "xelatex",
    "number_sections": True,
    "link_color": "docxplusred",
    "fatal_diagnostics": [r"^formalism\.lua:", r"^\[WARNING\]", r"^\[ERROR\]"],
    "benign_diagnostics": [],
}


def render_settings(config_path: Path) -> dict:
    """The ``render:`` block from the rendered config, over the defaults above."""
    settings = dict(DEFAULT_RENDER)
    if config_path.is_file():
        loaded = yaml.safe_load(config_path.read_text()) or {}
        settings.update(loaded.get("render") or {})
    return settings


def diagnose(stderr: str, settings: dict) -> list[str]:
    """Stderr lines that must fail the build, in the order they were emitted.

    Matching is per line so one fatal diagnostic in an otherwise chatty run is
    still caught, and exemption is applied after selection so an entry in
    ``benign_diagnostics`` can only ever subtract from the gate, never widen it.
    """
    fatal = [re.compile(p) for p in settings.get("fatal_diagnostics") or []]
    benign = [
        re.compile(entry["pattern"] if isinstance(entry, dict) else entry)
        for entry in settings.get("benign_diagnostics") or []
    ]
    hits = []
    for line in stderr.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if any(p.search(line) for p in fatal) and not any(p.search(line) for p in benign):
            hits.append(line)
    return hits


def missing_pdf_tools(settings: dict) -> list[str]:
    """Required PDF toolchain executables absent from PATH, in check order.

    A missing tool is a build failure, not a skip: pandoc-crossref is required for
    every ``[@fig:x]``/``[@sec:x]`` reference, and the engine is how the PDF is
    produced. ``--text-only`` is the explicitly named lightweight mode.
    """
    required = ["pandoc", "pandoc-crossref", str(settings.get("pdf_engine", "xelatex"))]
    return [tool for tool in required if shutil.which(tool) is None]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--text-only", action="store_true",
        help="substitute tokens and build figures without compiling the PDF",
    )
    args = parser.parse_args(argv)
    values = variables()
    root = project_root()
    src_dir = source_manuscript_dir()
    dirs = ensure_output_dirs()
    out_dir = dirs["output"] / "manuscript"
    out_dir.mkdir(parents=True, exist_ok=True)
    doc_dir = dirs["documents"]
    doc_dir.mkdir(parents=True, exist_ok=True)

    # First ensure figures are built
    build_fig_script = root / "scripts" / "build_figures.py"
    if build_fig_script.is_file():
        subprocess.run([sys.executable, str(build_fig_script)], check=True)

    unresolved: set[str] = set()
    rendered: list[Path] = []
    
    # Process all section markdown files in order
    for path in sorted(src_dir.glob("*.md")):
        if path.name in {"AGENTS.md", "README.md"}:  # not manuscript sections
            continue
        text, missing = render_text(path.read_text(), values)
        unresolved |= missing
        dest = out_dir / path.name
        dest.write_text(text)
        rendered.append(dest)

    # config.yaml carries {{TOKENS}} too (version, date), and pandoc reads it
    # verbatim, so it has to be substituted into the output tree like any section
    # rather than passed straight from source.
    config_src = src_dir / "config.yaml"
    config_out = config_src
    if config_src.is_file():
        text, missing = render_text(config_src.read_text(), values)
        unresolved |= missing
        config_out = out_dir / "config.yaml"
        config_out.write_text(text)

    for dest in rendered:
        print(f"Rendered: {dest}")
    if unresolved:
        sys.stderr.write(f"unresolved manuscript tokens: {sorted(unresolved)}\n")
        return 1

    if args.text_only:
        print("text-only render: PDF compilation skipped")
        return 0

    # PDF Compilation via Pandoc
    settings = render_settings(config_out)
    missing = missing_pdf_tools(settings)
    if missing:
        sys.stderr.write(
            "required PDF tools not found on PATH: " + ", ".join(missing)
            + "; install them or pass --text-only\n"
        )
        return 1
    pandoc = shutil.which("pandoc")
    pdf_out = doc_dir / "manuscript.pdf"
    cmd = [
        pandoc,
        "--metadata-file=" + str(config_out),
        "--pdf-engine=" + str(settings["pdf_engine"]),
        # Authored docs/manuscript/ and rendered output/manuscript/ both resolve
        # ../../output/figures/<name>.png to the actual figure directory.
        # Explicit resource roots keep those links independent of the caller's cwd.
        "--resource-path", os.pathsep.join([str(root), str(src_dir), str(out_dir)]),
    ]

    # Numbering is automatic, per docs/manuscript/README.md. Hand-typed section numbers
    # drift, and without real numbers pandoc-crossref renders every [@sec:x]
    # reference as a bare "sec." with nothing after it.
    if settings.get("number_sections", True):
        cmd.append("--number-sections")

    # Link colour MUST go through pandoc's variables, not the -H preamble. Pandoc
    # emits its own \hypersetup{...hidelinks...} *after* anything -H injects, so a
    # \hypersetup in the preamble is silently overridden and every link renders
    # black. The colour itself is defined in preamble.tex via xcolor and referenced
    # here by name. Margins stay in the preamble, where nothing competes with them.
    link_color = str(settings["link_color"])
    cmd.extend(["-V", "colorlinks=true"])
    for role in ("linkcolor", "citecolor", "urlcolor", "toccolor"):
        cmd.extend(["-V", f"{role}={link_color}"])

    # Add preamble if present
    preamble = src_dir / "preamble.tex"
    if preamble.is_file():
        cmd.extend(["-H", str(preamble)])

    # Filter order is load-bearing and must stay in this sequence:
    #   1. formalism.lua consumes [@def:x]-style references before any citation
    #      machinery sees them, so they never reach the bibliography as unresolved keys;
    #   2. pandoc-crossref resolves [@fig:x] / [@sec:x];
    #   3. citeproc resolves what remains against references.bib.
    # Running citeproc before pandoc-crossref leaves real citations as literal
    # "[@key]" text in the PDF, which is what this pipeline used to ship.
    formalism_lua = src_dir / "formalism.lua"
    if formalism_lua.is_file():
        cmd.extend(["--lua-filter", str(formalism_lua)])

    crossref = shutil.which("pandoc-crossref")
    if crossref:
        cmd.extend(["--filter", crossref])

    bib_file = src_dir / "references.bib"
    if bib_file.is_file():
        cmd.extend(["--bibliography", str(bib_file), "--citeproc"])

    cmd.extend(["-o", str(pdf_out)])
    cmd.extend([str(p) for p in rendered])

    print(f"Compiling PDF -> {pdf_out}")
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        sys.stderr.write(f"Pandoc error:\n{res.stderr}\n")
        return res.returncode

    # A zero exit code only means LaTeX produced a file. Whether that file says
    # what the manuscript meant is a separate question, and it is answered here.
    fatal = diagnose(res.stderr, settings)
    if fatal:
        sys.stderr.write(
            f"{len(fatal)} fatal diagnostic(s) from a pandoc run that exited 0 — "
            "the PDF was produced but is wrong:\n"
        )
        for line in fatal:
            sys.stderr.write(f"  {line}\n")
        sys.stderr.write(
            "Fix the manuscript, or, if a diagnostic is genuinely benign, add it to "
            "render.benign_diagnostics in docs/manuscript/config.yaml with a reason.\n"
        )
        return 1
    if res.stderr.strip():
        # Non-fatal output is still worth seeing; swallowing it is how the fatal
        # kind went unnoticed for as long as it did.
        sys.stderr.write(res.stderr)

    print(f"Successfully compiled PDF: {pdf_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

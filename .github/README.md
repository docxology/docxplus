# .github/ — continuous integration

One workflow, [`workflows/ci.yml`](workflows/ci.yml), on every push and pull request to
`main`. Ubuntu, Python 3.12, `uv`.

## The gates, in the order they fail

| # | Gate | Command |
| --- | --- | --- |
| 1 | install | `uv pip install -e '.[dev,media,figures]'` — all three extras |
| 2 | lint | `uvx ruff check src scripts docxplus_cli.py` |
| 3 | tests + coverage | `.venv/bin/python -m pytest --cov=src -q` (≥90% on `src/`, `fail_under` in `pyproject.toml`) |
| 4 | manuscript | `z_generate_manuscript_variables.py` then `render_manuscript.py` |

Run the same four locally before you push. Lint is first and cheapest, and it is the
one people skip.

## Why the manuscript is a CI gate

Gate 4 is not a documentation nicety. `render_manuscript.py` exits non-zero on an
undefined `{{TOKEN}}`, and the token values come from live code constants — so a
constant that changes without its documentation following it fails the build here.

## What CI does not cover — and how to tell

Read this before treating a green run as a full verification.

- **The pandoc diagnostic gate and the PDF.** `render_manuscript.py` skips PDF
  compilation and returns 0 when pandoc is absent, and no pandoc is installed here. So
  gate 4 in CI proves token resolution and nothing more. The gate that catches an
  unresolved cross-reference or a missing figure — the one that matters, because pandoc
  reports both and then exits 0 — runs only in a local `./run.sh render`. **Run it
  before tagging a release.**
- **The steganographer Rust backend.** Tests marked `requires_steganographer` skip; the
  pure-Python LSB path is exercised instead. If you change the bridge, run the marked
  tests locally against a built binary.
- **LibreOffice openability.** `tests/test_interop.py` verifies it when a headless
  LibreOffice is available, and skips otherwise.

A skip is visible in the CI log and is never counted as a pass. Each of these is a
place where green means "was not checked", so say which ones you verified locally when
a release depends on them.

Editing rules: [`AGENTS.md`](AGENTS.md).

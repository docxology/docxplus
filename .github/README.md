# .github/ — Continuous Integration & Quality Gates

The continuous integration workflow ([`workflows/ci.yml`](workflows/ci.yml)) executes on every push and pull request targeting `main` (Ubuntu Latest, Python 3.12, powered by `uv`).

## The Gates (in Execution Order)

| # | Gate | Canonical Command | Purpose & Pass Condition |
| --- | --- | --- | --- |
| 1 | **Environment & Dependencies** | `uv venv && uv pip install -e '.[dev,media,figures]'` | Installs editable package with all three extras (`dev` for test tools, `media` for Pillow LSB stego, `figures` for matplotlib plates). |
| 2 | **Lint & Style** | `uvx ruff check src scripts src/docxplus/cli.py` | Enforces zero lint/style violations across source, orchestrator scripts, and CLI entry points. |
| 3 | **Tests & Coverage** | `.venv/bin/python -m pytest --cov=src -q` | Executes deterministic real-data test suite; enforces strict **≥90% coverage on `src/`** (`fail_under = 90` in `pyproject.toml`). |
| 4 | **Manuscript & Token Integrity** | `.venv/bin/python scripts/z_generate_manuscript_variables.py && .venv/bin/python scripts/render_manuscript.py` | Verifies live code constant extraction and guarantees zero unresolved `{{TOKEN}}` references in research prose. |

Always run these four gates locally before pushing changes. Gate 2 (Ruff linting) is fast and cheap to run first.

## Why Manuscript Rendering is a CI Gate

Gate 4 is an automated consistency contract between codebase and research publication:
- `scripts/z_generate_manuscript_variables.py` extracts verified metrics, constants, and cryptographic invariants directly from `src/docxplus/`.
- `scripts/render_manuscript.py` hydrates manuscript markdown templates and **fails with non-zero exit code on any undefined token**.
- This guarantees that documentation, formal specs, and publication claims never drift from running code.

## Verification Matrix: CI vs. Local Release Validation

| Verification Scope | In GitHub CI | In Local Pipeline (`./run.sh`) | Notes & Pre-Release Requirement |
| --- | :---: | :---: | --- |
| **Python Unit & Integration Suite** | Checked (Pass) | Checked (Pass) | 600+ real-data tests with zero mock framework calls. |
| **Code Coverage Floor (≥90%)** | Enforced | Enforced | Monitored across all 21 core domain modules and channels. |
| **Token Hydration & Variable Invariants** | Enforced | Enforced | Catches drift between implementation constants and text. |
| **Pandoc Diagnostic Gate & Full PDF** | Skipped | **Required** | CI runs in headless environments without pandoc/LaTeX. Pandoc reports unresolved cross-references or missing figures as non-fatal warnings; local `./run.sh render` treats them as blocking gates. |
| **Rust Steganographer Backend** | Skipped | Optional / Local | CI runs the pure-Python LSB path. Tests marked `@pytest.mark.requires_steganographer` require local binary builds (`cargo build --release`). |
| **LibreOffice Headless Interoperability** | Skipped | Optional / Local | `tests/test_interop.py` validates real application openability when headless LibreOffice is installed. |

> **Release Rule**: A green CI badge confirms Python code health and token resolution. Always execute `./run.sh` locally to verify full pandoc PDF rendering, figure plate generation, and end-to-end container round-trips before tagging or publishing a release.

Editing and contribution rules: [`AGENTS.md`](AGENTS.md).

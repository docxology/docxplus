# .github/ — Continuous Integration & Quality Gates

The continuous integration workflow ([`workflows/ci.yml`](workflows/ci.yml)) runs
for main pushes/pull requests, version tags and manual dispatch on Ubuntu. It uses
the repository's pinned Python and locked all-extras environment, read-only
repository permissions and no persisted checkout credentials.

## The Gates (in Execution Order)

| # | Gate | Canonical Command | Purpose & Pass Condition |
| --- | --- | --- | --- |
| 1 | **Environment & Dependencies** | `uv python install && uv sync --locked --all-extras` | Uses the repository Python pin and installs all three locked extras; records the actual interpreter version. |
| 1a | **Linux reproduction sandbox** | `bwrap --unshare-user --unshare-net --ro-bind / / true` | Installs real bubblewrap and requires usable unprivileged user/network namespaces; no sandbox bypass. |
| 2 | **Lint & Style** | `.venv/bin/python -m ruff check src scripts tests` | Enforces zero lint/style violations across the `src/` package, the orchestrator scripts, and the test suite. Runs the ruff the `dev` extra pins, so CI and a local checkout judge the same version — an unpinned `uvx ruff` gate re-litigated the same findings on every ruff release. |
| 3 | **Tests & Coverage** | `.venv/bin/python -m pytest --cov=src -q` | Executes deterministic real-data test suite; enforces strict **>=90% coverage on `src/`** (`fail_under = 90` in `pyproject.toml`). |
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
| **Python Unit & Integration Suite** | Required | Required | Real-data suite with real subprocesses; no mock forwarding. |
| **Code Coverage Floor (>=90%)** | Enforced | Enforced | Whole `src/` domain surface, without omitting renderer modules. |
| **Token Hydration & Variable Invariants** | Enforced | Enforced | Catches drift between implementation constants and text. |
| **Pandoc Diagnostic Gate & Full PDF** | Skipped | **Required** | CI runs in headless environments without pandoc/LaTeX. Pandoc reports unresolved cross-references or missing figures as non-fatal warnings; local `./run.sh render` treats them as blocking gates. |
| **Rust Steganographer Backend** | Skipped | Optional / Local | CI runs the pure-Python LSB path. Tests marked `@pytest.mark.requires_steganographer` require local binary builds (`cargo build --release`). |
| **LibreOffice Headless Interoperability** | Skipped | Optional / Local | `tests/test_interop.py` validates real application openability when headless LibreOffice is installed. |

> **Release Rule**: A green CI badge is not full release proof. Use `./run.sh`
> with actual rendering tools/backend, or the separately qualified disposable
> Linux workflow in [`../scripts/README.md`](../scripts/README.md#release-validation).
> That workflow verifies isolation, full pipeline, current Rust CLI, actual PDF
> and template four-format roundtrips, wheel/sdist, and installed-artifact behavior
> before source-integrated generated outputs and a release tag.

Editing and contribution rules: [`AGENTS.md`](AGENTS.md).

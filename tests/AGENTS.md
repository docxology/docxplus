# tests/ — real-data, no-mocks suite

No `unittest.mock`, no `MagicMock`, no `patch` of dependency behavior. Use real files
(`tmp_path`), real crypto, real subprocess. `monkeypatch` is permitted only for
environment isolation (env vars, PATH resolution, redirecting a project root), never to
fake a dependency's return value.

Markers: `requires_steganographer` (real Rust CLI), `requires_pillow`, `slow`.
Coverage gate is 90% on `src/`. Run: `.venv/bin/python -m pytest --cov=src -q`.
The file-by-file map is in [`README.md`](README.md).

## What a test here has to do

- **Cross the byte boundary.** Build, serialise the package, read it back *from those
  bytes*, then assert. An in-memory shortcut skips part naming, content types, and ZIP
  determinism — the three things most likely to break.
- **Name what it pins.** A test docstring says which behaviour would silently return
  without it. For a regression, name the finding. The adversarial files exist so that
  a reader of [`../docs/redteam-audit.md`](../docs/redteam-audit.md) can go from a
  finding to the test that holds it closed.
- **Assert the negative too.** Most of the value in this suite is in what the code
  *refuses*: a symlink in a project tree, an unpinned key returning "authentic", a KDF
  envelope demanding 16 GiB, an unknown channel id. A test that only proves the happy
  path leaves the security claim unmeasured.
- **Fail rather than skip when the thing is required.** A skip is for a genuinely
  optional backend, declared by a marker. Never `pytest.skip` around a failure you did
  not want to debug — that converts a red into a green.

## Coverage is a floor, not the goal

90% is the gate; a line executed is not a line verified. When adding a branch to a
security-relevant path — sealing, unsealing, verification, intake, execution — add the
test that shows what the branch prevents, not just one that reaches it.

## Documentation checks exercise reader-visible failures

`test_docs.py` checks relative navigation targets. `test_manuscript_vars.py`
renders the actual manuscript sources with live variables. `test_numbering.py`
checks unresolved/duplicate references and fatal renderer diagnostics.
Do not pin prose, source text, inventories, incidental defaults or test counts.
The real release pipeline must still render the manuscript and retain its coverage floor.

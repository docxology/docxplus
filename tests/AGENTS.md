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

## The doc tests are load-bearing

`test_docs.py`, `test_manuscript_vars.py`, and `test_numbering.py` turn documentation
into a checked surface: a new module, channel, subcommand, `run.sh` stage, or directory
fails the build until it is documented, and a hand-typed drift-prone number fails it
immediately. If a change to those tests would make them easier to pass, that is the
signal to check whether it also makes them stop catching anything.

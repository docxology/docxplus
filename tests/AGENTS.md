# tests/ — real-data, no-mocks suite

No `unittest.mock`, no `MagicMock`, no `patch` of dependency behavior. Use real
files (`tmp_path`), real crypto, real subprocess. `monkeypatch` is permitted only
for environment isolation (env vars, PATH resolution, redirecting a project root),
never to fake a dependency's return value.

Markers: `requires_steganographer` (real Rust CLI), `requires_pillow`, `slow`.
Coverage gate is 90% on `src/`. Run: `.venv/bin/python -m pytest --cov=src -q`.

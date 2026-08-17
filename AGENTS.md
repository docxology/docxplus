# AGENTS.md — docxplus working guide

Standalone research repo implementing **docxplus**, an intelligent OOXML document
container. Follows the docxology `template_code_project` paradigm (tested `src/`,
thin `scripts/`, no-mocks tests, ≥90% coverage) but does **not** import the
template's shared `infrastructure/` layer — it is self-contained.

## Commands

```bash
uv venv && uv pip install -e '.[dev,media]'     # figures extra adds matplotlib
./run.sh                        # preflight, tests, example, dossier, round trips, manuscript
.venv/bin/python -m pytest --cov=src -q          # tests + 90% gate
uv run docxplus --help                           # the CLI
```

The optional steganographer backend needs a built Rust binary. On this machine:
`rustup run stable cargo build --release -p steganographer-cli` inside
`../steganographer`, with `/opt/homebrew/bin` on PATH and
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` (GStreamer). Integration tests are
marked `requires_steganographer` and skip gracefully when absent.

## Architecture (see docs/architecture.md)

Business logic lives only in `src/`. Scripts and `docxplus_cli.py` are thin
orchestrators — they coordinate I/O and print output paths, never implement a
channel or crypto primitive. The manifest (`intelligence/manifest.json`) is the
single source of truth for what a package carries; readers bind to it, never to
guessed part names.

## Invariants

- The surface `.docx` must stay OPC-conforming. `validate.py` is the gate; run it on
  anything you produce.
- Encryption is **payload-level only** (never whole-package) so the document stays
  openable.
- Deterministic output: fixed ZIP timestamps, sorted entries. Do not reintroduce
  wall-clock timestamps.
- Every structural claim about OOXML/ODF must trace to `docs/standards-report.md`.
  Do not invent spec behavior.
- No mocks in tests. Use real files, real crypto, real subprocess against the built
  steganographer binary.
- `steg_bridge` must never mask a real tool failure as success — absence skips,
  failure raises.

## Adding a channel

Implement the `Channel` protocol in `src/channels/` (`embed`/`extract`/`capacity`),
register it in `channels/__init__.py`, and add a real round-trip test. The manifest
records the channel id; unknown ids fail explicitly on read.

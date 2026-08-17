# AGENTS.md — docxplus working guide

Standalone research repo implementing **docxplus**, an intelligent OOXML/ODF document
container. Follows the docxology `template_code_project` paradigm (tested `src/`, thin
`scripts/`, no-mocks tests, ≥90% coverage) but does **not** import the template's
shared `infrastructure/` layer — it is self-contained.

Read this file, then the `AGENTS.md` in whichever directory you are about to touch.
This one holds only what is true everywhere.

| Directory | Its rules | Its inventory |
| --- | --- | --- |
| `src/` | [`src/AGENTS.md`](src/AGENTS.md) | [`src/README.md`](src/README.md) |
| `src/channels/` | [`src/channels/AGENTS.md`](src/channels/AGENTS.md) | [`src/channels/README.md`](src/channels/README.md) |
| `scripts/` | [`scripts/AGENTS.md`](scripts/AGENTS.md) | [`scripts/README.md`](scripts/README.md) |
| `tests/` | [`tests/AGENTS.md`](tests/AGENTS.md) | [`tests/README.md`](tests/README.md) |
| `docs/` | [`docs/AGENTS.md`](docs/AGENTS.md) | [`docs/README.md`](docs/README.md) |
| `manuscript/` | [`manuscript/AGENTS.md`](manuscript/AGENTS.md) | [`manuscript/README.md`](manuscript/README.md) |
| `output/` | [`output/AGENTS.md`](output/AGENTS.md) | [`output/README.md`](output/README.md) |
| `data/` | [`data/AGENTS.md`](data/AGENTS.md) | [`data/README.md`](data/README.md) |
| `.github/` | [`.github/AGENTS.md`](.github/AGENTS.md) | [`.github/README.md`](.github/README.md) |
| `.agents/` | [`.agents/AGENTS.md`](.agents/AGENTS.md) | [`.agents/README.md`](.agents/README.md) |

## Commands

```bash
uv venv && uv pip install -e '.[dev,media,figures]'   # install all three extras
./run.sh                        # preflight, tests, build, dossier, round trips, render, living
./run.sh help                   # the stage list, generated from the driver itself
uvx ruff check src scripts docxplus_cli.py            # CI's first gate — run it before committing
.venv/bin/python -m pytest --cov=src -q               # tests + the 90% gate
uv run docxplus --help                                # the CLI
```

Install **all three** extras. `dev` is pytest, `media` is Pillow for the LSB channel,
`figures` is matplotlib. `scripts/build_figures.py` exits 0 when matplotlib is absent,
so a render without `figures` reuses the committed plates instead of regenerating them
— green, and not what you measured. CI installs `.[dev,media,figures]`; match it.

The optional steganographer backend needs a built Rust binary. On this machine:
`rustup run stable cargo build --release -p steganographer-cli` inside
`../steganographer`, with `/opt/homebrew/bin` on PATH and
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` (GStreamer). Integration tests are
marked `requires_steganographer` and skip gracefully when absent.

## Architecture (see [`docs/architecture.md`](docs/architecture.md))

Business logic lives only in `src/`. Scripts and `docxplus_cli.py` are thin
orchestrators — they coordinate I/O and print output paths, never implement a channel
or crypto primitive. Modules form a strict dependency stack (L0 foundations → L6
orchestration); a lower layer never imports a higher one. The manifest
(`intelligence/manifest.json`) is the single source of truth for what a package
carries; readers bind to it, never to guessed part names.

Two profiles, one intelligence layer: `container.py` (`.docx`) and `odt_container.py`
(`.odt`) share the sealing and unsealing code rather than reimplementing it. A change
to one sealing lineage must hold for both — that sharing is why the profiles cannot
drift apart on the details that matter under attack.

## Invariants

- The surface `.docx`/`.odt` must stay conforming. `validate.py` is the gate; run it on
  anything you produce.
- Encryption is **payload-level only** (never whole-package) so the document stays
  openable.
- Deterministic output: fixed ZIP timestamps, sorted entries. Do not reintroduce
  wall-clock timestamps.
- Every structural claim about OOXML/ODF must trace to
  [`docs/standards-report.md`](docs/standards-report.md). Do not invent spec behavior.
- No mocks in tests. Real files, real crypto, real subprocess against the built
  steganographer binary.
- `steg_bridge` must never mask a real tool failure as success — absence skips,
  failure raises. The same rule holds everywhere: a missing capability must say so,
  never be reported as a pass.
- Execution happens in exactly one place — `reproduce.py`, and only when the caller
  passes `allow_execution=True`. Nothing on a read, extract, or verify path may
  execute anything.
- Authenticity always requires a pinned key. A check that does not pin proves
  self-consistency only, and any prose describing it must say so out loud.

## Documentation is a checked surface

Docs rot silently: a new module, channel, or subcommand ships and nothing fails.
`tests/test_docs.py` makes that a build failure instead — every module has an
architecture entry, every CLI command a reference entry, every channel a page, every
directory both guides, every internal link a live target.

Two rules follow, and they are the ones that get broken:

1. **Never type a drift-prone number.** Values come from
   `src/manuscript_vars.variables()`, which reads live code constants and the repo. In
   the manuscript they are `{{TOKENS}}`; in a README they are literals *pinned by a
   test*. A hand-typed count is how the root README came to claim eight audit cycles
   when the record held fourteen.
2. **Do not restate an enforced inventory.** `docs/architecture.md` owns the module
   map, `docs/cli.md` owns the subcommand list, `docs/README.md` owns the doc index.
   A second, unenforced copy is a second thing to forget.

When a claim would drift, regenerate and cite the real number rather than freezing a
stale one.

## Adding a channel

Implement the `Channel` protocol in `src/channels/` (`embed`/`extract`/`capacity`),
register it in `channels/__init__.py`, and add a real round-trip test. The manifest
records the channel id; unknown ids fail explicitly on read. Then document it in
`docs/channels.md` and `docs/format-spec.md` — the suite requires both. Full recipe:
[`src/channels/AGENTS.md`](src/channels/AGENTS.md).

## Prose

Timeless present-state, told once. No session logs, no "fixed this pass", no
round-numbered process narration. Negative results and the incident notes that justify
a gate stay — those are findings, not history.

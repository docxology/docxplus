# AGENTS.md — docxplus working guide

Standalone research repo implementing **docxplus**, an intelligent OOXML/ODF document
container. Follows the docxology `template_code_project` paradigm (tested `src/`, thin
`scripts/`, no-mocks tests, >=90% coverage) but does **not** import the template's
shared `infrastructure/` layer — it is self-contained.

Read this file, then the `AGENTS.md` in whichever directory you are about to touch.
This one holds only what is true everywhere.

| Directory | Its rules | Its inventory |
| --- | --- | --- |
| `src/` | [`src/AGENTS.md`](src/AGENTS.md) | [`src/README.md`](src/README.md) |
| `src/docxplus/` | [`src/docxplus/AGENTS.md`](src/docxplus/AGENTS.md) | [`src/docxplus/README.md`](src/docxplus/README.md) |
| `src/docxplus/channels/` | [`src/docxplus/channels/AGENTS.md`](src/docxplus/channels/AGENTS.md) | [`src/docxplus/channels/README.md`](src/docxplus/channels/README.md) |
| `scripts/` | [`scripts/AGENTS.md`](scripts/AGENTS.md) | [`scripts/README.md`](scripts/README.md) |
| `tests/` | [`tests/AGENTS.md`](tests/AGENTS.md) | [`tests/README.md`](tests/README.md) |
| `docs/` | [`docs/AGENTS.md`](docs/AGENTS.md) | [`docs/README.md`](docs/README.md) |
| `docs/manuscript/` | [`docs/manuscript/AGENTS.md`](docs/manuscript/AGENTS.md) | [`docs/manuscript/README.md`](docs/manuscript/README.md) |
| `output/` | [`output/AGENTS.md`](output/AGENTS.md) | [`output/README.md`](output/README.md) |
| `data/` | [`data/AGENTS.md`](data/AGENTS.md) | [`data/README.md`](data/README.md) |
| `.github/` | [`.github/AGENTS.md`](.github/AGENTS.md) | [`.github/README.md`](.github/README.md) |
| `.agents/` | [`.agents/AGENTS.md`](.agents/AGENTS.md) | [`.agents/README.md`](.agents/README.md) |

## Commands

```bash
uv sync --locked --all-extras                         # pinned Python and all extras
./run.sh                        # preflight, tests, build, dossier, round trips, render, living
./run.sh help                   # the stage list, generated from the driver itself
.venv/bin/python -m ruff check src scripts tests       # CI's first gate, verbatim:
                                                       # the ruff the dev extra pins
.venv/bin/python -m pytest --cov=src -q               # tests + the 90% gate
uv run docxplus --help                                # the CLI
```

Install **all three** extras. `dev` is pytest, `media` is Pillow for the LSB channel,
`figures` is matplotlib. `scripts/build_figures.py` exits 0 when matplotlib is absent,
so a render without `figures` reuses the committed plates instead of regenerating them
— green, and not what you measured. CI uses the same locked all-extras sync.

The optional steganographer backend needs an already-built Rust CLI, selected by
`STEGANOGRAPHER_BIN` or `PATH`. Do not build or mutate a sibling checkout. The
isolated validation workflow builds its private, frozen backend input instead.
Integration tests marked `requires_steganographer` skip when the tool is absent;
an explicitly selected unavailable backend or a failed response must raise.

Release validation additionally uses
[`scripts/validate_release.py`](scripts/validate_release.py) and
[`Dockerfile.release-validation`](Dockerfile.release-validation): separately
captured private inputs, network-enabled provisioning, then qualified offline
Linux compute with read-only source/runtime and real nested bubblewrap. See
[`scripts/README.md`](scripts/README.md#release-validation). Do not disable
production sandboxing to work around macOS nested-Seatbelt refusal. Collection
users capture/import under their manager's native short source leases; no long
pipeline belongs inside a canonical repository lease.

## Architecture (see [`docs/architecture.md`](docs/architecture.md))

Business logic lives only in `src/docxplus/`. Scripts and `src/docxplus/cli.py` are thin
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

Keep architecture, CLI and channel contracts aligned when their APIs change.
Documentation checks exercise live relative links, rendering, references and
diagnostics; they are not assertions of incidental prose, counts or defaults.

Two rules follow, and they are the ones that get broken:

1. **Do not freeze drift-prone numbers or phrases.** Manuscript metrics use
   `{{TOKENS}}` derived from `src/docxplus/manuscript_vars.variables()`.
   README claims should name the contract and source-bound evidence, not require
   tests of incidental wording, counts or defaults.
2. **Do not duplicate an inventory.** `docs/architecture.md` owns the module
   map, `docs/cli.md` the subcommands, `docs/README.md` the index.
   A second hand-maintained copy is another opportunity for drift.

Regeneration hydrates values; only actual source-bound receipts establish freshness.
Historic audit/report values stay historic, never a new release qualification.

## Adding a channel

Implement the `Channel` protocol in `src/docxplus/channels/` (`embed`/`extract`/`capacity`),
register it in `channels/__init__.py`, and add a real round-trip test. The manifest
records the channel id; unknown ids fail explicitly on read. Then document it in
`docs/channels.md` and `docs/format-spec.md` with actual contracts. Full recipe:
[`src/docxplus/channels/AGENTS.md`](src/docxplus/channels/AGENTS.md).

## Prose

Timeless present-state, told once. No session logs, no "fixed this pass", no
round-numbered process narration. Negative results and the incident notes that justify
a gate stay — those are findings, not history.

# tests/ — the suite

Real files, real crypto, real subprocesses. No mocks. The gate is 90% branch coverage
on `src/`.

```bash
.venv/bin/python -m pytest --cov=src -q          # everything, with the gate
.venv/bin/python -m pytest tests/test_odt.py -q  # one file
.venv/bin/python -m pytest -m "not slow" -q      # skip the full build round trips
```

Markers: `requires_steganographer` (the real Rust CLI), `requires_pillow`, `slow`.
Each skips cleanly when its dependency is absent — a skip is visible, and never
counted as a pass.

## What the files cover

**Primitives** — `test_opc`, `test_crypto`, `test_crypto_advanced`, `test_shamir`,
`test_provenance`, `test_transparency`, `test_lsb`, `test_project_paths`.
Deterministic serialisation, the KDF ceilings, X25519 multi-recipient sealing, k-of-n
sharing, Merkle roots and proofs, the append-only log, the LSB codec.

**Surface formats** — `test_wordml`, `test_odt`, `test_fileext`. The minimal
conforming documents, and the dual-name export that writes the same bytes twice.

**The intelligence layer** — `test_manifest`, `test_payloads`, `test_channels`,
`test_mce`, `test_stego_media`, `test_container`, `test_container_v2`,
`test_odt_container`, `test_validate`. Manifest canonicalisation and signing, the
typed payloads, each channel's round trip, and both container profiles end to end.

**The contracts that are easy to overclaim** — `test_project_fidelity` (what a
`project` payload preserves, normalises, and *refuses*), `test_reproduce` (attestation
and the execution boundary), `test_steganalysis_bounds` (what the shipped steganalysis
finds, what it misses, and what breaks a carrier), `test_steg_bridge` (resolution logic
on real files, plus the optional real tool).

**Adversarial regressions** — `test_hardening`, `test_redteam_round12`,
`test_redteam_round13`, `test_redteam_round14`, `test_v5_features`. Every confirmed
finding in [`../docs/redteam-audit.md`](../docs/redteam-audit.md) is pinned here so it
cannot come back. The rounds are kept as separate files because a finding is easier to
trace to its review than to a merged pile.

**The documentation and the paper** — `test_docs`, `test_manuscript_vars`,
`test_numbering`. These are why a stale doc fails the build rather than reaching a
reader: every module has an architecture entry, every CLI command a reference entry,
every channel a page, every directory both guides, every internal link a target, every
drift-prone number derived rather than typed, and every figure and formalism numbered
at render time rather than by hand.

**Interop** — `test_interop`, including optional headless LibreOffice openability
verification. The claim is that these files open in real software; where the software
is available, that is checked rather than asserted.

## The rule that shapes all of it

A test that mocks a dependency tests the mock. This suite builds a document, serialises
it to bytes, reads it back from those bytes, and compares — because part naming,
content types, and ZIP determinism only exist on the far side of that round trip.

Editing rules: [`AGENTS.md`](AGENTS.md).

---
name: docxplus
description: docxplus intelligent document container — build/read/validate a byte-valid .docx or .odt that also carries a signed, encrypted, modular intelligence layer through spec-sanctioned side-channels, with a steganographer media backend.
version: 1.0.0
author: docxology
license: MIT
tags: [ooxml, odf, docx, odt, steganography, document-security, thin-orchestrator]
---

# docxplus

Project-scoped skill for the docxplus container in this repo. Load it when working
inside the project — building documents, adding a channel, or validating output.
Then read the root `AGENTS.md` and the one in the directory you are about to touch;
this skill carries the entry points and the contracts, not the module map.

## When to use

- Producing or reading a docxplus file — a `.docx` or `.odt` carrying an intelligence
  layer.
- Adding a payload channel, payload type, sealing mode, or crypto option.
- Validating that a produced document is both format-conforming and
  manifest-consistent.
- Deciding what a verification result actually lets you conclude.

## Quick reference

```bash
uv venv && uv pip install -e '.[dev,media,figures]'   # all three extras; see AGENTS.md
./run.sh                                    # preflight, tests, build, dossier, round trips, render, living
uvx ruff check src scripts src/docxplus/cli.py  # CI's first gate
.venv/bin/python -m pytest --cov=src -q     # 90% gate

# .docx profile
uv run docxplus build out.docx --text "Report" --module brief:custom_xml:brief.json --password s3cret
uv run docxplus inspect out.docx
uv run docxplus extract out.docx brief --password s3cret --out brief.json
uv run docxplus validate out.docx

# .odt profile — same intelligence layer, same sealing lineages
uv run docxplus odt-build out.odt --module brief:brief.json --password s3cret --signing-key key.hex
uv run docxplus odt-validate out.odt
uv run docxplus odt-extract out.odt brief --password s3cret

# authenticity, as opposed to conformance
uv run docxplus verify out.docx --expected-key author.pub
```

`docxplus --help` lists all 19 subcommands; `docs/cli.md` is the contract.

## Contracts

- The surface `.docx`/`.odt` stays conforming (`validate.py` is the gate).
- Encryption is payload-level only; the document stays openable.
- The manifest is authoritative; readers bind to it, never guess part names.
- Both profiles share the sealing and unsealing code. A change to one lineage must
  hold for both — never fork it.
- **`validate` is conformance; `verify` is authenticity, and authenticity requires a
  pinned key.** The key inside a manifest is self-asserted, so an unpinned check
  proves self-consistency only.
- Execution happens in exactly one place: `reproduce.py`, behind an explicit
  `allow_execution=True`. Nothing on a read, extract, or verify path executes
  anything.
- Deterministic output: fixed ZIP timestamps, sorted entries, no wall-clock.
- No mocks; ground spec claims in `docs/standards-report.md`.
- The steganographer backend is optional (needs the built Rust binary); absence skips,
  failure raises — never a silent no-op.

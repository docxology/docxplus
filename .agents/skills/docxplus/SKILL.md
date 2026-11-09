---
name: docxplus
description: docxplus intelligent document container — build/read/validate a byte-valid .docx or .odt that also carries a signed, encrypted, modular intelligence layer through spec-sanctioned side-channels, with a steganographer media backend.
version: 2.2.2
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
- Checking a produced document's supported package structure and manifest consistency;
  full ISO/RNG/XSD conformance and universal consumer compatibility are separate claims.
- Deciding what a verification result actually lets you conclude.

## Quick reference

```bash
uv sync --locked --all-extras                 # pinned standalone toolchain; see AGENTS.md
./run.sh                                    # preflight, tests, build, dossier, round trips, render, living
.venv/bin/python -m ruff check src scripts tests  # CI's first gate (ruff pinned in the dev extra)
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

`docxplus --help` is the current command surface; `docs/cli.md` is the contract.

## Contracts

- Both `.docx` and `.odt` use standards-defined package extension points. The selected
  structural checks in `validate.py` are not complete conformance certification.
- Encryption is payload-level only; the document stays openable.
- The authenticated format-3 manifest is authoritative; readers never guess locations.
  Rebuild and re-sign trusted legacy inputs; there is no legacy verification fallback.
- Both profiles share sealing and unsealing. Changes must hold for both, never fork it.
- A valid self-signature proves self-consistency, not identity. Authenticity requires
  pinning the complete expected key, including both halves of a hybrid identity.
- Carried code executes only through `reproduce.py` with explicit `allow_execution=True`.
  Reads, extraction and verification never execute carried code; a requested trusted
  media decoder may run. Missing confinement refuses execution. Neither platform is
  a hermetic environment or a host-secret read boundary.
- Archive composition fixes timestamps and ordering for the same parts. Cryptographic
  entropy and explicit author attestations are not promised bit-for-bit reproducible.
- Ground spec claims in `docs/standards-report.md` and real consumer evidence, not mocks.
- Backend absence may skip optional tests, but requesting an unavailable backend or
  receiving a failed/invalid response raises. Never implicitly build or mutate a sibling.

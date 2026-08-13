---
name: docxplus
description: DOCX+ intelligent document container — build/read/validate a byte-valid .docx that also carries a signed, encrypted, modular intelligence layer through OOXML side-channels, with a steganographer media backend.
version: 0.1.0
author: docxology
license: MIT
tags: [ooxml, docx, steganography, document-security, thin-orchestrator]
---

# docxplus

Project-scoped skill for the DOCX+ container in this repo. Load it when working
inside the project — building documents, adding a channel, or validating output.

## When to use

- Producing or reading a DOCX+ file (a `.docx` carrying an intelligence layer).
- Adding a new payload channel or crypto option.
- Validating that a produced document is both OPC-conforming and manifest-consistent.

## Quick reference

```bash
uv venv && uv pip install -e '.[dev,media]'
./run.sh                                   # preflight -> tests -> build -> roundtrip
.venv/bin/python -m pytest --cov=src -q     # 90% gate
uv run docxplus build out.docx --text "Report" --module brief:custom_xml:brief.json --password s3cret
uv run docxplus inspect out.docx
uv run docxplus extract out.docx brief --password s3cret --out brief.json
uv run docxplus validate out.docx
```

## Contracts

- Surface `.docx` stays OPC-conforming (validate.py is the gate).
- Encryption is payload-level only; the document stays openable.
- The manifest is authoritative; readers bind to it, never guess part names.
- No mocks; ground spec claims in docs/standards-report.md.
- The steganographer backend is optional (needs the built Rust binary); absence
  skips, failure raises — never a silent no-op.

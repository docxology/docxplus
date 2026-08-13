# src/ — DOCX+ domain modules

All business logic lives here. Modules are imported flat (pyproject `pythonpath`
includes `src`): `import opc`, `import container`, `import channels`.

| Module | Responsibility |
| --- | --- |
| `opc.py` | OPC package model + deterministic ZIP (parts, content types, relationships) |
| `wordml.py` | minimal conforming WordprocessingML surface document |
| `crypto.py` | Scrypt (default) + PBKDF2 KDF, AES-256-GCM, X25519 multi-recipient sealing, BLAKE2b digest, Ed25519 sign/verify |
| `shamir.py` | Shamir k-of-n secret sharing over GF(256) (threshold sealing) |
| `payloads.py` | typed payload registry: bytes/text/json/project/docxplus |
| `provenance.py` | Merkle root + inclusion proofs over the module set |
| `reproduce.py` | reproduction attestation + opt-in hermetic sandbox runner (the ONLY code-execution path) |
| `lsb.py` | pure-Python LSB stego codec (Pillow) |
| `steg_bridge.py` | subprocess bridge to the steganographer Rust CLI |
| `channels/` | the modular side-channels (base protocol + implementations) |
| `manifest.py` | signed intelligence manifest (Merkle-bound canonical body) |
| `container.py` | DocxPlusBuilder / DocxPlusReader (typed payloads, sealing modes, nesting, projects) |
| `intake.py` | hardened untrusted-input scan (external rels / macros / altChunk); no execution |
| `validate.py` | OPC + intelligence conformance |
| `project_paths.py` | output directory resolution |
| `reference_docs.py` | the one canonical example document, defined once |
| `manuscript_vars.py` | derive every doc value from live constants (no hard-coding) + token renderer |

Extending: a new **payload type** registers in `payloads.py`; a new **sealing mode**
adds a branch in `container._place` / `DocxPlusReader._unseal` plus a `sealing.mode`
value; a new **channel** implements the `Channel` protocol. Add a real round-trip
test for each.

Rules: keep modules generic and deterministic; no wall-clock timestamps; every
public function typed and docstringed; ground spec claims in docs/standards-report.md.

# src/ — DOCX+ domain modules

All business logic lives here. Modules are imported flat (pyproject `pythonpath`
includes `src`): `import opc`, `import container`, `import channels`.

| Module | Responsibility |
| --- | --- |
| `opc.py` | OPC package model + deterministic ZIP (parts, content types, relationships) |
| `wordml.py` | minimal conforming WordprocessingML surface document |
| `crypto.py` | PBKDF2-SHA512 KDF, AES-256-GCM envelope, BLAKE2b digest, Ed25519 sign/verify |
| `lsb.py` | pure-Python LSB stego codec (Pillow) |
| `steg_bridge.py` | subprocess bridge to the steganographer Rust CLI |
| `channels/` | the modular side-channels (base protocol + implementations) |
| `manifest.py` | signed intelligence manifest |
| `container.py` | DocxPlusBuilder / DocxPlusReader |
| `validate.py` | OPC + intelligence conformance |
| `project_paths.py` | output directory resolution |

Rules: keep modules generic and deterministic; no wall-clock timestamps; every
public function typed and docstringed; ground spec claims in docs/standards-report.md.

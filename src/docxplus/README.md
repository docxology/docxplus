# src/ — the domain modules

All of docxplus's business logic. 21 modules plus the `channels/` package, imported
flat (`pyproject` puts `src` on `pythonpath`): `import opc`, `import container`,
`import channels`.

They form a strict dependency stack. A lower layer never imports a higher one, which
is what makes the crypto testable without a document and the container swappable
between profiles.

## L0 — foundations

Byte-level and mathematical primitives. No knowledge of documents.

| Module | Responsibility |
| --- | --- |
| `opc.py` | OPC package model and deterministic ZIP; the intake caps (bomb ratio, entry size, name collision) |
| `crypto.py` | Argon2id / Scrypt / PBKDF2 KDFs with work-factor **and** memory ceilings, AES-256-GCM, X25519 multi-recipient sealing, Ed25519, BLAKE2b digests |
| `shamir.py` | k-of-n secret sharing over GF(256), with downgrade-resistant VSS commitment tags |
| `provenance.py` | Merkle root (RFC 6962 splitting) and inclusion proofs over the module set |
| `cli.py` | the `docxplus` command line; parses arguments and calls into the modules above |
| `transparency.py` | append-only attestation log: hash chain, inclusion and consistency proofs, and the signed tree head that anchors them |
| `lsb.py` | pure-Python LSB stego codec over PNG carriers (Pillow) |
| `secure_io.py` | owner-only creation of key, share, and recovered-plaintext files |
| `project_paths.py` | repository-root and output-directory resolution, so nothing hardcodes a path |

## L1 — vocabulary

The two surface formats, the payload types, and the channel implementations.

| Module | Responsibility |
| --- | --- |
| `wordml.py` | minimal conforming WordprocessingML surface document |
| `odt.py` | conforming OASIS OpenDocument Text sibling container |
| `payloads.py` | typed payload registry — `bytes`, `text`, `json`, `project`, `docxplus` — and the `project` fidelity contract |
| `fileext.py` | the `.docx`/`.docxplus` and `.odt`/`.odtplus` extension pairs, media types, and dual-name export |
| `steg_bridge.py` | chi-squared steganalysis (always available) plus the subprocess bridge to the optional steganographer Rust CLI |
| `channels/` | the five side-channels behind one protocol — see [`channels/README.md`](channels/README.md) |

## L2 — format

Where bytes become a docxplus package rather than a zip with extras.

| Module | Responsibility |
| --- | --- |
| `manifest.py` | the signed intelligence manifest; canonical body bound to the Merkle root and the surface digest, with co-signatures |
| `reproduce.py` | reproduction attestation and the opt-in hermetic sandbox — the only code-execution path in the repository |
| `intake.py` | hardened untrusted-input threat scan for both profiles, executing nothing: OOXML macros / external relationships / `altChunk`, ODF scripts / Basic / off-package xlink |

## L3–L5 — composition, validation, reference

| Module | Layer | Responsibility |
| --- | --- | --- |
| `container.py` | L3 | `DocxPlusBuilder` / `DocxPlusReader`; `seal_module` is the format-independent sealing step |
| `odt_container.py` | L3 | the same intelligence layer over an ODT package, reusing `container`'s sealing and unsealing rather than duplicating it |
| `validate.py` | L4 | OPC, ODF, and intelligence conformance; refuses an OPC package signature whose reference set omits a manifest-named part |
| `reference_docs.py` | L5 | the one canonical example document, defined once and shared by scripts and tests |
| `manuscript_vars.py` | L5 | derives every documented value from live constants and the repository, so nothing drift-prone is typed by hand |

## Where to look first

- **"How is a document built?"** — `container.py`, then the data-flow diagrams in
  [`../docs/architecture.md`](../../docs/architecture.md).
- **"What can I trust about a file I was sent?"** — `validate.py` and `intake.py` for
  the no-execution checks, `manifest.py` and `provenance.py` for what a signature
  covers, [`../docs/security-model.md`](../../docs/security-model.md) for the boundary.
- **"Where does the payload physically go?"** — `channels/`.
- **"Why is this number in the docs?"** — `manuscript_vars.py`. It is the answer to
  every "where did that figure come from" question in this repo.

The authoritative module map, with layers and data flow, is
[`../docs/architecture.md`](../../docs/architecture.md); `tests/test_docs.py` fails the
build if a module is missing from it, or from this file.

Editing rules: [`AGENTS.md`](AGENTS.md).

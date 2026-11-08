# src/docxplus/ — the domain modules

All of docxplus's business logic, plus the `channels/` package, imported
from the package (`pyproject` puts `src` on `pythonpath`): `from docxplus import opc`,
`from docxplus import container`, `from docxplus import channels`.

They form a strict dependency stack. A lower layer never imports a higher one, which
is what makes the crypto testable without a document and the container swappable
between profiles.

## L0 — foundations

Byte-level and mathematical primitives. No knowledge of documents.

| Module | Responsibility |
| --- | --- |
| `opc.py` | OPC package model and deterministic ZIP; the intake caps (bomb ratio, entry size, name collision) |
| `crypto.py` | bounded KDFs, AES-GCM, classical DXE2/genuine ML-KEM-768 DXE3 recipients, Ed25519/ML-DSA-65 dual signing and portable suite-typed DXHK private keys |
| `shamir.py` | k-of-n GF(256) sharing with unkeyed tagged-share checksums, not Feldman VSS; signed full-share commitments live in the container manifest |
| `provenance.py` | Merkle root (RFC 6962 splitting) and inclusion proofs over the module set |
| `transparency.py` | append-only attestation log: hash chain, inclusion and consistency proofs, and the signed tree head that anchors them |
| `lsb.py` | pure-Python LSB stego codec over PNG carriers (Pillow) |
| `secure_io.py` | exclusive private secrets and sibling-temporary atomic replacement, never existing-inode truncation |
| `archive_limits.py` | stdlib ZIP-directory allocation and single-gzip/TAR physical preflight; byte/header/metadata budgets shared by packages, projects and release evidence |
| `project_paths.py` | repository-root and output-directory resolution, so nothing hardcodes a path |

## L1 — vocabulary

The two surface formats, the payload types, and the channel implementations.

| Module | Responsibility |
| --- | --- |
| `wordml.py` | minimal conforming WordprocessingML surface document |
| `odt.py` | conforming OASIS OpenDocument Text sibling container |
| `payloads.py` | typed registry and project fidelity; descriptor-pinned bounded capture and fresh private extraction with capability refusal |
| `fileext.py` | extension pairs, media types, target preflight/staging and per-entry atomic dual export; not a cross-file transaction |
| `steg_bridge.py` | pair-equality `p_value` statistics and real Rust encode/decode/analyze/capacity command contracts |
| `channels/` | the five side-channels behind one protocol — see [`channels/README.md`](channels/README.md) |

## L2 — format

Where bytes become a docxplus package rather than a zip with extras.

| Module | Responsibility |
| --- | --- |
| `manifest.py` | format-3 canonical body binds module/surface commitments plus primary and declared co-signer algorithms/identities |
| `reproduce.py` | signed output-tree-v3 claims and source_match; private scratch and opt-in platform custody, weaker detached cleanup on macOS |
| `intake.py` | hardened untrusted-input threat scan for both profiles, executing nothing: OOXML macros / external relationships / `altChunk`, ODF scripts / Basic / off-package xlink |

## L3–L6 — composition, validation, reference and orchestration

| Module | Layer | Responsibility |
| --- | --- | --- |
| `container.py` | L3 | `DocxPlusBuilder` / `DocxPlusReader`; `seal_module` is the format-independent sealing step |
| `odt_container.py` | L3 | the same intelligence layer over an ODT package, reusing `container`'s sealing and unsealing rather than duplicating it |
| `validate.py` | L4 | selected structural/intelligence checks, not complete ISO/schema conformance or native Office proof; syntactic OPC reference-set gate |
| `reference_docs.py` | L5 | serialized `ReferenceDossier` with ephemeral credentials; one exported specimen shared by scripts/manuscript |
| `manuscript_vars.py` | L5 | derives every documented value from live constants and the repository, so nothing drift-prone is typed by hand |
| `manuscript_figures.py` | L5 | draws every manuscript plate from `manuscript_vars` values with one shared visual language; matplotlib optional |
| `cli.py` | L6 | typed file/project/threshold/hybrid commands and staged I/O orchestration |

## Where to look first

- **"How is a document built?"** — `container.py`, then the data-flow diagrams in
  [`../../docs/architecture.md`](../../docs/architecture.md).
- **"What can I trust about a file I was sent?"** — `validate.py` and `intake.py` for
  the no-execution checks, `manifest.py` and `provenance.py` for what a signature
  covers, [`../../docs/security-model.md`](../../docs/security-model.md) for the boundary.
- **"Where does the payload physically go?"** — `channels/`.
- **"Why is this number in the docs?"** — `manuscript_vars.py`. It is the answer to
  every "where did that figure come from" question in this repo.

The authoritative module map, with layers and data flow, is
[`../../docs/architecture.md`](../../docs/architecture.md); update it alongside
real module interfaces rather than asserting incidental inventory text.

Editing rules: [`AGENTS.md`](AGENTS.md).

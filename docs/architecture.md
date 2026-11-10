# docxplus Architecture

docxplus follows the docxology `template_code_project` paradigm ([`docxology/template`](https://github.com/docxology/template)): tested domain modules
in `src/`, thin orchestrators in `scripts/`, real-data tests with a coverage gate,
deterministic outputs, token-driven docs. It is a **standalone** repository — it does
not import the template's shared `infrastructure/`; its domain (the docxplus container)
is self-contained. It is also integrated into the template pipeline as optional stage 13 (`scripts/pipeline/stage_13_docxplus.py`).

## Layering

Modules form a strict dependency stack — lower layers never import higher ones:

```
L0  foundations   opc • crypto • shamir • lsb • secure_io • provenance • project_paths • transparency • archive_limits • release_publication
L1  vocabulary    wordml • odt • payloads • steg_bridge • fileext • channels/(base,*)
L2  format        manifest • reproduce • intake
L3  composition   container  (DocxPlusBuilder / DocxPlusReader)
                  odt_container (OdtPlusBuilder / OdtPlusReader)
L4  validation    validate
L5  consumers     reference_docs • manuscript_vars • inspection • audit • comparison • export
L6  orchestration src/docxplus/cli.py • scripts/*
```

| Module | Layer | Responsibility |
| --- | --- | --- |
| `opc.py` | L0 | OPC package model + deterministic ZIP; intake caps (bomb/entry/collision) |
| `crypto.py` | L0 | bounded Argon2id/Scrypt/PBKDF2, AES-GCM, classical DXE2 and genuine provider ML-KEM-768 DXE3, Ed25519/ML-DSA-65 dual signing, portable suite-typed DXHK keys |
| `shamir.py` | L0 | k-of-n GF(256) sharing; unkeyed tagged-share checksums, not polynomial VSS; container authenticates complete shares against signed digests |
| `lsb.py` | L0 | pure-Python LSB stego codec |
| `provenance.py` | L0 | Merkle root (RFC 6962 splitting) + inclusion proofs over the module set |
| `cli.py` | L6 | typed/project/threshold and portable hybrid CLI; preflight/staged publication through domain APIs |
| `secure_io.py` | L0 | private exclusive secrets and sibling-temporary atomic replacement without inode truncation |
| `archive_limits.py` | L0 | stdlib ZIP-directory allocation and single-gzip/TAR physical-header/local-metadata preflight shared by package/project/evidence intake; no total-memory guarantee |
| `transparency.py` | L0 | append-only attestation log: hash chain, Merkle inclusion proofs, and the signed tree head that anchors them |
| `release_publication.py` | L0 | explicit-time release-asset plans, bounded descriptor-pinned files/receipts/checksums and exact remote identity/asset reconciliation; no ambient environment, network or publication authority |
| `wordml.py` | L1 | minimal conforming WordprocessingML surface document |
| `odt.py` | L1 | conforming OASIS OpenDocument Text (ODT) sibling container |
| `payloads.py` | L1 | typed registry and project fidelity; descriptor-pinned bounded capture, physical TAR preflight and fresh private extraction; capability refusal |
| `steg_bridge.py` | L1 | pair-equality `p_value` statistics and optional Rust encode/decode/analyze/exact-capacity CLI contracts |
| `channels/` | L1 | side-channels (base protocol + custom_xml, package_part, metadata, stego_media, mce) |
| `manifest.py` | L2 | format-3 canonical body binds module root/surface, primary algorithm and declared co-signer identities/algorithms |
| `reproduce.py` | L2 | output-tree-v3 claims/source_match; opt-in private-scratch execution, Linux private-init pidfd exit barrier; macOS profile requests fork denial |
| `intake.py` | L2 | hardened untrusted-input threat scan for both profiles (no execution): OOXML macros/external rels/altChunk, ODF scripts/Basic/off-package xlink |
| `container.py` | L3 | `DocxPlusBuilder` / `DocxPlusReader` — compose + read back; `seal_module` is the format-independent sealing step |
| `odt_container.py` | L3 | the intelligence layer over an ODT package; reuses `container`'s sealing and unsealing rather than duplicating them |
| `validate.py` | L4 | selected OPC/ODF structural/intelligence checks, not complete ISO/schema conformance; syntactic OPC signature-reference coverage, not XML-DSig trust |
| `reference_docs.py` | L5 | one serialized `ReferenceDossier` plus ephemeral credentials; scripts and manuscript evaluate that same exported artifact |
| `fileext.py` | L1 | dual-name document target preflight/staging and per-entry atomic export, not cross-file crash atomicity |
| `project_paths.py` | L0 | repository-root and output-directory resolution, so nothing hardcodes a path |
| `manuscript_vars.py` | L5 | derive every docs/manuscript value from live constants (no hard-coding) |
| `manuscript_figures.py` | L5 | the manuscript plates: every figure drawn from `manuscript_vars` values with one shared visual language (matplotlib optional) |
| `inspection.py` | L5 | non-decoding package/declaration/signature inspection, original-root evidence and bounded no-follow file reads |
| `audit.py` | L5 | independent per-document inspection and threat triage with preserved batch peers |
| `comparison.py` | L5 | deterministic logical package/module/signer-policy comparison without plaintext or rendering inference |
| `export.py` | L5 | bounded exact raw payload recovery to a private atomic no-replace tree; no typed-codec or recipe execution |

## Data flow — build

```
paragraphs ─► wordml.new_base_document ─► OpcPackage (surface .docx)
                                              │
for each module:  obj ─payloads.pack(type)─► plaintext
   ─[seal: crypto.encrypt | seal_multi | shamir+key | decoy]─► sealed
   ─► channel.embed(pkg) ─► ChannelRecord ─► manifest.add
                                              │
manifest.surface_digest = framed_digest(non-manifest parts + type/index authority
                                       + relationships including IDs)
manifest ─[sign + co-sign over canonical body]─► write_manifest ─► pkg.to_bytes()
```

## Data flow — read / verify (no execution)

```
.docx ─► opc.read_package (caps) ─► read_manifest ─► DocxPlusReader
  extract(slot)        channel.extract ─digest guard─ ­[unseal]─► payload
  verify_provenance()  signature over Merkle root + surface digest (+ pinned key)
  verify_cosigners()   surface-bound co-signature policy
  verify_reproduction()attestation bound to bytes; executes nothing
  intake.safe_open()   threat report; refuses under a strict policy
  verify-transparency  chain + signed tree head + inclusion proof (pinned signer)
```

## Data flow — reproduce (opt-in, executes)

```
reader.reproduce(slot, allow_execution=True)
  ─► scheme admission ─► extract_project ─► reproduce.run_and_digest (private scratch,
      network/write confinement, Linux private-init pidfd exit barrier;
      macOS profile requests fork denial) ─► source_match + output-tree-v3 comparison
```

## The documentation pipeline (no hard-coded values)

Every drift-prone number a doc cites is a token filled from the live system:

```
src/manuscript_vars.variables()   reads code constants (crypto.SCRYPT_N_LOG2,
   │                              channels.available_channels(), lsb.capacity_bytes,
   │                              opc.MAX_ENTRIES …) + the repo (test/module counts,
   │                              pyproject version) + a built reference_docs dossier
   ▼
scripts/z_generate_manuscript_variables.py ─► output/data/manuscript_variables.json
scripts/render_manuscript.py  ({{TOKEN}} → value) ─► output/manuscript/*.md
scripts/06_project_roundtrip.py  selected synthetic tree, both profiles
scripts/07_template_roundtrip.py real external project, all four formats
scripts/04_dossier.py            exports the shared ReferenceDossier bytes
```

Project comparisons enumerate both source and extracted trees (bytes, modes and
empty directories), so missing **and extra** entries matter. Reports must describe
the actual exported bytes, not a second in-memory specimen. Dossier source
extraction is not reproduction-attested; living/synthetic recipes carry their
own claims and separate execution evidence.

Values derive from live constants and actual artifacts; token hydration alone is
not a fresh run receipt. Keep meaningful rendered-output, reference and diagnostic
checks rather than freezing incidental prose or inventory counts.

## Release-asset publication boundary

`release_publication` binds an expiring canonical plan to the selected draft's
metadata, actor, main commit/tree and exact staged asset bytes. It refuses
unexpected files, unsafe file identities, inconsistent source/validation receipts,
payloads differing from their native qualification inventory and checksum drift.
Metadata has smaller pre-parser budgets than distribution binaries. Receipt syntax
and matching hashes do not authenticate a producer or establish fresh Linux,
Office or installed-wheel qualification.

The thin `scripts/publish_release_assets.py` adapter owns native manager admission,
pinned identity, release-class controls, transport and explicit confirmation; it
uploads only missing matching assets and publishes the same draft. Existing
matching assets remain untouched, including when reconciling an already published
release with an unexpired plan and no mutation budget. Changed metadata, identities
or remote bytes refuse rather than overwrite. Selected configuration/SDK revisions
remain bound; supervised binary readers cannot retain a host slot indefinitely.
Publication observations remain distinct from complete verification in receipts.
See [`../scripts/README.md`](../scripts/README.md#release-asset-publication) for
the operational contract. This is not a `run.sh all` stage or a Zenodo/DOI operation.

## Boundary rules

* Business logic lives only in `src/`. Scripts and the CLI coordinate I/O and print
  output paths; they never implement a channel, a crypto primitive, or a doc value.
* The manifest is the single source of truth for what a package carries and where.
* External tools (steganographer) are reached only through `steg_bridge`, which
  reports absence honestly and never masks a real failure as success.
* Numbers cited in docs derive from code constants via `manuscript_vars`, never
  re-typed.

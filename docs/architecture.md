# docxplus Architecture

docxplus follows the docxology `template_code_project` paradigm: tested domain modules
in `src/`, thin orchestrators in `scripts/`, real-data tests with a coverage gate,
deterministic outputs, token-driven docs. It is a **standalone** repository — it does
not import the template's shared `infrastructure/`; its domain (the docxplus container)
is self-contained.

## Layering

Modules form a strict dependency stack — lower layers never import higher ones:

```
L0  foundations   opc • crypto • shamir • lsb • provenance • project_paths • transparency
L1  vocabulary    wordml • odt • payloads • steg_bridge • fileext • channels/(base,*)
L2  format        manifest • reproduce • intake
L3  composition   container  (DocxPlusBuilder / DocxPlusReader)
                  odt_container (OdtPlusBuilder / OdtPlusReader)
L4  validation    validate
L5  reference     reference_docs • manuscript_vars
L6  orchestration src/docxplus/cli.py • scripts/*
```

| Module | Layer | Responsibility |
| --- | --- | --- |
| `opc.py` | L0 | OPC package model + deterministic ZIP; intake caps (bomb/entry/collision) |
| `crypto.py` | L0 | Argon2id/Scrypt/PBKDF2 KDFs (work-factor **and** memory capped), AES-GCM (DXE1), X25519 multi-recipient (DXE2), Ed25519, digests |
| `shamir.py` | L0 | k-of-n secret sharing over GF(256); VSS commitment tags with downgrade-resistant verification |
| `lsb.py` | L0 | pure-Python LSB stego codec |
| `provenance.py` | L0 | Merkle root (RFC 6962 splitting) + inclusion proofs over the module set |
| `cli.py` | L3 | the `docxplus` command; argument parsing only, all logic lives below it |
| `secure_io.py` | L0 | Owner-only creation of key, share, and recovered-plaintext files |
| `transparency.py` | L0 | append-only attestation log: hash chain, Merkle inclusion proofs, and the signed tree head that anchors them |
| `wordml.py` | L1 | minimal conforming WordprocessingML surface document |
| `odt.py` | L1 | conforming OASIS OpenDocument Text (ODT) sibling container |
| `payloads.py` | L1 | typed payload registry: bytes/text/json/project/docxplus; owns the `project` fidelity contract (format-spec §8.1) |
| `steg_bridge.py` | L1 | pure-Python chi-squared steganalysis (always available) + subprocess bridge to the optional steganographer Rust CLI |
| `channels/` | L1 | side-channels (base protocol + custom_xml, package_part, metadata, stego_media, mce) |
| `manifest.py` | L2 | signed intelligence manifest (Merkle + surface-digest bound body; co-signatures) |
| `reproduce.py` | L2 | reproduction attestation + opt-in hermetic sandbox (the only execution path) |
| `intake.py` | L2 | hardened untrusted-input threat scan for both profiles (no execution): OOXML macros/external rels/altChunk, ODF scripts/Basic/off-package xlink |
| `container.py` | L3 | `DocxPlusBuilder` / `DocxPlusReader` — compose + read back; `seal_module` is the format-independent sealing step |
| `odt_container.py` | L3 | the intelligence layer over an ODT package; reuses `container`'s sealing and unsealing rather than duplicating them |
| `validate.py` | L4 | OPC, ODF, and intelligence conformance; refuses an OPC package signature whose reference set omits a manifest-named part |
| `reference_docs.py` | L5 | the one canonical example document, defined once |
| `fileext.py` | L1 | the `.docx`/`.docxplus` and `.odt`/`.odtplus` extension pair, media types, and dual-name export |
| `project_paths.py` | L0 | repository-root and output-directory resolution, so nothing hardcodes a path |
| `manuscript_vars.py` | L5 | derive every doc/manuscript value from live constants (no hard-coding) |

## Data flow — build

```
paragraphs ─► wordml.new_base_document ─► OpcPackage (surface .docx)
                                              │
for each module:  obj ─payloads.pack(type)─► plaintext
   ─[seal: crypto.encrypt | seal_multi | shamir+key | decoy]─► sealed
   ─► channel.embed(pkg) ─► ChannelRecord ─► manifest.add
                                              │
manifest.surface_digest = digest(all story parts: document, headers,
                                 footers, footnotes, endnotes, comments)
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
  ─► extract_project ─► reproduce.run_and_digest (sandbox: scrubbed env, rlimits,
      network-denied, write-confined, process-group kill) ─► compare to attestation
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
scripts/06_project_roundtrip.py  synthetic tree, both profiles, 18 invariants
scripts/07_template_roundtrip.py real external project, all four formats
```

Guard tests (`tests/test_manuscript_vars.py`) assert the values derive from the
constants, that every token resolves, and that no drift-prone value is hard-coded in
a manuscript source — so a code change flows into the document, and a stale literal
fails the suite.

## Boundary rules

* Business logic lives only in `src/`. Scripts and the CLI coordinate I/O and print
  output paths; they never implement a channel, a crypto primitive, or a doc value.
* The manifest is the single source of truth for what a package carries and where.
* External tools (steganographer) are reached only through `steg_bridge`, which
  reports absence honestly and never masks a real failure as success.
* Numbers cited in docs derive from code constants via `manuscript_vars`, never
  re-typed.

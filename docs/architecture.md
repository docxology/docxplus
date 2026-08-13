# DOCX+ Architecture

DOCX+ follows the docxology `template_code_project` paradigm: tested domain modules
in `src/`, thin orchestrators in `scripts/`, real-data tests with a coverage gate,
deterministic outputs, token-driven docs. It is a **standalone** repository — it does
not import the template's shared `infrastructure/`; its domain (the DOCX+ container)
is self-contained.

## Layering

Modules form a strict dependency stack — lower layers never import higher ones:

```
L0  foundations   opc • crypto • shamir • lsb • provenance • project_paths • transparency
L1  vocabulary    wordml • odt • payloads • steg_bridge • channels/(base,*)
L2  format        manifest • reproduce • intake
L3  composition   container  (DocxPlusBuilder / DocxPlusReader)
L4  validation    validate
L5  reference     reference_docs • manuscript_vars
L6  orchestration docxplus_cli.py • scripts/*
```

| Module | Layer | Responsibility |
| --- | --- | --- |
| `opc.py` | L0 | OPC package model + deterministic ZIP; intake caps (bomb/entry/collision) |
| `crypto.py` | L0 | Scrypt/PBKDF2 KDF, AES-GCM (DXE1), X25519 multi-recipient (DXE2), Ed25519, digests |
| `shamir.py` | L0 | k-of-n secret sharing over GF(256) |
| `lsb.py` | L0 | pure-Python LSB stego codec |
| `provenance.py` | L0 | Merkle root + inclusion proofs over the module set |
| `transparency.py` | L0 | cryptographic transparency log & hash-chain for attestations |
| `wordml.py` | L1 | minimal conforming WordprocessingML surface document |
| `odt.py` | L1 | conforming OASIS OpenDocument Text (ODT) sibling container |
| `payloads.py` | L1 | typed payload registry: bytes/text/json/project/docxplus |
| `steg_bridge.py` | L1 | subprocess bridge to the steganographer Rust CLI |
| `channels/` | L1 | side-channels (base protocol + custom_xml, package_part, metadata, stego_media, mce) |
| `manifest.py` | L2 | signed intelligence manifest (Merkle + surface-digest bound body; co-signatures) |
| `reproduce.py` | L2 | reproduction attestation + opt-in hermetic sandbox (the only execution path) |
| `intake.py` | L2 | hardened untrusted-input threat scan (no execution) |
| `container.py` | L3 | `DocxPlusBuilder` / `DocxPlusReader` — compose + read back |
| `validate.py` | L4 | OPC + intelligence conformance |
| `reference_docs.py` | L5 | the one canonical example document, defined once |
| `manuscript_vars.py` | L5 | derive every doc/manuscript value from live constants (no hard-coding) |

## Data flow — build

```
paragraphs ─► wordml.new_base_document ─► OpcPackage (surface .docx)
                                              │
for each module:  obj ─payloads.pack(type)─► plaintext
   ─[seal: crypto.encrypt | seal_multi | shamir+key | decoy]─► sealed
   ─► channel.embed(pkg) ─► ChannelRecord ─► manifest.add
                                              │
manifest.surface_digest = digest(document.xml)
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

# DOCX+ Architecture

DOCX+ follows the docxology `template_code_project` paradigm: tested domain
modules in `src/`, thin orchestrators in `scripts/`, real-data tests with a 90%
coverage gate, deterministic outputs. It is a **standalone** repository — it does
not import the template's shared `infrastructure/` layer; its domain (the DOCX+
container) is self-contained.

## Layers

```
docxplus_cli.py            CLI (thin) ── argparse over src/
scripts/*.py               thin orchestrators (build, verify, figure) — no business logic
src/
  opc.py                   OPC package model: parts, content types, relationships, deterministic ZIP
  wordml.py                minimal valid WordprocessingML surface document
  crypto.py                PBKDF2-SHA512 KDF, AES-256-GCM envelope, BLAKE2b digest, Ed25519 sign/verify
  lsb.py                   pure-Python LSB stego codec (Pillow)
  steg_bridge.py           subprocess bridge to the steganographer Rust CLI
  channels/                the modular side-channels
    base.py                Channel protocol + ChannelRecord (manifest entry)
    custom_xml.py          customXml/ part channel
    package_part.py        intelligence/ additional-part channel
    metadata.py            docProps/custom.xml property channel
    stego_media.py         word/media/ LSB channel (python_lsb | steganographer backends)
  manifest.py              signed intelligence manifest (intelligence/manifest.json)
  container.py             DocxPlusBuilder / DocxPlusReader — compose + read back
  validate.py              OPC conformance + intelligence conformance
```

## Data flow (build)

```
paragraphs ─► wordml.new_base_document ─► OpcPackage (surface .docx)
                                              │
for each module:                              ▼
  payload ─[optional crypto.encrypt]─► channel.embed(pkg) ─► ChannelRecord ─► manifest.add
                                              │
manifest ─[optional crypto.sign]─► write_manifest(pkg) ─► pkg.to_bytes() ─► .docx
```

## Data flow (read)

```
.docx ─► opc.read_package ─► read_manifest ─► for slot:
            channel.extract(pkg, record) ─[optional crypto.decrypt]─► digest check ─► payload
```

## Boundary rules

* Business logic lives only in `src/`. Scripts and the CLI coordinate I/O and print
  output paths; they never implement a channel or a crypto primitive.
* The manifest is the single source of truth for what a package carries and where.
  Readers bind to the manifest, never to guessed part names.
* External tools (the steganographer CLI) are reached only through `steg_bridge`,
  which reports absence honestly and never masks a real failure as success.

## The steganographer relationship

The sibling `../steganographer` checkout is the premium media backend. `steg_bridge`
locates a built binary (env var → PATH → `target/release` → `cargo run`) and drives
its `encode`/`decode` generic-packet commands. The pure-Python `lsb` backend is the
zero-setup default so the media channel works without the Rust toolchain; the
manifest records which backend produced each carrier so extraction matches.

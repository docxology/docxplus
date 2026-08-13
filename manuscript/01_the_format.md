# 1. The DOCX+ format

## 1.1 Motivation

A `.docx` is an Open Packaging Conventions (OPC) container: a ZIP whose mandatory
index parts are `[Content_Types].xml` and `_rels/.rels`, in which every part must
be reachable by following relationships. The standard is explicit that "a package
may contain additional files" and that mapped content-control data is stored as
"flat Open XML markup" in custom XML parts. These are not loopholes; they are
documented extension points. DOCX+ asks a precise question: how much structured,
authenticated, optionally-concealed content can a file carry while remaining a
*conforming* Office document — not merely one that happens to open?

## 1.2 Two contracts in one file

A DOCX+ file satisfies two contracts. The **surface contract** is ordinary OOXML
conformance: mandatory index parts, a typed main document part, reachability, no
duplicate entries, deterministic bytes. The **intelligence contract** adds one
manifest part, `intelligence/manifest.json`, that enumerates every payload module,
its channel and location, a plaintext digest, an encryption flag, and an optional
Ed25519 signature over a canonical manifest body. A consumer ignorant of DOCX+ sees
only the surface; a DOCX+ reader binds to the manifest and recovers the modules.

## 1.3 Channels

Each channel is a spec-sanctioned side-channel with a uniform `embed`/`extract`
contract:

- **custom_xml** — base64 payload in `customXml/itemN.xml`, invisible in rendering.
- **package_part** — raw bytes in `intelligence/payloadN.dxp` with its own content
  type; the natural home for encrypted or steganography-bound blobs.
- **metadata** — a named custom document property in `docProps/custom.xml`; a
  short-string channel for routing tags.
- **stego_media** — LSB steganography in `word/media/imageN.png`, an image the
  document can visibly display, so the intelligence hides inside content a reader
  sees.

The manifest, not the byte layout, is authoritative; a reader never guesses part
names. This mirrors the role ODF assigns to its mandatory `META-INF/manifest.xml`.

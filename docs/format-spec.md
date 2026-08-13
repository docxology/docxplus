# DOCX+ Intelligent Container — Format Specification v1.0

DOCX+ is a profile of an ordinary Office Open XML (OOXML) WordprocessingML package
(`.docx`). A conforming DOCX+ file is, first, a conforming OPC package: opening it
in any word processor yields an ordinary document. Second, it carries an
**intelligence layer** — a signed manifest plus one or more payload modules — over
spec-sanctioned side-channels. A consumer that knows nothing of DOCX+ ignores the
extra parts; a DOCX+ reader uses the manifest to recover them.

This spec is deliberately implementable from the OOXML standard alone. Every
structural claim traces to the standards report in `docs/standards-report.md`.

## 1. Conformance

A file is **DOCX+ conforming** when:

1. It is a valid OPC package (ISO/IEC 29500-2): `[Content_Types].xml` and
   `_rels/.rels` are present; a main WordprocessingML document part exists and is
   typed `…wordprocessingml.document.main+xml`; every part is reachable by
   following relationships; there are no duplicate ZIP entry names.
2. It contains exactly one manifest part `intelligence/manifest.json`
   (content type `application/vnd.docxplus.manifest+json`), reachable by a
   package-level relationship of type `urn:docxplus:intelligence:1.0/manifest`.
3. Every module the manifest lists resolves to real bytes on its declared channel,
   with a matching plaintext digest (encrypted modules are length-checked).
4. If the manifest carries a signature, it validates over the canonical body.

A file lacking the manifest is a **plain document**, not a DOCX+; it is still a
valid `.docx`.

## 2. The manifest

`intelligence/manifest.json` is UTF-8 JSON:

```json
{
  "version": "1.0",
  "modules": [
    {
      "channel": "custom_xml",
      "slot": "brief",
      "size": 63,
      "digest": "<blake2b-256 hex of plaintext>",
      "encrypted": false,
      "content_type": "application/xml",
      "location": { "part": "customXml/item1.xml" }
    }
  ],
  "signature": { "algorithm": "ed25519", "public_key": "<hex>", "value": "<hex>" }
}
```

* `slot` is a unique caller-chosen name; extraction is by slot.
* `digest` is over the **plaintext** payload (before encryption), so a reader can
  verify integrity after decryption.
* `location` is channel-specific and tells the reader exactly where to look — the
  reader never guesses.
* **Canonical body** (what is signed): the compact JSON
  `{"version":…,"modules":[…]}` with sorted keys and modules sorted by slot, and
  the `signature` object omitted. This makes the signature stable regardless of
  serialisation whitespace.

## 3. Channels

### 3.1 `custom_xml`
Payload is base64-wrapped in a `<dx:payload>` element inside
`customXml/itemN.xml` (namespace `urn:docxplus:intelligence:1.0`), referenced by a
`customXml` relationship from the main document part. Invisible in rendering.
Unbounded capacity.

### 3.2 `package_part`
Payload is stored raw as `intelligence/payloadN.dxp` with Default content type
`application/vnd.docxplus.payload`, referenced by a package-level relationship.
The natural home for encrypted or steganography-bound blobs. Unbounded capacity.

### 3.3 `metadata`
Payload is base64-encoded into a named custom document property
(`dxplus_<slot>`) in `docProps/custom.xml`. A short-string channel (≤ 8000 bytes),
suited to routing tags and identifiers.

### 3.4 `stego_media`
Payload is hidden in the least-significant bits of a PNG stored at
`word/media/imageN.png` and referenced by an `image` relationship — an image the
document can visibly display. Two backends, recorded in `location.backend`:

* `python_lsb` — pure-Python LSB codec (`DXL1` framing: magic + uint32 length +
  bytes). Needs only Pillow. Capacity ≈ `(w·h·3)/8 − 8` bytes.
* `steganographer` — the docxology/steganographer Rust CLI generic-packet channel,
  adding BLAKE3 hashing, Ed25519 signing, and optional Reed-Solomon ECC.

## 4. Encryption

When a module is encrypted, the plaintext is wrapped in a `DXE1` envelope before
the channel places it:

```
"DXE1" | salt_len(1) | salt(16) | nonce_len(1) | nonce(12) | spin_count(4) | AES-256-GCM ciphertext
```

Key derivation is PBKDF2-HMAC-SHA512 over the password with the stored salt and
`spin_count` iterations (default 100 000) — the MS-OFFCRYPTO *agile* lineage.
Because only the payload is encrypted, the surface `.docx` remains a valid,
openable Office document; this is intentional and contrasts with whole-package
OOXML encryption, which yields a file most tools cannot open.

## 5. Determinism

Serialisation is reproducible: fixed ZIP timestamps (1980-01-01), content types
first, remaining entries sorted by name. Unencrypted, unsigned builds are
byte-stable across runs. Encryption and signing introduce fresh randomness
(salt/nonce, but Ed25519 is deterministic given the key) by design.

## 6. Extensibility

New channels register under the same `Channel` contract (`embed` / `extract` /
`capacity`) and appear in the manifest by id. Readers that do not recognise a
channel id fail that module explicitly rather than silently — the manifest is the
contract.

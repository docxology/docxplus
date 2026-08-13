# 2. Implementation

## 2.1 Package layer

`opc.py` implements the OPC model directly on stdlib `zipfile`: parts, per-extension
Default and per-part Override content types, and relationship sets keyed by owning
part. Serialisation is deterministic — fixed 1980 timestamps, `[Content_Types].xml`
first, remaining entries sorted by name — following the Reproducible Builds
guidance the standards report cites. Documented invariants are enforced on both
write and read: duplicate part names are rejected, `[Content_Types].xml` is
required, and every part must carry a resolvable content type. `wordml.py` builds
the minimal conforming WordprocessingML surface document.

## 2.2 Cryptography

`crypto.py` derives keys with PBKDF2-HMAC-SHA512 (a random salt and an agile
`spin_count`, default 100 000), matching the MS-OFFCRYPTO agile shape, and encrypts
payloads with AES-256-GCM in a self-describing `DXE1` envelope. GCM supplies the
authenticated-integrity the standards report flags as absent from ECMA-376
*standard* encryption. Manifests are signed with Ed25519 — the same curve as the
steganographer backend — over a canonical, whitespace-independent manifest body.

## 2.3 Media steganography

`lsb.py` is a pure-Python LSB codec: a `DXL1`-framed payload is written into the
least-significant bit of each RGB channel of a PNG, reversibly and
deterministically, needing only Pillow. `steg_bridge.py` locates and drives the
`docxology/steganographer` Rust CLI (env var → PATH → built binary → `cargo run`)
for the premium backend, which adds BLAKE3 hashing, Ed25519 signing, and optional
Reed-Solomon ECC. Absence of the toolchain is a graceful skip; a genuine
encode/decode failure raises rather than silently no-ops.

## 2.4 Composition and validation

`container.py` exposes `DocxPlusBuilder` (queue modules, optionally encrypt per
module, optionally sign the manifest, emit deterministic bytes) and
`DocxPlusReader` (list, extract, verify). `validate.py` checks both contracts and
returns a structured report: OPC conformance (index parts, main document,
reachability, typing) and intelligence conformance (each module resolves with a
matching digest; the signature, if present, validates). The `docxplus` CLI is a
thin orchestrator over these modules.

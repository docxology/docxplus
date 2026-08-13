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

`crypto.py` seals payloads with AES-256-GCM under a key from a self-describing,
KDF-tagged `DXE1` envelope. The default KDF is memory-hard **Scrypt**; PBKDF2-HMAC-
SHA512 (600 000 iterations) remains available for compatibility, and readers cap
attacker-supplied work factors so a hostile envelope cannot become a denial-of-
service. The module slot is bound as AEAD additional data, and the manifest digest
covers the stored ciphertext (never a plaintext digest, which would be an offline
confirmation oracle). `crypto.py` also provides X25519 multi-recipient hybrid
sealing (`DXE2`, content key wrapped per recipient) and Ed25519 signing; `shamir.py`
implements k-of-n secret sharing over GF(256) for threshold sealing. Manifests are
signed over a canonical, whitespace-independent body.

## 2.3 Typed payloads, provenance, and reproduction

`payloads.py` is a typed registry (`bytes`/`text`/`json`/`project`/`docxplus`); the
`project` type packs a directory into a deterministic, traversal- and bomb-guarded
tar. `provenance.py` computes a Merkle root over the module set and issues inclusion
proofs. The signed manifest body binds that root *and* a digest of `word/
document.xml`, so a signature covers both the module set and the visible text;
authenticity requires the caller to pin the signer's key (`expected_public_key`).
`reproduce.py` is the only code-execution path: it runs an attested command in a
best-effort hermetic sandbox (scrubbed environment, resource + file-size limits, a
clamped timeout, network denied and writes confined where the platform supports it)
and only under an explicit opt-in — a document never runs itself.

## 2.4 Media steganography

`lsb.py` is a pure-Python LSB codec: a `DXL1`-framed payload is written into the
least-significant bit of each RGB channel of a PNG, reversibly and
deterministically, needing only Pillow. `steg_bridge.py` locates and drives the
`docxology/steganographer` Rust CLI (env var → PATH → built binary → `cargo run`)
for the premium backend, which adds BLAKE3 hashing, Ed25519 signing, and optional
Reed-Solomon ECC. Absence of the toolchain is a graceful skip; a genuine
encode/decode failure raises rather than silently no-ops. A `redundancy=N` option
replicates the payload across N carriers, and extraction returns the replica whose
bytes match the module digest, so the document survives losing all but one.

## 2.5 Composition, validation, and intake

`container.py` exposes `DocxPlusBuilder` (queue typed modules, choose a sealing
lineage per module, sign and co-sign, attest a project's reproduction, emit
deterministic bytes) and `DocxPlusReader` (list, extract, `verify_provenance`,
`verify_cosigners`, `verify_reproduction`, opt-in `reproduce`). `validate.py` checks
both contracts and returns a structured report: OPC conformance (index parts, a
typed main document, root-anchored reachability, no duplicate or colliding entries)
and intelligence conformance (each module's stored bytes match its manifest digest;
the signature and Merkle root, if present, validate). `intake.py` adds a hardened
entry point for untrusted `.docx`: it applies the package caps and returns a threat
report (external references, macros, `altChunk` imports) without executing anything.
The `docxplus` CLI (`build`, `inspect`, `graph`, `extract`, `unpack-project`,
`validate`, `scan`, `verify-reproduction`, `reproduce`, `keygen`) is a thin
orchestrator over these modules.

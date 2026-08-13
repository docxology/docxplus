# DOCX+ Intelligent Container — Format Specification v2.0

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

When a module is password-sealed, the plaintext is wrapped in a self-describing
`DXE1` envelope before the channel places it:

```
"DXE1" | kdf_id(1) | salt_len(1) | salt | nonce_len(1) | nonce | params_len(1) | params | AES-256-GCM ciphertext
```

Key derivation is recorded per envelope. The default is **Scrypt** (memory-hard,
`N=2^15, r=8, p=1`; `kdf_id=2`, `params = n_log2 ‖ r ‖ p`); **PBKDF2-HMAC-SHA512**
is available for compatibility (`kdf_id=1`, `params = iterations(4)`, default
600 000 per OWASP-2023). Readers **cap** attacker-supplied work factors
(scrypt `N ≤ 2^21`, PBKDF2 `≤ 5,000,000`) so a hostile envelope cannot turn
opening into a denial-of-service.

The AEAD is bound to the module **slot as additional authenticated data (AAD)**, so
a ciphertext cannot be spliced into a different slot. The manifest digest for a
sealed module is over the **stored (ciphertext) bytes**, never the plaintext — a
plaintext digest would be an offline confirmation oracle against short secrets.
Plaintext integrity is the GCM tag, checked on decryption.

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

## 7. Payload types (v2.0)

A module records a `payload_type` id. The type owns how an object is packed to
bytes and back, so a payload is a typed object, not a blob. Built-in types:

| Type | Meaning | Packing |
| --- | --- | --- |
| `bytes` | opaque bytes | identity |
| `text` | UTF-8 string | encode/decode |
| `json` | JSON object | canonical compact JSON |
| `project` | a whole directory tree | deterministic tar.gz (fixed mtime, sorted, junk excluded); path-traversal-guarded on unpack |
| `docxplus` | a nested DOCX+ document | identity bytes, typed so readers recurse |

The digest recorded for a module is over the **stored bytes** the channel holds
(plaintext for a plain module, ciphertext for a sealed one), so it binds exactly
what travels and is checked before any decryption — never a plaintext digest of a
sealed module.

## 8. Sealing modes (v2.0)

Each module's `sealing.mode` selects how the packed payload is protected. All modes
seal the *payload*, never the package, so the surface `.docx` stays openable. The
manifest records only the mode (and, for threshold, `k`/`n`) — never recipient
identities, counts, or a "decoy" marker.

| Mode | Envelope | Credential to open | Use |
| --- | --- | --- | --- |
| `plain` | none | — | public modules |
| `password` | two framed `DXE1` envelopes (the payload + a chaff frame) | password | single secret |
| `recipients` | `DXE2` (X25519 → HKDF-SHA256 → AES-GCM, content key wrapped per recipient) | any recipient's X25519 private key | multi-recipient (referee packet) |
| `threshold` | AES-GCM under a random content key, key Shamir-split k-of-n over GF(256) | any `k` of `n` shares | dead-man's envelope |

`DXE2` layout: `"DXE2" | body_len(4) | body | recip_count(2) | [ eph_pub(32) wrap_len(2) wrap ]…` (ephemeral pubkeys only).

**Decoy / deniability.** A decoy is *not* a separate mode. It is a `password`
module whose two frames are a real payload and a cover story under different
passwords. Because every `password` module carries two frames (the second is
undecryptable chaff when there is no decoy), a decoy is byte-indistinguishable
from an ordinary password module — neither the manifest nor the frame count
reveals a hidden payload. This provides deniability against inspection, not a
proof of non-existence: an adversary who knows the scheme knows a second frame is
*always* present and cannot be forced to be chaff. See `docs/security-model.md`.

## 9. Provenance — Merkle binding + surface binding (v2.0)

The manifest carries a `merkle_root` over all modules: leaves are
`blake2b(0x00 ‖ slot ‖ 0x00 ‖ module_digest)`, internal nodes
`blake2b(0x01 ‖ left ‖ right)`, odd nodes promoted, modules ordered by slot. The
root **and** a `surface_digest` (the digest of `word/document.xml`) are folded into
the canonical body the Ed25519 signature covers, so the signature binds both the
**set** of modules and the **visible document text**: altering a module or a
paragraph invalidates it. `verify_provenance()` returns true only when the
signature validates and the surface document on disk matches the signed digest.
Validation independently recomputes and checks the stored `merkle_root`.

**Inclusion proofs.** `inclusion_proof(slot)` yields
`{slot, digest, siblings, root}` letting a third party confirm one module belongs
to the signed set without seeing the other modules — the capability that makes the
Merkle tree more than a re-hash of the signed list. Verify with
`provenance.verify_inclusion(proof)`.

**Detached co-signatures (v0.5).** `cosignatures: [{public_key, value}, ...]` in the
manifest are independent Ed25519 signatures by additional parties over the *same*
canonical body — "signed by author AND institution". `verify_cosigners([keys])`
returns true only when every expected key has a valid signature (the primary signer
counts when its signature validates). A stranger adding their own valid co-signature
does not help them: verification checks for *expected* keys, and — per §11 — every
verdict that means "authentic" requires the caller to pin the keys they trust.

## 11. Authenticity requires a pinned key (v0.4)

The manifest's signer public key is **self-asserted**: it travels inside the
manifest. A valid signature proves only that whoever holds that key signed this
content (integrity + a self-asserted signer) — an attacker can sign a fabricated
document with their own key and it validates as *self-consistent*. `signature_status`,
`verify_provenance`, and `verify_reproduction` therefore accept an
`expected_public_key`; only when the signer matches it (constant-time) is the verdict
`valid` / authentic. `signer()` exposes the key so a caller can decide out-of-band.

## 12. Hardened intake (v0.5)

`intake.safe_open(bytes, policy=...)` opens untrusted `.docx` bytes under caps and
returns a threat report — **executing nothing**. `read_package` enforces the
zip-bomb / duplicate-entry / size caps and defuses XML (DTDs off); `intake.scan`
adds the package-level surface a defender triages: external (off-package)
relationships, macro parts (`vbaProject.bin`, macro-enabled content types), and
`altChunk` foreign-content imports, plus a part-count cap. Under a strict policy a
non-clean report raises; otherwise the caller gets the report and (for a DOCX+) a
reader. This operationalises the standards report's untrusted-input checklist.

## 10. Reproduction attestation (v0.4)

A `project` module may carry a signed **reproduction attestation** so a reader can
trust that its outputs *follow from its code*, not merely that its bytes are
authentic (`docs/reproduction-design.md`). The attestation is a record field:

```json
"reproduction": {
  "command": ["python", "src/compute.py"],
  "outputs": ["output/result.json"],
  "timeout": 300,
  "output_digest": "<blake2b over the produced outputs>",
  "toolchain": {"python": "3.12.13", "implementation": "CPython", "platform": "…"}
}
```

It is folded into the signed manifest body, so the signature binds
`carried source → attested output`. Two trust paths, per the Council synthesis:

- **`verify_reproduction(slot)`** — cryptographic, **executes nothing**. Confirms an
  attestation exists and, on a signed document, that the signature binds it to
  exactly this source. This is the default: the reader relies on the signer's run.
- **`reproduce(slot, dest, allow_execution=True)`** — **opt-in, executes carried
  code**. Extracts the project and re-runs the attested command in a best-effort
  hermetic sandbox (scrubbed environment, resource caps, wall-clock timeout, network
  denied via `sandbox-exec`/`unshare` where available, throwaway directory), then
  compares output digests. Never reached without the explicit flag; never called on
  any read/validate/verify path.

An attestation with no declared outputs, or whose outputs are not produced, is
rejected as vacuous. Authors seal attestations over the *packed* content (a clean
extraction), so the attested digest matches what a reader reproduces. Honest limit:
a match proves the pipeline ran as stated on a matching toolchain — never that the
science is sound.

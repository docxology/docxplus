# docxplus Intelligent Container — Format Specification v3.0

Software 2.0.0 uses authenticated manifest format 3.0 for both OOXML `.docx`
and ODF `.odt`. Package extension points are grounded in
[`standards-report.md`](standards-report.md); selected structural validation is not
complete ISO/RNG/XSD conformance certification or universal consumer openability.

This is a breaking authenticated migration. Readers reject earlier manifest versions,
duplicate JSON keys, unknown fields and unsupported authority rather than guessing.
Do not rewrite a legacy version field: recover with a trusted legacy environment,
review the source and package authority, then rebuild and re-sign under format 3.0.
Earlier signatures do not authenticate the new framing.

## 1. Conformance

A DOCX file satisfies the implementation's **structural/intelligence checks** when:

1. It is a valid OPC package (ISO/IEC 29500-2): `[Content_Types].xml` and
   `_rels/.rels` are present; a main WordprocessingML document part exists and is
   typed `…wordprocessingml.document.main+xml`; every part is reachable by
   following relationships; there are no duplicate ZIP entry names.
2. It contains exactly one manifest part `intelligence/manifest.json`
   (content type `application/vnd.docxplus.manifest+json`), reachable by a
   package-level relationship of type `urn:docxplus:intelligence:1.0/manifest`.
3. Every module the manifest lists resolves to real bytes on its declared channel,
   whose digest matches the recorded one. The digest is taken over the **stored**
   bytes — ciphertext for a sealed module — so it is checkable without any
   credential and is verified before decryption is attempted (§4, §8).
4. If the manifest carries a signature, it validates over the canonical body.

A file lacking the intelligence manifest is a **plain document**, not a docxplus;
its application/schema conformance remains a separate question. ODT checks are in §14.

## 2. The manifest

`intelligence/manifest.json` is UTF-8 JSON:

```json
{
  "version": "3.0",
  "modules": [
    {
      "channel": "custom_xml",
      "slot": "brief",
      "size": 63,
      "digest": "<blake2b-256 hex of the STORED bytes>",
      "encrypted": false,
      "content_type": "application/xml",
      "payload_type": "json",
      "sealing": { "mode": "plain" },
      "reproduction": {},
      "location": { "part": "customXml/item1.xml" }
    }
  ],
  "merkle_root": "<hex root over all module leaves>",
  "surface_digest": "<blake2b-256 hex of the framed package surface>",
  "signature": { "algorithm": "ed25519", "public_key": "<hex>", "value": "<hex>" },
  "cosignatures": [ { "public_key": "<hex>", "algorithm": "ed25519", "value": "<hex>" } ]
}
```

* `slot` is a unique caller-chosen name; extraction is by slot.
* `digest` is over the **stored** bytes the channel holds — ciphertext for a sealed
  module, never the plaintext. A plaintext digest would be an offline confirmation
  oracle against short secrets (§4, §8).
* `payload_type` names the type that packs the object to bytes and back (§7);
  `sealing` records the mode; threshold also requires `k`, `n`,
  `checksummed_shares: true`, and `share_digests` (§9).
* `location` is channel-specific and tells the reader exactly where to look — the
  reader never guesses.
* `merkle_root` binds the module set (§10); `surface_digest` binds the public
  package model (§10); `cosignatures` are independent signatures over that body.
* **Canonical body** (what is signed): compact sorted-key JSON with modules sorted
  by slot, covering `version`, `modules`, `merkle_root`, `surface_digest`,
  `signature_algorithm`, and sorted `cosigners` identities/algorithms. Signature
  values are excluded, but all co-signers must be declared before signing.
  Strict key framing selects the verifier; the authenticated scheme must match
  that family (`ed25519` or `ed25519+ml-dsa-65`), never negotiate from an untrusted label.

## 3. Channels

### 3.1 `custom_xml`
Payload is base64-wrapped in a `<dx:payload>` element inside
`customXml/itemN.xml` (namespace `urn:docxplus:intelligence:1.0`), referenced by a
`customXml` relationship from the main document part. Invisible in rendering.
No channel-local limit; package entry/total/count budgets still apply.

### 3.2 `package_part`
Payload is stored raw as `intelligence/payloadN.dxp` with Default content type
`application/vnd.docxplus.payload`, referenced by a package-level relationship.
The natural home for sealed blobs. Package entry/total/count budgets still apply.

### 3.3 `metadata`
Payload is base64-encoded into a named custom document property
(`dxplus_<slot>`) in `docProps/custom.xml`. A short-string channel (≤ 8000 bytes),
suited to routing tags and identifiers.

### 3.4 `stego_media`
Payload is hidden in the least-significant bits of a PNG the document visibly displays:
under OOXML at `word/media/imageN.png` referenced by an `image` relationship and
rendered through a `<w:drawing>`; under ODF at `Pictures/figureN.png` rendered through
a `<draw:frame>` in `content.xml`. Two backends, recorded in `location.backend`:

* `python_lsb` — pure-Python LSB codec (`DXL1`: four-byte magic, unsigned
  big-endian uint32 payload length, then exact payload bytes). Truncated headers,
  lengths exceeding carrier capacity and payloads exceeding uint32 are refused,
  never silently sliced. Capacity is `floor(w·h·3/8) − 8` when framing fits.
* `steganographer` — the Rust generic-packet channel. The bridge asks the real
  `capacity` command for locator/envelope/signature overhead using the same
  `payload.bin` filename, `application/octet-stream` MIME type and signing policy
  as encode. Default packets are unsigned/non-ECC; signing requires an explicit
  key, and identity pinning is separate. The bridge exposes no ECC control.

### 3.5 `mce` (Markup Compatibility and Extensibility)
Payload is embedded inside `<mc:Choice Requires="dxm">` under the `urn:docxplus:mce:1.0`
ignorable extension namespace within `word/document.xml`, with standard empty `<mc:Fallback>`
elements. Unaware consumers discard the Choice branch and render the Fallback without error.

## 4. Encryption

When a module is password-sealed, the plaintext is wrapped in a self-describing
`DXE1` envelope before the channel places it:

```
"DXE1" | kdf_id(1) | salt_len(1) | salt | nonce_len(1) | nonce | params_len(1) | params | AES-256-GCM ciphertext
```

Key derivation is recorded per envelope. The default is **Scrypt** (memory-hard,
`N=2^15, r=8, p=1`; `kdf_id=2`, `params = n_log2 ‖ r ‖ p`); **Argon2id** (RFC 9106,
`memory_cost=65536 KiB, time_cost=3, parallelism=4`; `kdf_id=3`, `params = memory_cost(4) ‖ time_cost(2) ‖ parallelism(2)`)
provides first-line side-channel and GPU resistance; **PBKDF2-HMAC-SHA512**
is available for compatibility (`kdf_id=1`, `params = iterations(4)`, default
600 000 per OWASP-2023). Readers cap work and memory before KDF dispatch:
argon2id memory `≤ 256 MiB`, time `≤ 10`, parallelism `≤ 16`; scrypt `N ≤ 2^21`,
`128·N·r ≤ 256 MiB` and a separate `N·r·p` work cap; PBKDF2 `≤ 5,000,000`.
Exactly two complete frames, their lengths, envelopes, matching KDF parameters
and matching power-of-two padding buckets are admitted before either KDF runs.
Both frames are attempted. These are declared-work limits, not a total DoS bound.

The AEAD is bound to the module **slot as additional authenticated data (AAD)**, so
a ciphertext cannot be spliced into a different slot. The manifest digest for a
sealed module is over the **stored (ciphertext) bytes**, never the plaintext — a
plaintext digest would be an offline confirmation oracle against short secrets.
Plaintext integrity is the GCM tag, checked on decryption.

Because only the payload is encrypted, the surface `.docx` remains a valid,
openable Office document; this is intentional and contrasts with whole-package
OOXML encryption, which yields a file most tools cannot open.

## 5. File names and media types

A docxplus document is byte-identical to the ordinary Office document it also is, so
it is written under two names:

| Extension | Media type | Asserts |
| --- | --- | --- |
| `.docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | the surface contract |
| `.docxplus` | `application/vnd.docxplus.document+docx` | the intelligence contract |
| `.odt` | `application/vnd.oasis.opendocument.text` | the surface contract |
| `.odtplus` | `application/vnd.docxplus.document+odt` | the intelligence contract |

The two files in a pair differ in nothing but the name. A name is a claim; readers
resolve it with `validate` (`src/docxplus/fileext.py`, `src/docxplus/validate.py`). Consumers must accept
either extension, and must never treat the plus name as evidence that the intelligence
layer is present or valid.

Both targets are preflighted and staged before publication. Each directory-entry
replacement is atomic; the pair and related key/share files are not a cross-file
crash-atomic transaction.

## 6. Determinism

Serialisation is reproducible: fixed ZIP timestamps (1980-01-01), content types
first, remaining entries sorted by name. Unencrypted, unsigned builds are
byte-stable across runs. Encryption and signing introduce fresh randomness
(salt/nonce, but Ed25519 is deterministic given the key) by design.

## 7. Extensibility

New channels register under the same `Channel` contract (`embed` / `extract` /
`capacity`) and appear in the manifest by id. Readers that do not recognise a
channel id fail that module explicitly rather than silently — the manifest is the
contract.

## 8. Payload types

A module records a `payload_type` id. The type owns how an object is packed to
bytes and back, so a payload is a typed object, not a blob. Built-in types:

| Type | Meaning | Packing |
| --- | --- | --- |
| `bytes` | opaque bytes | identity |
| `text` | UTF-8 string | encode/decode |
| `json` | JSON object | canonical compact JSON |
| `project` | a whole directory tree | deterministic tar.gz (fixed mtime, sorted, junk excluded); preserves contents, the executable bit, and empty directories; refuses symlinks; path-traversal-guarded on unpack — see §8.1 |
| `docxplus` | a nested docxplus document | identity bytes, typed so readers recurse |

The digest recorded for a module is over the **stored bytes** the channel holds
(plaintext for a plain module, ciphertext for a sealed one), so it binds exactly
what travels and is checked before any decryption — never a plaintext digest of a
sealed module.

### 8.1 The `project` fidelity contract

A payload type that claims to carry a working tree has to say what it preserves, or
callers will assume more than it delivers. The contract is:

**Preserved** — file contents byte for byte; the executable bit; empty directories;
relative structure; filenames containing spaces or non-ASCII characters; zero-byte
files.

**Normalised** — mtimes (to the fixed 1980 epoch), uid/gid/uname/gname (to zero and
empty), and every mode bit other than execute. Determinism is worth more than
ownership metadata here, and arbitrary modes are a hazard at unpack time. Modes are
clamped to exactly `0o755` or `0o644`.

**Refused** — symlinks. `Path.is_file()` follows links, so packing one embeds its
*target's* bytes under the link's name: a tree containing `creds -> ~/.ssh/id_rsa`
would ship that key inside the document with nothing to indicate it. Packing raises
unless the caller passes `follow_symlinks=True`, which makes the decision explicit and
reviewable. Unpacking rejects link members unconditionally.

**Bounded capture, intake and publication.** File data, compressed bytes, member/
filesystem-node counts, metadata and path depth have independent budgets in
`payloads.py`. Capture retains directory/file descriptors, rejects source identity
changes and bounds reads; it is not a global snapshot across files. Quiesce sources
when cross-file consistency matters. Extraction bounds gzip expansion and physical
TAR/PAX headers before rich parsing, rejects unsupported metadata, aliases,
traversal, duplicates, links and file/directory conflicts, then publishes a fresh
private **0700 root** into an absent or empty destination. Existing files are
never merged, truncated, followed or chmodded. Descriptor-relative no-follow
directory support is required; unsupported platforms refuse. Shared
`archive_limits.py` also provides ZIP-directory preflight before `ZipInfo`
allocation and bounded gzip/TAR intake used by release evidence. These budgets
are not a total Python-memory quota. Readers expose
`extract_project(..., *, max_uncompressed=..., **creds)` separately from credentials;
author-side clean extraction must use the same selected budget.

**Excluded by policy**, in two tiers, because where a name appears decides whether
it means anything:

* *Root only* — `.venv`, `venv`, `output`, `htmlcov`, `node_modules`, `dist`, `build`.
  These are build artefacts at the top of a project and ordinary words anywhere else,
  so matching them at depth deletes real source such as `src/output/model.py`.
* *Any depth* — `__pycache__`, `.git`, `.pytest_cache`, `.ruff_cache`, `.mypy_cache`.
  A tool cache is never source, wherever it sits.

`scripts/06_project_roundtrip.py` measures this contract against both container
profiles on every run rather than trusting it.

## 9. Sealing modes

Each module's `sealing.mode` selects how the packed payload is protected. All modes
seal the *payload*, never the package, so the surface `.docx` stays openable. The
manifest records the mode; threshold additionally records `k`, `n` and full-share
digest commitments. Recipient identities/counts and a decoy marker are omitted.

| Mode | Envelope | Credential to open | Use |
| --- | --- | --- | --- |
| `plain` | none | — | public modules |
| `password` | two framed `DXE1` envelopes (the payload + a chaff frame) | password | single secret |
| `recipients` | `DXE2` (X25519/HKDF-SHA256) or `DXE3` (X25519 + ML-KEM-768/HKDF-SHA384), AES-GCM content-key wraps | matching raw classical or typed hybrid private key | one homogeneous recipient family |
| `threshold` | AES-GCM under a random content key, key Shamir-split k-of-n over GF(256) | any `k` of `n` shares | dead-man's envelope |

`DXE2` layout: `"DXE2" | body_len(4) | body | recip_count(2) | [ eph_pub(32) wrap_len(2) wrap ]…` (ephemeral pubkeys only).

`DXE3` is available through both profiles' ordinary recipient APIs when all recipients
are genuine hybrid keys; classical sets retain DXE2. Mixed or ambiguous key families
refuse. DXE3 uses X25519 + ML-KEM-768 with HKDF-SHA384 and AES-256-GCM. Its layout is
`"DXE3" | body_len(4) | body | count(2) | [slot_len(4) | eph_len(2) | eph | wrap_len(2) | wrap]…`,
with big-endian lengths, body at least 28 bytes, nonempty count, `eph` exactly
`X25519_pub(32) | kemct_len(2)=1088 | MLKEM_ct(1088)`, wrap 60 bytes and slot
1186 bytes. Every slot is validated before attempting any decrypt; trailing bytes
are refused. HKDF derives 32 bytes with no salt, info `docxplus/dxe3-hybrid`, and
input `ephemeral_X25519_pub || recipient_X25519_pub || X25519_secret || MLKEM_secret`.

Hybrid public keys frame `classical_pub(32) | pq_len(2) | pq_pub`: KEM PQ public
keys are 1184 bytes; ML-DSA-65 PQ public keys are 1952 bytes. Private PQ values
are provider seeds (KEM 64 bytes, DSA 32 bytes), not expanded keys. Hybrid signatures
frame `64(2) | Ed25519_sig(64) | 3309(2) | MLDSA_sig(3309)` and require **both**
verifications over `b"docxplus/hybrid-signature/v1\0" + message`. Pin the entire
combined public key, never just the classical half. Old simulated keys/signatures/
ciphertexts are incompatible; generate new keys and redistribute pins. An old
32-byte signing seed is not distinguishable by length alone and does not preserve
the former PQ public identity when reinterpreted. Missing native provider support
fails explicitly. [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) and
[FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) standardize components, not this
hybrid protocol or a FIPS-certified docxplus product.

Portable hybrid private serialization is `DXHK | version(1)=1 | suite(1) |
classical_seed(32) | classical_public(32) | pq_seed | pq_public`. Suite 1 is
X25519/ML-KEM-768 (64-byte seed, 1184-byte PQ public key); suite 2 is
Ed25519/ML-DSA-65 (32-byte seed, 1952-byte PQ public key). Exact lengths, suite,
version and both derived public halves are checked on import. Use
`HybridKeyPair.private_bytes` / `from_private_bytes`, not concatenated seeds.

**Decoy / deniability limits.** A decoy remains a `password` module, with real
and cover payloads under different passwords. An ordinary module instead has a
discarded-password chaff frame. Both use exactly two frames, one visible KDF/
parameter policy and equal power-of-two padded plaintext sizes (minimum 256 bytes,
including an eight-byte inner length). This removes simple frame-count, KDF and
exact-length distinctions; it does not establish distributional or timing
indistinguishability. Buckets leak size ranges, the manifest reveals format use,
and an adversary may demand another password. No universal deniability is claimed.

## 10. Provenance — Merkle binding + surface binding

Module leaves and internal nodes are domain-separated BLAKE2b values, ordered by
slot, using RFC 6962 largest-power-of-two tree splitting, not odd-node promotion.
Stored module and full-share commitments use BLAKE2b-256 (64 hexadecimal digits).
Inclusion proof size is logarithmic; producing a proof or checking an entire
document is not claimed to take logarithmic time.

The canonical signed body binds the root and `surface_digest`. The transcript is
BLAKE2b-256 over `b"docxplus:surface:3.0\0" + profile + b"\0"` followed by
records. Profile is `OPC` or `ODF`; a record is a **one-byte kind**, unsigned
four-byte big-endian **field count**, then each field's unsigned eight-byte
big-endian **byte length** and bytes. Strings are UTF-8. Content is hashed
directly rather than concatenated with delimiter-shaped headers or copied into
another package-sized transcript.

| Profile/order | Kind | Fields (in order) |
| --- | --- | --- |
| OPC parts, sorted by name; intelligence-manifest bytes excluded | `P` | name, eight-byte big-endian content length, fixed 32-byte SHA-256 content hash |
| OPC default types, sorted by extension | `D` | extension, content type |
| OPC overrides, sorted by part | `O` | part, content type |
| OPC relationships, sorted by source then ID/type/target/mode | `R` | source, **ID**, type, target, mode |
| ODF type | `T` | ODT mimetype bytes |
| ODF root version | `V` | version, or zero fields when absent |
| ODF content parts, sorted by name | `P` | name, eight-byte content length, fixed 32-byte SHA-256 hash |
| ODF declarations, sorted by name | `M` | name, media type |
| ODF supported entry attributes, sorted by path then key | `A` | path, attribute key, value |

OPC index XML is represented by its complete parsed types/relationships, not raw
serialization. ODF `mimetype`, `META-INF/manifest.xml` and `/` pseudo-root are
represented by the type/version/declaration/attribute records, not duplicate raw
part records; intelligence-manifest bytes cannot commit to themselves. The
intelligence manifest's index declaration remains bound in both profiles.
Unsupported/malformed authority refuses rather than disappearing. This commits
to a normalized package model, not ZIP bytes or a complete rendering model.

Assuming collision resistance, unforgeability and a trusted pinned signer, changes
to committed values are detected when provenance is recomputed. These assumptions
do not establish application acceptance or the truth of a signer's claims.

**Inclusion proofs.** `inclusion_proof(slot)` yields
`{slot, digest, siblings, root}` letting a third party confirm one module belongs
to the signed set without seeing the other modules — the capability that makes the
Merkle tree more than a re-hash of the signed list. Verify with
`provenance.verify_inclusion(proof, expected_root)`, with the independently trusted signed root.

**Detached co-signatures.** `cosignatures: [{public_key, algorithm, value}, ...]`
use each strict key family's Ed25519 or Ed25519 + ML-DSA-65 scheme over the same
canonical body, including all declared identities/algorithms. `verify_cosigners([keys])`
returns true only when every expected key has a valid signature (the primary signer
counts when its signature validates). Changing the declared co-signer roster or
scheme changes every signed body. Authenticity requires caller-pinned keys; a
self-asserted signer does not establish an institutional identity.

## 11. Reproduction attestation (v0.4)

A `project` module may carry a signed **reproduction attestation** binding carried
bytes to an author's recipe/output claim, not proving execution or scientific validity
([`reproduction-design.md`](reproduction-design.md)). The attestation is a record field:

```json
"reproduction": {
  "command": ["{python}", "src/compute.py"],
  "outputs": ["output/result.json"],
  "timeout": 300,
  "output_digest_scheme": "docxplus-output-tree-v3-blake2b-256",
  "output_digest": "<versioned output-tree digest>",
  "source_digest": "<digest of the selected packed source tree>",
  "toolchain": {"python": "3.12.13", "implementation": "CPython", "platform": "…"}
}
```

Missing/unknown/older output schemes refuse before execution. The v3 transcript
binds a domain, file count, sorted length-framed relative paths, byte sizes and
fixed-size BLAKE2b-256 content hashes. Re-attest trusted projects rather than
relabeling signed old digests. Comparison reports `source_match`; `match` requires
source and output equality, with `toolchain_match` reported separately.

It is folded into the signed manifest body, so the signature binds
`carried source → attested output`. Two trust paths, per the Council synthesis:

- **`verify_reproduction(slot, expected_public_key=...)`** executes nothing.
  `self_consistent` checks signed/stored-byte binding; `authentic` and `verified`
  additionally require the pinned signer. It authenticates a claim, not a witnessed run.
- **`reproduce(slot, dest, allow_execution=True)`** explicitly executes the carried
  recipe. Missing macOS Seatbelt/Linux bubblewrap raises `ReproError`; no raw or
  network-only fallback exists. Reads of host files remain possible; use disposable
  isolation for untrusted code. `{python}` resolves the recipient interpreter only
  as argv[0]; there is no shell or environment interpolation.

Every matched output must be a bounded regular nofollow file, newly created or
content-changed from its snapshot; unchanged carried inputs are refused individually.
Deadlines cover collection and hashing. Versioned filename/length/file-digest framing
binds output boundaries. A successful local comparison supports only the declared
recipe and selected outputs under the observed environment, not whole-project or
scientific reproducibility. See the design note for resource/confinement residuals.

## 12. Authenticity requires a pinned key (v0.4)

The manifest's signer public key is **self-asserted**: it travels inside the
manifest. A valid signature proves only that whoever holds that key signed this
content (integrity + a self-asserted signer) — an attacker can sign a fabricated
document with their own key and it validates as *self-consistent*. `signature_status`,
`verify_provenance`, and `verify_reproduction` therefore accept an
`expected_public_key`; only when the signer matches it (constant-time) is the verdict
`valid` / authentic. `signer()` exposes the key so a caller can decide out-of-band.

## 13. Hardened intake (v0.5)

`intake.safe_open(bytes, policy=...)` opens untrusted `.docx` bytes under caps and
returns a threat report — **executing nothing**. `read_package` enforces the
zip-bomb / duplicate-entry / size caps and defuses XML (DTDs off); `intake.scan`
adds the package-level surface a defender triages: external (off-package)
relationships, macro parts (`vbaProject.bin`, macro-enabled content types), and
`altChunk` foreign-content imports, plus a part-count cap. Under a strict policy a
non-clean report raises; otherwise the caller gets the report and (for a docxplus) a
reader. This operationalises the standards report's untrusted-input checklist.

Both profiles preflight encoded ZIP size, declared entries and central-directory
metadata before constructing `ZipInfo` objects, then compare actual counts and
enforce inflated part/total/ratio limits. Both writers enforce the same
entry/count/name/metadata budgets and use shared safe per-entry compression;
highly compressible large parts are stored rather than deflated past reader ratio
limits. Unsupported compression refuses before decoding. XML is parsed
structurally, including UTF-16 and supported UTF-32; `altChunk` cannot hide behind
an alternate tag byte encoding. Parse failures are non-clean, never a safe scan.
These bounds are not total-process-memory or antivirus guarantees.

## 14. Sibling profile, share commitments, and the transparency log

**OpenDocument Text (ODT) profile.** The emitted surface targets ODF 1.3; ODF 1.4
is also discussed in the standards report, not claimed as a separate certification.
`mimetype` is stored uncompressed (ZIP_STORED) as the first ZIP entry,
followed by `META-INF/manifest.xml`, `content.xml`, `meta.xml`, and payload entries.
The manifest lists neither itself nor `mimetype`, both of which are located
positionally. Archives use the same fixed 1980-01-01 DOS timestamp and normalised
permission bits as §6 requires, and the ODT reader enforces the same intake caps as
the OPC reader — entry count, decompression ratio, and rejection of traversal or
absolute entry names — because a second front door into the same container must not
be the weaker one.

The intelligence layer is implemented in `src/docxplus/odt_container.py`
(`OdtPlusBuilder` / `OdtPlusReader`):

* `intelligence/manifest.json` holds the same manifest structure as §2, declared as
  a file-entry in `META-INF/manifest.xml` like any other part.
* Payloads ride as ODF package entries at `intelligence/payloadN.dxp`. This is the
  ODF-native analogue of the OPC `package_part` channel, recorded in the manifest as
  channel `odt_package_part`.
* All four sealing lineages of §8 apply unchanged, because sealing is a property of
  the specification rather than of the packaging: `container.seal_module` and
  `DocxPlusReader._unseal` are shared between the profiles so the chaff frame, the
  AAD slot binding, and signed full-share digest commitments use one implementation.
* The ODF surface commitment covers all non-intelligence-manifest entries and the
  supported root/file-entry authority metadata, not only visible content. Standard
  file-entry version, size and preferred-view-mode are preserved/bound; unsupported
  implementation-defined QName modes are refused rather than losing namespace context.

**Channels that do not cross over.** ODF has no custom XML datastore part and no
Markup Compatibility `<mc:AlternateContent>` element, so the `custom_xml` and `mce`
channels are OOXML-only. `metadata` has a plausible ODF analogue (`meta.xml`
user-defined fields) that is not yet implemented. `stego_media` crosses over: the ODT
profile offers budgeted package entries and the LSB media channel at
`Pictures/figureN.png`, and shares the sealing, digest, and signature machinery with
the OOXML profile.

**Threshold share authentication.** Shamir tagged shares retain the wire header
`0xFF || x(1) || checksum(32) || payload`, with `x ≤ 254`. The checksum is public,
unkeyed BLAKE2b over `x || payload`: an attacker can recompute it. It is **not Feldman
or polynomial-verifiable secret sharing**, nor malicious-share authentication alone.
Format 3 threshold `sealing` objects contain exactly `mode`, `k`, `n`,
`checksummed_shares`, and `share_digests`. The mode is `"threshold"` and
`checksummed_shares` must be `true`; missing or false checksum policy is refused.
`share_digests` contains one BLAKE2b-256 digest of each complete issued share.
Readers check membership before combining and require tagged shares. Those
commitments authenticate issued bytes only when the manifest is trusted under a
pinned signer; they do not prove honest polynomial setup.

**Cryptographic transparency log.** `TransparencyLog` (`src/docxplus/transparency.py`)
maintains an append-only hash chain over reproduction attestations with Merkle
inclusion proofs, so a third party can confirm one attestation belongs to the log
without re-execution and without seeing the others. Chain verification establishes
only *self-consistency*: a log rewritten from its first entry is equally
self-consistent, and because no entry references the tip, the final entry admits
in-place edits that break no linkage. Authenticity rests on a **signed tree head** —
an Ed25519 or genuine dual Ed25519 + ML-DSA-65 signature, domain-separated by
`docxplus-transparency-sth-v1\x00` so it can never be replayed as a manifest
signature, over `{log_size, root_hash, timestamp}`. The signed head binds a particular
length/root, but freshness still requires an independently retained expected head.
`attestation_digest` hashes the **complete** canonical claim under
`docxplus/attestation/v2\0`, not only its output digest. A pinned head/inclusion proof
authenticates that logged claim, not independent execution, trustworthy time, or that
the document predates a document-key compromise. No head means unauthenticated.

**Sandbox linker scrubbing.** The reproduction harness strips `DYLD_*` and `LD_*`
injection vectors (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) along with `PYTHONPATH`,
`PYTHONHOME`, and the temp-directory variables before dispatching the child. It also
refuses to build a macOS seatbelt profile from any path containing a character that
cannot be safely quoted in SBPL, since a crafted directory name could otherwise
close the policy literal and append rules of its own.

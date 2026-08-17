# docxplus Intelligent Container — Format Specification v2.0

docxplus is a profile of an ordinary Office Open XML (OOXML) WordprocessingML package
(`.docx`). A conforming docxplus file is, first, a conforming OPC package: opening it
in any word processor yields an ordinary document. Second, it carries an
**intelligence layer** — a signed manifest plus one or more payload modules — over
spec-sanctioned side-channels. A consumer that knows nothing of docxplus ignores the
extra parts; a docxplus reader uses the manifest to recover them.

This spec is deliberately implementable from the OOXML standard alone. Every
structural claim traces to the standards report in `docs/standards-report.md`.

## 1. Conformance

A file is **docxplus conforming** when:

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

A file lacking the manifest is a **plain document**, not a docxplus; it is still a
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
  "surface_digest": "<hex digest over every visible story part>",
  "signature": { "algorithm": "ed25519", "public_key": "<hex>", "value": "<hex>" },
  "cosignatures": [ { "public_key": "<hex>", "value": "<hex>" } ]
}
```

* `slot` is a unique caller-chosen name; extraction is by slot.
* `digest` is over the **stored** bytes the channel holds — ciphertext for a sealed
  module, never the plaintext. A plaintext digest would be an offline confirmation
  oracle against short secrets (§4, §8).
* `payload_type` names the type that packs the object to bytes and back (§7);
  `sealing` records the protection mode and nothing more (§8).
* `location` is channel-specific and tells the reader exactly where to look — the
  reader never guesses.
* `merkle_root` binds the module *set* (§9); `surface_digest` binds the visible
  text (§9); `cosignatures` are independent signatures over the same body (§9).
* **Canonical body** (what is signed): compact JSON with sorted keys and modules
  sorted by slot, covering `version`, `modules`, `merkle_root`, and
  `surface_digest`, with `signature` and `cosignatures` omitted. This makes the
  signature stable regardless of serialisation whitespace.

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
600 000 per OWASP-2023). Readers **cap** attacker-supplied work factors
(argon2id memory `≤ 256 MiB`, time `≤ 10`, parallelism `≤ 16`; scrypt `N ≤ 2^21`
*and* `128·N·r ≤ 256 MiB`; PBKDF2 `≤ 5,000,000`) so a hostile envelope cannot turn
opening into a denial-of-service. Scrypt needs both bounds: its footprint is
`128·N·r`, so capping `N` while permitting `r ≤ 64` would still admit a
multi-gibibyte allocation.

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

## 8. Payload types (v2.0)

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

**Excluded by policy**, in two tiers, because where a name appears decides whether
it means anything:

* *Root only* — `.venv`, `venv`, `output`, `htmlcov`, `node_modules`, `dist`, `build`.
  These are build artefacts at the top of a project and ordinary words anywhere else,
  so matching them at depth deletes real source such as `src/output/model.py`.
* *Any depth* — `__pycache__`, `.git`, `.pytest_cache`, `.ruff_cache`, `.mypy_cache`.
  A tool cache is never source, wherever it sits.

`scripts/06_project_roundtrip.py` measures this contract against both container
profiles on every run rather than trusting it.

## 9. Sealing modes (v2.0)

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
undecryptable chaff when there is no decoy), a decoy is structurally indistinguishable
from an ordinary password module — neither the manifest nor the frame count
reveals a hidden payload. This provides deniability against inspection, not a
proof of non-existence: an adversary who knows the scheme knows a second frame is
*always* present and cannot be forced to be chaff. See `docs/security-model.md`.

## 10. Provenance — Merkle binding + surface binding (v2.0)

The manifest carries a `merkle_root` over all modules: leaves are
`blake2b(0x00 ‖ slot ‖ 0x00 ‖ module_digest)`, internal nodes
`blake2b(0x01 ‖ left ‖ right)`, odd nodes promoted, modules ordered by slot. The
root **and** a `surface_digest` are folded into the canonical body the Ed25519
signature covers, so the signature binds both the **set** of modules and the
**visible document text**: altering a module or a paragraph invalidates it. The
surface digest spans the *entire package* in sorted order: every part with its
bytes, every entry of the content-type map, and every relationship edge, excluding
only `intelligence/manifest.json`, which carries the digest and so cannot contain
itself.

Binding a list of part *names* is not sufficient, and the reason is structural rather
than a matter of coverage. OPC resolves the rendered document through the
officeDocument **relationship**, not the filename, so an attacker could add a second
document part, repoint that relationship at it, demote the original's content type,
and leave every signed byte untouched — producing a package that verified under a
pinned key while rendering different text. Content types and relationships are
therefore inside the signature, and the selection rule is "everything but one named
exception" rather than an enumeration that a new channel could fall outside of. `verify_provenance()` returns true only when the
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

## 11. Reproduction attestation (v0.4)

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

## 14. Sibling profile, verifiable shares, and the transparency log (v0.6)

**OpenDocument Text (ODT) profile.** A sibling container conforming to OASIS
OpenDocument v1.3/v1.4 Part 2, carrying the *same* intelligence layer as the OOXML
profile. `mimetype` is stored uncompressed (ZIP_STORED) as the first ZIP entry,
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
  AAD slot binding, and the signed-manifest VSS requirement cannot drift apart.
* The `surface_digest` of §9 binds `content.xml`, `styles.xml`, and `meta.xml` in
  sorted order — the ODF parts a reader actually sees.

**Channels that do not cross over.** ODF has no custom XML datastore part and no
Markup Compatibility `<mc:AlternateContent>` element, so the `custom_xml` and `mce`
channels are OOXML-only. `metadata` and `stego_media` have plausible ODF analogues
(`meta.xml` user-defined fields; `Pictures/`) and are not yet implemented; the ODT
profile currently offers the unbounded package-entry channel alone.

**Verifiable Secret Sharing (VSS).** Shamir shares carry an integrity header:
`0xFF ‖ x(1) ‖ digest(32) ‖ payload`, where `digest = blake2b(x ‖ payload)`. The
share index is capped at 254 so a legacy share can never begin with the `0xFF`
magic, keeping the two wire formats unambiguous. A tag only binds if the verifier
insists on it: stripping the header yields a legacy-format share carrying the same
tampered bytes, so reconstruction must be told to require the verifiable format.
Threshold modules therefore record `sealing.vss = true` in the *signed* manifest,
and the reader refuses any share lacking a valid tag — the requirement cannot itself
be downgraded without breaking the signature.

**Cryptographic transparency log.** `TransparencyLog` (`src/docxplus/transparency.py`)
maintains an append-only hash chain over reproduction attestations with Merkle
inclusion proofs, so a third party can confirm one attestation belongs to the log
without re-execution and without seeing the others. Chain verification establishes
only *self-consistency*: a log rewritten from its first entry is equally
self-consistent, and because no entry references the tip, the final entry admits
in-place edits that break no linkage. Authenticity rests on a **signed tree head** —
an Ed25519 signature, domain-separated by the prefix
`docxplus-transparency-sth-v1\x00` so it can never be replayed as a manifest
signature, over `{log_size, root_hash, timestamp}`. Committing to the length as well
as the root defeats truncation replay, since an earlier head cannot describe a
longer log. A log presented without a tree head is *unauthenticated*, however clean
its chain.

**Sandbox linker scrubbing.** The reproduction harness strips `DYLD_*` and `LD_*`
injection vectors (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) along with `PYTHONPATH`,
`PYTHONHOME`, and the temp-directory variables before dispatching the child. It also
refuses to build a macOS seatbelt profile from any path containing a character that
cannot be safely quoted in SBPL, since a crafted directory name could otherwise
close the policy literal and append rules of its own.

# docxplus Security Model

docxplus inherits the OOXML/ODF attack surface documented in
`docs/standards-report.md` (§6–§7) and adds an intelligence layer. This note states
what the format defends, what it deliberately does **not**, and the residual risks
an integrator must handle.

## What the format provides

| Property | Mechanism | Basis |
| --- | --- | --- |
| Payload confidentiality | AES-256-GCM over the payload; key from memory-hard **Argon2id** or **Scrypt** (default; PBKDF2-HMAC-SHA512 available), work factors capped on read | MS-OFFCRYPTO *agile* lineage (report §8.1); RFC 9106; OWASP-2023 |
| Payload integrity | GCM auth tag for plaintext; the manifest digest binds the **stored (ciphertext) bytes** and is checked before decryption | avoids the offline plaintext-confirmation oracle a plaintext digest would give |
| Context binding | the module **slot** is AAD in every AEAD operation | a ciphertext cannot be spliced into another slot |
| Manifest + package integrity | key-family-authenticated Ed25519 or Ed25519 + ML-DSA-65 signature over the canonical body binds the module Merkle root and a profile-separated typed/count/length/hash `surface_digest` | binds part bytes, type/ODF authority and full relationship edges including IDs; primary algorithm and declared co-signer identities/algorithms are signed |
| Authenticity (only with a pinned key) | `verify_provenance(expected_public_key=...)` / `signature_status(expected_public_key=...)` compare the signer to a caller-trusted key in constant time | the manifest's embedded key is **self-asserted**; without pinning, a forger can sign a fabricated document with their own key and it reads as self-consistent — never as authentic |
| Metadata minimalism | sealing metadata omits recipient identities/counts and a decoy marker; threshold records include `k`, `n`, checksum policy and full-share commitments | envelope family, padded slot count, module roster and size ranges remain visible |
| Untrusted-input intake | ZIP part/count/ratio budgets; shared bounded gzip/TAR physical preflight, path/link/member checks; nested-depth cap; KDF work/memory caps including `N·r·p` | byte/metadata budgets, not total-process-memory guarantees; see format-spec §8.1 |
| Openability preserved | encryption is payload-level, never whole-package | report §6.3, §14.3 |
| Optional media packet integrity | Rust generic packets hash content; explicit `signing_key` adds Ed25519 packet signing | default bridge packets are unsigned/non-ECC; packet identity requires a trusted pin, independently of document provenance |
| Issued-share byte authentication | threshold manifests commit to BLAKE2b-256 digests of complete issued shares, checked before combine | requires a trusted signed manifest; the standalone tagged-share checksum is unkeyed, not Feldman/polynomial VSS |
| Attestation log authenticity | a signed tree head over `(log_size, root_hash)`, domain-separated from the manifest signature, anchors the transparency log | a hash chain proves self-consistency, never authenticity |
| Project-payload containment | descriptor-relative no-follow capture pins source inodes and bounds reads; extraction validates paths/types/budgets and publishes a fresh private tree | not a cross-file snapshot; missing safe descriptor capabilities refuse |
| Sibling-profile parity | the ODT profile carries the same signed manifest, sealing lineages, Merkle root, and surface digest, sharing the OPC sealing/unsealing code rather than reimplementing it | a second front door must not be the weaker one, and duplicated crypto drifts |
| Signature-coverage honesty | a package carrying OPC signatures is rejected unless their reference set covers the intelligence manifest and every part it names | a valid-looking signature over a stripped payload set is worse than no signature |

## What it deliberately does not do

* **It is not whole-document DRM.** The surface document is intentionally readable
  by anyone. Confidentiality applies only to modules marked encrypted. The Library
  of Congress deposit rule forbids access-controlling DRM on archival text (report
  §9); docxplus keeps the surface document clean by design.
* **The manifest is not hidden.** A `custom_xml`/`package_part` module is
  discoverable by anyone who opens the archive. Concealment (not just
  confidentiality) is only offered by the `stego_media` channel, and even there LSB
  stego is detectable by steganalysis — treat it as obfuscation, not secrecy. The
  shipped detector is a heuristic: it proves neither presence nor absence
  (see Steganalysis below).
* **No watermarking.** docxplus does not implement visible or invisible watermarking,
  robust or fragile, and claims no marking that survives conversion or re-rendering.
  `stego_media` is a payload channel over a lossless PNG, not a mark, and its measured
  fragility is the reason the distinction matters: a lossless PNG re-save preserves the
  payload, while a JPEG round trip or any resize destroys it. Destruction is at least
  clean — extraction then refuses rather than returning corrupted bytes — but a channel
  that any lossy transform erases is not a watermark. Provenance that must outlive
  re-rendering needs a mechanism this format does not provide. Pinned by
  `tests/test_steganalysis_bounds.py`.
* **Decoy framing is not universal deniability.** Ordinary and decoy password
  modules use exactly two frames, one visible bounded KDF/parameter policy and
  equal power-of-two padding buckets. All framing/envelopes are admitted before
  KDF work and both frames are attempted. Ordinary chaff uses a discarded password;
  a decoy instead carries a cover payload. This removes simple frame-count, KDF and
  exact-length distinctions, not all timing or distributional differences.
  Buckets leak size ranges and the manifest reveals use of the format. Neither
  coercion resistance nor proof that another password does not exist is provided.
* **Unsigned = no provenance.** Without a signature, an attacker who rewrites a
  module can also rewrite its digest; validation emits a loud WARNING for unsigned
  documents. Only a signed manifest makes the module set and surface text
  tamper-evident.
* **A signature covers the package, but is not an OPC package signature.** The
  signed body binds every part, the content-type map, and the relationship graph, so
  altering a paragraph, adding a part, retyping one, or repointing a relationship all
  invalidate it. What it is *not* is an `_xmlsignatures` OPC signature, so Word will
  not display it and a reader who never runs `verify_provenance` gains nothing from
  it. Both OOXML and ODF also have documented signature-spoofing classes at the
  application layer (report §6.1, §7). `docs/opc-signatures.md` states why the
  whole-package form is not implemented and the invariant any implementation must
  hold.

## Residual risks an integrator must handle (report §14.3)

* **Untrusted input.** Parsing an unknown `.docx` still exposes ZIP-bomb, Zip-Slip,
  XXE, and importer memory-safety risks. docxplus's reader uses `defusedxml` and never
  extracts to disk, but a full intake pipeline should still enforce inflate-ratio
  and entry-size caps, disable DTDs, and sandbox parsing.
* **Encryption oracle / password handling.** Passwords are used only for KDF; the
  GCM tag is the trust boundary, not the checksum. Do not treat a decrypt failure
  as anything but "wrong key or tampering".
* **What your working tree contains.** A `project` module carries the tree you point
  it at. Junk directories are excluded and symlinks are refused, but nothing inspects
  the *content* of the files you chose to pack: a checked-in credential, a `.env`, or a
  private key inside the tree travels with the document. Review what you are packing;
  the format protects the boundary, not your judgement about what belongs inside it.
* **Metadata leakage.** `docProps/core.xml` carries author/timestamps; scrub before
  release if that matters (report §14.4). The `metadata` channel deliberately
  *adds* named custom properties — do not put secrets there in cleartext.
* **Steganalysis.** `p_value` is the chi-square upper-tail reference probability
  for Pearson adjacent-pair equality, **not** a posterior probability of embedding.
  Each populated pair contributes one degree of freedom; insufficient samples or
  expected counts make the approximation unavailable (`available=False`,
  `p_value=None`), not a clean negative. Balanced untouched covers can flag.
  Prefix sweeps reuse samples; no independent-test calibration, general sensitivity,
  false-positive rate or payload-size estimator is established. Optional external
  analysis has its own contract.

* **Carried project trees.** Only plain files/directories are published into a
  fresh private 0700 root at an absent/empty destination. Nonempty destinations,
  path aliases, conflicts, traversal, links, devices and FIFOs refuse. Carried
  file execute bits are normalized to 0644/0755 inside that private root.
  Compressed/file-data/member/node/metadata/path-depth budgets are independent;
  physical TAR/PAX checks precede rich parsing. Shared `archive_limits.py` also
  preflights ZIP directory allocation and bounded release-evidence gzip/TAR.
  These limits are not whole-process memory quotas.
* **Media/backend intake.** Python RGB/LSB processing has a shared pixel cap, not
  a total-memory guarantee. Rust discovery is only explicit `STEGANOGRAPHER_BIN` or PATH,
  never a sibling checkout or automatic Cargo build. An explicitly invalid backend
  fails; absent optional capability is not a pass. Wheel use needs no source sibling.

## Review and bulk-recovery boundaries

`inspection` and `audit` retain the original manifest declarations and distinguish
selected structural validity, threat findings, signature/surface self-consistency
and caller-pinned authenticity. A malformed manifest does not erase an obtainable
threat report or successful batch peers. Inspection checks no payload transport;
`payloads_verified: false` is deliberate, and is not full `validate` coverage or
proof that a decoder would recover the declared stored bytes. Every declared
co-signature is checked without decrypting payloads. Ordinary office files need
not carry an intelligence manifest; without a trusted complete key pin they are
never reported authentic.

`compare` is a deterministic comparison of selected package, module and signer
policy dimensions. Invalid declarations cannot become equal by normalizing their
serialized root. Logical equality is neither byte identity, rendered equivalence,
plaintext equality nor signer trust. Encryption can change stored bytes while
preserving plaintext; comparison never decrypts to guess that relation.

`export_modules` verifies selected declarations and requested identity policy,
then uses existing stored-digest and credential checks to recover exact packed
bytes. It does not invoke registered object codecs, recursively open nested
documents, unpack projects or run recipes. A requested trusted carrier decoder
can run for media extraction. Payload files and index are private; slot names
remain index data rather than filesystem components. The final directory must be
absent, and publication uses a native atomic no-replace operation. Missing safe
filesystem capabilities refuse, never fall back to a clobbering rename. Input,
module-count and combined payload/index byte budgets are independent of package
inflation limits and are not whole-process memory quotas.
The destination parent must belong to the calling UID and deny group/other
writes. Stage and destination modes are 0700; files are 0600. The parent ACL and
same-UID processes remain trusted, not sanitized. A protected holder descriptor
anchors publication and plaintext cleanup. Atomic publication does not promise
stable textual paths under hostile ancestor movement or crash durability.

## Executing carried code (reproduction)

The reproduction feature (`docs/reproduction-design.md`) is the one place docxplus can
run code a document carries. Its safety rests on two invariants:

1. **The document is inert data.** No read, parse, render, `validate`, `extract`,
   `verify_provenance`, or `verify_reproduction` path executes a byte. Only
   `reproduce(..., allow_execution=True)` does, and only on an explicit call.
2. **Execution requires confinement.** Missing Seatbelt on macOS or bubblewrap on
   Linux raises `ReproError`; there is no raw/unshare-only fallback. Private scratch,
   scrubbed environment, stdin closure and a wall-clock deadline limit exposure.
   Linux uses private user/PID/network namespaces, private procfs, a new session
   and a read-only host root. The carried command is private
   PID 1, `--` ends bubblewrap's own options so a command cannot supply
   `--share-net`/`--bind`, and the reported init is pinned with a pidfd. Success,
   timeout and cleanup all kill that leader and wait up to five additional seconds
   for pidfd exit readiness, after kernel namespace teardown. A failed join raises
   instead of collecting outputs; absent pidfd support refuses execution. The
   launch group is then killed/reaped. Per-process limits are not aggregate
   CPU/memory quotas.
   A cleanup-join error is not proof of completed teardown; external disposable
   isolation must remain in place when that completion cannot be observed.

The read-only host root is still **readable**. Scrubbing environment variables and
using `HOME=/nonexistent` does not hide host credential files. These controls are
not hermetic isolation or a microVM. For untrusted code use a disposable isolated
environment with no secrets. The macOS Seatbelt profile requests write/network
confinement and process-fork denial; it provides neither Linux's private PID/proc
view nor pidfd custody, so recipes needing subprocesses require Linux. Native macOS
enforcement remains unqualified here. Capability availability and production Linux
custody need fresh platform qualification, not inference.
Output collection uses deadlines and nofollow regular-file checks; every output
must be new/content-changed. Signed `output_digest_scheme` must equal
`docxplus-output-tree-v3-blake2b-256`; missing/old schemes refuse before execution.
`match` requires both `source_match` and selected-output digest equality;
`toolchain_match` is reported separately. A signature authenticates a claim only.

Release validation normally also requires Docker's outer proc/kernel path masks;
incompatible nested private-proc mounts refuse. The validate-only option
`--allow-unmasked-procfs-for-daemon ID` is an explicit, provision-bound exception
for an operator-controlled isolated Linux rootless VM. It must match the currently
verified daemon ID, with Linux and `name=rootless` eligibility checked before
compute creation. It adds container-local `systempaths=unconfined`, removing
Docker's outer proc **and kernel-path** masking/read-only defenses, including some
read restrictions. It does not weaken the production sandbox or preserve those
removed outer defenses by implication. UID 1000, zero capabilities,
no-new-privileges, read-only root/source/runtime, network denial, private PID/proc,
mount/credential restrictions, resource/TTL and source/image/reap custody remain
mandatory. No automatic fallback or host/global policy changes are permitted.
The actual guest receipt must prove kernel read-only `/sys`, non-mutating
write-open refusals for representative proc/kernel controls (EACCES/EPERM/EROFS,
or ENOENT where the interface is absent), ancestor PID/proc invisibility and
signal denial, writable project/scratch controls and detached-child teardown.
Ancestor descriptors are not inherited by construction (close-on-exec and no
descriptor passing), which is a code fact rather than receipt evidence.
Passing these probes qualifies only the recorded environment, not arbitrary
kernels, all removed read protections, macOS sandbox guarantees or payload survival
through Office editing. Operator procedure and evidence fields are in
[`scripts/README.md`](../scripts/README.md#release-validation).

## Against a well-resourced adversary

The controls above assume an opponent who inspects, tampers, and forges. A state-scale
opponent additionally *collects at scale, waits, and compels*. Four boundaries follow
from that and none of them is closed by the format alone.

**Harvest now, decrypt later.** Classical Ed25519/X25519-DXE2 documents do not
claim post-quantum protection. Both profiles can instead use genuine provider
ML-KEM-768 with X25519/HKDF-SHA384 (DXE3 recipients), and ML-DSA-65 with Ed25519
(manifest, co-signature and log signing) through `cryptography >= 50`.
Both signatures are required under a pin of the entire composite public identity.
Portable `DXHK` private keys carry a version and signing/recipient suite tag, exact
seed/public lengths and checked derived public halves. Mixed recipient families,
wrong-suite, ambiguous and simulated keys refuse without a classical fallback.
[NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) and
[FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) standardize the components; they
do not certify docxplus or prove this hybrid construction. Generate fresh keys and
redistribute full-key pins for simulated material. Rebuild and re-sign trusted
format-2 inputs; no insecure legacy surface verifier or version-field rewrite.

**Recipient count is observable, identities are not.** A DXE2 envelope carries one
wrapped content key per recipient and records the number as a field, so the count is
recoverable both from that field and from the envelope's length. The manifest goes to
some trouble to record neither identities nor number, and that intent is only half met
without addressing the envelope: for the blind-review packet this lineage exists to
serve, "sealed to three people" is itself information about the review. Pass
`--pad-recipients N` (or `recipient_padding=N`) to raise the slot count to a fixed
bucket by wrapping the content key to freshly generated public keys whose private
halves are discarded before the call returns. A padded slot is a genuine wrap,
indistinguishable from a real one and decryptable by nobody, and slots are shuffled so
position does not give the padding away. The default is unpadded and therefore leaks
the count; the leak is pinned by `tests/test_redteam_round13.py` so it stays a stated
default rather than becoming an unexamined one.

**Using the tool is not deniable.** Deniability covers the *second frame* of a sealed
module, never the fact that a docxplus document is one: `intelligence/manifest.json`
is a plainly named part, by design, because the manifest must be authoritative. An
opponent who treats possession of the format as itself significant is not addressed
here and cannot be.

**Coercion beats the decoy.** The decoy lineage answers an inspector. It does not
answer an opponent who knows the scheme, knows a second frame is always present, and
can compel the production of a second password indefinitely. That is a property of
rubber-hose cryptanalysis rather than a gap in the implementation, but a reader
choosing this lineage under that threat should choose it knowingly.

## Boundaries the trust model does not draw

Three follow from the design rather than from any adversary, and are recorded because
a reader will otherwise assume the mechanism exists.

**There is no key lifecycle.** No revocation, no expiry, no rotation, no notion of a
key having been trusted at one time and not another. A signing key that is later
compromised does not invalidate anything it signed, and there is no in-band way to say
so. Trust is pinned per verification by the caller passing `--expected-key`, so
revocation is whatever the caller's own key distribution does — which is a real answer,
but it is the caller's answer and not the format's.

**The signature binds no trusted time.** The canonical body covers version, module
records, Merkle root, surface digest, primary scheme and co-signer identities/schemes.
It binds no trusted timestamp, so a document alone cannot establish pre-compromise signing.
A pinned signed log head authenticates inclusion of the complete canonical attestation
claim, not independent time or execution. It cannot by itself establish that a
document predates compromise; external retained checkpoints/witnesses are required.

**Key-family selection is not algorithm negotiation.** Strict key framing chooses
Ed25519 or Ed25519 + ML-DSA-65. The authenticated primary/co-signer algorithm
labels must match the parsed key family; they do not select an attacker-chosen
verifier or authorize a classical fallback. Every co-signer identity and scheme
is declared before signing; only signature values are omitted from that body.
An authenticity policy still needs explicit caller-pinned identities.

**Publication is per entry, not a transaction.** Keys and shares default to exclusive
private creation. Plaintext replacement uses a complete private sibling temporary
and atomic directory-entry replacement rather than following/truncating an old
inode. Related keys, shares and dual-name documents preflight and stage before
publication; this is not cross-file crash atomicity.

## Threat-model summary

docxplus raises the bar from "bytes anyone can read" to "authenticated,
integrity-checked, optionally-encrypted modules bound by a signed manifest, with a
concealment option" — while never sacrificing the one property that makes the file
useful in the wild: it stays an ordinary, openable `.docx`.

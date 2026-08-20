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
| Manifest + package integrity | Ed25519 signature over the canonical body binds the Merkle root over all modules **and** a `surface_digest` over the *entire package*: every part and its bytes, the whole content-type map, and every relationship edge | binding filenames is not enough — OPC resolves the rendered part through the officeDocument *relationship*, so a name-scoped digest let an attacker repoint it and keep a valid verdict |
| Authenticity (only with a pinned key) | `verify_provenance(expected_public_key=...)` / `signature_status(expected_public_key=...)` compare the signer to a caller-trusted key in constant time | the manifest's embedded key is **self-asserted**; without pinning, a forger can sign a fabricated document with their own key and it reads as self-consistent — never as authentic |
| Metadata minimalism | the manifest records only sealing mode (+ threshold `k`/`n`); never recipient identities/counts or a decoy marker | blind-review packets do not leak reviewers |
| Untrusted-input intake | zip-bomb caps (per-entry/total/ratio) on OPC read; project tar.gz caps + `data` filter + link/traversal rejection; nested-depth cap; KDF work-factor **and memory** caps (scrypt bounds `128·N·r`, not merely `N`) | report §14.3, §6.1 |
| Openability preserved | encryption is payload-level, never whole-package | report §6.3, §14.3 |
| Premium media provenance | steganographer backend BLAKE3-hashes and Ed25519-signs the embedded packet | steganographer docs |
| Share tampering detection | threshold shares carry VSS commitment tags; the signed manifest records that they are required, so a header-stripped share is refused rather than silently reconstructed | Feldman VSS; the tag binds only if the verifier demands it |
| Attestation log authenticity | a signed tree head over `(log_size, root_hash)`, domain-separated from the manifest signature, anchors the transparency log | a hash chain proves self-consistency, never authenticity |
| Project-payload containment | packing refuses symlinks, so a tree cannot smuggle out-of-tree files into a document by reference; unpacking rejects link members and path traversal | the pack side was the open half: `is_file()` follows links, embedding the target's bytes |
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
  converse is not offered either: the shipped detector proves presence, never absence
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
* **Deniability is against inspection, not proof.** A decoy module is structurally
  identical to an ordinary password module — same manifest record, same two-frame
  layout, same envelope format, and the second frame is undecryptable chaff when
  there is no decoy. Size does not separate them either: the chaff frame is randomly
  sized, so no observed module size implies a particular payload length, and a
  decoy's size falls inside the range an ordinary module already spans. **Nor does
  timing**: every frame is attempted whichever one matches, so opening with the real
  password, the cover password, or a wrong one costs the same. Returning at the first
  success made the real payload in frame 1 cost one key derivation and the cover story
  in frame 2 cost two, which measured as 154 ms against 307 ms — an adversary who had
  compelled a password could time the extraction and learn whether they had been given
  the whole story. Nothing in
  the file *reveals* a hidden payload. Note the precise scope — this is
  indistinguishability to an inspector holding one document and not knowing the
  payload lengths, which is the stated threat; it is not a proof of
  indistinguishability against a distributional attack, and the format does not
  claim one. But an adversary who knows the scheme knows a second
  frame is always present and cannot be compelled to accept it as chaff. This is
  layered access with a cover story, not cryptographic proof of non-existence.
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
* **Steganalysis.** The `stego_media` channel changes pixel LSBs, and that is
  detectable — treat it as obfuscation, never secrecy. `steg_bridge.py` ships the
  chi-squared attack on LSB replacement in pure Python so a carrier can always be
  assessed, with a prefix sweep that also localises a partially-filled carrier the
  whole-image statistic would miss. The optional steganographer backend's `analyze`
  command adds further tests when it is installed. Check your own carriers: the
  point of shipping the attack is that you should run it before an adversary does.

* **Carried project trees.** `unpack-project` writes plain files and directories and
  nothing else: links, FIFOs, and device nodes are refused by a positive check rather
  than a list of rejected types, and permission bits are clamped to 0644/0755 so
  setuid and setgid never survive. None of this depends on the interpreter. It used
  to — extraction was `extractall(filter="data")` with a fallback to an unfiltered
  `extractall` on Python below 3.12, which `requires-python = ">=3.10"` makes a
  supported configuration, and on which a payload carrying `run.sh` at mode 04755
  extracted with the setuid bit intact.

  **The attack's own boundary is part of the model.** Chi-squared PoV analysis keys
  on the histogram flattening a *uniform* bit stream causes. A sealed module is
  ciphertext and is therefore the maximally detectable case (p ≈ 1 at full fill); an
  unsealed low-entropy payload — plaintext, a constant fill, a structured record —
  is not detected at any fill rate and reports the same p ≈ 0 as an untouched
  carrier. `analyze-carrier` can establish that a carrier *is* embedded. It cannot
  establish that one is not, and no verdict from it should be read that way. This is
  measured behaviour, pinned by `tests/test_steganalysis_bounds.py`.

## Executing carried code (reproduction)

The reproduction feature (`docs/reproduction-design.md`) is the one place docxplus can
run code a document carries. Its safety rests on two invariants:

1. **The document is inert data.** No read, parse, render, `validate`, `extract`,
   `verify_provenance`, or `verify_reproduction` path executes a byte. Only
   `reproduce(..., allow_execution=True)` does, and only on an explicit call.
2. **Execution is confined (best-effort).** The re-run happens in a scrubbed
   environment (no host credentials, `HOME=/nonexistent`, stdin closed), in its own
   process group so a timeout reaps orphaned grandchildren, under
   CPU/address-space/process-count/**file-size** limits and a clamped wall-clock
   timeout. The network is denied and **writes are confined to the project and temp
   directories** via a `sandbox-exec` seatbelt profile (macOS) or `bwrap` (Linux).

Honest residual risks, stated plainly: the sandbox is best-effort, not a microVM.
On macOS/Linux-with-bwrap writes are confined to the project+temp dirs and the
network is denied; on Linux with only `unshare -n` the network is denied but **writes
are not confined**; on any other platform there is **no** confinement and the caller
must supply their own jail. Resource limits are POSIX-only. A sandbox escape in the
OS primitive would defeat confinement. Reproduction is therefore a build-server /
disposable-VM activity a reader chooses, never a side effect of opening a file. A
digest match attests process, not validity: it proves the declared command produced
the sealed outputs on a matching toolchain — surfaced as `toolchain_match` — not that
the method is correct. The reproduction binds only genuinely *computed* outputs: a
declared output that is a carried input unchanged by the run is rejected.

## Against a well-resourced adversary

The controls above assume an opponent who inspects, tampers, and forges. A state-scale
opponent additionally *collects at scale, waits, and compels*. Four boundaries follow
from that and none of them is closed by the format alone.

**Harvest now, decrypt later.** Classical key exchange is X25519 and classical signatures are Ed25519.
Both fall to a cryptographically relevant quantum computer; AES-256-GCM does not, being
reduced by Grover to a still-adequate ~128-bit margin. A document sealed today under purely
classical asymmetric keys and collected today is readable by an opponent who acquires that capability
before the payload stops mattering. docxplus provides hybrid post-quantum cryptographic primitives
(`DXE3` hybrid KEM and dual-signing) in `crypto.py` combining classical algorithms with quantum-resistant
encapsulation and signing shims under HKDF-SHA384. The password
lineage is the classical symmetric alternative: content sealed under a high-entropy passphrase with
Argon2id never performs an asymmetric key exchange, inheriting the full symmetric margin.

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

**The signature binds no time.** The canonical body covers the version, the module
records, the Merkle root, and the surface digest. It carries no timestamp, so a
document alone cannot establish whether it was signed before or after a compromise.
That ordering is exactly what the transparency log supplies, which is the argument for
treating the log as part of the mechanism rather than as an optional extra: without it,
"signed by a key that was later revoked" is unanswerable from the file.

**Crypto agility is absent by construction.** The manifest declares its signature
algorithm and the verifier refuses any value it does not implement, but it never
*dispatches* on the field — selecting a verifier from an attacker-supplied algorithm
name is the JWT `alg`-confusion class. The field is also outside the signed body, so it
is unauthenticated: flipping it turns a valid document into a refused one, a nuisance
rather than a compromise. The consequence is that replacing Ed25519 means a format
version, not a negotiation.

## Threat-model summary

docxplus raises the bar from "bytes anyone can read" to "authenticated,
integrity-checked, optionally-encrypted modules bound by a signed manifest, with a
concealment option" — while never sacrificing the one property that makes the file
useful in the wild: it stays an ordinary, openable `.docx`.

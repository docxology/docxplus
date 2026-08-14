# DOCX+ Security Model

DOCX+ inherits the OOXML/ODF attack surface documented in
`docs/standards-report.md` (§6–§7) and adds an intelligence layer. This note states
what the format defends, what it deliberately does **not**, and the residual risks
an integrator must handle.

## What the format provides

| Property | Mechanism | Basis |
| --- | --- | --- |
| Payload confidentiality | AES-256-GCM over the payload; key from memory-hard **Argon2id** or **Scrypt** (default; PBKDF2-HMAC-SHA512 available), work factors capped on read | MS-OFFCRYPTO *agile* lineage (report §7.1); RFC 9106; OWASP-2023 |
| Payload integrity | GCM auth tag for plaintext; the manifest digest binds the **stored (ciphertext) bytes** and is checked before decryption | avoids the offline plaintext-confirmation oracle a plaintext digest would give |
| Context binding | the module **slot** is AAD in every AEAD operation | a ciphertext cannot be spliced into another slot |
| Manifest + surface integrity | Ed25519 signature over the canonical body binds the Merkle root over all modules **and** the digest of `word/document.xml` | signature covers both the module set and the visible text |
| Authenticity (only with a pinned key) | `verify_provenance(expected_public_key=...)` / `signature_status(expected_public_key=...)` compare the signer to a caller-trusted key in constant time | the manifest's embedded key is **self-asserted**; without pinning, a forger can sign a fabricated document with their own key and it reads as self-consistent — never as authentic |
| Metadata minimalism | the manifest records only sealing mode (+ threshold `k`/`n`); never recipient identities/counts or a decoy marker | blind-review packets do not leak reviewers |
| Untrusted-input intake | zip-bomb caps (per-entry/total/ratio) on OPC read; project tar.gz caps + `data` filter + link/traversal rejection; nested-depth cap; KDF work-factor cap | report §14.3, §6.1 |
| Openability preserved | encryption is payload-level, never whole-package | report §6.3, §14.3 |
| Premium media provenance | steganographer backend BLAKE3-hashes and Ed25519-signs the embedded packet | steganographer docs |

## What it deliberately does not do

* **It is not whole-document DRM.** The surface document is intentionally readable
  by anyone. Confidentiality applies only to modules marked encrypted. The Library
  of Congress deposit rule forbids access-controlling DRM on archival text (report
  §9); DOCX+ keeps the surface document clean by design.
* **The manifest is not hidden.** A `custom_xml`/`package_part` module is
  discoverable by anyone who opens the archive. Concealment (not just
  confidentiality) is only offered by the `stego_media` channel, and even there LSB
  stego is detectable by steganalysis — treat it as obfuscation, not secrecy.
* **Deniability is against inspection, not proof.** A decoy module is
  byte-indistinguishable from an ordinary password module (both carry two envelope
  frames; the second is chaff when there is no decoy), so nothing in the file
  *reveals* a hidden payload. But an adversary who knows the scheme knows a second
  frame is always present and cannot be compelled to accept it as chaff. This is
  layered access with a cover story, not cryptographic proof of non-existence.
* **Unsigned = no provenance.** Without a signature, an attacker who rewrites a
  module can also rewrite its digest; validation emits a loud WARNING for unsigned
  documents. Only a signed manifest makes the module set and surface text
  tamper-evident.
* **A signature proves the manifest, not the surface prose.** As the report notes
  (§6.1, §7), both OOXML and ODF have documented signature-spoofing classes; DOCX+
  signs its own manifest body, which does not attest the visible document text.

## Residual risks an integrator must handle (report §14.3)

* **Untrusted input.** Parsing an unknown `.docx` still exposes ZIP-bomb, Zip-Slip,
  XXE, and importer memory-safety risks. DOCX+'s reader uses `defusedxml` and never
  extracts to disk, but a full intake pipeline should still enforce inflate-ratio
  and entry-size caps, disable DTDs, and sandbox parsing.
* **Encryption oracle / password handling.** Passwords are used only for KDF; the
  GCM tag is the trust boundary, not the checksum. Do not treat a decrypt failure
  as anything but "wrong key or tampering".
* **Metadata leakage.** `docProps/core.xml` carries author/timestamps; scrub before
  release if that matters (report §14.4). The `metadata` channel deliberately
  *adds* named custom properties — do not put secrets there in cleartext.
* **Steganalysis.** The `stego_media` channel changes pixel LSBs; chi-squared and
  sample-pair analysis can flag it. The steganographer backend's own `analyze`
  command can be used to check detectability.

## Executing carried code (reproduction)

The reproduction feature (`docs/reproduction-design.md`) is the one place DOCX+ can
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

## Threat-model summary

DOCX+ raises the bar from "bytes anyone can read" to "authenticated,
integrity-checked, optionally-encrypted modules bound by a signed manifest, with a
concealment option" — while never sacrificing the one property that makes the file
useful in the wild: it stays an ordinary, openable `.docx`.

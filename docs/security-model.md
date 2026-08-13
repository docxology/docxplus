# DOCX+ Security Model

DOCX+ inherits the OOXML/ODF attack surface documented in
`docs/standards-report.md` (§6–§7) and adds an intelligence layer. This note states
what the format defends, what it deliberately does **not**, and the residual risks
an integrator must handle.

## What the format provides

| Property | Mechanism | Basis |
| --- | --- | --- |
| Payload confidentiality | AES-256-GCM over the payload; key from memory-hard **Scrypt** (default; PBKDF2-HMAC-SHA512 available), work factors capped on read | MS-OFFCRYPTO *agile* lineage (report §7.1); OWASP-2023 |
| Payload integrity | GCM auth tag for plaintext; the manifest digest binds the **stored (ciphertext) bytes** and is checked before decryption | avoids the offline plaintext-confirmation oracle a plaintext digest would give |
| Context binding | the module **slot** is AAD in every AEAD operation | a ciphertext cannot be spliced into another slot |
| Manifest + surface authenticity | Ed25519 signature over the canonical body, which binds the Merkle root over all modules **and** the digest of `word/document.xml` | signature covers both the module set and the visible text |
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

## Threat-model summary

DOCX+ raises the bar from "bytes anyone can read" to "authenticated,
integrity-checked, optionally-encrypted modules bound by a signed manifest, with a
concealment option" — while never sacrificing the one property that makes the file
useful in the wild: it stays an ordinary, openable `.docx`.

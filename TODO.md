# TODO — DOCX+

Registered next steps (present-state; no session logs).

## Shipped in v0.2
Typed payloads (bytes/text/json/**project**/**docxplus**), multi-recipient X25519
sealing, Shamir k-of-n threshold, decoy/plausible-deniability, matryoshka nesting,
and a signed Merkle provenance root. See `docs/cookbook.md` and `scripts/04_dossier.py`.

## Shipped in v0.3 (RedTeam hardening — `docs/redteam-audit.md`)
Memory-hard Scrypt KDF (default) with capped work factors; ciphertext-bound module
digests (no plaintext oracle); AAD slot binding; recipient-set and decoy metadata
no longer leak; signature binds the visible document text (`surface_digest`); Merkle
inclusion proofs; zip/tar decompression-bomb + traversal + symlink + nesting caps;
root-anchored reachability. 18 confirmed findings closed, each pinned by a test.

## Format
- [ ] Whole-package OPC digital signature alongside the manifest signature
      (Digital Signature Origin part), per standards-report §7.1.
- [ ] MCE `AlternateContent`/`Choice`/`Fallback` channel exercising an Ignorable
      extension namespace inside `document.xml` (standards-report §4.1).
- [ ] Detached co-signatures: multiple independent signers over one Merkle root.
- [ ] Redundant/spread media carriers (ECC across N images) for the polyglot carrier.
- [ ] ODT sibling profile using `META-INF/manifest.xml` directly (standards-report §2.2).

## Hardening
- [ ] Untrusted-input intake wrapper around the reader: inflate-ratio cap,
      per-entry size cap, Zip-Slip canonicalisation, DTD disabling, sandboxed parse
      (standards-report §14.3). `defusedxml`, no-disk-extraction, and the project
      unpack path-traversal guard are already in place.
- [ ] Steganalysis self-check via the steganographer `analyze` command.
- [ ] Argon2id KDF option alongside PBKDF2 for password sealing.

## Interop
- [ ] Validate produced documents against Office-o-tron and the ODF Toolkit
      validator in CI (standards-report §11.6).
- [ ] Headless LibreOffice convert-to-pdf smoke test to confirm openability.

## Packaging
- [ ] CI workflow (uv + pytest + coverage gate + ruff). Optional steganographer job.
- [ ] Publish flow (tag → Zenodo DOI) if the repo goes public.

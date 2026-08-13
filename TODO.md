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

## Shipped in v0.4-v0.5
Reproduction attestation (verify_reproduction / opt-in sandboxed reproduce), the
trust-anchor fix (expected_public_key pinning), detached co-signatures (surface-bound),
hardened untrusted-intake `intake.safe_open` (external rels / macros / altChunk +
entry/collision caps), and redundant media carriers. See docs/redteam-audit.md v0.4-v0.5.

## Shipped in v0.6
MCE `AlternateContent`/`Choice`/`Fallback` channel (`src/channels/mce.py`), ODT sibling
profile using `META-INF/manifest.xml` directly (`src/odt.py`), Verifiable Secret Sharing
(VSS) integrity tags (`src/shamir.py`), Argon2id memory-hard KDF (`src/crypto.py`),
cryptographic transparency log (`src/transparency.py`), CI workflow (`.github/workflows/ci.yml`),
and linker-scrubbed sandbox execution. See `docs/redteam-audit.md` v0.6.

## Format
- [ ] Whole-package OPC digital signature alongside the manifest signature
      (Digital Signature Origin part), per standards-report §7.1.
- [x] MCE `AlternateContent`/`Choice`/`Fallback` channel exercising an Ignorable
      extension namespace inside `document.xml` (standards-report §4.1).
- [x] ODT sibling profile using `META-INF/manifest.xml` directly (standards-report §2.2).

## Hardening
- [ ] Steganalysis self-check via the steganographer `analyze` command.
- [x] Argon2id KDF option alongside PBKDF2 for password sealing.

## Interop
- [ ] Validate produced documents against Office-o-tron and the ODF Toolkit
      validator in CI (standards-report §11.6).
- [x] Headless LibreOffice convert-to-pdf smoke test to confirm openability.

## Packaging
- [x] CI workflow (uv + pytest + coverage gate + ruff). Optional steganographer job.
- [ ] Publish flow (tag → Zenodo DOI) if the repo goes public.

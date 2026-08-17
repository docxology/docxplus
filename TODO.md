# TODO — docxplus

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
MCE `AlternateContent`/`Choice`/`Fallback` channel (`src/docxplus/channels/mce.py`), ODT sibling
profile using `META-INF/manifest.xml` directly (`src/docxplus/odt.py`), Verifiable Secret Sharing
(VSS) integrity tags (`src/docxplus/shamir.py`), Argon2id memory-hard KDF (`src/docxplus/crypto.py`),
cryptographic transparency log (`src/docxplus/transparency.py`), CI workflow (`.github/workflows/ci.yml`),
and linker-scrubbed sandbox execution. See `docs/redteam-audit.md` v0.6.

## Known limitations at v1.0.0

Verified, documented, and deliberately not blocking. Each is a narrowing of a stated
guarantee rather than a false claim.

- [ ] No post-quantum or hybrid suite. X25519 and Ed25519 both fall to a CRQC, so a
      sealed document collected today is readable, and its signature forgeable, from
      whenever that capability arrives. Adding a hybrid suite is a format change
      rather than a flag. Stated in `docs/security-model.md`.
- [ ] The recipient-slot count is unpadded by default, so an envelope's length reveals
      how many recipients a module was sealed to. `--pad-recipients N` closes it;
      making padding the default would change every existing envelope's size.
- [ ] No key revocation, expiry, or rotation, and the signed body carries no
      timestamp. Signing order comes from the transparency log or from nowhere.
- [ ] The `metadata` channel retypes a pre-existing custom document property to
      `vt:lpwstr` rather than refusing the collision.
- [ ] The shipped chi-squared steganalysis does not detect a low-entropy payload at
      any fill rate. The attack keys on the uniformity a random payload imposes, so
      sealed modules are maximally detectable and unsealed structured ones are
      invisible to it. Documented in `docs/security-model.md`, `docs/channels.md`
      and `docs/cli.md`, and pinned by `tests/test_steganalysis_bounds.py`. A
      complementary LSB-plane structure test would close the regime, but shipping an
      uncalibrated estimator is the mistake sample-pair analysis was withdrawn for.
- [ ] A decoy module's stored size is deterministic given its two payload lengths,
      while an ordinary sealed module's is randomised by chaff. The ranges overlap,
      so a single observation separates nothing and the documented threat (inspection
      of one document, payload lengths unknown) holds. Equalising the two
      distributions would let the stronger claim be made; until then the docs claim
      only structural indistinguishability.
- [ ] The prefix sweep's `embedded_fraction_estimate` is quantised to the step size
      and biased upward; it localises a payload but should not be read as a
      calibrated extent.
- [ ] `follow_symlinks=True` drops symlinked *directories* and their contents; only
      symlinked files are dereferenced. The default (refusal) is unaffected.
- [ ] `OdtPlusBuilder` cannot wrap an existing `.odt`; it always synthesises a base
      package, where `DocxPlusBuilder` accepts `base_package`.
- [ ] `extract_project` on the ODT reader lacks the OPC reader's payload-type guard.
- [ ] `pack_project` accepts trees whose inflated size `unpack_project` will refuse,
      and the cap is not caller-adjustable.
- [ ] Extraction does not restore hard links as links, and `docs/format-spec.md` §8.1
      states the contract for files and directories only.
- [ ] An unsigned package passes `validate`; only `docxplus verify` distinguishes
      signed from unsigned, and it is the command a release process should run.

## Format
- [x] The `validate.py` guard for whole-package OPC signatures:
      `check_opc_signature_coverage` refuses a package whose OPC signature
      reference set omits the intelligence manifest or any part it names. Written
      before signing support on purpose — it is what stops the feature becoming a
      trust-laundering surface.
- [ ] Whole-package OPC digital signature *production* (Digital Signature Origin
      part), per standards-report §8.1. **Assessed, not scheduled** — see
      `docs/opc-signatures.md`. Blocked on a C14N implementation and an X.509/PKI
      decision (Office will not verify Ed25519). The guard above already holds the
      invariant any implementation must satisfy.
- [x] ODT intelligence layer: `src/docxplus/odt_container.py` gives the sibling profile the
      full Intelligence Contract, sharing sealing/unsealing with the OPC path.
- [ ] `metadata` and `stego_media` channel analogues for ODT (`meta.xml`
      user-defined fields; `Pictures/`). The package-entry channel is implemented;
      these two are not, and the docs say so.
- [x] An ODT equivalent of `intake.safe_open`: `intake.scan_odt` /
      `safe_open_odt` flag ODF Basic/Scripts containers, off-package `xlink:href`
      targets, and embedded objects. CLI: `docxplus odt-scan [--strict]`.
- [x] MCE `AlternateContent`/`Choice`/`Fallback` channel exercising an Ignorable
      extension namespace inside `document.xml` (standards-report §4.1).
- [x] ODT sibling profile using `META-INF/manifest.xml` directly (standards-report §2.2).

## Hardening
- [x] Steganalysis self-check via the steganographer `analyze` command.
- [x] Argon2id KDF option alongside PBKDF2 for password sealing.
- [x] Pure-Python chi-squared LSB steganalysis with a prefix sweep that localizes
      sequential embedding — no external toolchain required (`steg_bridge.py`).
- [ ] Calibrated sample-pair analysis (SPA) over natural-image carriers. Built and
      measured in v0.6.2, then withdrawn: monotonic in the true embedding rate but
      mis-scaled by ~10× and carrier-dependent, so it cannot honestly be reported
      as an embedding-rate estimate. Negative result recorded in
      `docs/redteam-audit.md`.

## Interop
- [ ] Validate produced documents against Office-o-tron and the ODF Toolkit
      validator in CI (standards-report §11.6).
- [x] Headless LibreOffice convert-to-pdf smoke test to confirm openability.

## Packaging
- [x] CI workflow (uv + pytest + coverage gate + ruff). Optional steganographer job.
- [ ] Publish flow (tag → Zenodo DOI) if the repo goes public.

## Shipped in v0.7.0 (project round-trip fidelity, both profiles)
`scripts/06_project_roundtrip.py` carries a real project into a `.docx` and a `.odt`,
validates both, extracts both, and diffs against the original by content, mode, and
directory set — 18 invariants including cross-profile nesting and byte-identical
payload parity. Building it surfaced four findings: `pack_project` silently
dereferenced symlinks (embedding whatever they pointed at), discarded the executable
bit, dropped empty directories, and was **never deterministic** because
`tar.gzip_mtime = 0` set a non-existent attribute. ODT gained `add_project`,
`add_nested`, `verify_reproduction`, and `reproduce`; `open_document` dispatches on
the container rather than the caller. See `docs/redteam-audit.md` v0.7.0 and
format-spec §8.1.

## Shipped in v0.6.3 (ODT intelligence parity + signature-coverage guard)
`src/docxplus/odt_container.py` gives the ODT sibling the full Intelligence Contract — typed
payloads, all four sealing lineages, Merkle root, ODF surface digest, Ed25519
signature and co-signatures, inclusion proofs — reusing `container.seal_module` and
`DocxPlusReader._unseal` so the two profiles cannot drift. `validate.validate_odt_bytes`
checks both contracts, and `check_opc_signature_coverage` refuses an OPC signature
that does not cover the payloads. Six new CLI commands: `odt-build`, `odt-inspect`,
`odt-extract`, `odt-validate`, `analyze-carrier` (the shipped chi-squared detector,
previously reachable only from Python), and `transparency-append` (the producer
`verify-transparency` had no counterpart for). See `docs/redteam-audit.md` v0.6.3.

## Shipped in v0.6.2 (Transparency anchoring + red-team pass)
Signed tree heads (`TransparencyLog.signed_tree_head` / `verify_signed_tree_head`)
give the attestation log a trust anchor — a hash chain alone only proves
self-consistency, and its tip is editable in place. New `docxplus
verify-transparency` CLI verifies the chain, the STH under a pinned signer, a
pinned Merkle root, and per-entry inclusion proofs, failing closed on each and
reporting an unanchored log as UNAUTHENTICATED. Pure-Python chi-squared
steganalysis with prefix-sweep localization. Seven red-team findings closed,
including two incomplete earlier fixes (scrypt memory ceiling, VSS downgrade).
See `docs/redteam-audit.md` v0.6.2.

## Shipped in v0.6.1 (Defensive Recommendations Hardening)
- Expanded `surface_digest` to cover all WordprocessingML story parts (`word/document.xml`, `header*.xml`, `footer*.xml`, `footnotes*.xml`, `endnotes*.xml`, `comments*.xml`).
- Added decompression bomb guard checks to `OdtPackage.from_bytes`.
- Bound `TransparencyLog` timestamps to `SOURCE_DATE_EPOCH` and explicit timestamp overrides for reproducible determinism.
- Scrubbed `PYTHONPATH`, `PYTHONHOME`, `TMPDIR`, `TEMP`, `TMP` in `reproduce._scrubbed_env()`.

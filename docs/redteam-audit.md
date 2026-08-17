# RedTeam Audit

Every confirmed adversarial finding and its fix, newest cycle last. Each is pinned by a
regression test. Negative results — work built, measured, and withdrawn — are recorded
here too, because an unshipped estimator is a result.

## v0.2 → v0.3

An adversarial review of docxplus v0.2 ran five parallel finder dimensions (crypto,
deniability/metadata-leak, parsing/resource-safety, format-conformance, overclaims)
with an independent verification pass that reproduced each finding against the live
tree. Confirmed findings and their resolution in v0.3:

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | critical | Manifest announced `mode:"decoy"`, destroying deniability | Decoy is now an ordinary `password` module; every password module carries a chaff second frame, so it is byte-indistinguishable |
| 2 | high | Manifest stored an unkeyed **plaintext** digest of encrypted modules — an offline confirmation oracle | Digest now binds the **stored ciphertext** bytes; plaintext integrity is the GCM tag |
| 3 | high | `recipients` sealing wrote recipient X25519 pubkeys + count into the manifest | Manifest records only `{mode: recipients}`; the DXE2 envelope carries what extraction needs |
| 4 | high | Zip-Slip guard used `str.startswith`, allowing sibling-dir escape | Containment via `Path.is_relative_to` |
| 5 | high | `tar.extractall` unfiltered — symlink escape past the lexical pre-scan | Reject link members + `filter="data"` (3.12+) |
| 6 | high | Project tar.gz had no size/ratio cap (decompression bomb) | Per-total uncompressed cap enforced before extract |
| 7 | high | OPC zip read buffered every entry with no caps (zip bomb) | Per-entry / total / inflate-ratio caps in `read_package` |
| 8 | high | Signature did not bind the visible document text | `surface_digest` of `word/document.xml` folded into the signed body; `verify_provenance` checks it |
| 9 | medium | Unsigned packages are forgeable | Inherent without a signature; validation now emits a loud WARNING and the model documents it |
| 10 | medium | Attacker-controlled KDF work factor → DoS | Scrypt `N ≤ 2^21`, PBKDF2 `≤ 5M` enforced on read |
| 11 | medium | Decoy `DXD1` magic + length betrayed the second envelope | Removed; self-delimiting frames with no magic, uniform 2-frame layout |
| 12 | medium | Nested `docxplus` opening had no depth cap | `MAX_NEST_DEPTH` tracked across the chain |
| 13 | medium | Reachability check was not root-anchored (orphan chains passed) | Root-anchored BFS from package relationships |
| 14 | medium | Docs described PBKDF2/old envelope layout | Spec/security-model/README updated to Scrypt + KDF-tagged envelope |
| 15 | low | Shamir `combine` does no share verification | Fails closed via the AEAD tag (wrong key → GCM failure); VSS is future work |
| 16 | low | Merkle root exposed no inclusion proofs (redundant with signed list) | Added `inclusion_proof` / `verify_inclusion` |
| 17 | low | Stored `merkle_root` was never verified (inert) | Validation recomputes and checks it |
| 18 | low | Cookbook referenced nonexistent API (`extract_threshold`, `redundancy=`) | Cookbook corrected; redundant media marked roadmap |

Each fix is pinned by a regression test in `tests/test_hardening.py`, so a
reintroduced defect fails the suite. The adversarial method — find, then
independently reproduce before believing — is itself the deliverable: green tests
are necessary, not sufficient, and every claim here traces to a reproduced defect.

## v0.4 — reproduction/execution surface (11 confirmed)

A second RedTeam pass (four dimensions + independent verification) attacked the new
reproduction attestation and sandbox. Confirmed findings and their resolution:

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | Sandbox denied only the network; the reproduce command could write anywhere the user can | macOS seatbelt / Linux `bwrap` now confine writes to the project + temp dirs; honest per-platform limits documented |
| 2 | high | **No trust anchor** — a forger signs a fabricated document with their own key and it reads as "valid"/"authentic" | `verify_provenance`/`signature_status`/`verify_reproduction` take `expected_public_key` (constant-time); without it the verdict is "self-consistent, self-asserted signer", never "authentic". `signer()` exposes the key |
| 3 | high | An attestation could bind a carried **input** (a source file) instead of a computed product | outputs are snapshotted before the run; a digested file unchanged by the run is rejected |
| 4 | medium | Author-controlled timeout was uncapped (hang) | clamped to `MAX_REPRO_SECONDS`; stdin closed |
| 5 | medium | Timeout reaped only the direct child; orphans survived | child runs in its own session; the whole process group is killed |
| 6 | medium | Output `read_bytes()` pulled attacker-sized files into the parent | streamed in chunks with a per-file size ceiling; child `RLIMIT_FSIZE` set |
| 7 | medium | `verify_reproduction` reported `signed:true` without binding the actual carried bytes | it now recomputes the stored payload digest and only reports `verified` when the signature holds AND the bytes are intact |
| 8 | medium | Toolchain mismatch was not surfaced in the reproduce verdict | `reproduce()` returns an explicit `toolchain_match` |
| 9 | medium | A literal declared output matching nothing was silently dropped | a non-wildcard output producing no file is now an error |
| 10 | low | No confinement on non-POSIX platforms | documented explicitly; the caller must supply a jail |
| 11 | low | `verify_reproduction` surfaced an unbound digest on unsigned docs | the digest/command are nested under `unverified_attestation` until `verified` |

One verifier agent was interrupted by an upstream cyber-safeguard false positive; the
other three dimensions verified fully. Every fix above is pinned by a test in
`tests/test_reproduce.py` or `tests/test_hardening.py`.

## v0.5 — co-signatures, intake, redundant media (8 confirmed)

A RedTeam pass over the three new features confirmed 8 findings, all closed and
pinned (`tests/test_v5_features.py`):

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | Co-signatures/`cosigners()` did not bind the visible text — editing the paragraphs left co-signers "valid" | `cosigners()` is surface-bound (returns `[]` on a surface-digest mismatch); the primary-signer branch of `verify_cosigners` now gates on `verify_provenance()` |
| 2 | high | `altChunk` intake detection scanned only `.xml`-named parts — evadable by a non-`.xml` main-document part | detection is by resolved content type and XML parsing, not filename extension |
| 3 | medium | `altChunk` substring match false-positived on benign prose | matches the `altChunk` element in the WordprocessingML namespace via `defusedxml`, not a raw substring |
| 4 | medium | Macro filename match was case-sensitive vs case-insensitive OPC part names | case-folded match + flag by the `vbaProject` relationship type |
| 5 | medium | `read_package` materialized all entries with no count cap | `MAX_ENTRIES` enforced before any part is read |
| 6 | medium | Duplicate guard missed path-normalization/case collisions (silent part overwrite) | rejects any entries that collapse to the same normalized+casefolded part name |
| 7 | low | `verify_cosigners([])` passed vacuously | an empty expected-key policy is rejected |
| 8 | low | External-relationship `TargetMode` matched case-sensitively | case-folded comparison |

One finder agent was interrupted by the same upstream cyber-safeguard false positive
(redundant-media); its integrity concern was pre-empted independently — extraction
returns the replica whose bytes match the module digest.

## v0.6 — MCE channel, ODT profile, VSS share verification, sandbox linkers (6 confirmed)

An adversarial pass over the v0.6 extensions confirmed and resolved 6 findings:

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | Sandbox environment inherited dangerous dynamic linker variables (`DYLD_INSERT_LIBRARIES`, `LD_PRELOAD`) | Explicitly scrubbed in `_scrubbed_env()` before child execution |
| 2 | high | Shamir threshold shares lacked polynomial/share tampering detection before reconstruction attempt | Added Verifiable Secret Sharing (VSS) tagged shares with cryptographic commitment verification (`verify_share`) in `src/docxplus/shamir.py` |
| 3 | medium | MCE `<mc:Choice>` injection lacked namespace declaration verification in root element | Root `document.xml` parsing dynamically provisions `xmlns:mc` and `mc:Ignorable` namespaces if absent |
| 4 | medium | ODT package builder did not guarantee `mimetype` first and uncompressed (ZIP_STORED) | `OdtPackage.to_bytes()` explicitly emits uncompressed `mimetype` as byte-exact first ZIP record |
| 5 | low | MCE payload extraction did not handle malformed/missing XML gracefully | Wrapped in safe XML parser with explicit `ValueError` fail-closed semantics |
| 6 | low | Headless interop tests lacked graceful skipping when LibreOffice binary is absent | Added `@pytest.mark.skipif` for headless convert tests in `tests/test_interop.py` |

## v0.6.1 — Surface digest, ODT bomb defense, Transparency determinism, Sandbox isolation (4 confirmed)

A hardening pass addressing defensive recommendations closed 4 findings:

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | medium | Surface digest bound only `word/document.xml`, omitting headers/footers/footnotes/endnotes/comments | `_compute_surface_digest` deterministically binds all WordprocessingML story parts in sorted order |
| 2 | low | ODT package parser did not enforce decompression bomb guards | `OdtPackage.from_bytes` now routes through `_guard_zip_bomb` checks |
| 3 | low | `TransparencyLog.append` used unseeded `time.time()` | Added `SOURCE_DATE_EPOCH` env check and optional explicit `timestamp` parameter |
| 4 | low | Sandbox environment did not scrub `PYTHONPATH`, `PYTHONHOME`, `TMPDIR` | Explicitly stripped and clamped in `_scrubbed_env()` |

## v0.6.2 — Transparency anchoring, ODT intake parity, VSS downgrade, KDF and sandbox ceilings (7 confirmed)

This pass audited the modules named in the v0.6.1 handoff — `channels/mce.py`,
`odt.py`, `shamir.py`, `crypto.py`, `reproduce.py` — plus the transparency log, and
reproduced every finding against the live tree before fixing it. Two of the seven
are **incomplete earlier fixes**: v0.3 #10 (KDF work-factor DoS) and v0.6 #2 (share
tampering) were both closed in a way that left the boundary reachable.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | Scrypt's work-factor ceiling bounded `N` but not memory. Because the footprint is `128·N·r` and `r ≤ 64` was permitted, an envelope declaring `N=2^21, r=64` forces a **16 GiB** allocation on the reader — 64× the 256 MiB ceiling Argon2id enforces. The v0.3 #10 fix was incomplete. | `MAX_SCRYPT_MEMORY_BYTES` (256 MiB) bounds the `128·N·r` product, aligning scrypt with the Argon2id ceiling |
| 2 | high | VSS integrity was bypassable by **format downgrade**: stripping the 34-byte header off a tampered verifiable share yields a legacy `x‖payload` share, which `combine` accepted, silently reconstructing a wrong secret. Separately, `container.py` never passed `verifiable=True`, so no shipped document ever carried VSS shares — the v0.6 #2 fix was inert. | `combine(..., require_verifiable=True)` refuses unauthenticated shares; the builder now issues VSS shares and records `vss: true` in the **signed** manifest, which the reader enforces on extract |
| 3 | medium | The macOS seatbelt profile interpolated the project path into a quoted SBPL literal. A directory named `x") (allow network*) (subpath "/` closes the literal and appends rules — silently restoring the network the profile exists to deny | `_sandbox_wrap` refuses to build a profile when the project or temp path contains `"`, `\`, newline, or NUL (rejection, not escaping — a hard refusal cannot be defeated by a quoting subtlety) |
| 4 | medium | `OdtPackage.from_bytes` enforced only the decompression-bomb cap: no entry-count cap and no path-traversal rejection, so the ODT front door was weaker than the OPC one it mirrors | Entry count capped at `MAX_ENTRIES` and traversal/absolute/Windows-style names rejected via `_reject_unsafe_entry`, reaching parity with `read_package` |
| 5 | medium | `EncryptedPayload.from_bytes` sliced without bounds checks: truncated envelopes raised `IndexError` (not the `ValueError` callers filter on), and a header declaring a 200-byte salt over a 4-byte remainder parsed "successfully" into a short salt | Every field is length-checked before it is read; all malformed envelopes raise `ValueError` |
| 6 | low | Shamir share formats were told apart by sniffing for `0xFF`, but `n=255` mints a legacy share whose first byte *is* `0xFF`. With a secret ≥ 33 bytes such a share was misread as VSS and rejected as "tampered" when nothing had touched it | `MAX_X = 254` reserves `0xFF` for the magic, making the two formats unambiguous |
| 7 | low | ODT archives used a hand-written `2026-01-01` DOS timestamp and set no permission bits, contradicting the repository's stated determinism invariant (`1980-01-01`, as `opc.py` uses) and letting mode bits vary by platform. A parsed-then-rebuilt package also listed `mimetype` and the manifest itself as manifest file-entries | ODT reuses `opc._FIXED_ZIP_TIME` and pins `external_attr` to `0o600`; `_UNLISTED_IN_MANIFEST` excludes the positional parts |

### Not fixed — recorded as a negative result

**Sample-pair analysis (SPA) was implemented, measured, and withdrawn.** The
Dumitrescu–Wu–Wang estimator was built and evaluated against carriers embedded at
known rates. It is monotonic in the true rate but badly mis-scaled on the synthetic
carriers this project generates: a fully-embedded carrier estimates ≈0.10 against a
true rate of 1.0, and the scale factor varies with the carrier (≈0.23 for a gradient,
≈0.10 for a smooth analytic surface). Shipping that number under the name
"estimated embedding rate" would be exactly the class of overclaim this audit
exists to catch, so it was not shipped. The chi-squared detector in
`steg_bridge.py` covers the sequential-embedding case that `lsb.embed` actually
produces, and covers it correctly. Calibrated SPA over natural-image carriers
remains open (see `TODO.md`).

## v0.6.3 — ODT intelligence parity and the OPC signature reference set (2 confirmed)

An overclaim audit compared each documented capability against the code path that
would have to implement it.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | **The ODT profile had no intelligence layer.** `odt.py` was unreferenced by `container.py`, `channels/`, `validate.py`, and the CLI: it could build a conforming ODF package and hold loose bytes via `add_part`, and nothing more. Meanwhile the manuscript claimed a `.odt` satisfies the Intelligence Contract and asserted "standards parity", the format spec described an ODT profile carrying the intelligence layer, and the README listed it as shipped. No signed manifest, no sealing, no provenance, no validation existed for ODT | Implemented the layer rather than narrowing the claim: `src/docxplus/odt_container.py` adds `OdtPlusBuilder` / `OdtPlusReader` with typed payloads, all four sealing lineages, Merkle root, ODF surface digest, Ed25519 signature and co-signatures, and inclusion proofs. Sealing and unsealing are *shared* with the OPC path (`container.seal_module`, `DocxPlusReader._unseal`) so the two profiles cannot drift on the security-relevant details. `validate.validate_odt_bytes` checks both contracts; four `odt-*` CLI commands expose it |
| 2 | medium | A whole-package OPC signature covering only the conventional Word parts would render as valid in a desktop office suite over a package whose intelligence layer had been stripped or swapped — the visible trust indicator would attest the *absence* of what a reader assumes it covers | `validate.check_opc_signature_coverage` fails closed when a package carries OPC signatures whose combined reference set omits the intelligence manifest or any part it names. Written before signing support exists, deliberately: the rule is what stops the feature from becoming a trust-laundering surface (`docs/opc-signatures.md`) |

Both were found by asking, for each documented capability, which code path implements
it — the question that catches a claim no test contradicts because no test exercises
the claim at all.

## v0.7.0 — Project round-trip fidelity, the symlink door, and a determinism no-op (4 confirmed)

Building an end-to-end round-trip harness (`scripts/06_project_roundtrip.py`) was the
review: carrying a real project into both containers and diffing what came back
surfaced defects that no unit test had been shaped to notice, because every existing
test packed a tree of ordinary files.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | **`pack_project` silently dereferenced symlinks.** `Path.is_file()` follows links, so a tree containing `creds -> ~/.ssh/id_rsa` had the *target's bytes* packed into the document under the link's name. Nothing in the manifest, the package, or the API suggested the document now carried a file from outside the project. The unpack side had rejected link members since v0.3; the pack side was never closed, and the security model documented only the unpack half | `pack_project` refuses any symlink by default, naming the offending paths, and dereferences only under an explicit `follow_symlinks=True`. Refusal rather than silent skipping: skipping would trade one silent loss for another |
| 2 | medium | The executable bit was discarded — every file was written at mode `0o644`. A carried `run.sh` came back non-executable, so a project whose entrypoint is a shell script did not survive the round trip the manuscript claims for it | Mode is now `0o755` for executable files and `0o644` otherwise, clamped to exactly those two so no arbitrary mode rides along. Every other mode bit stays normalised for determinism |
| 3 | high | **`pack_project` was never deterministic.** `tar.gzip_mtime = 0` assigned an attribute `TarFile` does not define — a silent no-op carrying a `# type: ignore[attr-defined]` on the exact line where the intent failed — so the gzip header embedded wall-clock time. Two packs of the same tree seconds apart produced different bytes and therefore different module digests, defeating reproducible builds of any document carrying a project. `test_packing_is_deterministic` passed only because its two calls usually landed in the same second | The tar is built uncompressed and gzipped explicitly with `mtime=0` and no embedded filename. Determinism is now asserted against the header field itself and across a simulated hour-long clock advance, neither of which can pass by racing the clock |
| 4 | low | Empty directories vanished, because the walk selected `is_file()` only. Build systems that require a present-but-empty directory would find it missing after a round trip | Directories with no contents of their own are emitted as explicit tar members |

### Two notes on how these were found

Findings 1 and 3 share a shape worth naming: both were *silent*. The symlink door
produced a document that looked correct and carried more than it said; the
determinism no-op produced bytes that looked deterministic under any test fast
enough to run twice in one second. Neither had a failing test, and neither would
have acquired one, because the existing tests were shaped around trees of ordinary
files packed twice in quick succession. The harness found them by carrying a tree
built specifically from the awkward cases and by separating the two packs with real
work.

Finding 1 is exploitable in the ordinary case rather than a contrived one: an author
packing a checkout that happens to contain a symlink into their home directory
publishes its target. The severity is bounded only by the author's own tree, which is
precisely the material a research document is most likely to carry.

### Also closed

`OdtPlusReader` reached shared verification logic by unbound call, and
`verify_reproduction` resolved a module's stored bytes through the OPC channel
registry — so the ODF profile raised `unknown channel: odt_package_part` the first
time an attestation was verified. The lookup is now a `_stored_bytes` seam each
profile supplies, which is what made the shared-code parity claim actually hold under
the paths the harness exercises.

## v0.7.0b — Multi-agent adversarial review: the signature scope (3 confirmed here)

A first-principles deconstruction followed by five parallel attack dimensions, each
finding independently re-verified against the live tree by a separate reviewer whose
instruction was to refute it. Twenty-four findings survived verification; the three
that change the security model are below, and the remainder are tracked in `TODO.md`.

The deconstruction is what produced the critical one. Asked to classify every
constraint as HARD, SOFT, or ASSUMPTION, it flagged the surface digest as *"the single
load-bearing place where a naming convention is standing in for a graph property"* —
and the attack dimension then built the exploit.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | **critical** | **The signature bound a list of filenames, not the part graph.** `_compute_surface_digest` selected the signed surface by name prefix (`word/document.xml`, `word/header*`, …). But OPC decides which part a consumer *renders* through the officeDocument **relationship**, not the filename — and relationships live in `pkg.relationships`, content types in `pkg.override_types`, neither of which was hashed by anything. An attacker could add `word/document2.xml` carrying different text, repoint that relationship, demote the original's content type, and leave every signed byte untouched. `verify_provenance(expected_public_key=trusted_key)` — the strongest check the API offers — returned **True** while a renderer displayed the attacker's text. Reproduced end to end: a contract reading "100 USD" rendered as "100000 USD" under a valid pinned-key verdict | `_compute_surface_digest` now binds the whole package: every part and its bytes, the complete content-type map, and every relationship edge, in sorted order, excluding only the manifest that carries the digest. The rule went from "these six name families" to "everything but one named exception" — strictly simpler, and it survives a new channel being added, which the prefix list demonstrably did not. `compute_odt_surface_digest` mirrors it |
| 2 | high | The ODT reader had no duplicate- or colliding-entry-name guard, so a signed `.odt` could carry two `content.xml` streams — one signed, one rendered. Which a consumer picks depends on whether it reads local headers or the central directory. `read_package` rejects both cases and says so in a comment; the ODF door, added for parity, did not, while the audit log claimed parity had been reached | Both checks ported verbatim into `OdtPackage.from_bytes`: duplicate names, and names that collapse to one key under normalisation (`content.xml` vs `./content.xml`) |
| 3 | high | The MCE channel inserted `<mc:AlternateContent>` at the end of `<w:body>`, after the body-level `<w:sectPr>`. `CT_Body` is `(EG_BlockLevelElts*, sectPr?)` — `sectPr` must be last — so the one channel that writes into the main story part emitted schema-invalid markup, on the channel the manuscript advertises as the standards-elegant one | Tracked; see `TODO.md`. The fix is to insert before `sectPr` and emit an empty `<mc:Fallback/>` |

### Why the deconstruction mattered

The critical finding was not visible as a bug. Every test passed, the digest did
exactly what its code said, and its docstring described the behaviour accurately. What
was wrong was one level up: a *soft* constraint (our naming convention for story
parts) had been placed where a *hard* one (the format's own rule about which part is
the document) belonged. That is the class of defect first-principles decomposition is
for, and it is invisible to a reviewer who starts from "does the code do what it says".

## v0.7.0c — Release-gate pass (3 confirmed)

Running the publication gate before a v1.0.0 tag, rather than after.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | **Junk exclusion deleted real source at depth.** `_excluded` matched a bare directory name against *any* path component, so a carried tree lost `src/output/model.py` and `docs/venv/notes.md` entirely — silent data loss under the flagship "carries the software that produced it" claim. The round-trip harness could not see it because every junk directory it created sat at the top level, which is the only place the names are unambiguous | Split into `_ROOT_ONLY_EXCLUDE` (build outputs: matched against the first component only) and `_ANY_DEPTH_EXCLUDE` (tool caches: junk wherever they sit). The harness now builds real files under both names, and its junk detector delegates to the packer's rule instead of keeping a second copy that could disagree |
| 2 | high | **The living manuscript did not carry the repository it claimed to.** `scripts/05_living_manuscript.py` packed an unrelated external exemplar at a hardcoded absolute path under one developer's home directory. The manuscript states the document "packs the complete, runnable docxplus repository"; that was false on every machine, and `run.sh` failed outright on any other checkout | The carried tree is resolved from `project_root()`. A test asserts it, and a second test fails the build on any absolute home path in a tracked file |
| 3 | medium | Release metadata disagreed on the version: `pyproject.toml` 0.7.0, `CITATION.cff` 0.6.0, `codemeta.json` 0.6.0, `.zenodo.json` unset; repository URLs still pointed at the pre-rename `docxology/docx` | All four aligned and URL-corrected, with a test that fails when they drift. A Zenodo record minted from a stale codemeta is a citation that points at the wrong artefact permanently |

## v1.0.0 — Closing the release-gate blockers (10 confirmed)

The four category-A blockers from the publication gate, plus six of the mediums and
lows they sat above. Each was a claim the documentation made that the code did not
keep, or a control the code implied but did not enforce.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | **The MCE channel emitted schema-invalid markup.** `<mc:AlternateContent>` was appended at `</w:body>`, landing *after* the body-level `<w:sectPr>`. `CT_Body` is `(EG_BlockLevelElts*, sectPr?)`, so sectPr must be last; Word validates `document.xml` on load and offers repair. This was on the one channel that writes into the main story part, and the one the manuscript calls standards-elegant. The `<mc:Fallback>` also carried an empty `<w:p>`, so each concealed module appended a blank paragraph — independently falsifying dual-contract independence | Insertion moved before the body-level sectPr (`_body_insertion_point`, which ignores a `w:pPr` section break), and the fallback is now `<mc:Fallback/>`. Tests assert sectPr stays last and that concealment changes no paragraph count |
| 2 | high | **No CLI command reached `verify_provenance`.** `validate` exits 0 and `inspect` prints `signature: valid` on a document whose visible text was rewritten after signing. The strongest check the library offers had no way to be run from a shell | New `docxplus verify`, which checks the signature, the package binding, and an optional co-signer policy. It **exits nonzero without `--expected-key`**, because integrity is not authenticity and a zero exit would say otherwise |
| 3 | high | **Argon2id had no producer path.** `crypto.encrypt` accepted `kdf=` and nothing above it ever passed one, so no document the tool emitted had ever used Argon2id — while the abstract, conclusion, security model, and architecture all state it in the present tense | `kdf` threaded through `_Pending`, `seal_module`, both builders, and `--kdf` on both build commands. All three lineages are now produced and round-trip |
| 4 | high | The evaluation section claimed the dossier "exercises every operational mode" while its own generated table showed two of five channels | Coverage is now derived into tokens and the prose states exactly what the table shows: every sealing lineage, two channels |
| 5 | medium | **The builder emitted packages its own reader rejected.** A compressible payload above 1 MiB tripped the read-side inflate-ratio guard, so `validate` failed and `extract` raised — the payload was unrecoverable through the public API | `_compression_for` stores an entry uncompressed when deflating it would trip the reader's own heuristic. A writer must never emit what it would refuse |
| 6 | medium | **The stego carrier was never displayed.** The channel's premise is a figure the document visibly shows; the image part had a relationship but no `<w:drawing>`, so it rendered nowhere | A drawing paragraph referencing the carrier by relationship id is inserted, before the sectPr |
| 7 | medium | `open_nested` on the ODT reader had no depth cap and no payload-type check, so one ODT hop reset the OPC nesting budget | Depth is carried across the profile boundary and the payload type is checked |
| 8 | medium | The transparency log had no consistency proof, so "append-only" was a promise: an operator could drop an entry and re-sign, and every check still passed | `consistency_proof` / `verify_consistency`, plus `--consistent-with` and `--emit-proof` on the CLI. Truncation, rewriting a retained entry, and unrelated logs all fail closed |
| 9 | low | `verify_reproduction` returned `verified: True` for a module carrying no attestation, so a caller reading that field alone would conclude a reproduction claim had been validated when none was made | Returns `verified: False` when `attested` is false |
| 10 | low | Cookbook recipe 10 claimed ODT archives carry "the same signed intelligence manifest" while its code used `new_base_odt` + `add_part`, which produces a plain unmanifested package; the cookbook also had two sections numbered 10, and the README claimed one script builds every recipe | Recipe rewritten against `OdtPlusBuilder`, sections renumbered contiguously, README corrected |

## v1.0.0b — Provenance construction and the validator's blind spot (4 confirmed)

A round aimed at the surfaces earlier cycles had not attacked: the Merkle construction
itself, the manifest read path, ZIP entry naming, and the boundary between what
`validate` checks and what only `verify` checks. Twelve further attacks on the
transparency log (STH substitution, truncation, entry rewriting, reordering, forged
consistency proofs) and twenty-five on the cryptographic envelope (including an
exhaustive single-bit-flip sweep over every envelope byte) produced no findings.

The four below share a shape: each was a guarantee that held only because some *other*
component happened to check something. Every fix moves the check into the component
that owns the property.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | **Merkle second preimage (CVE-2012-2459 shape).** Odd levels were padded by duplicating the trailing node, so the tree over three leaves hashed identically to a four-leaf tree whose last two leaves were equal: `merkle_root([a,b,c]) == merkle_root([a,b,c,c])`. The documented promise that adding, removing, or swapping any module breaks the root was therefore false in exactly that case, and `verify_root` returned true for a set it should have rejected. Slot uniqueness made it unreachable through a well-formed manifest — but only because a *different* module enforced it | Tree shape changed to RFC 6962, splitting at the largest power of two below the node count, which removes the ambiguity from the construction rather than relying on any caller. `inclusion_proof`/`verify_inclusion` follow the same shape. `merkle_root` additionally refuses a duplicate slot. Proofs are asserted for every leaf at every tree size from 1 to 17, crossing the power-of-two boundaries where splitting bugs live |
| 2 | high | **`validate` did not recompute the surface digest.** The signature covers `surface_digest` as a *stored field*, so editing the visible text of `word/document.xml` left the signature self-consistent. A package whose prose had been rewritten passed `docxplus validate` with **no findings at all**; only `verify` caught it. The Merkle root was already recomputed, so the omission was an asymmetry rather than a design position — and `validate` is the command a release process runs | Both profiles now recompute the surface digest from the package in hand and compare it to the stored value. Reproduced first on four separate tampers — edited text, altered content type, added part, repointed relationship — each of which the validator had accepted |
| 3 | medium | **Duplicate manifest slots on the read path.** `Manifest.add` refuses a repeated slot, but a manifest parsed from a package never goes through `add`, so a hand-crafted one could carry two records under one name. `slot()` returns the first match while a validator iterating `records` sees both: the module a reader extracts need not be the module a validator checked | `from_bytes` refuses duplicates, at the point untrusted bytes actually enter |
| 4 | medium | **Non-canonical ZIP entry names were silently rewritten.** Traversal was refused, but `/abs/x.xml` was stored as `abs/x.xml`, `a/../b.xml` as `b.xml`, and `//srv/share/x.xml` and `C:\x.xml` were accepted outright. A reader operating on a part whose name no other consumer agrees with is the same class as the case-folding collision closed earlier: disagreement about *which part this is* | Entry names must arrive already canonical or be refused — one rule rather than a list of bad prefixes, since the previous list named `..` and admitted every other shape. The collision check remains and is still exercised by a case-folding pair, which canonical-form checking cannot catch |

An API change accompanies finding 1. `verify_inclusion(proof)` folded a proof to the
root carried *inside that proof*, which establishes internal consistency and nothing
more: an attacker supplying the proof supplies the root, so they can build a tree
containing any module they like and hand over a self-consistent proof of its
membership. The CLI already compared against the signed root, but the library signature
invited the unsafe call and two tests demonstrated it. `verify_inclusion` now requires
the expected root as an argument, which makes the misuse unspellable.

## v1.0.0c — First principles, security review, nation-state (5 confirmed)

Four lenses over the same tree. First principles asked which guarantees the design
claims but has no mechanism to keep; the security review looked at how the tool
treats its own outputs; the nation-state lens assumed an opponent who collects at
scale, waits, and compels. Twenty-five attacks on the cryptographic envelope and
twelve on the transparency log were re-run and still produce nothing.

The findings share an omission rather than a mechanism: each is a place where the
threat model stopped at the boundary of the file.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | **The tool wrote its own secrets world-readable.** `keygen` created Ed25519 and X25519 *private* keys at the process umask — 0644 under the common default — and so did `--shares-dir` output and `extract --out`. Any local user could read the signing identity behind every document the operator had produced, and the recovered plaintext of every payload they had opened. A container format whose purpose is protecting payloads had not protected its own | New `secure_io.write_secret` creates at 0600 via `os.open`, before any content exists, so there is no window at the wider mode — write-then-`chmod` would have left exactly the interval a watcher waits for. Key and share writes are exclusive creates, because silently replacing a signing key destroys an identity with no recovery; the CLI exits nonzero instead. Public keys stay 0644 deliberately |
| 2 | medium | **The DXE2 envelope published the recipient count.** One wrapped key per recipient, plus an explicit count field, so the number is recoverable from the field and independently from the envelope length. The manifest records neither identities nor number and the docstring claimed the envelope "does not leak the recipient set" — true of identities, false of the count. For the blind-review packet this lineage exists to serve, "sealed to three people" is information about the review | `seal_multi(..., pad_to=N)` and `--pad-recipients N` raise the slot count to a fixed bucket by wrapping to freshly generated public keys whose private halves are discarded before the call returns. A padded slot is a genuine wrap, indistinguishable from a recipient's and decryptable by nobody — the same move the password lineage makes with its chaff frame. Slots are shuffled with a CSPRNG, since appending decoys would have put every real recipient first and reconstructed the count from position. The default stays unpadded and the leak is pinned by a test, so it remains a stated default rather than an unexamined one |
| 3 | low | **The declared signature algorithm was recorded and never read.** A manifest could declare `"algorithm": "rsa-4096"` and still verify, because verification hard-codes Ed25519. Nothing was exploitable — hard-coding is what made it safe — but a recorded value nobody checks is a claim the format cannot keep | The value is now checked against the compiled-in constant and a mismatch fails closed. It is deliberately never used to *select* a verifier: dispatching on an attacker-supplied algorithm name is the JWT `alg`-confusion class. The field sits outside the signed body and is therefore unauthenticated, which is documented alongside the check |
| 4 | doc | **No post-quantum posture was stated anywhere.** X25519 and Ed25519 both fall to a CRQC; AES-256-GCM does not. A format built to carry sealed research long-term had no statement about harvest-now-decrypt-later, which is the canonical adversary at this tier | Stated as a boundary in `security-model.md`, including the partial exception: a payload sealed under a high-entropy passphrase with Argon2id performs no key exchange and inherits only the symmetric margin. Adding a hybrid suite is a format change, not a flag, and is not claimed |
| 5 | doc | **The trust model has no key lifecycle and the signature binds no time.** No revocation, expiry, or rotation, and the canonical body carries no timestamp — so a document alone cannot establish whether it was signed before or after a compromise | Recorded as boundaries rather than papered over. Both sharpen the argument for the transparency log: signing order is exactly what it supplies, which makes it part of the mechanism rather than an optional extra |

## v1.0.0d — Where data becomes behaviour (3 confirmed)

A security review of the three paths on which untrusted material stops being data:
a tarball becoming files on disk, a carried command becoming a process, and a
password attempt becoming an observable duration. The intake scanner was re-verified
against real macro, `altChunk`, and external-relationship payloads and detects all
three with no false positive on a clean document; error messages were checked and
carry no password or key material.

Each finding is a control that held in the configuration it was developed in and not
in one the project supports.

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | high | **Extraction hardening depended on the interpreter version.** `unpack_project` called `extractall(filter="data")` with a `TypeError` fallback to a bare, unfiltered `extractall` for Python below 3.12 — and `requires-python` is `>=3.10`, so that branch was reachable in supported configurations. The manual pre-check loop refused links and traversal and said nothing about permission bits or special files, so on 3.10 and 3.11 a payload carrying `run.sh` at mode 04755 **extracted with the setuid bit intact**, and FIFOs and device nodes were created as given. The only thing standing between a hostile document and a setuid binary was a feature of the running interpreter | Members are written out explicitly rather than handed to `extractall`. A positive check admits plain files and directories and refuses everything else, so a tar member type nobody has considered is refused by default instead of admitted. Permission bits are clamped to 0644/0755, preserving the executable bit the format promises to carry and discarding setuid and setgid. The untested fallback branch is gone, and a structural test refuses any reintroduction of `extractall` |
| 2 | medium | **The execution confinement bounded the child and not the verifier.** Network denied, writes confined, environment scrubbed, CPU, address space, process count and file size all limited — every one of them applying to the child. The parent read both streams through `subprocess.communicate()`, which buffers into its own address space, and no child limit reaches a pipe the parent is reading. Measured: 400 MiB of child stdout grew the verifier's resident set by roughly a gigabyte, with the run reported as a success | Both streams go to files rather than pipes, which puts the child's own `RLIMIT_FSIZE` back in the path, and the parent reads only a bounded prefix of stderr for its failure message. Stdout is discarded, as it already was |
| 3 | high | **A stopwatch defeated the decoy.** Frames were tried in order and the first success returned. The builder writes the real payload into frame 1 and the cover story into frame 2, so the real password cost one key derivation and the cover password cost two: 154 ms against 307 ms, a clean factor of two on a derivation that is deliberately expensive. Under the one threat this lineage exists for — an adversary who has compelled a password and wants to know whether it was the whole story — the answer was on the wall clock. The chaff frame, the shared manifest record and the overlapping size ranges were all defeated by timing | Every frame is attempted whichever one matches, so the real password, the cover password and a wrong one all cost one derivation per frame. Measured after the fix at 320 / 313 / 317 ms across the three cases, and an ordinary sealed module now costs the same as a decoy, which it must or timing separates "has a hidden payload" from "does not". The price is that opening any password-sealed module costs a derivation per frame; that is the cost of the property the format claims rather than an inefficiency to remove |

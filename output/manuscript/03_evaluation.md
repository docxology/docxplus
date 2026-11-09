# Evaluation {#sec:evaluation}

> Live constants, source inventories and available reports feed the manuscript variable extractor.
> Token hydration prevents literal drift, not stale evidence.
> Report-derived values below are historical unless a source-bound release receipt identifies the exact
> final inputs and successful run. No fresh full-suite, coverage, native-Office or render result is asserted here.

## Round-Trip Integrity Across Every Sealing Mode {#sec:eval-roundtrip}

The reference dossier (`src/docxplus/reference_docs.py`, `scripts/04_dossier.py`) carries 5
heterogeneous modules in a single archive, covering all 3 sealing lineages
(`password`, `recipients`, `threshold`) across 1 of the 5 transport channels
(`package_part`). Sealing is what the dossier is for; the remaining channels are exercised by the
round-trip and channel suites rather than here. One `ReferenceDossier` supplies serialized artifact bytes
and ephemeral credentials to both the exporter and table; checks read those bytes through its reader:

| Slot | Channel | Sealing |
| --- | --- | --- |
| `annex` | package_part | password |
| `notes` | package_part | password |
| `review` | package_part | recipients |
| `source` | package_part | password |
| `vault` | package_part | threshold |

The generated dossier table specifies the fixture's intended extraction/verification checks:

- **Structure.** Selected OPC graph checks (collisions and relationship resolution), not full ISO conformance.
- **Provenance.** Signature, module Merkle root and package-surface commitments recompute; a caller-pinned
  key is needed to authenticate the signer.
- **Sealing.** Selected password, recipient, threshold and decoy round trips, including signed full-share
  digest membership before combine. Standalone share checksums do not establish malicious-share resistance.
- **Project extraction.** The dossier source slot is extracted but is not reproduction-attested.
  Living/synthetic suites own their recipe claims and separate local execution evidence.

The source inventory comprises 721 test functions under a 90% coverage policy,
not that many freshly passed cases. Tests use real primitives, files and subprocesses; optional compiled-backend
and native-application cases require their capabilities and cannot count a skip as an exercised result.

## A Manuscript That Carries Its Own Repository {#sec:living-manuscript}

`scripts/05_living_manuscript.py` packs the selected docxplus repository tree into a `.docx` with a signed
attestation for a dependency-free hash of selected Python source files. It does **not** rerun the tests,
figures, rendered paper or full scientific workflow. The carried archive is distinct from this rendered PDF.

![Authoring runs left to right and ends at one self-contained file; what a reader does with that file forks. The default branch is entirely cryptographic and executes nothing. The other requires an explicit flag and re-runs the attested command under confinement. The fork exists because the two verdicts are not interchangeable: one says the author's claim has not been altered, the other says it reproduces on this machine, and neither substitutes for the other.](../../output/figures/reproduction_lifecycle.png){#fig:reproduction-lifecycle width=95%}

A recipient can engage at three levels of increasing commitment. The last two are the branches that
fork in [@fig:reproduction-lifecycle]:

1. **Read it.** The public document surface is intended for ordinary Office consumers; native compatibility
   remains an application/version/fixture-specific empirical question.
2. **Verify it, executing nothing.** `docxplus verify-reproduction --expected-key ...` authenticates the
   signed recipe claim against carried bytes. Unpinned verification establishes only self-consistency;
   neither path witnesses execution.
3. **Re-run it.** `docxplus reproduce` opts in to instantiating the project in a confined sandbox, executing
   the attested command, and comparing the resulting digests against the author's.

The third tier is optional and potentially dangerous. A successful local run compares the declared selected
outputs in the observed environment; it does not establish independence from readable host inputs, an exact
environment match, or scientific validity. The source-hash demonstration is intentionally narrower than a
whole-project reproduction claim and is insensitive to changes outside its selected source set.

## Carrying a Project Out and Back {#sec:roundtrip}

The claim that a document can carry the software that produced it is only worth as much as the fidelity of
the round trip, so the fidelity is measured rather than asserted. `scripts/06_project_roundtrip.py` builds a
project tree chosen to contain exactly the cases naive packing loses — an executable entrypoint, an empty
directory, a zero-byte file, filenames with spaces and non-ASCII characters, two files with identical
content, and build junk that must *not* travel — carries it into both containers, then reads actual exported
artifacts and enumerates both source and extracted trees. Extra entries fail alongside missing/changed
files, execute bits and empty directories.

The available report records a 14-file, 9-directory selected synthetic tree and
18 of 18 checks, with 12 compared files. Those tokens describe the report,
not a fresh run. It reports package sizes of 5,389 bytes (DOCX) and 4,552 bytes (ODT),
plus cross-profile packed-payload parity. Shared packing makes consistent behavior plausible, but does not
replace independent end-to-end evidence for either profile or imply arbitrary-project fidelity.

![A selected project fixture carried into a container and compared with what came back. The preservation contract includes file contents and the executable bit; metadata is normalized, symlinks refused by default and build directories excluded. Counts come from the available harness report at render time, not from a freshness check or a general fidelity proof.](../../output/figures/roundtrip_fidelity.png){#fig:fidelity width=95%}

[@Fig:fidelity] states the contract in full: what is preserved, what is normalised away on purpose, what
is refused outright, and what never travels at all.

Two results are worth separating from the pass count. The first is what the harness found on its way to
passing: packing previously forced every file to mode `0644`, so a carried `run.sh` came back
non-executable, and empty directories vanished under a files-only walk. Both are now preserved. The second
is a security finding rather than a fidelity one. `Path.is_file()` follows symbolic links, so a tree
containing `creds -> ~/.ssh/id_rsa` had the *key's contents* packed into the document under the link's name,
with nothing in the manifest to suggest it. The unpack side had always rejected link members; the pack side
was the open door. Symlinks are now refused unless a caller passes `follow_symlinks=True` and thereby says
so in a way that survives review.

[@Fig:parity] sets the two profiles side by side. What matters there is not the count of ticks but the
dividing line: above it the profiles execute the *same code*, so parity is structural rather than a
coincidence that survives until someone patches one side.

The harness also exercises what a single-container round trip cannot reach: a signed `.docx` carried as a
nested module *inside* a signed `.odt`, opened through a dispatcher that reads the container's own magic
rather than trusting the caller to declare it, with the inner document's provenance and project both
verifying after extraction.

![The two profiles drawn as shells around a shared core. Shared sealing and provenance code narrows security drift; each profile still needs consumer-specific evidence. ODT implements package parts, displayed media and metadata user fields. The OOXML custom XML datastore and MCE constructs have no ODF-native counterpart. Transport differences do not require a second sealing or signature implementation.](../../output/figures/profile_parity.png){#fig:parity width=95%}

## Channel Capacity {#sec:capacity}

Capacity is channel- and backend-specific; no channel-local limit removes package entry/total/count budgets.

![Channel capacity under the selected Python LSB framing and package budgets. Metadata has a docxplus-imposed per-payload ceiling; media scales with carrier area only within the decoded-pixel budget; the other channels have no channel-local ceiling. Regeneration performs boundary round trips before plotting measured points. A committed plate without a source-bound receipt is historical, not fresh capacity evidence.](../../output/figures/capacity.png){#fig:capacity width=85%}

[@Fig:capacity] distinguishes implementation policy, carrier framing/pixel admission and package budgets:

- **`metadata`** has a conservative implementation limit of 8000 payload bytes in
  `docProps/custom.xml` (and ODF `odt_metadata` fields in `meta.xml`), not a standards-imposed maximum.
  It is intended for routing headers, identifiers, status flags and key shares.
- **`custom_xml`, `package_part`, and `mce`** have no channel-local ceiling, but XML/base64, part, archive
  metadata, count and total-size limits still apply.
- **`python_lsb` media** uses DXL1 framing: a $256\times 256$ RGB PNG holds 24568 bytes and a
  $512\times 512$ PNG holds 98296. Rust media instead queries actual CLI capacity with the
  same metadata/signing policy as encode. Replication requires a surviving digest-matching carrier;
  it does not preserve signed package authenticity through edits.

## Conformance, Openability, and Determinism {#sec:conformance}

The construction uses documented OPC/ODF extension points [@iso29500; @oasis_odf] and payload-level rather
than whole-package encryption [@msoffcrypto]. Structural checks are not complete schema validation.
Native application openability needs receipts naming each application/version and emitted fixture; no current
Word/Google Docs proof or fresh LibreOffice conversion is inferred from unit tests or PDF generation.
The release Office gate renders actual installed-wheel DOCX/ODT, saves through Writer, then renders again.
Its tool-bound receipt retains original/saved document/PDF/text/raster hashes and visible/hidden sentinel
checks. It qualifies the recorded fixture's visible rendering only, not payload survival or signature
validity after Office editing. Qualification remains conditional until a fresh receipt is imported.

Repeated unencrypted-build tests express deterministic serialization obligations. Fresh salts/nonces make
encrypted output intentionally nonidentical; fixed part order alone does not establish whole-workflow determinism.

## Adversarial Verification {#sec:threat-audit}

The audit record describes 14 review cycles and 88 confirmed
findings. Historical regression claims, current static findings, observed baseline failures and unavailable
fresh qualification are distinguished in `docs/redteam-audit.md`. Counts are not a security proof or pass tally.
The newest source changes require final source-bound integration evidence; prior successful runs do not
automatically qualify new format framing, keys, consumers or platform controls.

![Threat classes grouped by layer and the intended controls that address them. Arrows depict design boundaries, not proof that every adversary or current platform probe is blocked. The audit distinguishes observed failures, source-derived mitigations and unavailable qualification evidence.](../../output/figures/redteam_matrix.png){#fig:redteam-matrix width=95%}

[@Fig:redteam-matrix] maps the classes to their controls. Four findings generalise past this
implementation, and they are the reason the review is worth reporting at all.

**A naming convention cannot carry a security property.** The manifest signature originally bound a list
of part *names*, while OPC resolves the rendered document through the officeDocument *relationship*
[@iso29500]. Every test passed, because each asserted what the code said it did; the defect lay in the
space between two individually correct components, the position Dolev and Yao formalised for protocols
[@dolevyao1983]. What closed it was a change of question — asking of each constraint whether it was a law
of the format or a convention this project had chosen — rather than a better test.

**A control needs an authenticated reference.** A public share checksum can be recomputed after mutation;
requiring its header never made it Feldman VSS [@feldman1987]. Signed full-share digest commitments instead
authenticate issued bytes under a pinned trusted manifest. That does not prove polynomial consistency or an
honest dealer. The distinction is between an accidental-corruption check and an adversarial authenticity
boundary; downgrade controls alone cannot upgrade the former into the latter.

**Absence of a failing test is not evidence of a working control.** Two findings were silent: a
determinism guarantee implemented by assignment to a non-existent attribute, and a capability documented
in prose with no implementing code path. Both produced artefacts that looked correct under inspection.
Tests defend against the failure modes they were shaped to anticipate, and neither of these was shaped
like a failure — the selection problem Goodenough and Gerhart set out at the foundation of testing theory
[@goodenough1975].

**A guarantee delegated to a neighbour is not a guarantee.** The Merkle construction padded odd levels by
duplicating the trailing node, which makes the tree over three leaves hash identically to a four-leaf tree
whose last two leaves are equal — the second-preimage ambiguity found in Bitcoin as CVE-2012-2459. The
documented promise that adding a module always changes the root was therefore false in that case. It was
unreachable through a well-formed manifest only because slots are unique, and slots were unique only
because a *different* module checked them on the write path; the read path did not. In the same round the
validator was found to recompute the Merkle root but not the surface digest, so a package whose visible
prose had been rewritten passed `docxplus validate` with no findings at all, protected only by whether the
reader happened to run `verify` instead. Both fixes move the check into the component that owns the
property: RFC 6962 tree splitting makes the root unambiguous by construction rather than by a caller's
diligence, and the validator recomputes what it had been trusting. A property that holds because something
else is careful is a property with an undocumented dependency, and undocumented dependencies are what
change when code does.

The record also carries a negative result. A sample-pair analysis estimator [@dumitrescu2003] was
implemented and measured against carriers embedded at known rates. It proved monotonic in the true rate
but mis-scaled by roughly an order of magnitude and dependent on carrier statistics, so it was withdrawn
rather than shipped under a name implying a calibration it did not possess.

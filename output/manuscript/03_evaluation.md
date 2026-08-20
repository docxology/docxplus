# Evaluation {#sec:evaluation}

> Every quantity in this section is substituted at render time from live code constants via
> `scripts/render_manuscript.py` and `src/docxplus/manuscript_vars.py`. The manuscript sources contain no hardcoded
> metrics, so a claim here cannot drift from the implementation without the render failing. The figures draw
> from the same source.

## Round-Trip Integrity Across Every Sealing Mode {#sec:eval-roundtrip}

The reference dossier (`src/docxplus/reference_docs.py`, `scripts/04_dossier.py`) carries 5
heterogeneous modules in a single archive, covering all 4 sealing lineages
(`password`, `plain`, `recipients`, `threshold`) across 2 of the 5 transport channels
(`custom_xml`, `package_part`). Sealing is what the dossier is for; the remaining channels are exercised by the
round-trip and channel test suites rather than here, and the table below is generated from the document the
code actually produces:

| Slot | Channel | Sealing |
| --- | --- | --- |
| `annex` | package_part | password |
| `brief` | custom_xml | plain |
| `notes` | package_part | password |
| `review` | package_part | recipients |
| `vault` | package_part | threshold |

All 5 modules extract and verify:

- **Structure.** The container passes OPC conformance (`opc_valid = True`): no part collisions, no broken
  relationship pointers.
- **Provenance.** The Ed25519 manifest signature, the module Merkle tree, and the composite
  surface digest over the package graph all validate.
- **Sealing.** Argon2id and Scrypt password modules decrypt; X25519 multi-recipient envelopes open for each
  authorised key; Shamir $(k,n)$ shares reconstruct on reaching quorum and are refused when a share's
  verifiable tag is absent or wrong; dual-frame decoy modules return their respective plaintexts under their
  respective passphrases.
- **Reproducibility.** Carried `project` tarballs unpack without path traversal, and reproduction
  attestations verify cryptographically.

The harness comprises 496 test functions under a 90% coverage gate, with no mocks
anywhere: tests run against real cryptographic primitives, real ZIP archives, real subprocess CLI
invocations, and the compiled Rust steganography engine when it is present.

## A Manuscript That Carries Its Own Repository {#sec:living-manuscript}

`scripts/05_living_manuscript.py` packs the complete, runnable docxplus repository — source and test suite —
into a `.docx` carrying a signed reproduction attestation. That `.docx` is a sibling of the PDF you are
reading, not this file; the evaluation below describes the carried archive, not the rendered paper.

![Authoring runs left to right and ends at one self-contained file; what a reader does with that file forks. The default branch is entirely cryptographic and executes nothing. The other requires an explicit flag and re-runs the attested command under confinement. The fork exists because the two verdicts are not interchangeable: one says the author's claim has not been altered, the other says it reproduces on this machine, and neither substitutes for the other.](../output/figures/reproduction_lifecycle.png){#fig:reproduction-lifecycle width=95%}

A recipient can engage at three levels of increasing commitment. The last two are the branches that
fork in [@fig:reproduction-lifecycle]:

1. **Read it.** Open the `.docx` in Word, LibreOffice Writer, or Google Docs. Nothing about the intelligence
   layer intrudes.
2. **Verify it, executing nothing.** `docxplus verify-reproduction` checks the Ed25519 signature and the
   digest chain over the attested recipe. This is the default trust path, and it treats the document as
   inert data throughout.
3. **Re-run it.** `docxplus reproduce` opts in to instantiating the project in a confined sandbox, executing
   the attested command, and comparing the resulting digests against the author's.

The third tier is the interesting one precisely because it is optional. A document that reproduced itself on
open would be malware; the value lies in the reader choosing, on their own hardware, when to spend that
trust. What a match proves is bounded and worth stating: the declared command produced the sealed outputs on
a matching toolchain. It says nothing about whether the method was sound.

## Carrying a Project Out and Back {#sec:roundtrip}

The claim that a document can carry the software that produced it is only worth as much as the fidelity of
the round trip, so the fidelity is measured rather than asserted. `scripts/06_project_roundtrip.py` builds a
project tree chosen to contain exactly the cases naive packing loses — an executable entrypoint, an empty
directory, a zero-byte file, filenames with spaces and non-ASCII characters, two files with identical
content, and build junk that must *not* travel — carries it into both containers, and compares what comes
back file by file, byte by byte, and mode by mode.

Over a 14-file, 9-directory tree, all 18 of 18 invariants hold.
Both profiles validate against their own conformance rules; both verify provenance under a pinned key and
refuse a wrong one; both extract 12 files identical to the originals; both carry and
cryptographically verify a reproduction attestation. The sealed `.docx` is 4,538 bytes and the
`.odt` 3,650 bytes, and the packed project payload is *byte-identical between them* — parity that
holds because the two profiles share the packing code rather than agreeing by inspection.

![A real project tree carried into a container and diffed against what came back. The through-line is what survives byte for byte, including the executable bit — a carried entrypoint that returns non-executable is not carried software. Three diversions leave that line at the point they occur: metadata normalised because determinism is worth more than an mtime, symlinks refused outright because packing one would embed its target, and build directories never packed at all. Counts are read from the harness output at render time, so a fidelity regression changes this figure rather than merely failing a test.](../output/figures/roundtrip_fidelity.png){#fig:fidelity width=95%}

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

![The two profiles drawn as shells around a shared core. Every capability in the centre block is one implementation both profiles call, which makes parity a structural property rather than a coincidence that survives until someone patches one side. Divergence is confined to the dashed boxes at the transport edge — two constructs ODF does not define, and two analogues that are plausible but not built — and none of it touches how a payload is sealed, digested, signed, or refused. That is what stops the weaker profile becoming the one an attacker chooses to present.](../output/figures/profile_parity.png){#fig:parity width=95%}

## Channel Capacity {#sec:capacity}

Capacity spans four orders of magnitude, and the spread is the design's point rather than an artefact:
different channels answer different needs.

![What bounds each channel, plotted against the axis on which they actually differ. `metadata` has a hard ceiling fixed by the format and flat in carrier size; `stego_media` scales with carrier area and overtakes that ceiling at roughly 147 pixels a side; the remaining three have no channel-imposed limit at all and are drawn as an open region rather than given an invented number. The marked points are measured rather than computed: a payload of exactly that size was embedded into a real carrier and read back before the point was plotted.](../output/figures/capacity.png){#fig:capacity width=85%}

[@Fig:capacity] plots the spread on a log scale, distinguishing the channels with a real format ceiling
from those that simply have none:

- **`metadata`** is deliberately small, bounded at 8000 bytes in `docProps/custom.xml`:
  routing headers, identifiers, status flags, key shares.
- **`custom_xml`, `package_part`, and `mce`** carry no format-imposed ceiling, scaling until host storage or
  the reader's own decompression caps intervene.
- **`stego_media`** scales with carrier resolution under 1-bit LSB encoding: a $256\times 256$ RGB PNG holds
  24568 bytes, a $512\times 512$ PNG holds 98296. Under `redundancy=N` the payload is
  replicated across $N$ carriers, trading capacity for survival of carrier loss.

## Conformance, Openability, and Determinism {#sec:conformance}

Generated packages comply with ISO/IEC 29500-2 [@iso29500]. Because protection is applied per payload rather
than by wrapping the archive in an MS-OFFCRYPTO compound file [@msoffcrypto], the document stays readable by
ordinary tools — the property [@sec:motivation] set out to preserve.

Determinism is asserted, not assumed: `test_container.py::test_build_is_deterministic` requires byte-identical
digests across repeated unencrypted builds. Encrypted and signed builds introduce fresh salts, IVs, and
nonces by design, while part ordering stays fixed. Headless LibreOffice conversions confirm that the
resulting files open and render.

## Adversarial Verification {#sec:threat-audit}

Security claims are worth what their falsification attempts are worth, so the format has been through
14 cycles of adversarial review closing 88 confirmed findings.
Each cycle decomposed the design into atomic claims, attacked them from independent perspectives, and
required a second reviewer to *reproduce* a finding against the running system before it was accepted.
Every accepted finding produced both a fix and a regression test that fails without it. The complete
record — severities, reproduction steps, and results withdrawn rather than shipped — is maintained in
`docs/redteam-audit.md` and is not reproduced here.

![Threat classes grouped by the layer each one attacks, with the boundary it fails against drawn between the attack and the invariant. Every arrow stops on the wall. None of the classes is hypothetical — each was reproduced against a running build before its control was written — and the grouping shows what a flat list obscured: the coverage spans the surface contract, the manifest, the sealing layer, and the sandbox, rather than concentrating where the code was easiest to harden.](../output/figures/redteam_matrix.png){#fig:redteam-matrix width=95%}

[@Fig:redteam-matrix] maps the classes to their controls. Four findings generalise past this
implementation, and they are the reason the review is worth reporting at all.

**A naming convention cannot carry a security property.** The manifest signature originally bound a list
of part *names*, while OPC resolves the rendered document through the officeDocument *relationship*
[@iso29500]. Every test passed, because each asserted what the code said it did; the defect lay in the
space between two individually correct components, the position Dolev and Yao formalised for protocols
[@dolevyao1983]. What closed it was a change of question — asking of each constraint whether it was a law
of the format or a convention this project had chosen — rather than a better test.

**A control is only as strong as the verifier's obligation to invoke it.** Verifiable secret shares
[@feldman1987] carried integrity tags defeatable by stripping the header rather than by cryptanalysis,
because nothing obliged the reconstructing party to demand the tagged form. Recording the requirement in
the *signed* manifest moves it from the verifier's discretion to the attacker's impossibility. Downgrade
resistance has to be structural; TLS reached the same conclusion about version negotiation only after
repeated failures [@rfc8446].

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

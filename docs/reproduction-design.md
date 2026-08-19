# Reproduction Attestation — Design (v0.4)

Synthesis of a four-lens review (FirstPrinciples, Council, Science, RedTeam) for
making the "self-verifying dossier" real: a docxplus that carries
`template_code_project` ([`docxology/template`](https://github.com/docxology/template)) and lets a reader trust that its results *follow from its
code*, not just that its bytes are authentic.

## First-principles decomposition

Verification is not one act; it is a chain of separable links:

- **Integrity** — "these bytes are the bytes the author sealed." A signature/digest
  proves this and nothing more. A signature over final bytes *notarizes* whatever
  was sealed, including a hand-edited figure — it can authenticate a lie.
- **Validity** — "these outputs were produced by this code over this data on this
  toolchain." Only *execution* establishes this.
- **RCE** decomposes into **Remote** (who triggers) and **Arbitrary** (what authority
  it runs with). Neither is inherent: the document can be inert data that never
  triggers execution, and execution can be confined to a hermetic sandbox.

## Council verdict (4 members, converged)

The document is **inert data** — opening, parsing, rendering never executes a byte.
Execution belongs to a **separate, user-invoked verifier**, never to `open`. When
run, it runs in a **hermetic, network-denied, resource-capped, deterministic**
sandbox the reader deliberately enters. Following the provenance lens: the author
(or a trusted CI) **executes once** and emits a **signed attestation** binding
`source_digest + toolchain + output_digest`; downstream readers **verify
cryptographically, executing nothing**; a zero-trust reader may **opt in** to
re-execute in their own sandbox. Honest limit: an attestation proves the pipeline
ran as stated, never that the science is sound.

## Science — the falsifiable experiment

**Goal.** A reader can be confident the carried project reproduces the sealed
outputs, without trusting the author's word.

**Hypotheses (≥3, falsifiable):**
- **H1 (reproducibility):** re-running the carried project's declared command in a
  clean sandbox yields outputs whose digest equals the sealed attestation digest.
- **H2 (negative control):** if the carried source is altered by even one byte, the
  re-run's output digest differs — reproduction *must fail*. A test that cannot fail
  here is hollow.
- **H3 (determinism):** two independent reproductions of the untouched source yield
  the same digest (the selected outputs are deterministic).

**Deterministic-output selection.** Attest only over outputs free of wall-clock
timestamps and unseeded RNG. The hermetic fixture writes a seeded JSON; the real
`template_code_project` showcase attests a dependency-free digest computed over its
own source tree, so the command re-runs identically offline.

**Pass criterion.** H1 ∧ H3 hold (digests equal across independent clean runs) **and**
H2 fires (tampered source ⇒ digest mismatch ⇒ `reproduce()` returns a mismatch and
`verify_reproduction()` rejects on the source digest). All three are pinned by tests
in `tests/test_reproduce.py`.

## Security invariants (RedTeam-enforced)

1. Nothing in `read_package`, `validate`, `extract`, `verify_provenance`, or
   `verify_reproduction` executes carried code — ever.
2. `reproduce()` executes only under an explicit `allow_execution=True` and runs in a
   scrubbed-environment, resource-capped, timed-out subprocess, network-denied where
   the platform supports it (`sandbox-exec` on macOS, `unshare -n` on Linux),
   in a project+temp-confined directory (macOS seatbelt / Linux bwrap) with no host credentials.
3. The attestation is folded into the signed manifest body, so it is bound to the
   exact source and cannot be swapped.

## What bounds the verifier, not only the child

The confinement list — network denied, writes confined, environment scrubbed, CPU,
address space, process count and file size limited — describes what the *child*
cannot do. None of it reaches the parent, and the parent used to read both of the
child's streams through `subprocess.communicate()`, which buffers them in its own
address space. A carried command that simply printed could therefore exhaust the
machine doing the verifying while every listed control held: 400 MiB of child stdout
grew the verifier's resident set by roughly a gigabyte, and the run was reported as a
success.

Both streams now go to files rather than pipes, which puts the child's own
`RLIMIT_FSIZE` back in the path, and the parent reads only a bounded prefix of stderr
for its failure message. Standard output is discarded, as it always was.

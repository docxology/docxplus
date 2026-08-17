# docs/ — reference documentation

- `format-spec.md` — the docxplus container specification (v2.0; implementable alone):
  conformance, manifest, channels, typed payloads, sealing modes, provenance +
  inclusion proofs + co-signatures, the pinned-key authenticity rule, reproduction
  attestation, and hardened intake.
- `architecture.md` — module map and data flow.
- `design-rationale.md` — the first-principles decomposition: the axes the format
  scales along.
- `reproduction-design.md` — the four-lens (FirstPrinciples / Council / Science /
  RedTeam) design of the reproduction attestation and its security invariants.
- `README.md` — the index: which document answers which question.
- `cli.md` — every subcommand, grouped by purpose.
- `channels.md` — per-channel reference: capacity, visibility, cost, caveats.
- `cookbook.md` — 12 buildable "intelligent document" kinds, each a real recipe,
  including the self-carrying project verified across both containers.
- `security-model.md` — what the format defends, what it does not, residual risks,
  and the execute-only-on-opt-in reproduction invariant.
- `redteam-audit.md` — every adversarial-review finding and its fix, each pinned
  by a regression test. Also records negative results: work that was built,
  measured, and withdrawn rather than shipped.
- `opc-signatures.md` — assessment of whole-package OPC XML-DSig alongside the
  manifest signature, and the reference-set invariant any implementation must hold.
- `standards-report.md` — the standards-first OOXML/ODT research report; every
  structural claim in the codebase traces here. Do not paraphrase spec behavior
  that is not in this report.

Keep these consistent with the code: documented API names, CLI commands, KDF/version
facts, and evaluation numbers must match the shipped `src/`, `docxplus_cli.py`, and
the regenerated artifacts under `output/`. When a claim would drift (a test count, a
coverage %), regenerate and cite the real number rather than freezing a stale one.

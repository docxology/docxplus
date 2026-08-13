# docs/ — reference documentation

- `format-spec.md` — the DOCX+ container specification (v2.0; implementable alone):
  conformance, manifest, channels, typed payloads, sealing modes, provenance +
  inclusion proofs + co-signatures, the pinned-key authenticity rule, reproduction
  attestation, and hardened intake.
- `architecture.md` — module map and data flow.
- `design-rationale.md` — the first-principles decomposition: the axes the format
  scales along.
- `reproduction-design.md` — the four-lens (FirstPrinciples / Council / Science /
  RedTeam) design of the reproduction attestation and its security invariants.
- `cookbook.md` — eight buildable "intelligent document" kinds, each a real recipe.
- `security-model.md` — what the format defends, what it does not, residual risks,
  and the execute-only-on-opt-in reproduction invariant.
- `redteam-audit.md` — every adversarial-review finding (v0.3–v0.5) and its fix,
  each pinned by a regression test.
- `standards-report.md` — the standards-first OOXML/ODT research report; every
  structural claim in the codebase traces here. Do not paraphrase spec behavior
  that is not in this report.

Keep these consistent with the code: documented API names, CLI commands, KDF/version
facts, and evaluation numbers must match the shipped `src/`, `docxplus_cli.py`, and
the regenerated artifacts under `output/`. When a claim would drift (a test count, a
coverage %), regenerate and cite the real number rather than freezing a stale one.

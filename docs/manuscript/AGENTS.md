# docs/manuscript/ — the docxplus format write-up

Modular, token-driven sections (00–04) plus `config.yaml`. The file inventory and the
render pipeline are in [`README.md`](README.md); the full pipeline reference is
[`../manuscript-pipeline.md`](../manuscript-pipeline.md). Rendered output
goes to [`../../output/manuscript/`](../../output/manuscript/AGENTS.md) — never edit there.

**No hard-coded values.** Every drift-prone number is a `{{TOKEN}}` filled from
`src/docxplus/manuscript_vars.variables()`, which reads live code constants and the repository.
To cite a new value, add it to that generator — reading the code constant, never
restating it — and reference the token. Preserve meaningful rendered-output and
diagnostic checks; do not pin incidental source prose or counts.

**No hand-written numbering.** No "Figure 2", no "Definition 3", no "Section 1.4".
Declare a label, reference it, and let the render assign the number. Every formalism
and figure must be referenced at least once and every reference must resolve;
`tests/test_numbering.py` enforces both.

**Bind results before claiming freshness.** Keep generated metric tokens intact.
Only the release owner runs qualification/regeneration; source-only editors do not
run builds/tests/renderers. Historical reports stay labeled historical until actual
receipts bind exact source inputs and outputs. Token hydration alone is not evidence.

**Say what a check proves.** The manuscript's central claims are about verification.
Where a check requires a pinned key, say so; a signed attestation authenticates a
claim, not a witnessed run, and local digest comparison covers only selected
outputs in an observed environment. Tests cannot establish the truth of prose.

**Timeless present-state, told once.** No session logs, no "fixed this pass", no
round-numbered process narration. Negative results stay — work built, measured, and
withdrawn is a finding, and the paper reports it as one.

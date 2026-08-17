# manuscript/ — the docxplus format write-up

Modular, token-driven sections (00–04) plus `config.yaml`. The file inventory and the
render pipeline are in [`README.md`](README.md); the full pipeline reference is
[`../docs/manuscript-pipeline.md`](../docs/manuscript-pipeline.md). Rendered output
goes to [`../output/manuscript/`](../output/manuscript/AGENTS.md) — never edit there.

**No hard-coded values.** Every drift-prone number is a `{{TOKEN}}` filled from
`src/manuscript_vars.variables()`, which reads live code constants and the repository.
To cite a new value, add it to that generator — reading the code constant, never
restating it — and reference the token. `tests/test_manuscript_vars.py` fails the build
on any undefined token or hard-coded drift-prone literal.

**No hand-written numbering.** No "Figure 2", no "Definition 3", no "Section 1.4".
Declare a label, reference it, and let the render assign the number. Every formalism
and figure must be referenced at least once and every reference must resolve;
`tests/test_numbering.py` enforces both.

**Regenerate before you claim.** Result claims must match the artifacts under
`output/`. Run the stage that produces the evidence, then re-render, then change the
sentence — in that order. A number moved by hand is a number no longer tied to a
measurement.

**Say what a check proves.** The manuscript's central claims are about verification.
Where a check requires a pinned key, the prose must say so; where a digest match
attests process rather than correctness, the prose must say that too. Overstating a
verification here is the one error the test suite cannot catch.

**Timeless present-state, told once.** No session logs, no "fixed this pass", no
round-numbered process narration. Negative results stay — work built, measured, and
withdrawn is a finding, and the paper reports it as one.

# output/ — generated; do not edit by hand

Every file here is produced by `./run.sh`. Editing one directly breaks the only
property that makes committing build output worth doing: that the artefacts are the
measurement, not a description of it.

## Rules

- **Never hand-edit a report to make a claim true.** `reports/*.json` is what
  `src/manuscript_vars.py` reads, and therefore what the manuscript asserts. Change the
  code, rerun the stage, and let the number move.
- **Never hand-edit a rendered section.** `manuscript/*.md` here is the token-substituted
  output of `scripts/render_manuscript.py`. The sources are in
  [`../manuscript/`](../manuscript/AGENTS.md).
- **Regenerate before claiming.** If you changed anything a result depends on, run the
  stage that produces it and commit the new artefact alongside the change. A committed
  artefact older than the code it evidences is worse than no artefact.
- **Do not touch `roundtrip/`.** It holds trees extracted from carried payloads so they
  can be diffed against their originals. It is gitignored and rebuilt each run; a
  stray edit there corrupts a fidelity comparison rather than failing it.
- **The dual names are byte-identical.** `report.docx` and `report.docxplus` are the
  same bytes under two names. Never regenerate one without the other, and never let
  them diverge — `tests/test_fileext.py` checks it.

## When output changes unexpectedly

A diff here on an unrelated change usually means non-determinism crept into `src/` — a
wall-clock timestamp, an unsorted iteration, an environment-dependent path. That is a
bug in the builder, not noise to commit past. Deterministic output is an invariant:
same input, same bytes.

# manuscript/ — the DOCX+ format write-up

Modular, token-driven sections (00–04) plus `config.yaml`. See `README.md` for the
render pipeline. Result claims must match the regenerated artifacts under `output/`.

**No hard-coded values.** Every drift-prone number is a `{{TOKEN}}` filled from
`src/manuscript_vars.variables()` (which reads live code constants + the repo). To
cite a new value, add it to that generator (reading the code constant, never
restating it) and reference the token. `tests/test_manuscript_vars.py` fails the
build on any undefined token or hard-coded drift-prone literal. Regenerate variables
and artifacts before changing a result claim.

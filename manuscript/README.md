# manuscript/ — the DOCX+ format write-up (token-driven)

The manuscript is **modular and generated**, not hand-numbered. Each section is a
source file with `{{TOKENS}}`; every drift-prone value (channel count, KDF
parameters, capacities, caps, module/test counts, the evaluation table) is filled at
render time from the live system.

## Sections

| File | Content |
| --- | --- |
| `00_abstract.md` | one-paragraph statement of the format and its capabilities |
| `01_the_format.md` | the two-contract model and the channels |
| `02_implementation.md` | the module layers (package, crypto, payloads/provenance/reproduction, media, composition/intake) |
| `03_evaluation.md` | round-trip integrity, the living manuscript, capacity, conformance, adversarial verification |
| `04_conclusion.md` | what the format achieves and its honest boundaries |
| `config.yaml` | paper metadata (title, authors, version) |

## Rendering

```bash
uv run python scripts/z_generate_manuscript_variables.py   # -> output/data/manuscript_variables.json
uv run python scripts/render_manuscript.py                 # -> output/manuscript/*.md (tokens filled)
```

The renderer fails if any `{{TOKEN}}` is undefined. The values come from
`src/manuscript_vars.variables()`, which reads code constants and the repository —
so changing a constant changes the manuscript, and `tests/test_manuscript_vars.py`
fails the build if a source file hard-codes a value that should be a token.

## Editing rules

* Never type a drift-prone number. Add it to `src/manuscript_vars.variables()` (read
  from the code constant, not restated) and reference the `{{TOKEN}}`.
* Result claims must match the regenerated artifacts under `output/`.
* Prose is timeless present-state, told once (no session logs, no "fixed this pass").

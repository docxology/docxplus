# manuscript/ — the docxplus format write-up (token-driven)

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
| `00_00_cover.md` | cover plate |
| `config.yaml` | paper metadata, formalism kinds, and render settings |
| `formalism.lua` | numbers definitions/theorems/propositions and resolves references to them |
| `preamble.tex` | page geometry and colour definitions |
| `references.bib` | bibliography |

## Rendering

```bash
./run.sh render     # tokens, figures, PDF, and the diagnostic gate
```

or the two steps individually:

```bash
uv run python scripts/z_generate_manuscript_variables.py   # -> output/data/manuscript_variables.json
uv run python scripts/render_manuscript.py                 # -> output/manuscript/*.md, then the PDF
```

The renderer fails if any `{{TOKEN}}` is undefined. The values come from
`src/manuscript_vars.variables()`, which reads code constants and the repository —
so changing a constant changes the manuscript, and `tests/test_manuscript_vars.py`
fails the build if a source file hard-codes a value that should be a token.

It also fails on a pandoc diagnostic even when pandoc itself exits 0, which it does
for an unresolved cross-reference and for a missing figure. The full pipeline,
including how numbering works and what is configurable, is documented in
[`../docs/manuscript-pipeline.md`](../docs/manuscript-pipeline.md).

## Editing rules

* Never type a drift-prone **value**. Add it to `src/manuscript_vars.variables()`
  (read from the code constant, not restated) and reference the `{{TOKEN}}`.
* Never type a **number that names something numbered** — no "Figure 2", no
  "Definition 3", no "Section 1.4". Declare a label and reference it:

  | Thing | Declare | Reference |
  | --- | --- | --- |
  | figure | `{#fig:name}` on the image | `[@fig:name]` |
  | section | `{#sec:name}` on the heading | `[@sec:name]` |
  | formalism | `::: {.theorem #thm:name title="..."}` | `[@thm:name]` |

  Numbering is assigned at render time and every reference follows automatically.
  Add a new numbered kind under `formalism_kinds` in `config.yaml`; no code changes.
* Every formalism and figure must be referenced at least once, and every reference
  must resolve. `tests/test_numbering.py` enforces all of the above.
* Result claims must match the regenerated artifacts under `output/`.
* Prose is timeless present-state, told once (no session logs, no "fixed this pass").

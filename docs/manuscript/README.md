# docs/manuscript/ — the docxplus format write-up (token-driven)

The manuscript is **modular and generated**, not hand-numbered. Each section is a
source file with `{{TOKENS}}`; every drift-prone value (channel count, KDF
parameters, capacities, caps, module/test counts, the evaluation table) is filled at
render time from the live system.

Maintain the manuscript in this directory. The [standalone pipeline](../manuscript-pipeline.md)
hydrates it into `output/manuscript/` and can compile the native PDF. The
tracked output tree records generated snapshots. Edit these authored files
before regenerating their output.

## Sections

| File | Content |
| --- | --- |
| [`00_abstract.md`](00_abstract.md) | one-paragraph statement of the format and its capabilities |
| [`01_the_format.md`](01_the_format.md) | the two-contract model and the channels |
| [`02_implementation.md`](02_implementation.md) | the module layers (package, crypto, payloads/provenance/reproduction, media, composition/intake) |
| [`03_evaluation.md`](03_evaluation.md) | round-trip integrity, the living manuscript, capacity, conformance, adversarial verification |
| [`04_conclusion.md`](04_conclusion.md) | what the format achieves and its honest boundaries |
| [`00_00_cover.md`](00_00_cover.md) | cover plate |
| [`config.yaml`](config.yaml) | paper metadata, formalism kinds, and render settings |
| [`formalism.lua`](formalism.lua) | numbers definitions/theorems/propositions and resolves references to them |
| [Figure registry](figure_registry.json) | Figure labels and accessibility text for the shared renderer |
| [`preamble.md`](preamble.md) | page geometry and colour definitions |
| [`references.bib`](references.bib) | bibliography |
| [`MANUSCRIPT_STATUS.md`](MANUSCRIPT_STATUS.md) | publication-readiness status of this manuscript |

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
`src/docxplus/manuscript_vars.variables()`, which reads constants and actual artifacts.
Rendering/reference/diagnostic checks should exercise those outputs, not freeze
incidental source wording or inventory counts.

Hydration does not establish evidence freshness: source test-function counts are
not executed-pass counts, and report tokens can describe historical runs. Fresh
qualification needs receipts binding exact inputs and regenerated outputs. The
living example hashes selected source, not the full test/figure/manuscript pipeline.

It also fails on a pandoc diagnostic even when pandoc itself exits 0, which it does
for an unresolved cross-reference and for a missing figure. The full pipeline,
including how numbering works and what is configurable, is documented in
[`../manuscript-pipeline.md`](../manuscript-pipeline.md).

Use the [pinned shared-render workflow](../manuscript-pipeline.md#verify-with-the-pinned-template)
for a separate PDF, HTML, and provenance check.

## Editing rules

* Never type a drift-prone **value**. Add it to `src/docxplus/manuscript_vars.variables()`
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

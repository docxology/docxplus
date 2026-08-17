# The manuscript pipeline

How a manuscript source file becomes the published PDF, what is generated rather
than typed, and which failures the pipeline is built to refuse.

Three things in this manuscript are never written by hand: **values**, **numbers**,
and **cross-references**. Each has a mechanism and each has a gate, because all three
are the kind of claim that stays correct until someone edits nearby and then quietly
stops being correct.

---

## The stages

```bash
./run.sh render          # tokens -> figures -> pandoc -> PDF, with the gate
```

| Stage | Script | Produces |
| --- | --- | --- |
| Token generation | `scripts/z_generate_manuscript_variables.py` | `output/data/manuscript_variables.json` |
| Figure generation | `scripts/build_figures.py`, `scripts/03_capacity_figure.py` | `output/figures/*.png` |
| Token substitution | `scripts/render_manuscript.py` | `output/manuscript/*.md` |
| Typesetting | pandoc → XeLaTeX | `output/documents/manuscript.pdf` |

`./run.sh all` includes the render. It has to: the render is the only stage that runs
the diagnostic gate below, and leaving it out meant a broken cross-reference could
reach the committed PDF with every other stage green.

---

## Values: `{{TOKEN}}` substitution

Every drift-prone quantity — channel count, KDF parameters, capacities, caps, test
and module counts — is a token resolved from `src/manuscript_vars.variables()`, which
reads live code constants rather than restating them. Changing a constant changes the
manuscript.

**Gate.** `render_manuscript.py` exits nonzero on any unresolved token, and
`tests/test_manuscript_vars.py` fails the build if a source hard-codes a value that
should be one.

---

## Numbers: automatic, for everything numbered

No number that names a figure, table, section, equation, or formalism appears in any
manuscript source. Two filters assign them at render time:

* **pandoc-crossref** numbers figures, tables, equations, listings, and sections.
  Declare `{#fig:name}` on a figure and write `[@fig:name]`.
* **`manuscript/formalism.lua`** numbers definitions, theorems, propositions, and the
  rest, which pandoc-crossref has no support for. Write a fenced div and reference it
  the same way:

  ```markdown
  ::: {.definition #def:transport-channel title="Transport Channel"}
  A transport channel is a triple of deterministic operations.
  :::

  Each channel below satisfies [@def:transport-channel].
  ```

  which renders as **Definition 3 (Transport Channel).** …, with the reference
  resolving to `Definition 3` and hyperlinking to the block.

Counters are per kind and run in document order, so inserting a block in the middle
renumbers everything after it and every reference follows. There is no number in the
sources that can go stale, because there is no number in the sources.

**Adding a numbered environment is a config change, not a filter edit.** Declare the
class under `formalism_kinds` in [`../manuscript/config.yaml`](../manuscript/config.yaml)
and it is numbered and referenceable immediately. `formalism_reset_level` restarts
counters at a given header level, for a collected volume that reproduces several
works; a standalone paper leaves it at `0`.

**Gates.** `tests/test_numbering.py` rejects a typed number after any numbered noun —
the noun list is derived from the configured kinds and pandoc-crossref's prefixes, so
adding a kind extends the guard rather than escaping it. It also requires every
reference to resolve, every formalism and figure to be referenced at least once, and
no label to be declared twice.

---

## Filter order is load-bearing

```
formalism.lua  →  pandoc-crossref  →  citeproc
```

`[@def:x]`, `[@fig:x]`, and `[@smith2020]` are all pandoc `Cite` nodes; only their
prefix distinguishes them. Each filter must consume its own vocabulary before the
next one sees it.

* Running **citeproc before pandoc-crossref** leaves real citations as literal
  `[@key]` text in the PDF.
* Letting a formalism reference **survive to the citation machinery** emits
  `\citep{def:x}` under natbib and ships `[?]`.

`formalism.lua` therefore consumes every reference it recognises, including broken
ones, which it re-emits as the author's literal text and reports on stderr. A mixed
group such as `[@def:x; @smith2020]` is partitioned: the formalism half is resolved
and the bibliography half handed back as a narrowed `Cite`.

---

## Cross-references: the gate that had to be added

**pandoc reports an unresolved cross-reference on stderr and then exits 0.** So does a
missing figure, and so does an unresolved citation. `render_manuscript.py` used to
discard stderr whenever the exit code was zero, which meant a mistyped
`[@thm:label]` shipped into the PDF as the literal string `[@thm:label]` with nothing
failing: not pandoc, not the render script, not `run.sh`. The same silence dropped a
missing figure and left the PDF a page short of an image.

Every stderr line is now matched against `render.fatal_diagnostics` in
[`../manuscript/config.yaml`](../manuscript/config.yaml) and any hit fails the build.
The patterns name **classes** of diagnostic — `^formalism\.lua:`, `^\[WARNING\]`,
unresolved-reference and undefined-control-sequence forms — rather than the one
message that happened to be found first, so a new instance of the same class is
caught instead of a repeat of the one already fixed.

`render.benign_diagnostics` subtracts from the gate and can only ever subtract. Each
entry must carry a `reason`; a test enforces that, because an unexplained exemption is
how a gate stops being a gate. The correct state of that list is empty.

---

## Configuration

Everything below is read from `manuscript/config.yaml`, so none of it requires editing
Python or Lua.

| Key | Controls |
| --- | --- |
| `paper`, `authors`, `keywords`, `metadata` | front matter |
| `linkReferences`, `nameInLink` | whether crossref references are hyperlinks |
| `formalism_kinds` | which classes are numbered, and their displayed titles |
| `formalism_reset_level` | header level at which counters restart (`0` = never) |
| `render.pdf_engine` | the LaTeX engine |
| `render.number_sections` | automatic section numbering |
| `render.link_color` | link, citation, URL, and TOC colour, defined in `preamble.tex` |
| `render.fatal_diagnostics` | stderr patterns that fail a zero-exit render |
| `render.benign_diagnostics` | reasoned exemptions from the above |

Page geometry and colour definitions live in
[`../manuscript/preamble.tex`](../manuscript/preamble.tex). Link colour is the one
exception that must **not** go there: pandoc emits its own `\hypersetup{...hidelinks}`
after anything `-H` injects, so a preamble `\hypersetup` is silently overridden and
every link renders black. It is passed as a pandoc variable instead.

---

## Authoring rules

* Never type a number that names something numbered. Declare a label; reference it.
* Never type a drift-prone value. Add it to `manuscript_vars.variables()` as a token.
* Figures are referenced as `../output/figures/<name>.png`, relative to `manuscript/`.
  The rendered copies live elsewhere, which is what `--resource-path` reconciles.
* Prose is timeless present-state, told once — no session logs, no "fixed this pass".

See [`../manuscript/README.md`](../manuscript/README.md) for the section inventory.

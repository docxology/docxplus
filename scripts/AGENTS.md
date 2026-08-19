# scripts/ — thin orchestrators

Scripts coordinate I/O, run the domain modules in `src/`, and print output paths to
stdout. They contain **no business logic**. The inventory is in
[`README.md`](README.md); [`../run.sh`](../run.sh) is what actually drives them.

## Rules

- If you are about to write a crypto call, a channel placement, or a format decision
  here, it belongs in `src/`. A script that grows logic also grows an untested surface:
  the coverage gate measures `src/`, not this directory.
- **Never mask an absence as a pass.** `00_preflight.py` exists to say what is missing.
  A stage that cannot do its job must exit non-zero or state plainly that it did
  nothing. The one exception — `build_figures.py` exiting 0 when matplotlib is absent —
  is exactly why every install instruction in this repo insists on the `figures` extra.
  Do not add a second exception.
- No absolute paths, ever. Resolve through `project_paths.py`. A hardcoded home
  directory once made the living manuscript pack an unrelated external exemplar while
  still claiming to carry its own source; `tests/test_manuscript_vars.py` now fails the
  build on any absolute home path in a tracked source.
- Deterministic output. Same input, same bytes. Do not stamp a wall-clock time into
  anything a test or a reader will compare.
- Print the paths you wrote. That output is the interface — `run.sh` composes stages,
  and a stage that writes silently is a stage nobody can verify.
- Ruff clean: CI runs `uvx ruff check src scripts tests` before the tests.

## Adding a stage

1. Number it by pipeline position, or prefix `z_` if it feeds the manuscript.
2. Add a `run_*` function and a `case` arm in `run.sh`, **and** a line in that file's
   usage text. `tests/test_docs.py` fails if the two disagree in either direction — a
   stage missing from the usage, or a usage entry with no implementation.
3. Decide deliberately whether it belongs in `all`. If it is a gate, it does.
4. Add it to [`README.md`](README.md), which the suite checks for completeness.

## The reports are evidence, not logs

`output/reports/*.json` is where the manuscript's numbers are read from, through
`src/docxplus/manuscript_vars.py`. Changing a report's shape changes what the paper can claim,
so regenerate the artifacts and re-render before touching a result. Never hand-edit a
report to make a claim true.

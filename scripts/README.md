# scripts/ — the pipeline stages

Eleven thin orchestrators. Each coordinates I/O, calls the domain modules in `src/`,
and prints the paths it wrote. None contains business logic.

You rarely run them directly — [`../run.sh`](../run.sh) drives them in dependency
order, and `./run.sh help` prints the stage list from the driver itself. The numbering
is the order.

## The numbered pipeline

| Script | What it does | `run.sh` stage |
| --- | --- | --- |
| `00_preflight.py` | reports which capabilities this environment actually has — and reports absence as absence, never as a pass | `preflight` |
| `01_build_example.py` | builds the demonstration document carrying intelligence across every pure channel | `build` |
| `02_roundtrip_report.py` | reads that document back, verifies every module, writes `output/reports/roundtrip.json` | `build` |
| `03_capacity_figure.py` | the per-channel capacity plot (needs matplotlib) | `figure` |
| `04_dossier.py` | builds and verifies the self-verifying dossier — every sealing lineage in one document | `dossier` |
| `05_living_manuscript.py` | the manuscript that carries and reproduces its own source | `living` |
| `06_project_roundtrip.py` | a synthetic project tree, shaped to contain the awkward cases, through both profiles | `roundtrip` |
| `07_template_roundtrip.py` | a **real** external repository through all four emitted formats, diffed file by file | `roundtrip` |

## The manuscript stages

| Script | What it does | `run.sh` stage |
| --- | --- | --- |
| `z_generate_manuscript_variables.py` | derives every documented value from the live system → `output/data/manuscript_variables.json` | `render` |
| `render_manuscript.py` | substitutes tokens, builds the figures, compiles the PDF, and runs the pandoc diagnostic gate | `render` |
| `build_figures.py` | the manuscript plates; invoked by the renderer, not usually alone | — |
| `set_doi.py` | writes a minted Zenodo DOI into CITATION.cff and the metadata files, after resolving it against the Zenodo API; run once per release | — |
| `zenodo_release.py` | reserve / upload / publish the Zenodo record for a release; the reserved DOI is what lets the PDF cite its own record | — |

`render` is the only stage that runs the diagnostic gate, which is why the default
pipeline includes it: pandoc reports an unresolved cross-reference and then exits 0,
so leaving the render out meant a broken reference could reach the committed PDF with
every other stage green.

## Why 06 and 07 both exist

A synthetic tree can be shaped until it passes. A real one cannot. `06` carries a tree
built specifically to contain the hard cases — an executable entrypoint, an empty
directory, a zero-byte file, non-ASCII and spaced filenames — and checks 18 invariants
including cross-profile nesting and byte-identical payload parity. `07` carries the
docxology `template_code_project` (126 files, 15 directories) through `.docx`,
`.docxplus`, `.odt`, and `.odtplus`, reads each back *from that name*, and diffs
against the original. Both, every run.

## Outputs

Everything lands under [`../output/`](../output/README.md): documents in `documents/`,
JSON in `reports/`, plates in `figures/`, derived values in `data/`. Nothing is written
outside the repository, and no script hardcodes a path — they resolve through
`project_paths.py`.

Editing rules: [`AGENTS.md`](AGENTS.md).

# data/ — deliberately empty

This project has no input dataset, and that is a property of the design rather than an
omission.

docxplus's evidence is *generated*: the example document, the dossier, the synthetic
project tree with its awkward cases, and the real external repository carried through
all four formats. Every one is built during `./run.sh` from code and from repositories
resolved at run time. There is nothing to check in and nothing to keep in sync.

The directory is kept because the `template_code_project` layout defines it, and
because an empty, documented `data/` answers "where is the input data?" faster than a
missing one.

- Generated values live in `output/data/` (gitignored, regenerated every render).
- Committed evidence lives in [`../output/`](../output/README.md) (tracked, because it
  backs the manuscript's claims).

If a real input file ever arrives, read [`AGENTS.md`](AGENTS.md) before adding it.

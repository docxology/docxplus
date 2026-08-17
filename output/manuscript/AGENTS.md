# output/manuscript/ — rendered sections; do not edit

These files are the **output** of `scripts/render_manuscript.py`: the sources in
[`../../manuscript/`](../../manuscript/AGENTS.md) with every `{{TOKEN}}` substituted
from `src/manuscript_vars.variables()`. The PDF is compiled from them.

Edit the sources, then `./run.sh render`. An edit made here is overwritten by the next
render, and in the meantime it makes the paper say something the live system does not.

The one thing to check here rather than upstream: if a `{{TOKEN}}` survives
substitution into these files, the render failed to resolve it. That is a build
failure, not a formatting problem — `render_manuscript.py` refuses an undefined token,
and `tests/test_manuscript_vars.py` refuses a hard-coded value that should have been
one.

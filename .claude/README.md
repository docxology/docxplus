# .claude/ — Claude Code configuration

The directory Claude Code reads when a session starts in this repository.

## Contents

`git ls-files .claude` lists two files and nothing else:

- `README.md` — this inventory
- `AGENTS.md` — the editing rules for this directory

No project configuration, no staging directories. The project-scoped agent skill —
the entry points and contracts for working on docxplus itself — lives in
[`../.agents/`](../.agents/README.md).

Editing rules: [`AGENTS.md`](AGENTS.md).

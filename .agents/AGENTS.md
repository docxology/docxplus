# .agents/ — editing the project skill

Contents and purpose: [`README.md`](README.md).

## Rules

- **The skill is a pointer.** It carries entry-point commands and the contracts that
  hold across versions. It must not grow a module map, a channel list, or a subcommand
  table — those are enforced elsewhere, and an unenforced copy here drifts silently
  because no test reads it.
- **Keep `version` in the frontmatter in step with `pyproject.toml`.** Four files
  already agree on the project version and are checked for it; this is the fifth.
- **Both profiles or neither.** If the skill states a contract, it must state it for
  `.docx` and `.odt` alike. The two profiles share their sealing code precisely so
  guidance cannot describe one and quietly omit the other.
- **State the boundaries, not just the capabilities.** Payload-level encryption only,
  execution only via `reproduce.py` with `allow_execution=True`, authenticity only
  under a pinned key, absence skips and failure raises. An agent that learns the verbs
  without the boundaries will produce something that validates and proves nothing.
- Do not add skills for work that has no repository-specific contract. A general
  capability belongs in the operator's own skill collection, not vendored here.

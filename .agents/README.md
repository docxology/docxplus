# .agents/ — the project-scoped agent skill

One skill, [`skills/docxplus/SKILL.md`](skills/docxplus/SKILL.md). It is a *pointer*,
not a second source of truth: an agent that discovers this repository through a skill
loader gets the commands and the hard contracts, then reads the `AGENTS.md` files for
the rest.

| | |
| --- | --- |
| **Loaded by** | agent runtimes that scan `.agents/skills/` |
| **Scope** | this repository only |
| **Says** | how to install, build, read, and validate a docxplus document; the contracts that must not be broken |
| **Does not say** | the module map, the layering rules, the channel recipe — those live in the `AGENTS.md` next to the code |

## The rule that keeps it useful

Anything in `SKILL.md` that duplicates a fact from elsewhere will drift, because
nothing regenerates it. Keep it to the entry points and the invariants that are true
across every version, and let it hand off:

- root [`AGENTS.md`](../AGENTS.md) — the working guide and the directory map
- [`docs/architecture.md`](../docs/architecture.md) — the module map
- [`docs/cli.md`](../docs/cli.md) — the subcommand contract

Editing rules: [`AGENTS.md`](AGENTS.md).

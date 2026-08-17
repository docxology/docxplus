# docs/ — reference documentation

The index is [`README.md`](README.md), and it is enforced: `tests/test_docs.py` fails
the build if a document here is not linked from it, or if it links something that does
not exist. This file used to carry a second, hand-maintained list of the same
documents; it drifted — omitting `manuscript-pipeline.md` — and is gone. Add a
document, add it to the index.

## What each document owns

Ownership matters more than contents, because it decides where a fact belongs.

| Document | Owns |
| --- | --- |
| `standards-report.md` | **what OOXML and ODF actually permit.** Every structural claim anywhere in this repository traces here. Nothing else may paraphrase spec behaviour that is not in this report. |
| `format-spec.md` | the normative container definition — implementable from this document plus the OOXML standard alone |
| `architecture.md` | the module map, layers, and data flow. Authoritative; every `src/*.py` must appear |
| `cli.md` | the subcommand contract. Every `add_parser` must have an entry |
| `channels.md` | per-channel capacity, visibility, cost, caveats, and what does not cross to ODF |
| `design-rationale.md` | the first-principles decomposition — which constraints are real and which inherited |
| `security-model.md` | what the format defends, what it explicitly does not, and the residual risks an integrator carries |
| `reproduction-design.md` | the reproduction attestation and the execution boundary |
| `opc-signatures.md` | whole-package OPC XML-DSig alongside the manifest signature, and the reference-set invariant |
| `manuscript-pipeline.md` | tokens, automatic numbering, filter order, the diagnostic gate, and what is configurable without code |
| `redteam-audit.md` | every confirmed adversarial finding and its fix, each pinned by a regression test |
| `cookbook.md` | buildable document kinds, each a real recipe |

## Rules

- **Cite, do not freeze.** Documented API names, CLI commands, KDF and version facts,
  and evaluation numbers must match the shipped `src/`, `docxplus_cli.py`, and the
  regenerated artifacts under `output/`. When a claim would drift — a test count, a
  coverage percentage, an audit tally — regenerate and cite the real number rather than
  typing a stale one.
- **Say what a check lets a reader conclude.** The distinction between *valid*,
  *self-consistent*, and *authentic* carries the whole security argument. A
  verification described without its pinned-key requirement is a claim this project
  does not make.
- **Record negative results.** `redteam-audit.md` keeps work that was built, measured,
  and withdrawn, and keeps the occasions when an earlier fix turned out to be
  incomplete. That record is a finding, not a log, and it stays.
- **Every document opens with an H1**, and every relative link resolves. Both are
  enforced.
- **The project is `docxplus`.** Only `redteam-audit.md` may quote the pre-rename name,
  because it records the rename as a finding.
- Prose is timeless present-state, told once. No session narration.

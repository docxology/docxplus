# docxplus documentation

Each document answers one question. Start with the one that matches yours.

## Understanding the format

| Doc | Answers |
| --- | --- |
| [`format-spec.md`](format-spec.md) | **What is a docxplus file?** Format 3 manifest, channel, envelope and authenticated migration contracts for OOXML and ODF; implementation structural checks are not complete standards certification. |
| [`channels.md`](channels.md) | **Where do payloads physically live?** Per-channel reference: capacity, visibility, cost, caveats, and what does not cross to ODF. |
| [`design-rationale.md`](design-rationale.md) | **Why is it built this way?** First-principles decomposition, and which constraints are real versus inherited. |
| [`standards-report.md`](standards-report.md) | **What do OOXML and ODF actually permit?** The standards-first research report every structural claim traces back to. |

## Using it

| Doc | Answers |
| --- | --- |
| [`cli.md`](cli.md) | **How do I run it?** Every subcommand, grouped by purpose, with what each verification verb does and does not let you conclude. |
| [`cookbook.md`](cookbook.md) | **What can I build?** Buildable document kinds, each a real recipe. |
| [`architecture.md`](architecture.md) | **How is the code laid out?** Module map, layering, data flow, and the boundary rules. |
| [`manuscript-pipeline.md`](manuscript-pipeline.md) | **How is the paper built?** Token substitution, automatic numbering for figures and formalisms, filter order, the diagnostic gate, and everything configurable without editing code. |

## Trusting it

| Doc | Answers |
| --- | --- |
| [`security-model.md`](security-model.md) | **What does it defend, and what does it not?** Properties, explicit non-goals, and residual risks an integrator must handle. |
| [`reproduction-design.md`](reproduction-design.md) | **How can carried code be trusted?** The attestation design and the execution boundary. |
| [`opc-signatures.md`](opc-signatures.md) | **Why no Word-visible signature?** The whole-package OPC XML-DSig assessment, and the invariant any implementation must hold. |
| [`redteam-audit.md`](redteam-audit.md) | **What has gone wrong?** Every confirmed adversarial finding and its fix, including incomplete earlier fixes and results withdrawn rather than shipped. |

## Conventions

Drift-prone manuscript metrics use tokens from `src/docxplus/manuscript_vars.py`.
Some values come from source inventories, others from available generated reports.
Token hydration is not a freshness/success check: current empirical claims need
source-bound receipts; historical results must remain identified as historical.

The same rule covers *numbering*: no figure, table, section, equation, or formalism
number is written into a source. Labels are declared and referenced, and the numbers
are assigned at render time — see
[`manuscript-pipeline.md`](manuscript-pipeline.md). `AGENTS.md` states the rules for
editing here.

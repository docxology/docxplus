# src/ — docxplus domain modules

All business logic lives here. Modules are imported flat (pyproject `pythonpath`
includes `src`): `import opc`, `import container`, `import channels`.

The module inventory is **not** repeated in this file. It lives in
[`README.md`](README.md) (grouped by layer, for orientation) and in
[`../docs/architecture.md`](../../docs/architecture.md) (authoritative, with data flow).
Both are enforced by `tests/test_docs.py`. A third hand-maintained copy would drift,
and did: this file once described sixteen modules while twenty-one shipped, hiding the
entire ODT profile and the transparency log from anyone who read it.

## Layering

L0 foundations → L1 vocabulary → L2 format → L3 composition → L4 validation →
L5 reference → L6 orchestration (`scripts/`, `src/docxplus/cli.py`, outside this
directory). **A lower layer never imports a higher one.** If a fix seems to need that
import, the logic is in the wrong module.

## Rules

- Generic and deterministic. No wall-clock timestamps, no ambient environment reads,
  no randomness that is not either cryptographic or explicitly seeded.
- Every public function typed and docstringed. The docstring says what the caller may
  conclude, not just what the code does — the difference matters most on the
  verification functions, where "valid" and "authentic" are not the same word.
- Ground every spec claim in [`../docs/standards-report.md`](../../docs/standards-report.md).
  If the behaviour is not in that report, do not assert it.
- No absolute paths. Resolve through `project_paths.py`.
- A missing optional capability skips loudly; a broken one raises. Never `except:
  pass`, never a fallback that makes an absent tool look like a successful run.
- Files carrying keys, Shamir shares, or recovered plaintext go through
  `secure_io.py`, never a bare `write_bytes`.

## Extending

| Adding a… | Touch | Also required |
| --- | --- | --- |
| payload type | register it in `payloads.py` | real round-trip test; entry in `docs/format-spec.md` |
| sealing mode | branch in `container._place` and `DocxPlusReader._unseal`, plus a `sealing.mode` value | the ODT profile inherits it through the shared sealing code — add a test proving that, do not fork the logic |
| channel | implement the `Channel` protocol in `channels/` | see [`channels/AGENTS.md`](channels/AGENTS.md) |
| module | place it in the right layer | an entry in `README.md` **and** `docs/architecture.md`, or the suite fails |

## The two boundaries that are load-bearing

**Execution.** `reproduce.py` is the only module that may run anything, and only
behind an explicit `allow_execution=True`. If a change puts a `subprocess` call on a
read, extract, or verify path, it is wrong regardless of how well it is sandboxed —
`steg_bridge.py`'s bridge is the sole exception, and it is invoked to *decode a
carrier*, never to run carried content.

**Authenticity.** The public key inside a manifest is self-asserted. Any function that
verifies without a caller-pinned key proves self-consistency only, must be named and
documented that way, and must not return a bare `True` that a caller could read as
"authentic".

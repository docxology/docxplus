# docxplus — the Intelligent Document Container

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21983948.svg)](https://doi.org/10.5281/zenodo.21983948)

> A byte-valid OOXML `.docx` that is **also** a modular, signed, encrypted
> intelligence carrier. It opens as an ordinary document in Word, LibreOffice, and
> Google Docs, while carrying structured payloads through the spec-sanctioned
> side-channels that the OOXML/ODF standards actually permit.

**v1.0.1** · MIT · Python ≥ 3.10 · [CHANGELOG](CHANGELOG.md) ·
[docs index](docs/README.md) · [CLI reference](docs/cli.md)

docxplus is a standards-first reference implementation. Every channel it uses is
grounded in a documented feature of ISO/IEC 29500 (OOXML) or its ODF cousin —
custom XML parts, additional package parts, custom document properties, embedded
media — layered with an Ed25519-signed manifest and AES-256-GCM payload
encryption. The media channel bridges to
[docxology/steganographer](https://github.com/docxology/steganographer) so the
intelligence can ride inside the least-significant bits of an image the document
visibly displays.

## Why this is not "just a zip trick"

A `.docx` is an Open Packaging Conventions (OPC) ZIP. The standards report this
project is built on (`docs/standards-report.md`) establishes the exact rules:
mandatory `[Content_Types].xml` + `_rels/.rels`, every part reachable by
following relationships, no duplicate entries, deterministic output. docxplus obeys
all of them — so the surface document stays *conforming*, not merely openable —
and then uses the standard's own extension points to carry more.

## Channels (modules)

| Channel | Where the payload lives | In-spec basis | Good for |
| --- | --- | --- | --- |
| `custom_xml` | `customXml/itemN.xml` | mapped content-control data is "flat Open XML markup" (§3.1) | structured records |
| `package_part` | `intelligence/payloadN.dxp` | "a package may contain additional files" (§2.2) | bulk / encrypted blobs |
| `metadata` | `docProps/custom.xml` property | custom document properties (§9) | short routing tags |
| `stego_media` | LSBs of `word/media/imageN.png` | embedded image parts (§2.1) + LSB stego | payload hidden in a visible figure |
| `mce` | `<mc:Choice>` in `word/document.xml` | MCE AlternateContent (§4.1) | payload in an ignorable extension namespace |

Every module is described by a signed **manifest** (`intelligence/manifest.json`)
— the authoritative list of what the package carries, playing the role ODF
assigns to `META-INF/manifest.xml`.

## What the container carries

The primitives scale on five orthogonal axes (see `docs/design-rationale.md`):

- **Typed payloads** — `bytes`, `text`, `json`, **`project`** (a whole reproducible
  repo packed to a deterministic tar), **`docxplus`** (a nested container). A
  document can literally carry the software that produced it.
- **Cryptographic depth** — `password` (AES-GCM), **multi-recipient** (X25519, one
  file that opens for many key-holders), **k-of-n threshold** (Shamir with
  verifiable shares; no single holder can open it), and **decoy** (two secrets,
  two passwords, structurally indistinguishable from an ordinary sealed module).
- **Composition** — nest a sealed docxplus inside another (matryoshka).
- **Provenance** — a signed **Merkle root** binds the whole module set, and a
  `surface_digest` binds every visible story part; adding, dropping, or swapping a
  module — or editing a footnote — breaks the signature.
- **Covert depth** — the media channel's dual LSB backends, with chi-squared
  steganalysis shipped so you can measure your own carrier's detectability.

`docs/cookbook.md` gives 12 buildable document kinds (self-verifying dossier,
dead-man's envelope, sealed referee packet, provenance ledger, …). The showcase
`scripts/04_dossier.py` builds and verifies the sealing recipes in one file; the
channel and round-trip recipes are covered by their own scripts and tests.

## Both containers, one intelligence layer

The `.odt` profile is not a stub. `OdtPlusBuilder` / `OdtPlusReader` carry the same
signed manifest, the same four sealing lineages, the same Merkle root and surface
digest, and the same co-signature policy as the `.docx` profile — sharing the sealing
and unsealing code rather than reimplementing it, so the two cannot drift apart on
the details that matter under attack.

```bash
uv run docxplus odt-build report.odt --module brief:brief.json --password s3cret \
    --signing-key key.hex
uv run docxplus odt-validate report.odt        # ODF + intelligence conformance
uv run docxplus odt-extract report.odt brief --password s3cret
```

Two OOXML channels have no ODF analogue and do not cross over: `custom_xml` (no
custom XML datastore part) and `mce` (no Markup Compatibility element). ODT payloads
ride as ODF package entries, the unbounded channel.

## Two names, one file

Every export writes the document twice under two names, byte for byte identical:

| | |
| --- | --- |
| `report.docx` / `report.odt` | the **surface contract**. Double-click it; Word or LibreOffice opens it |
| `report.docxplus` / `report.odtplus` | the same bytes, asserting the **intelligence contract** |

An extension is a claim about content. `.docxplus` says "this carries a signed
intelligence layer", and `docxplus validate` is what turns the assertion into a
verdict — either name validates, because they are the same bytes. Writing both also
removes a trap: a lone `.docxplus` on a system with no handler for it looks broken,
while the identical `.docx` beside it does not.

## Carrying a project, and getting it back

The flagship payload type carries a whole directory tree. What that preserves is a
contract, not a hope, and `./run.sh roundtrip` measures it on every run: a project is
carried into **both** containers, extracted, and diffed against the original file by
file, byte by byte, and mode by mode.

| | |
| --- | --- |
| **Preserved** | contents, the executable bit, empty directories, structure, spaced and non-ASCII filenames, zero-byte files |
| **Normalised** | mtimes, uid/gid, every mode bit but execute — determinism is worth more than that metadata |
| **Refused** | symlinks. `is_file()` follows them, so packing one embeds its *target*: a tree with `creds -> ~/.ssh/id_rsa` would ship the key. Pass `follow_symlinks=True` to say so deliberately |
| **Excluded** | `.git`, `.venv`, `output`, `__pycache__`, and the rest of the build junk |

```bash
./run.sh roundtrip      # two suites, run back to back
```

The first carries a *synthetic* tree built to contain the awkward cases — an executable
entrypoint, an empty directory, a zero-byte file, non-ASCII and spaced filenames — through
both profiles, checking 18 invariants including cross-profile nesting and byte-identical
payload parity. The second carries a *real* external repository (the docxology
`template_code_project`, 126 source files) through all four emitted formats:

| Artefact | |
| --- | --- |
| `output/documents/template_code_project.docx` | surface name, OOXML |
| `output/documents/template_code_project.docxplus` | same bytes, intelligence name |
| `output/documents/template_code_project.odt` | surface name, ODF |
| `output/documents/template_code_project.odtplus` | same bytes, intelligence name |

Each is validated, read back *from that name*, and diffed against the original. A
synthetic tree can be shaped to pass; a real one cannot, which is why both run.

Those artefacts are committed. `output/` is tracked rather than ignored, because the
documents and reports there are the evidence for the manuscript's claims — a reader
should be able to clone and inspect them instead of taking the numbers on trust.

The harness also covers what a single round trip cannot: the same tree packing to
*byte-identical* payloads in both containers, and a signed `.docx` nested inside a
signed `.odt`, opened by a dispatcher that reads the container's own magic rather than
trusting the caller.

## Trust: what a reader can check, and what it costs

Every verification path is available *without executing a byte*. That is the
organising rule, not an optimisation.

- **Signed manifest + co-signatures.** `verify_provenance(expected_public_key=…)`
  and `verify_cosigners([keys])` enforce a signing policy — author AND institution.
  Authenticity always requires the caller to pin the key they trust: the key inside
  the manifest is self-asserted, so an unpinned check proves self-consistency only.
- **Reproduction attestation.** A `project` module can bind its source to a
  deterministic output digest, so a reader can trust results *follow from the code*.
  `verify_reproduction(slot)` is cryptographic and executes nothing;
  `reproduce(slot, dest, allow_execution=True)` is the opt-in path that re-runs the
  attested command in a best-effort hermetic sandbox and compares digests. A digest
  match attests process, never that the science is sound.
- **Transparency log.** Attestations chain into an append-only log with Merkle
  inclusion proofs. A chain alone proves only self-consistency, so authenticity
  rests on a **signed tree head** over `(log_size, root_hash)`;
  `docxplus verify-transparency` checks the chain, the head under a pinned signer,
  and per-entry proofs, and says UNAUTHENTICATED out loud when no head is supplied.
- **Hardened intake.** `intake.safe_open(bytes, policy)` opens untrusted `.docx`
  under caps and reports threats — external relationships, macros, `altChunk`
  imports — without executing anything. CLI: `docxplus scan file.docx [--strict]`.

## Adversarial review

Fourteen cycles of adversarial review ([`docs/redteam-audit.md`](docs/redteam-audit.md))
have closed 88 confirmed findings, each pinned by a regression test. The record is
kept in full, including the two occasions when an earlier fix turned out to be
incomplete, and one negative result: a sample-pair steganalysis estimator that was
built, measured, found mis-calibrated, and withdrawn rather than shipped.

Those two counts are not typed by hand. `src/docxplus/manuscript_vars.py` derives them from
the audit record itself, and `tests/test_docs.py` fails the build if this paragraph
disagrees with the live value — the same rule the manuscript follows.

## Quick start

```bash
uv venv && uv pip install -e '.[dev,media,figures]'
./run.sh                      # preflight, tests, example, dossier, round trips, manuscript

# Or use the CLI directly:
uv run docxplus build report.docx --text "Quarterly summary" \
    --module brief:custom_xml:brief.json --password s3cret
uv run docxplus inspect report.docx
uv run docxplus extract report.docx brief --password s3cret --out brief.json
uv run docxplus validate report.docx
```

Three extras, and what each one buys: `dev` is pytest and the coverage gate, `media`
is Pillow for the LSB stego channel, `figures` is matplotlib for the manuscript
plates. Install all three. `scripts/build_figures.py` *skips* when matplotlib is
absent rather than failing, so a render on a `dev,media`-only environment silently
reuses whatever figures are already committed — green, and not what you measured.
CI installs all three for exactly that reason.

## Security posture

Payloads are encrypted at the *payload* level (AES-256-GCM, keyed by memory-hard
**Scrypt** by default, with **Argon2id** available and PBKDF2-HMAC-SHA512 kept for
compatibility — the MS-OFFCRYPTO agile lineage), **not** as whole-package OOXML
encryption, so the document stays a valid, openable Office file. Readers cap
attacker-supplied KDF work factors *and* the memory they imply, so a hostile
envelope cannot turn opening a file into a denial-of-service. The manifest is
Ed25519-signed for provenance. See `docs/security-model.md` for the full threat
model, grounded in the USENIX 2022/2023 analyses the standards report cites.

## Layout

Every directory carries two guides, and they answer different questions: `README.md`
is for a person deciding what is in there, `AGENTS.md` is the rules that bind anyone —
human or agent — editing it.

| Directory | What lives there | Guides |
| --- | --- | --- |
| [`src/`](src/docxplus/README.md) | the 21 tested domain modules plus `channels/`; all business logic | [README](src/docxplus/README.md) · [AGENTS](src/docxplus/AGENTS.md) |
| [`src/docxplus/channels/`](src/docxplus/channels/README.md) | the five side-channels behind one `Channel` protocol | [README](src/docxplus/channels/README.md) · [AGENTS](src/docxplus/channels/AGENTS.md) |
| [`scripts/`](scripts/README.md) | 11 thin orchestrators; the stages `run.sh` drives | [README](scripts/README.md) · [AGENTS](scripts/AGENTS.md) |
| [`tests/`](tests/README.md) | the real-data, no-mocks suite behind the 90% gate | [README](tests/README.md) · [AGENTS](tests/AGENTS.md) |
| [`docs/`](docs/README.md) | spec, architecture, security model, cookbook, audit | [README](docs/README.md) · [AGENTS](docs/AGENTS.md) |
| [`manuscript/`](manuscript/README.md) | the token-driven format write-up | [README](manuscript/README.md) · [AGENTS](manuscript/AGENTS.md) |
| [`output/`](output/README.md) | committed evidence: documents, figures, reports | [README](output/README.md) · [AGENTS](output/AGENTS.md) |
| [`data/`](data/README.md) | deliberately empty — inputs are generated, not stored | [README](data/README.md) · [AGENTS](data/AGENTS.md) |
| [`.github/`](.github/README.md) | the CI gates, in the order they fail | [README](.github/README.md) · [AGENTS](.github/AGENTS.md) |
| [`.agents/`](.agents/README.md) | the project-scoped agent skill | [README](.agents/README.md) · [AGENTS](.agents/AGENTS.md) |

Top-level files: `src/docxplus/cli.py` (the CLI, 19 subcommands — see
[`docs/cli.md`](docs/cli.md)), `run.sh` (the pipeline driver, `./run.sh help` for the
stages), `pyproject.toml`, `CHANGELOG.md`, and the citation metadata
(`CITATION.cff`, `codemeta.json`, `.zenodo.json`).

The CLI's own surface is not restated here — it drifted once by omitting `verify`,
the authenticity verb, which is the worst possible command to leave out of a summary.
`docs/cli.md` is the contract, and `tests/test_docs.py` fails if a subcommand exists
without an entry there.

## Documentation

| Doc | What it covers |
| --- | --- |
| [`docs/README.md`](docs/README.md) | **start here** — which document answers which question |
| [`docs/cli.md`](docs/cli.md) | every subcommand, grouped by purpose |
| [`docs/channels.md`](docs/channels.md) | per-channel reference: capacity, visibility, cost, caveats |
| [`docs/format-spec.md`](docs/format-spec.md) | the container specification (implementable alone) |
| [`docs/architecture.md`](docs/architecture.md) | module map and data flow |
| [`docs/design-rationale.md`](docs/design-rationale.md) | first-principles decomposition |
| [`docs/security-model.md`](docs/security-model.md) | defenses, non-defenses, residual risks |
| [`docs/reproduction-design.md`](docs/reproduction-design.md) | the four-lens reproduction design |
| [`docs/cookbook.md`](docs/cookbook.md) | 12 buildable document kinds |
| [`docs/manuscript-pipeline.md`](docs/manuscript-pipeline.md) | how the paper is built: tokens, automatic numbering, the diagnostic gate |
| [`docs/redteam-audit.md`](docs/redteam-audit.md) | every adversarial finding and its fix |
| [`docs/opc-signatures.md`](docs/opc-signatures.md) | whole-package OPC signature integration assessment |
| [`docs/standards-report.md`](docs/standards-report.md) | the standards-first OOXML/ODT research report |

## License

MIT. See `LICENSE`.

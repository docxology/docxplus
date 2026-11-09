# docxplus — the Intelligent Document Container

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21983948.svg)](https://doi.org/10.5281/zenodo.21983948)

> An OOXML `.docx` or ODF `.odt` carrying a modular, signed, encrypted
> intelligence layer through documented package extension points. Structural
> validation is not a universal Office-application interoperability guarantee.

[Latest release](https://github.com/docxology/docxplus/releases/latest) · MIT · Python >= 3.11 · [CHANGELOG](CHANGELOG.md) ·
[docs index](docs/README.md) · [CLI reference](docs/cli.md)

docxplus is a standards-first reference implementation. Every channel it uses is
grounded in a documented feature of ISO/IEC 29500 (OOXML) or its ODF cousin —
custom XML parts, additional package parts, custom document properties, embedded
media — layered with a key-family-authenticated signed manifest and AES-256-GCM
payload encryption. The media channel bridges to
[docxology/steganographer](https://github.com/docxology/steganographer) so the
intelligence can ride inside the least-significant bits of an image the document
visibly displays.

## Why this is not "just a zip trick"

A `.docx` is an Open Packaging Conventions (OPC) ZIP. The standards report
[`docs/standards-report.md`](docs/standards-report.md) grounds the extension points.
The implementation checks selected package graphs, namespaces and intelligence
invariants; it does not implement complete ISO schema validation or prove that
every Office application accepts every generated file. Deterministic archive
serialization is a project policy, not an OPC conformance requirement.

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

- **Typed payloads** — `bytes`, `text`, `json`, **`project`** (a selected directory
  tree packed to a deterministic tar), and **`docxplus`** (a nested container).
  Carrying source does not by itself reproduce its results.
- **Cryptographic depth** — `password` (AES-GCM), **multi-recipient** (X25519
  or genuine X25519 + ML-KEM-768), **k-of-n threshold** (Shamir with signed
  full-share digest commitments), and **decoy** (two bounded password frames
  sharing a KDF and power-of-two padding policy, not universal deniability).
- **Composition** — nest a sealed docxplus inside another (matryoshka).
- **Provenance** — a signed **Merkle root** binds the whole module set, and a
  profile-separated typed/count/length/hash `surface_digest` binds the package graph;
  adding, dropping or swapping a module — or editing a footnote — breaks the signature.
- **Covert depth** — dual LSB backends, with a chi-squared heuristic for inspecting
  selected carriers, not a calibrated presence probability or absence guarantee.

`docs/cookbook.md` gives buildable document kinds (self-verifying dossier,
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
uv run docxplus odt-validate report.odt        # structural + intelligence checks
uv run docxplus odt-extract report.odt brief --password s3cret
```

Two OOXML channels have no ODF analogue and do not cross over: `custom_xml` (no
custom XML datastore part) and `mce` (no Markup Compatibility element). ODT payloads
ride as ODF package entries, bounded by archive intake limits, or as `odt_metadata`
user-defined fields in `meta.xml` for short strings.

## Two names, one file

Every export writes the document twice under two names, byte for byte identical:

| | |
| --- | --- |
| `report.docx` / `report.odt` | the **surface contract**; application/version-specific openability requires its own evidence |
| `report.docxplus` / `report.odtplus` | the same bytes, asserting the **intelligence contract** |

An extension is a claim about content. `.docxplus` asserts an intelligence
manifest, not authenticity. `docxplus validate` checks selected structural and
integrity obligations under either name; only caller-pinned verification authenticates it.
Writing both names also avoids the missing-handler trap of a lone `.docxplus`;
the ordinary `.docx` surface name remains available beside it.

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

The first carries a *synthetic* tree selected to contain awkward cases — an executable
entrypoint, an empty directory, a zero-byte file, non-ASCII and spaced filenames —
through both profiles, including cross-profile nesting and payload parity. The
second carries the selected external `template_code_project` snapshot through
the emitted surface/intelligence names; its inventory comes from its report:

| Artefact | |
| --- | --- |
| `output/documents/template_code_project.docx` | surface name, OOXML |
| `output/documents/template_code_project.docxplus` | same bytes, intelligence name |
| `output/documents/template_code_project.odt` | surface name, ODF |
| `output/documents/template_code_project.odtplus` | same bytes, intelligence name |

Each is read back *from that name* and compared against the captured source.
Neither a synthetic fixture nor one external project is a general fidelity proof.
Committed `output/` artifacts are historical evidence unless a source-bound fresh
release receipt identifies the exact inputs and successful run that produced them.

Capture uses retained source descriptors and bounded reads, not a global snapshot:
quiesce the tree if cross-file consistency matters. Extraction validates first and
publishes a fresh private 0700 root into an absent/empty destination. Platforms
without descriptor-relative no-follow directory support refuse safe project I/O.

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
- **Reproduction attestation.** A `project` module binds carried bytes to a signed
  claim about a recipe, toolchain and output digest, not proof of execution.
  `verify_reproduction(slot, expected_public_key=…)` authenticates that claim without
  executing it; without pinning, only `self_consistent` may be true.
  `reproduce(slot, dest, allow_execution=True)` explicitly runs the recipe under
  available confinement and compares digests. Missing confinement refuses execution.
  Readable host files remain exposed; use a disposable isolated environment for
  untrusted code. The living example hashes selected source; it does not rerun the
  full test/figure/manuscript pipeline or prove scientific reproducibility.
- **Transparency log.** Attestations chain into an append-only log with Merkle
  inclusion proofs. A chain alone proves only self-consistency, so authenticity
  rests on a **signed tree head** over `(log_size, root_hash)`;
  `docxplus verify-transparency` checks the chain, the head under a pinned signer,
  and per-entry proofs, and says UNAUTHENTICATED out loud when no head is supplied.
- **Hardened intake.** `intake.safe_open(bytes, policy)` opens untrusted `.docx`
  under caps and reports threats — external relationships, macros, `altChunk`
  imports — without executing anything. CLI: `docxplus scan file.docx [--strict]`.

## Adversarial review

[`docs/redteam-audit.md`](docs/redteam-audit.md) records confirmed findings,
incomplete earlier mitigations, rejected findings and negative results. Counts
generated by `src/docxplus/manuscript_vars.py` describe that record, not a fresh
passing suite or a security proof. Current integration evidence and unavailable
release/interoperability proof are distinguished there from historical results.

## Quick start

```bash
uv sync --locked --all-extras
./run.sh                      # preflight, tests, example, dossier, round trips, manuscript

# Or use the CLI directly:
uv run docxplus build report.docx --text "Quarterly summary" \
    --module brief:custom_xml:brief.json --password s3cret
uv run docxplus inspect report.docx
uv run docxplus extract report.docx brief --password s3cret --out brief.json
uv run docxplus validate report.docx
```

The extras, and what each one buys: `dev` is pytest and the coverage gate, `media`
is Pillow for the LSB stego channel, `figures` is matplotlib for the manuscript
plates. Install all of them. `scripts/build_figures.py` *skips* when matplotlib is
absent rather than failing, so a render on a `dev,media`-only environment silently
reuses whatever figures are already committed — green, and not what you measured.
CI installs all of them for exactly that reason.

### Isolated Linux release validation

`scripts/validate_release.py` separates network-enabled image provisioning from
offline release computation. Use independently copied, privately captured source
snapshots, not live vault mounts. The input manifest and capture rules are in
[`scripts/README.md`](scripts/README.md#release-validation).

```bash
python3 scripts/validate_release.py provision --inputs "$MANIFEST" \
    --output "$PRIVATE/provision-new" --docker-context "$DOCKER_CONTEXT"
python3 scripts/validate_release.py validate --inputs "$MANIFEST" \
    --provision-record "$PRIVATE/provision-new/provision.json" \
    --output "$PRIVATE/validation-new" --docker-context "$DOCKER_CONTEXT"
```

The disposable Linux container must qualify real bubblewrap, network denial and
read-only source/runtime before running the unchanged coverage floor, full
pipeline, renderer, real Rust backend, template roundtrips and installed-wheel
smoke. No host bind/socket mounts, capabilities, inherited credentials or global
security changes. Container-local `seccomp=unconfined` permits nested user
namespaces; the other enforced controls and negative probes are mandatory.
This is a separate qualification workflow, not a way to disable production
sandboxing or turn capability absence into a passing release.

Docker's default proc/kernel path masks remain required; if they prevent mounting
private procfs, validation refuses rather than weakening the sandbox. Only within
an operator-controlled isolated **Linux rootless VM**, validation can explicitly
select `--allow-unmasked-procfs-for-daemon "$VERIFIED_DAEMON_ID"`. The ID must equal
the currently verified, provision-bound daemon ID; it is not a context name.
This container-only exception removes Docker's outer proc **and kernel-path**
masking/read-only defenses (`systempaths=unconfined`), not production bubblewrap's
private PID/proc or any other confinement control. There is no automatic fallback
or host/global policy change. See the operator eligibility and evidence
requirements in [`scripts/README.md`](scripts/README.md#release-validation);
fresh actual denial/custody probes are required and do not certify arbitrary
kernels or macOS detached-process custody.

The Office gate renders actual installed-wheel DOCX/ODT exports, saves each through
LibreOffice Writer, then renders the saved package again. Its
`docxplus.release-office.v1` receipt records tool versions/hashes and original/saved
document, PDF, extracted text and nonblank raster hashes/sizes. Visible sentinels
must remain and hidden sentinels must not render. **Payload survival or signature
validity after an Office edit is not asserted**: saving may strip or rewrite them.
Qualification remains conditional until the release owner imports a successful
receipt bound to the final sources; these gates are not a current pass claim.

## Security posture

Payloads are encrypted at the *payload* level (AES-256-GCM, keyed by memory-hard
**Scrypt** by default, with **Argon2id** available and PBKDF2-HMAC-SHA512 kept for
compatibility — the MS-OFFCRYPTO agile lineage), **not** as whole-package OOXML
encryption, so the public surface is not credential-gated. Readers bound declared
KDF work and memory, but those bounds are not a total-process resource guarantee.
Format 3.0 is an authenticated breaking migration: format-2 manifests and simulated
hybrid material are refused; rebuild and re-sign trusted inputs rather than editing
a version field. Both profiles support Ed25519 or genuine Ed25519 + ML-DSA-65
manifest/co-signing, and DXE2 classical or DXE3 all-hybrid recipient sealing through
`cryptography >= 50`. Portable typed `DXHK` private keys distinguish signing from
recipient suites and check derived public halves. Mixed recipient families and
ambiguous keys refuse; pin the entire composite public identity. Component standards
do not certify this product. See [`docs/security-model.md`](docs/security-model.md).

## Layout

Every directory carries two guides, and they answer different questions: `README.md`
is for a person deciding what is in there, `AGENTS.md` is the rules that bind anyone —
human or agent — editing it.

| Directory | What lives there | Guides |
| --- | --- | --- |
| [`src/`](src/README.md) | the import root; holds no modules of its own | [README](src/README.md) · [AGENTS](src/AGENTS.md) |
| [`src/docxplus/`](src/docxplus/README.md) | domain modules plus `channels/`; all business logic | [README](src/docxplus/README.md) · [AGENTS](src/docxplus/AGENTS.md) |
| [`src/docxplus/channels/`](src/docxplus/channels/README.md) | the five side-channels behind one `Channel` protocol | [README](src/docxplus/channels/README.md) · [AGENTS](src/docxplus/channels/AGENTS.md) |
| [`scripts/`](scripts/README.md) | thin pipeline and isolated-release orchestrators | [README](scripts/README.md) · [AGENTS](scripts/AGENTS.md) |
| [`tests/`](tests/README.md) | the real-data, no-mocks suite behind the 90% gate | [README](tests/README.md) · [AGENTS](tests/AGENTS.md) |
| [`docs/`](docs/README.md) | spec, architecture, security model, cookbook, audit | [README](docs/README.md) · [AGENTS](docs/AGENTS.md) |
| [`docs/manuscript/`](docs/manuscript/README.md) | the token-driven format write-up | [README](docs/manuscript/README.md) · [AGENTS](docs/manuscript/AGENTS.md) |
| [`output/`](output/README.md) | committed evidence: documents, figures, reports | [README](output/README.md) · [AGENTS](output/AGENTS.md) |
| [`data/`](data/README.md) | deliberately empty — inputs are generated, not stored | [README](data/README.md) · [AGENTS](data/AGENTS.md) |
| [`.github/`](.github/README.md) | the CI gates, in the order they fail | [README](.github/README.md) · [AGENTS](.github/AGENTS.md) |
| [`.agents/`](.agents/README.md) | the project-scoped agent skill | [README](.agents/README.md) · [AGENTS](.agents/AGENTS.md) |

Top-level files: `src/docxplus/cli.py` (the CLI — see
[`docs/cli.md`](docs/cli.md)), `run.sh` (the pipeline driver, `./run.sh help` for the
stages), `pyproject.toml`, `CHANGELOG.md`, and the citation metadata
(`CITATION.cff`, `codemeta.json`, `.zenodo.json`).

The CLI's own surface is not restated here — it drifted once by omitting `verify`,
the authenticity verb, which is the worst possible command to leave out of a summary.
`docs/cli.md` is the contract; update it alongside actual CLI behavior.

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
| [`docs/cookbook.md`](docs/cookbook.md) | buildable document kinds |
| [`docs/manuscript-pipeline.md`](docs/manuscript-pipeline.md) | how the paper is built: tokens, automatic numbering, the diagnostic gate |
| [`docs/redteam-audit.md`](docs/redteam-audit.md) | every adversarial finding and its fix |
| [`docs/opc-signatures.md`](docs/opc-signatures.md) | whole-package OPC signature integration assessment |
| [`docs/standards-report.md`](docs/standards-report.md) | the standards-first OOXML/ODT research report |

## License

MIT. See `LICENSE`.

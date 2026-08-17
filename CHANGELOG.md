# Changelog

All notable changes to docxplus. Format follows [Keep a Changelog](https://keepachangelog.com/);
versioning is [semantic](https://semver.org/).

Findings referenced by number are recorded in full in [`docs/redteam-audit.md`](docs/redteam-audit.md).

## [Unreleased]

## [1.0.1] — 2026-08-17

### Fixed

- **The package was not installable.** `pip install docxplus` reported success and
  left nothing importable: the modules lived in `src/` as flat top-level files that
  no wheel shipped, `[tool.uv] package = false` kept it out of any build, and the
  console script crashed on `from docxplus_cli import main`. Anyone who installed
  v1.0.0 got an empty package, which the tests never caught because they ran from a
  checkout with `src/` on the path — the one configuration where it worked.

### Changed

- Modules moved under a real `docxplus` package and now import each other
  relatively, so the layout is relocatable and a checkout behaves like an install.
  Flat imports (`import crypto`) become `from docxplus import crypto`.
- The CLI moved into the package as `docxplus.cli`; invoke it with
  `python -m docxplus.cli`, or through the `docxplus` console script.
- `project_root()` finds the checkout by looking for it rather than by counting
  parent directories, which is what broke when the modules gained a level.
- Coverage now follows the CLI into the subprocesses that exercise it. Measuring the
  parent only, the most end-to-end-tested module in the repository reported 0%.

## [1.0.0] — 2026-08-17

First stable release. Cleared every category-A and category-B blocker from the
publication gate; see `docs/redteam-audit.md` v1.0.0 for the ten findings.

### Security

- **The MCE channel emitted schema-invalid markup** — `<mc:AlternateContent>` landed
  after the body-level `<w:sectPr>`, violating `CT_Body`, on the one channel that
  writes into the main story part. Insertion moved before the sectPr; the fallback is
  now empty, so concealing a module adds no visible paragraph.
- **The builder emitted packages its own reader rejected** as zip bombs, making
  compressible payloads above 1 MiB unrecoverable through the public API.
- **`open_nested` had no depth cap on the ODT side**, so one hop reset the OPC
  matryoshka budget.
- **The transparency log had no consistency proof**, so append-only was unverifiable:
  an operator could drop an entry and re-sign. `consistency_proof` /
  `verify_consistency` close it, with `--consistent-with` and `--emit-proof`.
- `verify_reproduction` no longer reports `verified: True` for a module carrying no
  attestation.

### Added

- `docxplus verify` — the authenticity command. Checks signature, package binding, and
  co-signer policy, and **exits nonzero without `--expected-key`**, because integrity
  is not authenticity.
- `--kdf {scrypt,argon2id,pbkdf2}` on both build commands. Argon2id had been documented
  in the present tense while no code path could produce it.
- The stego carrier is now inserted as a `<w:drawing>`, so the figure the channel
  claims the document displays is actually displayed.

### Fixed

- Evaluation prose claimed the dossier "exercises every operational mode"; coverage is
  now derived into tokens and states exactly what the generated table shows.
- Cookbook recipe 10 claimed a signed ODT manifest its code could not produce; two
  sections were numbered 10; the README claimed one script builds every recipe.

## [0.7.0] — 2026-08-16

### Security

- **Critical — the signature bound filenames, not the part graph.** `_compute_surface_digest`
  selected the signed surface by name prefix, while OPC resolves the rendered document through
  the officeDocument *relationship*. An attacker could add a second document part, repoint that
  relationship, and leave every signed byte untouched: `verify_provenance(expected_public_key=…)`
  returned true while a renderer displayed attacker text. The digest now binds every part, the
  content-type map, and every relationship edge.
- **High — `pack_project` silently dereferenced symlinks**, embedding the target's bytes under
  the link's name. Symlinks are refused unless `follow_symlinks=True` is passed explicitly.
- **High — the ODT reader accepted duplicate and colliding entry names**, letting a signed `.odt`
  carry two `content.xml` streams. Both checks ported from the OPC reader.
- **High — `pack_project` was never deterministic**: `tar.gzip_mtime = 0` set an attribute
  `TarFile` does not define, so the gzip header carried wall-clock time. Now gzipped explicitly
  with `mtime=0`.

### Added

- `.docxplus` / `.odtplus` extensions. Every export writes the document under both its surface
  and its docxplus name, byte-identical (`src/docxplus/fileext.py`).
- ODT intelligence layer parity: `add_project`, `add_nested`, `verify_reproduction`, `reproduce`,
  and `open_document` profile dispatch (`src/docxplus/odt_container.py`).
- ODF threat intake: `intake.scan_odt` / `safe_open_odt`, CLI `docxplus odt-scan`.
- `scripts/06_project_roundtrip.py` — 18 invariants carrying a project through both containers.
- CLI: `odt-build`, `odt-inspect`, `odt-extract`, `odt-validate`, `odt-scan`, `analyze-carrier`,
  `transparency-append`.
- Project payloads preserve the executable bit and empty directories.

### Changed

- Project renamed to **docxplus** throughout.
- The living manuscript now carries *this* repository rather than an external exemplar at a
  hardcoded absolute path, which made the "carries its own source" claim false off one machine.
- Release metadata (`pyproject.toml`, `CITATION.cff`, `codemeta.json`, `.zenodo.json`) is version
  -consistent, enforced by a test.

## [0.6.x] — earlier

Transparency-log signed tree heads; chi-squared steganalysis; ODT intelligence layer;
OPC signature-coverage guard; scrypt memory ceiling; VSS downgrade refusal. See
`docs/redteam-audit.md` v0.6–v0.6.3.

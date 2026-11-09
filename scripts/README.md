# scripts/ — the pipeline stages

Thin pipeline and release orchestrators coordinate I/O, call the domain modules in
`src/`, and print the paths they wrote. None reimplements business logic.

You rarely run them directly — [`../run.sh`](../run.sh) drives them in dependency
order, and `./run.sh help` prints the stage list from the driver itself. The numbering
is the order.

## The numbered pipeline

| Script | What it does | `run.sh` stage |
| --- | --- | --- |
| `00_preflight.py` | reports which capabilities this environment actually has — and reports absence as absence, never as a pass | `preflight` |
| `01_build_example.py` | builds the demonstration document carrying intelligence across every pure channel | `build` |
| `02_roundtrip_report.py` | reads that document back, verifies every module, writes `output/reports/roundtrip.json` | `build` |
| `03_capacity_figure.py` | the per-channel capacity plot (needs matplotlib) | `figure` |
| `04_dossier.py` | builds and verifies the self-verifying dossier — every sealing lineage in one document | `dossier` |
| `05_living_manuscript.py` | carries the selected repository tree and attests a dependency-free source-hash demonstration, not full-project reproduction | `living` |
| `06_project_roundtrip.py` | a synthetic project tree, shaped to contain the awkward cases, through both profiles | `roundtrip` |
| `07_template_roundtrip.py` | a **real** external repository through all four emitted formats, diffed file by file | `roundtrip` |

## The manuscript stages

| Script | What it does | `run.sh` stage |
| --- | --- | --- |
| `z_generate_manuscript_variables.py` | derives every documented value from the live system → `output/data/manuscript_variables.json` | `render` |
| `render_manuscript.py` | substitutes tokens, builds the figures, compiles the PDF, and runs the pandoc diagnostic gate | `render` |
| `build_figures.py` | the manuscript plates, drawn by `src/docxplus/manuscript_figures.py`; invoked by the renderer, not usually alone | — |
| `set_doi.py` | writes a minted Zenodo DOI into CITATION.cff and the metadata files, after resolving it against the Zenodo API; run once per release | — |
| `zenodo_release.py` | reserve / upload / publish the Zenodo record for a release; the reserved DOI is what lets the PDF cite its own record | — |

`render` is the only stage that runs the diagnostic gate, which is why the default
pipeline includes it: pandoc reports an unresolved cross-reference and then exits 0,
so leaving the render out meant a broken reference could reach the committed PDF with
every other stage green.

## Why 06 and 07 both exist

`06` carries a selected synthetic fixture containing an executable entrypoint,
empty directory, zero-byte file and non-ASCII/spaced filenames; it checks the
reported invariants, cross-profile nesting and payload parity. `07` carries the
captured `template_code_project` snapshot through `.docx`, `.docxplus`, `.odt` and
`.odtplus`, reading each name and comparing with its source. Inventory counts belong
to the generated report, not a hardcoded example. Neither selection proves general
fidelity. Committed reports are historical unless tied to a fresh source-bound run.

Comparisons read the actual exported artifacts and enumerate both directions:
extra extracted entries fail alongside missing/changed content, execute bits and
empty directories. `reference_docs.build_reference_dossier()` returns one
`ReferenceDossier` (serialized data and ephemeral verification credentials);
`04_dossier.py` and manuscript tables use that specimen, not independent rebuilds.
Its source uses Argon2id, nested annex default Scrypt; source extraction itself is
not reproduction-attested. Living/synthetic recipes own their separate claims.

## Release validation

| Script | Purpose | Invocation |
| --- | --- | --- |
| `validate_release.py` | Bind private source snapshots and acquired image identity; supervise bounded offline Docker compute, verify controls and collect evidence | `python3 scripts/validate_release.py provision\|validate --help` |
| `release_guest.py` | Image-only qualification, unchanged full checks/pipeline, installed-artifact smoke and bounded evidence export | [`../Dockerfile.release-validation`](../Dockerfile.release-validation) entrypoint |

These are release orchestration, not recursive `run.sh all` stages.
`provision` may acquire dependencies; `validate` has no network. Use an explicit
Docker context backed by a disposable Linux VM/engine. Neither command switches
the active context. All output directories must be new and private.
Provisioning requires Docker Buildx/BuildKit, never the deprecated legacy builder.
Install `docker-buildx` on `PATH` (Homebrew: `brew install docker-buildx`) or in
Docker's system plugin directory. The supervisor exposes a standalone executable
only through its private client configuration and records its version/hash;
it does not edit the user's Docker configuration or copy registry credentials.

The required JSON input has `schema: "docxplus.release-inputs.v1"` and a `sources`
object with exactly `docxplus`, `steganographer` and `template`. Each entry has:

- `root`: absolute path to an independently copied snapshot beneath a private,
  caller-owned directory; no live checkout, symlinks, history or credential files.
- `files`: exhaustive relative-POSIX-path map to `{sha256, bytes, mode}`, where
  `mode` is permission bits (`stat.S_IMODE`) and hashes cover actual file bytes.
- `dirs`: every relative directory, including empty ones.
- `sha256`: SHA256 of
  `json.dumps(files, sort_keys=True, separators=(",", ":")).encode()`.
- `identity`, `base_commit` and `dirty`: honest source provenance; a dirty
  snapshot's base commit is not the identity of its actual source bytes.

Before creating output or configuring Docker, admission checks the docxplus
snapshot's release identities against `pyproject.toml`: the package version,
`uv.lock`, `CITATION.cff`, CodeMeta, Zenodo metadata and skill frontmatter must
agree. Citation/frontmatter versions must be single top-level literal scalars;
the package version must be a single literal assignment. Inspection never imports
snapshot package code. Hash-valid snapshots with conflicting identities still
refuse. Re-capture the inventory after synchronizing metadata; do not rewrite an
old qualification receipt to advertise a new version.

The release image uses Setuptools 84.1.0 for wheel/sdist building; no standalone
`wheel` CLI is needed. A successful distribution build is not full Linux,
confinement, Office or manuscript qualification.

Capture each source under its repository manager's native short source lease,
verify it has not drifted, then release the lease before provisioning/compute.
The template input is the actual `projects/templates/template_code_project`
tree, excluding its venv/build/output/cache directories; it is read, not executed
or released. Preserve file modes. The supervisor rechecks exhaustive inventories,
digests and the acquired image before and after validation.

An authorized repository-owned private lane can keep a byte-identical supervisor
deployment, its independent source snapshots and its outputs in disjoint sibling
directories. Retain `scripts/validate_release.py` and its checkout-relative
`src/docxplus/archive_limits.py` companion in the deployment. Bind both deployed
files to the tested docxplus snapshot; do not remove containment, inventory,
privacy or runtime checks to accommodate a layout. Never use the live checkout as
an input snapshot or hold a canonical lease around provisioning/compute.

Given a captured manifest in `$MANIFEST`, a private output parent `$PRIVATE`, and
explicit `$DOCKER_CONTEXT`, run the commands in
[`../README.md`](../README.md#isolated-linux-release-validation).
Provisioning records actual image/runtime/tool/source bindings. Validation
requires network-none, read-only root/source/runtime, UID 1000, no capabilities,
no-new-privileges, private PID namespace, no host mounts/sockets and a hard
30-minute in-container lifetime. Per-container `seccomp=unconfined` exposes the
namespace syscalls needed by real bubblewrap; it never changes host policy.
Actual write/network/namespace probes must pass before any release-success claim.
The guest kernel/LSM must also permit unprivileged user, mount and network
namespaces. Ubuntu's enforced `unprivileged_userns` AppArmor profile can deny
bubblewrap even with the per-container seccomp exception. Choose a compatible
isolated guest; do not change host policy, add capabilities or bypass production
bubblewrap to make qualification pass.

Docker's default nonempty `MaskedPaths` and `ReadonlyPaths` are also required.
Some nested namespace configurations refuse bubblewrap's private proc mount under
those outer restrictions. The default remains refusal, not automatic fallback.
Only when needed inside an operator-controlled isolated **Linux rootless VM**, an
operator may explicitly authorize a single provision-bound daemon:

```bash
python3 scripts/validate_release.py validate --inputs "$MANIFEST" \
    --provision-record "$PRIVATE/provision-new/provision.json" \
    --output "$PRIVATE/validation-unmasked-new" --docker-context "$DOCKER_CONTEXT" \
    --allow-unmasked-procfs-for-daemon "$VERIFIED_DAEMON_ID"
```

Set `VERIFIED_DAEMON_ID` to the recorded `build.custody.daemon.ID` only after
confirming that this is the intended isolated daemon. The supervisor independently
rechecks its current identity: the option must exactly match it, the daemon must
report Linux and `name=rootless` in `SecurityOptions`, and provisioning custody
must still match. A wrong ID or ineligible daemon refuses before compute-container
creation. This is a validate-only ID option, not a boolean switch, a Docker context
alias, or permission to change provisioning or host/global policy.

The selected compute container alone receives
`--security-opt systempaths=unconfined`. This removes Docker's outer proc **and
kernel-path** masking/read-only defenses, not just the obstruction to private proc
mounting; some outer read restrictions are lost. Validation requires the actual
unmasked path fields and exact selected security options, and records the profile
and authorized daemon identity in its lifecycle/result evidence. It still checks
every other control before/after start: UID 1000, zero capabilities,
no-new-privileges, network-none, read-only root/source/runtime, private PID
namespace, no host mounts/sockets/credentials, resource/lifetime bounds,
source/image custody and stop/reap ownership. Production bubblewrap remains
mandatory with private user/PID/network namespaces and private procfs; do not
disable it, add capabilities/privileged mode, or relax host policy.

`qualification.json` must contain actual kernel read-only `/sys` evidence in
`read_only_filesystems` and `kernel_write_refusals` for
`/proc/sys/kernel/hostname`, `/proc/sysrq-trigger` and
`/sys/kernel/uevent_helper`. These probes use only `O_WRONLY | O_CLOEXEC`, with no
create, truncate or write. Only actual `EACCES`, `EPERM`, `EROFS` or `ENOENT`
refusals qualify; a successful open is closed and fails qualification. The
receipt also requires the unchanged network/write denials, real production
private PID/proc, ancestor-root invisibility and signal denial, positive
project/scratch writes and successful-leader detached-child teardown. Ancestor
descriptors are closed before exec (close-on-exec, no descriptor passing), which
is a code property rather than a probe. These representative probes are
additional evidence, not proof that all removed outer read restrictions are
preserved or certification of arbitrary host kernels or macOS sandbox guarantees.

Evidence streams out before tmpfs disappears: qualification, full logs, coverage,
real CLI cases, complete `run.sh all`, regenerated PDF/figures/template reports,
wheel/sdist and installed-wheel roundtrips. The host verifies bounded archive
contents and stop/reap evidence. Failure remains failure; old outputs are never
overwritten. Import generated `output/` only after successful qualification,
source-drift checks and a new native source-integration lease.
Installed-wheel checks use the wheel's real console script and fresh venv Python.
The script is interpreted explicitly because writable `/work` remains `noexec`;
the workflow never grants executable scratch storage to make a smoke test pass.

### Office render-save-render receipt

The installed-wheel gate builds, validates and extracts every non-media DOCX
channel (custom XML, package parts, properties and MCE), plus ODT package parts.
It exports real DOCX/ODT, renders each through LibreOffice, saves through Writer's
profile-specific filter, and renders the saved package. Each invocation owns private
profile/home/cache/temp state. Both PDFs must retain visible text sentinels, omit
hidden payload text and yield nonblank raster previews.
`office/evidence.json` uses `docxplus.release-office.v1`, recording actual tool
versions/SHA-256 identities and hashes/sizes of original/saved documents, PDFs,
extracted text and PNG previews. The release gate also requires genuine text and
Python/Rust carrier interoperability cases rather than skipped cases.
The host additionally compares all sixteen exported artifact hashes/sizes against
its own collected inventory, original documents against installed-wheel inputs,
tool versions against the qualified runtime, and text against the visible/hidden
sentinels (including hidden base64). Both actual exported JUnit suites must contain
the required Office cases without duplicate identities, skips, errors or failures.

This qualifies only the recorded application/version/fixtures and visible
rendering. **Payload survival and provenance after an Office edit are not asserted**;
saving can strip modules or invalidate signatures. A current-source successful
receipt is still required before claiming qualification. No fresh Office or Linux
custody pass is implied by these instructions.

## Outputs

Pipeline stages write under [`../output/`](../output/README.md): documents in
`documents/`, JSON in `reports/`, plates in `figures/`, derived values in `data/`.
They resolve through `project_paths.py`. Isolated release evidence instead uses
the caller's explicit private output directories; fixed `/source`, `/opt`,
`/work` and `/outputs` paths exist only inside the disposable image.

Editing rules: [`AGENTS.md`](AGENTS.md).

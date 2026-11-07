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
| `05_living_manuscript.py` | the manuscript that carries and reproduces its own source | `living` |
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

A synthetic tree can be shaped until it passes. A real one cannot. `06` carries a tree
built specifically to contain the hard cases — an executable entrypoint, an empty
directory, a zero-byte file, non-ASCII and spaced filenames — and checks 18 invariants
including cross-profile nesting and byte-identical payload parity. `07` carries the
docxology `template_code_project` (126 files, 13 directories) through `.docx`,
`.docxplus`, `.odt`, and `.odtplus`, reads each back *from that name*, and diffs
against the original. Both, every run.

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

Capture each source under its repository manager's native short source lease,
verify it has not drifted, then release the lease before provisioning/compute.
The template input is the actual `projects/templates/template_code_project`
tree, excluding its venv/build/output/cache directories; it is read, not executed
or released. Preserve file modes. The supervisor rechecks exhaustive inventories,
digests and the acquired image before and after validation.

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

Evidence streams out before tmpfs disappears: qualification, full logs, coverage,
real CLI cases, complete `run.sh all`, regenerated PDF/figures/template reports,
wheel/sdist and installed-wheel roundtrips. The host verifies bounded archive
contents and stop/reap evidence. Failure remains failure; old outputs are never
overwritten. Import generated `output/` only after successful qualification,
source-drift checks and a new native source-integration lease.
Installed-wheel checks use the wheel's real console script and fresh venv Python.
The script is interpreted explicitly because writable `/work` remains `noexec`;
the workflow never grants executable scratch storage to make a smoke test pass.

## Outputs

Pipeline stages write under [`../output/`](../output/README.md): documents in
`documents/`, JSON in `reports/`, plates in `figures/`, derived values in `data/`.
They resolve through `project_paths.py`. Isolated release evidence instead uses
the caller's explicit private output directories; fixed `/source`, `/opt`,
`/work` and `/outputs` paths exist only inside the disposable image.

Editing rules: [`AGENTS.md`](AGENTS.md).

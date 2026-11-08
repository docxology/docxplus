# Reproduction Attestation — Claim and Execution Boundaries

Both DOCX and ODT bind carried project bytes to a signed recipe, toolchain and
selected-output claim. Authentication and local re-execution are different
operations. The living example is a dependency-free source-hash demonstration,
not a re-run of the repository's test, figure or manuscript pipeline.

## First-principles decomposition

Verification is not one act; it is a chain of separable links:

- **Integrity** — "these bytes are the bytes the author sealed." A signature/digest
  proves this and nothing more. A signature over final bytes *notarizes* whatever
  was sealed, including a hand-edited figure — it can authenticate a lie.
- **Local execution evidence** — a recipient can run a declared command and compare
  selected output digests. A match observes that run, not scientific validity or
  independence from every undeclared input.
- **Execution authority** — opening/parsing does not execute carried recipes.
  Explicit execution remains dangerous and belongs in disposable isolation.

## Trust paths

`verify_reproduction(slot, expected_public_key=...)` executes nothing. Its
`self_consistent` verdict checks signed claim/stored-byte binding; `authentic` and
`verified` additionally require the caller's pinned key. An embedded key alone is
not an identity anchor, and a signer can authenticate a false claim.

`reproduce(..., allow_execution=True)` separately runs the declared recipe and
compares selected output digests. Missing macOS Seatbelt/Linux bubblewrap refuses
execution; no raw or network-only fallback is permitted. The literal `{python}`
resolves the recipient interpreter only at argv[0], with no shell/environment
interpolation. Toolchain metadata is reported, not a complete environment lock.

The signed `output_digest_scheme` must be exactly
`docxplus-output-tree-v3-blake2b-256`. Missing, older or unknown schemes refuse
before sandbox execution, even if a digest happens to match. Rebuild trusted
carried projects and produce a fresh attestation; do not reinterpret an old signed
digest or edit its scheme field. The result reports `source_match` independently:
`match` requires both source-tree and selected-output equality, while
`toolchain_match` remains a separate observation.

## Science — the falsifiable experiment

**Goal.** Measure selected deterministic recipes against declared outputs, without
promoting fixture behavior to a universal reproducibility theorem.

**Conditional hypotheses:**
- **H1:** a selected recipe whose inputs/toolchain/environment satisfy its assumptions
  produces the attested selected-output digest on an independent run.
- **H2:** a mutation affecting a recipe's measured outputs produces a mismatch;
  separately, mutation of signed carried bytes fails integrity verification under
  the pinned original signer. Arbitrary source changes need not affect outputs.
- **H3:** repeated selected runs give equal digests when the computation and all
  relevant inputs are deterministic.

`tests/test_reproduce.py` defines fixture controls; their existence is not a fresh
execution receipt. The living manuscript hashes selected Python source files with
no third-party dependencies. It can demonstrate source/output binding while a
non-Python input change leaves its computed digest unchanged. A full-project
reproduction claim needs an actual full-project recipe and source-bound run evidence.

## Security invariants (RedTeam-enforced)

1. Nothing in `read_package`, `validate`, `extract`, `verify_provenance`, or
   `verify_reproduction` executes carried code — ever.
2. Execution is explicit, timed, and write/network-confined using private scratch.
   Linux bubblewrap adds private user/PID/network namespaces, isolated procfs and
   a new session, and `--` ends bubblewrap's own options so the carried command
   cannot inject `--share-net`, `--bind` or similar. The command runs as private
   PID 1 and bubblewrap's reported init is pinned with a pidfd: killing it, or its
   own exit, makes the kernel terminate every member, so `setsid` descendants die
   before collection instead of orphaning a reaper to the caller. A killed member
   may linger as a zombie until its adopter reaps it; a zombie cannot execute or
   write. Without pidfd support Linux execution refuses. CPU, address-space and
   file-size limits are per-process controls, not aggregate quotas, and no UID-wide
   process cap is applied because it would refuse namespace creation on a busy
   desktop. macOS Seatbelt confines writes and network and denies process creation,
   so a recipe that needs subprocesses must run on the Linux backend. Capability
   and production custody qualification need actual platform receipts, not a
   source-code inference.
3. The signed module record binds the attestation to carried stored bytes. The
   complete canonical claim is also what a transparency log hashes; a pinned signed
   head authenticates inclusion, not execution, reliable time or pre-compromise order.

The host root remains readable even when mounted read-only. A scrubbed environment
does not protect filesystem credentials. This is **not hermetic isolation**: use
an isolated disposable environment with no secrets for untrusted code.

The separate release supervisor keeps Docker's default outer proc/kernel path
protections and refuses incompatible nested proc mounts. When necessary only in
an operator-controlled isolated Linux rootless VM, its validate-only
`--allow-unmasked-procfs-for-daemon ID` option can authorize the exact currently
verified, provision-bound daemon. Linux/rootless eligibility and ID mismatch
refuse before compute creation. The container-local `systempaths=unconfined`
profile removes outer proc **and kernel-path** masking/read-only defenses, not
production bubblewrap or private PID/proc. All other UID/capability,
no-new-privileges, read-only source/runtime/root, network, mount/credential,
resource/lifetime and source/image/reap controls remain mandatory. There is no
automatic fallback or host/global policy change.

Qualification must actually observe read-only `/sys`, non-mutating write-open
attempts against representative proc/kernel controls (EACCES/EPERM/EROFS, or
ENOENT where the interface is absent), private PID/network namespaces, ancestor
PID/proc invisibility and signal denial, positive project/scratch writes and
detached-child teardown. A successful kernel-control open fails without writing,
and no ancestor descriptor is inherited (close-on-exec, no descriptor passing).
These probes do not restore or certify all removed outer read restrictions,
arbitrary kernels, macOS sandbox guarantees or payload survival through Office
edits. See
[`scripts/README.md`](../scripts/README.md#release-validation) for eligibility,
the invocation and required receipt fields; documentation is not a passing receipt.

## Output binding

Collection and hashing have a shared deadline and bounded nofollow regular-file
reads: at most 128 patterns, 4096 outputs, 256 MiB per output and 512 MiB total.
Each matched output must be newly created or content-changed from its own pre-run
snapshot; an unchanged carried input is rejected even if another output changed.
The v3 output transcript starts with `docxplus/reproduction-outputs/v3\0`, counts
files, then binds sorted relative UTF-8 paths (length-framed), byte sizes and
fixed-size per-file BLAKE2b-256 digests. It does not concatenate filenames with
arbitrary file contents. Extraction publishes a new private 0700 root at an
absent/empty destination, never a nonempty merge.

## What bounds the verifier, not only the child

Child limits do not bound parent memory. The harness redirects both child streams
to files instead of buffering arbitrary stdout/stderr through `communicate()`.
The earlier implementation admitted large parent allocations despite child limits;
this is the reason output collection and stderr reads also have explicit budgets.

Both streams now go to files rather than pipes, which puts the child's own
`RLIMIT_FSIZE` back in the path, and the parent reads only a bounded prefix of stderr
for its failure message. Standard output is discarded, as it always was.

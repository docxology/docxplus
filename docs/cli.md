# The `docxplus` command line

Complete reference for every subcommand. The CLI is a thin orchestrator: it parses
arguments, calls `src/`, and prints JSON or paths. No logic lives here, so anything
the CLI can do the library can do, and the reverse should be true too — a capability
reachable only from Python is a capability most users do not have.

Commands are grouped by purpose. Update this contract when their actual behavior changes.

Every build command writes the document under **both** names (`report.docx` and
`report.docxplus`, byte-identical) per [`format-spec.md`](format-spec.md) §5. Every
reader accepts either.

---

## Authoring — OOXML (`.docx` / `.docxplus`)

### `build`

Compose a document from typed, optionally sealed modules.

```bash
docxplus build report.docx --text "Quarterly summary" \
    --module brief:custom_xml:brief.json --payload-type json \
    --password s3cret --kdf argon2id --signing-key key.hex
```

| Flag | Meaning |
| --- | --- |
| `--text`, `--title` | the visible surface document |
| `--module SLOT:CHANNEL:FILE` | one payload; repeatable. Channels: [`channels.md`](channels.md) |
| `--project SLOT:DIR` | carry a whole directory tree ([`format-spec.md`](format-spec.md) §8.1) |
| `--attest` | explicitly run each project's recipe under required confinement and seal its claim; carrying/extracting a project alone never executes it |
| `--payload-type` | file-module codecs `bytes`, `text`, `json`; use `--project` for directory trees and the Python API for typed nested containers |
| `--password` | password-seal every module |
| `--kdf` | `scrypt` (default), `argon2id`, `pbkdf2` |
| `--recipient HEXPUB` | repeatable raw X25519 or composite X25519 + ML-KEM-768 public bytes; one homogeneous family only |
| `--pad-recipients N` | raise the envelope's recipient-slot count to `N`, so its length stops revealing how many recipients there really are ([`security-model.md`](security-model.md)) |
| `--threshold K:N`, `--shares-dir` | seal file **and project** modules with Shamir k-of-n; exclusive private shares carry checksums and signed full-share commitments |
| `--max-uncompressed` | project content-byte budget, also used by author-side clean extraction |
| `--signing-key`, `--cosign` | raw Ed25519 or portable DXHK hybrid signing key files; algorithms/declared co-signer identities are authenticated |

`text` inputs decode UTF-8; `json` inputs parse JSON objects/values before canonical
packing rather than embedding their source bytes as strings. Password, recipient
and threshold policies are mutually exclusive. Documents and share paths/inputs
are preflighted for collisions, then staged before per-entry publication; no
cross-file crash-atomic transaction is claimed.

### `inspect`

Dump the intelligence manifest as JSON: modules, Merkle root, signature status.
**`signature: valid` here means self-consistent, not authentic** — use `verify`.

### `graph`

One-line-per-module tree: slot, payload type, channel, sealing mode, stored size.

### `extract`

Recover one module by slot. Credentials as required: `--password`, `--private-key`,
`--share` (repeatable). `--out` uses a private 0600 temporary file and atomic
replacement, never truncating a symlink/hardlink target; serialization failure
preserves the previous destination. Stdout remains caller-controlled disclosure.

### `unpack-project`

Recover a bounded plain-file project into an absent/empty destination as a fresh
private 0700 tree. Preflight rejects unsafe paths/types, aliases, duplicates and
file/directory conflicts; no existing file is merged/truncated/chmodded.
`--max-uncompressed` is explicit and separate from credentials. Safe project I/O
refuses platforms without descriptor-relative no-follow directory support.

---

## Authoring — OpenDocument (`.odt` / `.odtplus`)

The ODF profile carries the same signed intelligence layer. Two OOXML channels have no
ODF analogue; ODT payloads ride as package entries or the `odt_metadata` field
channel; see [`channels.md`](channels.md).

### `odt-build`

As `build`, with `--module SLOT[:CHANNEL]:FILE`. The channel defaults to
`odt_package_part`; `odt_metadata` selects the `meta.xml` user-defined-field
transport and `stego_media` the displayed-image carrier. A middle field that is
not a known ODF channel id stays part of the file path, preserving the older
`SLOT:FILE` form. Supports typed file codecs, `--project`, `--attest`,
`--max-uncompressed`, `--password`, `--kdf`, homogeneous classical/hybrid
`--recipient`, `--pad-recipients`, `--threshold`, `--shares-dir`,
`--signing-key` and `--cosign`.

### `odt-inspect`, `odt-extract`

The ODF counterparts of `inspect` and `extract`.

---

## Verification

These are the commands a release process should run. They differ in what they let you
conclude; [`security-model.md`](security-model.md) sets out the ladder.

### `verify`

**The authenticity command.** Checks the signature, that the signed digest still
matches the package in hand, and optionally a co-signer policy. Accepts either profile
and detects which from the container.

```bash
docxplus verify report.docxplus --expected-key signer.pub \
    --require-cosigner institution.pub
```

Exits **nonzero without `--expected-key`**, and says why: without a pinned key this
proves the package matches what *some* key signed, which is integrity, not
authenticity. A forger signing their own document produces the same output.

### `validate` / `odt-validate`

Selected structural and intelligence checks, not complete ISO/RNG/XSD conformance
or authenticity. Checks module resolution/stored digests, Merkle and package-surface
commitments, and signatures if present. An unsigned package can pass; pin `verify`.

Also refuses a package carrying an OPC signature whose reference set omits a
manifest-named part ([`opc-signatures.md`](opc-signatures.md)).

### `verify-reproduction`

Cryptographically verify a carried reproduction attestation. **Executes nothing.**
Reports `verified: false` when no attestation exists, rather than vacuously true.

### `verify-transparency`

Verify an attestation log: hash chain, signed tree head under a pinned signer, a
pinned Merkle root, per-entry inclusion proofs, and append-only consistency against an
earlier proof.

```bash
docxplus verify-transparency log.json --sth sth.json --expected-key signer.pub \
    --prove 3 --consistent-with yesterday.proof --emit-proof today.proof
```

A log offered without `--sth` is reported **UNAUTHENTICATED**: a clean chain only shows
the log does not contradict itself, which a wholly rewritten log also achieves.

---

## Inspection and intake

### `scan` / `odt-scan`

Threat-scan a file of unknown origin. **Executes no carried recipe.** OOXML reports
external relationships, macros and `altChunk`; ODF reports Basic/Scripts and
off-package `xlink:href`, including relative root escapes. Structural XML parsing
handles UTF-8/UTF-16 (and supported UTF-32), not byte-search tag spellings.
Unscannable XML is non-clean; `--strict` refuses. This remains incomplete threat
triage, not antivirus or exhaustive isolation.

### `analyze-carrier`

PNG adjacent-pair equality compatibility and repeated-prefix sweep. `p_value`
is a chi-square upper-tail reference probability, **not** an embedding posterior.
Insufficient samples/expected counts yield `available=False`, `p_value=None`.
Balanced untouched covers can flag; prefix tests are dependent. Neither a flag
nor a clean result proves payload presence/absence or its size. See
[`channels.md`](channels.md).

---

## Cross-profile review and recovery

These commands detect the profile from admitted container bytes, not the filename.
They never execute carried recipes. File reads are bounded and refuse symlinked
inputs/ancestors or unavailable descriptor-relative no-follow capabilities.

### `audit`

Audit several documents independently and emit `docxplus.audit-batch.v1` JSON:

```bash
docxplus audit report.docx packet.odt --expected-key author.pub \
    --require-cosigner institution.pub
```

Batches exceeding `--max-documents` refuse before input reads, never truncate.
Each input retains its own inspection, threat findings and errors; a missing or
malformed file does not discard successful peers. Exit 0 requires every selected
check to pass; any failed row exits 1. Invalid caller policy exits 2. Ordinary office
documents can pass structural/triage checks without an intelligence manifest.

Inspection separates selected package structure, original manifest declarations,
current package-surface binding, every declared co-signature and optional complete
key pins. Without `--expected-key`, `signature.authentic` is `null`, not a claim of
identity. Required co-signers need a primary pin. `payloads_verified: false` means
no payload transport was decoded; audit is not full `validate`, antivirus,
ISO/schema certification or proof of scientific/reproduction claims.

### `compare`

```bash
docxplus compare earlier.docx later.odt --expected-key author.pub
```

Emit `docxplus.comparison.v1`: selected inspection results, byte/profile/logical
package comparisons, signer-policy equality, and sorted added/removed/changed
module records. All record fields matter, not just the Merkle root. Different
valid profiles are comparable but unequal. ZIP timestamps, compression and member
ordering do not define logical equality. Re-sealing equal plaintext can produce
different stored bytes; neither plaintext nor rendered equivalence is inferred.

Exit 0 means selected checks passed and the compared dimensions match; exit 1
means valid differences; exit 2 means invalid input/required identity policy.
Invalid declarations produce `equal: null`, even when both inputs contain the
same tampering. No payload is decrypted, media-decoded or opened recursively.

### `export`

```bash
docxplus export packet.odt recovered --slot brief --password s3cret \
    --expected-key author.pub
```

Export selected slots (all by default) as exact packed plaintext bytes, with an
`index.json` mapping original slot/type to deterministic ordinal `.bin` files and
actual byte sizes/hashes. JSON/text retain their packed bytes; projects and nested
documents stay inert archives/documents. Registered object codecs are not called.
Credentials use `--password`, `--private-key` or repeated `--share` as for extraction.
Share bundles are routed by complete manifest commitments. Shares committed to
unselected modules may remain in a bundle; globally unrecognized shares refuse.

The destination must be absent: files, empty/nonempty directories and symlinks
refuse unchanged. All content is staged in a private tree, then published with a
native atomic no-replace rename; unsupported platforms refuse. Destination/stage
permissions are 0700 and recovered files/index 0600. An extraction, budget or index
failure publishes no partial tree. Created parent directories may remain; cleanup
I/O failures can retain a private stage. The destination parent must be owned by
the calling UID and not group/other-writable. Its ACLs and same-UID actors must be
trusted: Unix mode bits are enforced, not ACL sanitization or hostile-filesystem
protection. Publication and plaintext cleanup use a retained private holder
descriptor rather than re-opening a mutable staging name.

`--max-input-bytes` bounds each read before ZIP parsing. Export additionally uses
`--max-modules` and `--max-bytes` for recovered payload plus index bytes. These are
not whole-process memory quotas; package inflation and media decoding retain their
separate limits. Requested extraction may run the explicitly configured trusted
carrier decoder, never a carried recipe. Successful extraction/decryption alone
does not authenticate a signer; only a supplied complete trusted pin does.

## Execution (opt-in)

### `reproduce`

**Recipient-side recipe execution.** Requires `--allow-execution`; missing
Seatbelt/bubblewrap refuses, with no raw/network-only fallback. Missing/old
`output_digest_scheme` also refuses before execution. `--max-uncompressed` controls
project extraction. `match` requires source and output equality (`source_match`
is explicit); `toolchain_match` is separate. The host root remains readable.
Linux runs the command as private PID 1 with pidfd-owned namespace teardown;
macOS Seatbelt denies process creation, so a recipe that needs subprocesses must
run on the Linux backend. See [`reproduction-design.md`](reproduction-design.md).

---

## Keys and logs

### `keygen`

Generate `ed25519` (signing), `x25519` (recipient), `hybrid-recipient`, or `hybrid-signing` keys. Writes the private key to
the named path and the public key alongside as `<path>.pub`.

Hybrid private files contain hex-encoded portable suite-typed DXHK bytes, with
checked derived public halves; public files pin the complete composite identity.
Both profiles use these keys for actual signing/co-signing and homogeneous hybrid
recipient sealing, not just primitive demonstrations. For example:

```bash
docxplus keygen signer.hex --type hybrid-signing
docxplus keygen reviewer.hex --type hybrid-recipient
docxplus build report.docx --module brief:package_part:brief.json --payload-type json \
    --recipient "$(cat reviewer.hex.pub)" --signing-key signer.hex
docxplus verify report.docx --expected-key signer.hex.pub
docxplus extract report.docx brief --private-key reviewer.hex --out recovered.json
```

For ODF use `odt-build report.odt --module brief:brief.json` and `odt-extract`.
Old simulated material is incompatible; generate fresh keys and redistribute pins.

The private key is **created at mode 0600**, not written and then tightened, so it
never exists on disk at a wider mode. An existing file is never silently replaced —
overwriting a signing key destroys an identity with no recovery — so the command exits
nonzero and says so. Shares also use exclusive private creation. Ordinary
`extract --out` uses private atomic replacement instead of exclusive creation.

### `transparency-append`

Append an attestation to a log, optionally emitting a signed tree head with
`--signing-key`. Without one it says the log is **UNANCHORED**. `--timestamp` pins the
entry time for reproducible builds.

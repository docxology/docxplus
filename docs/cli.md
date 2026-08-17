# The `docxplus` command line

Complete reference for every subcommand. The CLI is a thin orchestrator: it parses
arguments, calls `src/`, and prints JSON or paths. No logic lives here, so anything
the CLI can do the library can do, and the reverse should be true too — a capability
reachable only from Python is a capability most users do not have.

Commands are grouped by what they are *for*. `tests/test_docs.py` fails the build if a
subcommand exists without an entry here.

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
| `--attest` | run the project's `.docxplus-reproduce.json` and seal the attestation |
| `--payload-type` | `bytes`, `text`, `json`, `project`, `docxplus` |
| `--password` | password-seal every module |
| `--kdf` | `scrypt` (default), `argon2id`, `pbkdf2` |
| `--recipient HEXPUB` | X25519 recipient; repeatable, for multi-recipient sealing |
| `--pad-recipients N` | raise the envelope's recipient-slot count to `N`, so its length stops revealing how many recipients there really are ([`security-model.md`](security-model.md)) |
| `--threshold K:N`, `--shares-dir` | Shamir k-of-n; shares are written out, not kept |
| `--signing-key`, `--cosign` | Ed25519 signing and co-signing |

### `inspect`

Dump the intelligence manifest as JSON: modules, Merkle root, signature status.
**`signature: valid` here means self-consistent, not authentic** — use `verify`.

### `graph`

One-line-per-module tree: slot, payload type, channel, sealing mode, stored size.

### `extract`

Recover one module by slot. Credentials as required: `--password`, `--private-key`,
`--share` (repeatable). Writes to `--out` or stdout.

### `unpack-project`

Recover a `project` module and unpack the tree to a directory. Applies the
decompression-bomb cap, path-traversal guard, and link-member refusal.

---

## Authoring — OpenDocument (`.odt` / `.odtplus`)

The ODF profile carries the same signed intelligence layer. Two OOXML channels have no
ODF analogue, so payloads ride as ODF package entries; see [`channels.md`](channels.md).

### `odt-build`

As `build`, minus `--module`'s channel field (there is one channel):
`--module SLOT:FILE`. Supports `--password`, `--kdf`, `--recipient`, `--threshold`,
`--signing-key`, `--cosign`.

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

Conformance, not authenticity. Checks OPC/ODF structure, that every module resolves
with a matching stored digest, that the Merkle root recomputes, and that a signature
(if present) validates. An **unsigned** package passes; only `verify` distinguishes.

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

Threat-scan a file of unknown origin. **Executes nothing.** OOXML looks for external
relationship targets, macro parts, and `altChunk` imports; ODF for Basic/Scripts
containers, off-package `xlink:href` targets, and embedded objects. `--strict` refuses
rather than reports.

### `analyze-carrier`

Statistical steganalysis of a PNG: the chi-squared attack on LSB replacement plus a
prefix sweep that localises partially-filled carriers. Exits nonzero when the carrier
looks embedded, so it works as a gate. Ships in-tree, so it runs without the optional
Rust backend — check your own carriers before an adversary does.

**A clean result is not a clean carrier.** The attack detects the uniformity a random
payload imposes, so it finds sealed modules and misses unsealed low-entropy ones at
every fill rate ([`channels.md`](channels.md)). Use it to confirm a carrier *is*
embedded, never to conclude that one is not.

---

## Execution (opt-in)

### `reproduce`

**The only command that runs carried code.** Requires `--allow-execution`; without it
the command refuses and explains. Re-runs the attested command in a best-effort
confined sandbox and compares digests. See [`reproduction-design.md`](reproduction-design.md)
for what confinement does and does not guarantee on each platform.

---

## Keys and logs

### `keygen`

Generate `ed25519` (signing) or `x25519` (recipient) keys. Writes the private key to
the named path and the public key alongside as `<path>.pub`.

The private key is **created at mode 0600**, not written and then tightened, so it
never exists on disk at a wider mode. An existing file is never silently replaced —
overwriting a signing key destroys an identity with no recovery — so the command exits
nonzero and says so. `--shares-dir` output and `extract --out` are written the same
way, since a threshold share and a recovered plaintext are secrets too.

### `transparency-append`

Append an attestation to a log, optionally emitting a signed tree head with
`--signing-key`. Without one it says the log is **UNANCHORED**. `--timestamp` pins the
entry time for reproducible builds.

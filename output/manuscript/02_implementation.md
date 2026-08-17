# Implementation {#sec:implementation}

## The Package Layer and Its Determinism {#sec:pkg-arch}

The container engine (`opc.py`) implements the Open Packaging Conventions directly over the standard
library's ZIP facilities: part indexing, extension-based `Default` and part-specific `Override` content
types, and root-anchored relationship graphs. Serialisation is deterministic so that a build is a function of
its inputs rather than of the machine that ran it. Every archive entry carries the fixed DOS timestamp
1980-01-01, `[Content_Types].xml` is written first, and the remaining parts follow in lexicographic order.
Packaging invariants are enforced in both directions: duplicate ZIP entries and colliding part paths are
rejected on read and on write, content types are validated, and XML is parsed with entity expansion disabled.

`wordml.py` synthesises the minimal conforming WordprocessingML surface document. `odt.py` builds the OASIS
OpenDocument sibling, placing `mimetype` uncompressed as the first entry, generating `META-INF/manifest.xml`,
and applying the same entry-count, decompression-ratio, and path-traversal guards the OPC reader applies.

## Sealing and Key Derivation {#sec:crypto-sealing}

::: {.definition #def:dxe1-envelope title="DXE1 Symmetric Sealing Envelope"}
A `DXE1` envelope encrypts payload $P$ under symmetric key $K = \text{KDF}(\text{passphrase}, \text{salt})$
using $\text{AES-256-GCM}$. The module slot name $s$ is bound as Additional Authenticated Data (AAD):
$$C, T = \text{AES-GCM-Encrypt}_K(\text{IV}, P, \text{AAD}=s)$$
The manifest stores $\text{Blake2b}(C \parallel T)$ rather than a plaintext digest.
:::

::: {.proposition #prop:slot-binding-integrity title="Slot-Splicing Invariance"}
By [@def:dxe1-envelope], a ciphertext $C$ generated for slot $s_i$ cannot be spliced into slot $s_j$ ($i \neq j$)
without causing the GCM authentication tag verification to fail closed.
:::

Two choices in [@def:dxe1-envelope] are worth drawing out. Binding the slot as AAD gives
[@prop:slot-binding-integrity] for free: a ciphertext is cryptographically fixed to the position it was
sealed for. Digesting the *ciphertext* rather than the plaintext removes an offline confirmation oracle — a
plaintext digest would let anyone holding the file test guesses against a short secret without ever
attempting decryption. The digest is checkable without any credential, and is checked before decryption is
attempted.

Key derivation favours memory-hard functions, which is what raises the cost of offline dictionary attacks on
GPU and ASIC hardware:

- **Argon2id** (RFC 9106 recommended profile) [@rfc9106] — 64 MiB memory cost, time cost
  $t=3$, parallelism $p=4$.
- **Scrypt** (the default) [@rfc7914] — $N=32768$ ($2^{15}$), $r=8$,
  $p=1$: memory-hard at negligible interactive cost.
- **PBKDF2-HMAC-SHA512** (compatibility) — 600000 iterations, per OWASP 2023 guidance, for
  constrained or FIPS-bound environments.

Because the envelope declares its own work factors, those factors are attacker-controlled input, and readers
cap them. The ceilings bound *memory*, not merely the iteration parameter: Scrypt's footprint is
$128 \cdot N \cdot r$, so a cap on $N$ that leaves $r$ free bounds nothing at all. The reader admits
$128 \cdot N \cdot r \le 256$ MiB, the same ceiling Argon2id already enforced.
[@sec:threat-audit] returns to how that gap survived a first hardening pass.

[@Fig:crypto-pipeline] traces a payload through the whole path. It branches only at the sealing mode, and
every branch reconverges on the same stored bytes — which is what the manifest records a digest of. The
alternative, digesting the plaintext, would ship an offline oracle against the passphrase inside the file the
attacker already has. Every parameter in the figure is read from the live constants rather than transcribed.

The recipients lineage keeps identities out of the envelope and, by default, does not keep their number out:
one wrapped content key per recipient, plus an explicit count field, so the total is readable from the
envelope's length. The manifest records neither identities nor number, which makes the omission an
inconsistency rather than a policy — for the blind-review packet this lineage is meant to serve, "sealed to
three people" is itself information about the review. Padding raises the slot count to a fixed bucket by
wrapping to freshly generated public keys whose private halves are discarded before the call returns, so a
padded slot is a real wrap that nobody can open, exactly as the chaff frame is. It is opt-in, and the
unpadded default therefore still leaks the count.

Beyond symmetric sealing, `crypto.py` provides X25519 multi-recipient key encapsulation (`DXE2`) [@rfc7748],
wrapping one content key separately for each recipient, alongside Ed25519 signing [@rfc8032]. `shamir.py`
implements $(k, n)$ threshold sharing over $\text{GF}(256)$ [@shamir1979] with verifiable-share commitment
tags [@feldman1987]. A commitment binds only if the verifier insists on it: an adversary can strip the tag
and present the same bytes as a legacy-format share, so reconstruction must be told to require the verifiable
form. Threshold modules therefore record that requirement in the signed manifest, where it cannot be
downgraded without breaking the signature. Decoy modules carry two independent frames, the second
indistinguishable from chaff. Indistinguishability has a dynamic half that the static one does not imply:
frames were once tried in order and the first success returned, so opening with the real password cost one
key derivation and opening with the cover story cost two — a factor of two on a deliberately expensive
function, and therefore an answer, on the wall clock, to the one question the lineage exists to refuse.
Every frame is now attempted whichever one matches, which costs a derivation per frame and buys the
property the format claims. Signatures are computed over a canonical, whitespace-invariant JSON body.

![How a typed payload becomes a signed module. The path branches only at the sealing mode, and all 4 branches reconverge on the same stored bytes — which is what the manifest digests. Digesting the plaintext instead would leave an offline oracle against the passphrase in a file the attacker already holds. Key-derivation profiles and the ceilings imposed on attacker-declared work factors are read from the live constants rather than transcribed.](../output/figures/cryptographic_pipeline.png){#fig:crypto-pipeline width=95%}

## Binding the Payloads to the Prose {#sec:payloads-provenance}

::: {.definition #def:composite-surface-digest title="Composite Surface Digest"}
Let $\mathcal{P}$ be a package and let $\mathcal{M}$ be its intelligence manifest part. The **composite
surface digest** $D_{\text{surface}}$ is the Blake2b digest of three sorted families, each tagged so a
part, a content type, and a relationship edge cannot collide: every part and its bytes except
$\mathcal{M}$; the content-type map (defaults and overrides) except the override for $\mathcal{M}$;
and every relationship edge except the one that points at $\mathcal{M}$. The manifest is the sole
exclusion because it carries this digest and cannot contain itself.
:::

::: {.theorem #thm:story-part-provenance title="Package-Graph Integrity"}
By [@def:composite-surface-digest], any alteration to a rendered part, a content type, or a
relationship edge — including a swap of the officeDocument target — modifies $D_{\text{surface}}$ and
invalidates the Ed25519 manifest signature.
:::

`payloads.py` keeps an extensible registry of payload encoders (`bytes`, `text`, `json`, `project`,
`docxplus`). The `project` handler packs an entire directory tree into a deterministic, traversal-guarded,
size-capped tarball, which is what lets a document carry the software that produced it.

`provenance.py` builds a Merkle tree [@merkle1987] over the module digests, giving logarithmic inclusion
proofs: a third party can confirm that one module belongs to the signed set without being shown the others.
The signature covers that root together with the composite surface digest of
[@def:composite-surface-digest], so tampering with a header, a style, a font table, or the
officeDocument relationship breaks provenance exactly as tampering with a payload does.
[@thm:story-part-provenance] states the property. An earlier version hashed a list of story-part
*names*; [@sec:threat-audit] records why a naming convention cannot carry it. Authenticity, throughout, requires the caller to pin
`expected_public_key`; a key that travels inside the manifest is an identity claim, not a verified one.

`transparency.py` maintains an append-only log of reproduction attestations, following the
tamper-evident-logging construction of Crosby and Wallach [@crosby2009] and the signed-tree-head discipline
that Certificate Transparency established for the same problem in the WebPKI [@rfc6962]. Hash chaining as a
tamper-evidence primitive dates to Lamport's one-way password chains [@lamport1981]; the lesson the later
work adds is that a chain must be *anchored* to mean anything. Chain verification establishes
only self-consistency, which is weaker than it sounds: an adversary who rewrites the log from its first entry
produces an equally self-consistent chain, and because no entry references the tip, the final entry's body
can be edited in place without breaking any linkage. Authenticity therefore rests on a **signed tree head** —
an Ed25519 signature, domain-separated from the manifest signature so it cannot be replayed as one, over the
pair (log length, Merkle root). Committing to the length as well as the root defeats truncation replay, since
an earlier head cannot describe a longer log. The `verify-transparency` command checks the chain, the tree
head under a caller-pinned signer, a pinned root, and per-entry inclusion proofs, failing closed on each and
reporting a log offered without a tree head as explicitly unauthenticated.

Determinism is a precondition rather than a nicety here: an attestation over a build that varies between
runs attests nothing, which is the argument the Reproducible Builds project has made for toolchains
generally [@reproduciblebuilds]. `reproduce.py` is the only path that executes carried code, and it does so solely on an explicit opt-in,
inside a scrubbed sandbox: dynamic-linker injection variables purged, resource and file-size limits clamped,
wall-clock timeout enforced, network denied, and writes confined to the project and temporary directories
where the platform supports it.

## Concealment, and Measuring It {#sec:stego-mce}

`lsb.py` provides a pure-Python least-significant-bit codec. Payloads are framed under a `DXL1` magic header
and written across the RGB channels of PNG image parts. `steg_bridge.py` integrates the optional
`docxology/steganographer` Rust backend, which adds BLAKE3 hashing, Ed25519 payload signatures,
Reed-Solomon error correction, and its own `analyze` command.

That backend is optional, and a security property that depends on an optional dependency is not a property.
`steg_bridge.py` therefore implements the chi-squared attack on LSB replacement [@westfeld2000] directly,
requiring nothing beyond the imaging library. Embedding equalises the frequencies within each
pairs-of-values bin, so a *low* statistic is the evidence of embedding rather than the usual reverse; the
upper-tail probability comes from a regularised incomplete gamma function evaluated in-tree rather than
through a numerical dependency.

That equalisation requires the embedded bits to be *uniform*, which is the attack's necessary condition and
therefore its boundary. Sealed modules are ciphertext, so the default path is the maximally detectable one:
a fully embedded carrier reports $p \approx 1$. An **unsealed low-entropy payload is not detected at any
fill rate** — plaintext, a constant fill, or a structured record leaves the pairs-of-values asymmetry intact
and reports $p \approx 0$, indistinguishable from a clean carrier. A clean verdict is evidence about this
attack, never evidence that a carrier is unmodified. Two further wrinkles matter in practice: because the codec fills carriers
sequentially, a partially-filled carrier is invisible to whole-image analysis, since the untouched remainder
dominates the histogram. The detector answers this by sweeping increasing prefixes of the sample stream, and
the prefix at which the statistic collapses both localises the payload and estimates its extent, though
only coarsely: the estimate is quantised to the sweep's step size and biased upward. A `redundancy=N` mode
replicates a payload across $N$ carriers so the document survives losing all but one.

`mce.py` implements the Markup Compatibility and Extensibility channel (ISO/IEC 29500-3) [@iso29500],
wrapping payloads in `<mc:Choice>` elements under an ignorable namespace in `word/document.xml`. A compliant
application that does not recognise the namespace discards the Choice branch and renders the fallback, with no
warning and no error. That fallback is deliberately empty, so a concealed module leaves the paragraph count
unchanged; an earlier version emitted a blank `<w:p>` and thereby falsified the independence it was supposed
to demonstrate. Placement is equally load-bearing: `CT_Body` is `(EG_BlockLevelElts*, sectPr?)`, so the block
is inserted *before* the body-level `<w:sectPr>` rather than appended at `</w:body>`.

## Composition, Validation, and Untrusted Input {#sec:validation-intake}

`container.py` runs the document lifecycle from both ends. `DocxPlusBuilder` queues typed modules, applies
per-module sealing, computes the surface digest and Merkle root, and serialises deterministically;
`DocxPlusReader` recovers the manifest, extracts payloads, and verifies provenance, co-signers, and
attestations.

`odt_container.py` provides `OdtPlusBuilder` and `OdtPlusReader`, the same lifecycle over an ODF package.
It reuses `container`'s sealing step and unsealing path verbatim; only placement differs, since ODF locates
parts through `META-INF/manifest.xml` rather than a relationship graph.

`validate.py` audits both contracts for both containers. For OOXML: OPC structure (index parts, relationship
reachability, absence of ZIP collisions) and intelligence structure (Merkle root consistency, per-module
ciphertext digests, signature verification, and recomputation of the composite surface digest). That last
check is recent and its absence was a defect rather than an omission: the signature covers the digest as a
*stored field*, so a package whose visible prose had been rewritten still had a self-consistent signature
and passed validation with no findings at all. Only `verify` caught it, and `validate` is the command a
release process runs. For ODF: the positional `mimetype` rule, manifest completeness —
an undeclared entry is unreachable to a conforming consumer, the ODF analogue of OPC reachability — and the
same intelligence checks.

One validator rule exists for a feature that does not: a package carrying whole-package OPC signatures is
rejected unless their combined reference set covers the intelligence manifest and every part it names. A
signature enumerating only the conventional Word parts would render as valid in a desktop office suite over a
document whose intelligence layer had been stripped, so the trust indicator would be attesting the absence of
what a reader assumes it covers. Writing the rule before the signing code is deliberate; it is the invariant
that keeps the feature from becoming a way to launder missing payloads ([@sec:future-work]).

`intake.py` is the hardened gateway for files of unknown origin, reporting external relationship targets,
macro parts, and foreign `altChunk` imports statically, executing nothing. The `docxplus` CLI is a thin
orchestration layer over these modules and implements no logic of its own; it currently exposes
19 commands: analyze-carrier, build, extract, graph, inspect, keygen, odt-build, odt-extract, odt-inspect, odt-scan, odt-validate, reproduce, scan, transparency-append, unpack-project, validate, verify, verify-reproduction, verify-transparency.

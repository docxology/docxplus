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
Both writers share reader-compatible per-entry compression policy and enforce package budgets before emission;
ZIP directory preflight bounds allocation before rich entry parsing.

## Sealing and Key Derivation {#sec:crypto-sealing}

::: {.definition #def:dxe1-envelope title="DXE1 Symmetric Sealing Envelope"}
A `DXE1` envelope encrypts payload $P$ under symmetric key $K = \text{KDF}(\text{passphrase}, \text{salt})$
using $\text{AES-256-GCM}$. The module slot name $s$ is bound as Additional Authenticated Data (AAD):
$$C, T = \text{AES-GCM-Encrypt}_K(\text{IV}, P, \text{AAD}=s)$$
The manifest digests the complete stored envelope rather than the plaintext.
:::

::: {.proposition #prop:slot-binding-integrity title="Slot-Splicing Invariance"}
Assuming AEAD integrity, [@def:dxe1-envelope] binds a ciphertext generated for $s_i$ to that AAD;
moving it to distinct slot $s_j$ fails verification except with negligible successful-forgery probability.
:::

Binding the slot as AAD gives the conditional integrity argument in [@prop:slot-binding-integrity].
Digesting the stored envelope rather than plaintext removes a direct public confirmation oracle — a
plaintext digest would let anyone holding the file test guesses against a short secret without ever
attempting decryption. The digest is checkable without any credential, and is checked before decryption is
attempted.

Key derivation favours memory-hard functions, which is what raises the cost of offline dictionary attacks on
GPU and ASIC hardware:

- **Argon2id** (RFC 9106 recommended profile) [@rfc9106] — 64 MiB memory cost, time cost
  $t=3$, parallelism $p=4$.
- **Scrypt** (the default) [@rfc7914] — $N=32768$ ($2^{15}$), $r=8$,
  $p=1$: the default memory-hard profile, with environment-dependent interactive cost.
- **PBKDF2-HMAC-SHA512** (compatibility) — 600000 iterations, per OWASP 2023 guidance.
  Algorithm availability does not establish a FIPS-certified product or environment.

Because the envelope declares its own work factors, those factors are attacker-controlled input, and readers
cap them before either password frame invokes a KDF. Scrypt bounds both $128 \cdot N \cdot r$ memory
and $N \cdot r \cdot p$ work; chaff uses the selected KDF. These declared-work ceilings are not an
aggregate process-memory guarantee. [@sec:threat-audit] records why bounding one parameter was insufficient.

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

Beyond symmetric sealing, both document profiles support classical X25519 recipients (`DXE2`) [@rfc7748]
or homogeneous genuine X25519 + ML-KEM-768 recipients (`DXE3`) [@nist_fips203]. Manifest, co-signature and
log signing support Ed25519 [@rfc8032] or dual Ed25519 + ML-DSA-65 [@nist_fips204] through
`cryptography` 50 or newer. Both signatures are required under a pin of the entire composite identity.
Portable `DXHK` private keys distinguish recipient/signing suites and validate exact lengths and derived
public halves. Mixed/ambiguous families and simulated material refuse, with no classical fallback.
Component standards do not certify this protocol or product; migrate by fresh keys and full-key pin distribution.

`shamir.py` implements $(k,n)$ sharing over $\text{GF}(256)$ [@shamir1979]. Its public wire checksum can
be recomputed by an attacker and is not Feldman/polynomial VSS. Threshold records instead commit in the
signed manifest to digests of complete issued shares, checked before combination. Trust in those issued
bytes requires the pinned manifest signer; polynomial consistency of an honest setup is an assumption.
Password modules admit exactly two complete bounded frames before KDF work, then attempt both. Ordinary
and decoy frames share KDF parameters and equal power-of-two padding buckets. Size ranges still leak;
timing/distributional indistinguishability, coercion resistance and universal deniability are not established.

![How a typed payload becomes a signed module. The path branches only at the sealing mode, and all 4 branches reconverge on the same stored bytes — which is what the manifest digests. Digesting the plaintext instead would leave an offline oracle against the passphrase in a file the attacker already holds. Key-derivation profiles and the ceilings imposed on attacker-declared work factors are read from the live constants rather than transcribed.](../../output/figures/cryptographic_pipeline.png){#fig:crypto-pipeline width=95%}

## Binding the Payloads to the Prose {#sec:payloads-provenance}

::: {.definition #def:composite-surface-digest title="Composite Surface Digest"}
Let $\mathcal{P}$ be a package and let $\mathcal{M}$ be its intelligence manifest part. The **composite
surface digest** $D_{\text{surface}}$ is a domain-separated, counted and length-framed BLAKE2b commitment to a
normalized package model. Part records bind names, lengths and SHA-256 content hashes. OPC also binds all
content-type declarations and each relationship's source, ID, type, target and mode. ODF uses a distinct profile domain and commits to
non-$\mathcal{M}$ content plus supported root/file-entry authority metadata. Intelligence-manifest bytes
are excluded; physical index bytes are represented by normalized authority. Unsupported authority refuses.
:::

::: {.proposition #thm:story-part-provenance title="Conditional Package-Graph Integrity"}
Assuming collision resistance of both the content and transcript hashes, signature unforgeability and a trusted pinned signer,
a change to a committed package-model value in [@def:composite-surface-digest] is detected when the surface
commitment and signature are recomputed. This does not prove full schema conformance or rendering equivalence.
:::

`payloads.py` retains the typed registry (`bytes`, `text`, `json`, `project`, `docxplus`). Shared stdlib
`archive_limits.py` preflights ZIP-directory allocation and bounded release-evidence gzip/TAR metadata.
Project capture uses retained descriptors and bounded reads, not a global cross-file snapshot. Project
intake bounds compressed/file bytes, members/nodes, physical TAR/PAX metadata and path depth before
publishing a fresh private root into an absent/empty destination; unsafe paths/types and missing safe
descriptor capabilities refuse. These budgets are not a whole-process-memory quota.

`provenance.py` uses RFC 6962 tree splitting [@rfc6962] over module digests. Inclusion proofs contain a
logarithmic number of sibling hashes; proof construction and whole-document verification are not log-time claims.
The signature covers that root together with the composite surface digest of
[@def:composite-surface-digest], so tampering with a header, a style, a font table, or the
officeDocument relationship breaks provenance exactly as tampering with a payload does.
[@thm:story-part-provenance] states the property. An earlier version hashed a list of story-part
*names*; [@sec:threat-audit] records why a naming convention cannot carry it. Authenticity, throughout, requires the caller to pin
`expected_public_key`; a key that travels inside the manifest is an identity claim, not a verified one.
The canonical body also binds the actual primary signing scheme and all declared co-signer identities/
schemes. Strict key framing chooses the verifier; an untrusted label cannot downgrade a hybrid signature.

`transparency.py` maintains an append-only log of reproduction attestations, following the
tamper-evident-logging construction of Crosby and Wallach [@crosby2009] and the signed-tree-head discipline
that Certificate Transparency established for the same problem in the WebPKI [@rfc6962]. Hash chaining as a
tamper-evidence primitive dates to Lamport's one-way password chains [@lamport1981]; the lesson the later
work adds is that a chain must be *anchored* to mean anything. Chain verification establishes
only self-consistency, which is weaker than it sounds: an adversary who rewrites the log from its first entry
produces an equally self-consistent chain, and because no entry references the tip, the final entry's body
can be edited in place without breaking any linkage. Authenticity therefore rests on a **signed tree head** —
an Ed25519 or genuine dual Ed25519 + ML-DSA-65 signature, domain-separated from manifest signing, over the
tuple (log length, Merkle root, claimed timestamp). A retained expected head is needed for freshness.
`attestation_digest` commits to the complete canonical claim, not only its output digest. Pinned-head inclusion
authenticates that claim; it does not witness execution, trustworthy time, or pre-compromise document signing.
An offered log without an authenticated head remains unauthenticated.

Deterministic selected outputs make repeated digest comparison useful [@reproduciblebuilds], but do not
establish scientific validity. `reproduce.py` runs carried recipes only after explicit opt-in, refusing when
the required platform confinement is absent. The signed output-tree-v3 scheme refuses legacy/missing schemes
before execution. Local `match` requires `source_match` and output digest equality; toolchain equality is
reported separately. Linux private PID/proc/network namespaces, a new session and retained-group reaping
own detached descendants; macOS group cleanup is weaker and needs external supervision for those descendants.
Per-process limits are not aggregate quotas. Private scratch does not hide the readable host root or credentials.
Use disposable isolation for untrusted code; the living example does not execute the full pipeline.

## Concealment, and Measuring It {#sec:stego-mce}

`lsb.py` provides a pure-Python RGB PNG codec. `DXL1` has a four-byte magic, uint32 length and exact payload;
truncated headers, over-capacity lengths and uint32 overflow refuse rather than silently slicing.
`steg_bridge.py` uses the actual Rust `capacity` command and carrier dimensions, with identical stable
`payload.bin` filename, MIME metadata and signing policy in capacity and encode. Default packets are
unsigned/non-ECC; signing requires an explicit key and identity pinning is separate. No ECC knob is exposed.

Discovery uses explicit `STEGANOGRAPHER_BIN` or PATH, never a sibling search/Cargo build; invalid explicit
configuration fails. RGB processing has a shared pixel budget, not a total-memory guarantee.

Pearson adjacent-pair equality statistics report `p_value`, an upper-tail reference probability, not an
embedding posterior. Each populated pair contributes a degree of freedom; insufficient samples/expected
counts return unavailable, not a clean negative. Balanced untouched covers can flag. Prefix sweeps reuse
samples and are not independently calibrated. Selected fixtures do not establish general sensitivity,
false-positive rates or a payload-size estimator. `redundancy=N` needs a surviving digest-matching replica;
it does not promise that edited packages retain valid provenance.

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

`validate.py` checks selected structural and intelligence invariants in both profiles: graph reachability,
namespaces, collisions, digest/Merkle/surface consistency, and signatures if present. It is not a complete
ISO/XSD/RNG validator or an Office implementation proof. Signature self-consistency remains distinct from
pinned authenticity; an unsigned document can pass structural checks without provenance. Intake reports
XML parse failures as non-clean rather than silently treating unscannable parts as safe.

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

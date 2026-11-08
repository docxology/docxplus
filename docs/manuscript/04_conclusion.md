# Conclusion {#sec:conclusion}

## What This Demonstrates {#sec:summary}

An ordinary Office container can carry authenticated, selectively sealed computational payloads through
documented extension points. The mechanism separates a public **surface contract** from a signed modular
**intelligence contract**. Preservation depends on profile/channel construction obligations, supported
consumer behavior and cryptographic assumptions; universal readability or full conformance is not proved.

Concretely:

1. **Payload-level rather than package-level sealing.** Argon2id [@rfc9106], Scrypt [@rfc7914], and
   AES-{{KEY_BITS}}-GCM; X25519 multi-recipient encapsulation [@rfc7748]; threshold sharing [@shamir1979]
   with signed full-share digest commitments; decoy chaffing — all applied to payloads, not the whole archive.
2. **Provenance over the package graph.** Merkle trees [@merkle1987] over the module set bound together
   with every part, content type, and relationship — not merely the story parts — under one
   signature [@rfc8032].
3. **Authenticatable reproduction claims.** Carried project archives and signed attestations can be checked
   without execution under a pinned key. Local re-execution is separate, opt-in and requires confinement;
   the living source-hash example is not full-project scientific reproduction.
4. **{{CHANNEL_COUNT}} documented transport channels**, spanning custom XML, package parts, document
   properties, MCE choice blocks and LSB steganography, with an uncalibrated in-tree inspection heuristic
   [@westfeld2000] rather than a statistical presence/absence guarantee.
5. **Standards parity** across Office Open XML [@iso29500] and OASIS OpenDocument Text [@oasis_odf]: the
   same signed manifest, sealing lineages, and provenance in both containers, implemented by shared code
   rather than by two implementations that agree today. Parity holds at the intake boundary too, where the
   sibling profile enforces the same ceilings. Two OOXML channels have no ODF analogue and are named as
   such.

## What This Does Not Do {#sec:security-limits}

The boundaries below are load-bearing. Stating them is part of the contribution, since a security property a
reader misunderstands is worse than one absent (`docs/security-model.md`).

![What a reader may conclude at each rung of verification, what it costs them, and — the column that usually goes missing — what it still does not buy. The rungs are cumulative and none is skippable. The step from *verify signature* to *pin the key* is the one that carries the weight: until the reader supplies the identity they trust, a valid signature establishes only that the document is internally consistent with itself, which is a property a forger can supply just as easily as an author.](../../output/figures/trust_ladder.png){#fig:trust-ladder width=95%}

The boundaries below correspond to the rungs in [@fig:trust-ladder]; each one names a conclusion the format
does *not* license. Stating them precisely is itself a design obligation: cryptographic software fails far
more often through misunderstood interfaces and unstated assumptions than through broken primitives
[@lazar2014], and a system whose guarantees a reader over-reads has failed even when every algorithm in it
is sound.

- **The surface is public on purpose.** docxplus is not digital rights management. The prose is meant to be
  readable, and confidentiality reaches only the modules marked for it.
- **Concealment is obfuscation, not secrecy.** Adjacent-pair `p_value` measures compatibility with an
  equal-pair reference model, not embedding probability. Sparse samples are unavailable; balanced untouched
  covers can flag. Prefix sweeps are dependent and no general detection calibration is established.
- **Common decoy policy is not universal deniability.** Exactly two bounded frames share visible KDF
  parameters and power-of-two padding, whether carrying chaff or a cover story. Buckets leak size ranges;
  timing/distributional indistinguishability and resistance to compelled disclosure are not proved.
- **Integrity is not authenticity.** A valid signature proves the manifest was signed by whoever holds the
  embedded key. Only comparison against a caller-pinned key makes that signer anyone in particular.
- **A local comparison is not scientific proof.** It measures selected outputs of a declared run in an
  observed environment. A signed attestation authenticates a claim, not execution; a pinned transparency
  head adds authenticated inclusion, not trustworthy time or pre-compromise ordering. Host files remain
  readable under the confinement wrappers; scrubbed environment variables do not hide credentials.
- **Desktop suites do not verify the intelligence signature.** The signed body now binds the module set
  and the whole package graph, but Word and LibreOffice will not check it. Native validation is a
  different signature (OPC XML-DSig), and that is the first item below.
- **An Office save is not payload preservation.** The release gate renders actual installed-wheel DOCX/ODT,
  saves via Writer, then renders again, retaining PDF/text/raster and tool-bound receipts. It checks visible
  text and nonblank previews, not survival of modules or signatures through editing. Current qualification
  remains conditional on the release owner's actual source-bound receipt.

## Future Work {#sec:future-work}

The nearest open item is producing a whole-package OPC XML-DSig signature alongside the manifest
signature, which would let desktop office suites validate a docxplus document natively. The assessment in
`docs/opc-signatures.md` sets out why it is not yet implemented: it needs canonical XML and an X.509 trust
story, and Office will not verify Ed25519. The invariant it must satisfy is already enforced. An OPC
signature enumerating only the conventional Word parts would display as valid over a package whose
intelligence layer had been stripped, which is worse than no signature at all — it would launder the absence
of the thing it appeared to attest. The validator therefore already rejects any package whose OPC signature
reference set omits a manifest-named part, written before the signing code precisely so the feature cannot
ship without it.

Beyond that: calibrating sample-pair analysis against natural-image carriers, so the withdrawn
estimator of [@sec:threat-audit] can return with the accuracy its name implies; validating produced documents
against Office-o-tron and the ODF Toolkit in continuous integration; establishing formal arguments for
container parsing (none are claimed here); and selective attribute disclosure via zero-knowledge proofs,
for workflows where a reader must confirm a payload property without opening it.

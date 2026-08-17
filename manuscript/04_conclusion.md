# Conclusion {#sec:conclusion}

## What This Demonstrates {#sec:summary}

An ordinary Office container can be an authenticated, selectively sealed computational carrier without
giving up conformance to the standards that make it ordinary. The mechanism is the separation this paper
began with: hold the **surface contract** (OPC/OOXML and ODF conformance) apart from the **intelligence
contract** (a signed, modular payload manifest), and the two stop competing. Universal readability and
fine-grained cryptographic access control turn out not to be a trade-off, only a design that had not been
drawn that way.

Concretely:

1. **Payload-level rather than package-level sealing.** Argon2id [@rfc9106], Scrypt [@rfc7914], and
   AES-{{KEY_BITS}}-GCM; X25519 multi-recipient encapsulation [@rfc7748]; verifiable threshold sharing
   [@feldman1987]; decoy chaffing — all applied to modules, leaving the document open.
2. **Provenance over the package graph.** Merkle trees [@merkle1987] over the module set bound together
   with every part, content type, and relationship — not merely the story parts — under one
   signature [@rfc8032].
3. **Reproducibility a reader can check without trusting the author.** Carried project archives, signed
   reproduction attestations verifiable with zero execution, an anchored transparency log, and re-execution
   confined behind an explicit opt-in.
4. **{{CHANNEL_COUNT}} spec-sanctioned transport channels**, spanning custom XML, package parts, document
   properties, MCE choice blocks, and LSB steganography whose detectability is measured in-tree
   [@westfeld2000] rather than asserted.
5. **Standards parity** across Office Open XML [@iso29500] and OASIS OpenDocument Text [@oasis_odf]: the
   same signed manifest, sealing lineages, and provenance in both containers, implemented by shared code
   rather than by two implementations that agree today. Parity holds at the intake boundary too, where the
   sibling profile enforces the same ceilings. Two OOXML channels have no ODF analogue and are named as
   such.

## What This Does Not Do {#sec:security-limits}

The boundaries below are load-bearing. Stating them is part of the contribution, since a security property a
reader misunderstands is worse than one absent (`docs/security-model.md`).

![What a reader may conclude at each rung of verification, what it costs them, and — the column that usually goes missing — what it still does not buy. The rungs are cumulative and none is skippable. The step from *verify signature* to *pin the key* is the one that carries the weight: until the reader supplies the identity they trust, a valid signature establishes only that the document is internally consistent with itself, which is a property a forger can supply just as easily as an author.](../output/figures/trust_ladder.png){#fig:trust-ladder width=95%}

The boundaries below correspond to the rungs in [@fig:trust-ladder]; each one names a conclusion the format
does *not* license. Stating them precisely is itself a design obligation: cryptographic software fails far
more often through misunderstood interfaces and unstated assumptions than through broken primitives
[@lazar2014], and a system whose guarantees a reader over-reads has failed even when every algorithm in it
is sound.

- **The surface is public on purpose.** docxplus is not digital rights management. The prose is meant to be
  readable, and confidentiality reaches only the modules marked for it.
- **Concealment is obfuscation, not secrecy.** LSB embedding is detectable by statistical steganalysis,
  which is why the chi-squared detector ships with the tool rather than being left to an adversary. Its own
  boundary is stated with it: the attack keys on the uniformity a random payload imposes, so it finds
  sealed modules and misses unsealed low-entropy ones entirely. A clean verdict bounds one attack, not the
  space of them. Treat a concealed module as hidden from casual inspection, never as undiscoverable.
- **Deniability holds against inspection, not against proof.** A decoy is structurally indistinguishable
  from an ordinary sealed module — same manifest record, same two frames — and randomly sized chaff keeps
  size from implying a payload length, so nothing in the file reveals a second payload. But an adversary who
  knows the scheme knows a second frame is *always* present, and cannot be compelled to accept it as chaff.
  The property claimed is inspection resistance for a single document, not indistinguishability under a
  distributional attack.
- **Integrity is not authenticity.** A valid signature proves the manifest was signed by whoever holds the
  embedded key. Only comparison against a caller-pinned key makes that signer anyone in particular.
- **A reproduction proves process, not science.** A digest match shows the declared command produced the
  attested output on a matching toolchain. Whether the method was correct is outside what any container can
  attest.
- **Desktop suites do not verify the intelligence signature.** The signed body now binds the module set
  and the whole package graph, but Word and LibreOffice will not check it. Native validation is a
  different signature (OPC XML-DSig), and that is the first item below.

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

Beyond that: ODF analogues of the metadata and media channels, so the two profiles differ only where the
standards genuinely do; calibrating sample-pair analysis against natural-image carriers, so the withdrawn
estimator of [@sec:threat-audit] can return with the accuracy its name implies; validating produced documents
against Office-o-tron and the ODF Toolkit in continuous integration; extending formal verification to the
container parsing logic; and selective attribute disclosure via zero-knowledge proofs, for workflows where a
reader must confirm a property of a payload without opening it.

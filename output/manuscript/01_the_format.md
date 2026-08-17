# The docxplus Format {#sec:format}

## What a Document Cannot Currently Do {#sec:motivation}

A `.docx` file is an Open Packaging Conventions (OPC; ISO/IEC 29500-2 / ECMA-376-2) container [@iso29500]:
a ZIP archive whose mandatory index parts are `[Content_Types].xml` and `_rels/.rels`, and in which every
valid part is reached by following an explicit, typed relationship. The standard provides that "a package may
contain additional files", and that mapped content-control data may live in custom XML parts. These are not
loopholes discovered by inspection. They are documented extension points, put there so that a package can
outlive the assumptions of any one consumer.

Yet the moment a document needs to carry something more — an analysis script, a dataset, a sealed attachment
for one named reader — the available options are both bad. Whole-package encryption (the MS-OFFCRYPTO
compound envelope [@msoffcrypto]) protects the payload by making the entire artefact unreadable: the
non-secret prose disappears behind a credential, and the file stops being a document at all for anyone
without one, archives included. The alternative, an unencrypted attachment sitting beside the file, has no
authenticated provenance, no typing, and no access control worth the name. Neither option is a document that
carries intelligence; one is a locked box, the other a paper clip.

The gap matters because the document is where results are actually communicated. Reproducible-research
practice has converged on the principle that code, data, and the narrative describing them should travel
together and be independently re-executable [@peng2011; @sandve2013], and the FAIR principles make
machine-actionable metadata a first-class requirement rather than a courtesy [@wilkinson2016]. Yet the
artefact a reader receives is almost always the one component that carries none of it: a rendered document,
severed from its inputs, linked at best to a repository that may move or change. Supplementary-material
archives and data repositories address the storage problem while leaving the binding problem open — nothing
cryptographically ties the figure on the page to the code that produced it.

This paper asks what falls out of refusing the original choice. How much structured, authenticated,
selectively sealed, and optionally concealed material can a document carry while remaining a strictly
*conforming* Office document across mainstream word processors?

## Two Contracts, One Archive {#sec:architecture}

::: {.definition #def:surface-contract title="Surface Contract"}
A package $\mathcal{P}$ satisfies the **Surface Contract** if it strictly conforms to ISO/IEC 29500-2 (OPC)
and Part 1 (WordprocessingML), comprising valid `[Content_Types].xml`, root relationship graphs `_rels/.rels`,
a typed main story part `word/document.xml`, and deterministic ZIP serialization with zero colliding part names.
Any conforming consumer $\mathcal{C}_{\text{std}}$ parses $\mathcal{P}$ without error.
:::

::: {.definition #def:intelligence-contract title="Intelligence Contract"}
A package $\mathcal{P}$ satisfies the **Intelligence Contract** if it contains an authoritative manifest part
$\mathcal{M} = \texttt{intelligence/manifest.json}$ that maps a finite set of module slots
$\mathcal{S} = \{s_1, \dots, s_k\}$ to their transport channel, content type, Blake2b ciphertext digest,
sealing parameters, and optional reproduction attestation, signed by an Ed25519 key [@rfc8032] over a canonical JSON serialization.
:::

::: {.theorem #thm:dual-contract-independence title="Dual-Contract Independence"}
Let $\mathcal{P}$ be a docxplus package satisfying [@def:surface-contract] and [@def:intelligence-contract].
Then the addition, removal, encryption, or steganographic concealment of any module $s \in \mathcal{S}$
leaves the surface validity of $\mathcal{P}$ invariant under $\mathcal{C}_{\text{std}}$.
:::

The independence in [@thm:dual-contract-independence] is what makes the format usable rather than merely
clever: an author can add, seal, or remove intelligence without ever risking the document's openability, and
a reader who has never heard of docxplus is never inconvenienced. [@Fig:architecture] shows both contracts as
parts of a single archive, and where each channel writes.

![The package tree with every transport channel drawn on the row of the part it writes into. A blue marker is a part the surface contract requires, a green one a part only docxplus reads, and a split marker a required part reused as transport — which is how three of the 5 channels carry a payload without adding any part a conforming reader would find surprising. Rows with no badge carry nothing. Capacities are read from the live code constants.](../output/figures/architecture.png){#fig:architecture width=95%}

## Transport Channels {#sec:channels}

docxplus defines 5 spec-sanctioned transport channels, each implementing a uniform
`embed`/`extract`/`capacity` lifecycle:

::: {.definition #def:transport-channel title="Transport Channel"}
A transport channel $\Gamma = (\text{embed}, \text{extract}, \text{capacity})$ is a triple of deterministic
operations mapping an OPC package $\mathcal{P}$ and payload bytes $b \in \{0, 1\}^*$ to an updated package
$\mathcal{P}'$ and a manifest locator record, such that $\text{extract}(\mathcal{P}', \text{embed}(\mathcal{P}, b)) = b$.
:::

Each channel below satisfies [@def:transport-channel]; the round-trip identity in that definition is what
every channel's test asserts against real packages rather than mocks, so the definition is a checked
obligation rather than a description. The supported channels comprise:

- **`custom_xml`** — Base64 payloads in `customXml/itemN.xml` parts registered via
  `customXml/itemPropsN.xml`. Layout engines ignore these parts while they remain fully compliant with the
  OOXML custom XML mapping schemas [@iso29500].
- **`package_part`** — Raw binary payloads in `intelligence/payloadN.dxp` under a declared content type. The
  high-throughput channel: large datasets, code archives, and ciphertext envelopes.
- **`metadata`** — String-encoded payloads in custom document properties within `docProps/custom.xml`.
  Bounded at 8000 bytes, which suits routing tags, identifiers, and key shares rather than
  content.
- **`stego_media`** — Payloads in the least-significant bits of RGB image parts such as
  `word/media/imageN.png`. The carrier is a figure the document actually displays, so the channel offers
  concealment on top of confidentiality — with the caveat, quantified in [@sec:stego-mce], that concealment
  is detectable.
- **`mce`** — Markup Compatibility and Extensibility (ISO/IEC 29500-3) `<mc:AlternateContent>` blocks inside
  `word/document.xml`. Payloads sit in `<mc:Choice>` guarded by an ignorable namespace, above an *empty*
  `<mc:Fallback/>`: a fallback carrying visible markup would add a paragraph per concealed module, which is
  precisely the surface change [@thm:dual-contract-independence] forbids.

One rule governs discovery: the manifest is authoritative. Readers resolve modules through manifest
declarations, never by walking ZIP entries and guessing, which is what keeps an attacker from introducing a
part the reader will treat as intelligence.

## The OpenDocument Sibling {#sec:odf-profile}

Nothing in the design depends on OOXML specifically, and the ODT profile (OASIS ODF v1.3/v1.4 Part 2)
[@oasis_odf] demonstrates that. An ODT package places the `mimetype` entry first and stored uncompressed so
consumers can identify the format positionally, registers its parts in `META-INF/manifest.xml`, and carries
the same signed intelligence layer as the OOXML profile: the manifest of
[@def:intelligence-contract], every sealing lineage, the Merkle root over the module set, a surface digest
over the visible ODF content, and the same co-signature policy.

That parity is a property of the *code*, not a parallel implementation that resembles it. Sealing and
unsealing are shared between the two profiles rather than written twice, because a second implementation is
free to drift on exactly the details that carry the security: the chaff frame that makes a decoy
indistinguishable, the slot bound as AAD, the verifiable-share requirement recorded in the signed manifest.
Two profiles that agree only by inspection eventually disagree under attack.

Untrusted intake is scanned on both sides too, though not by the same code: ODF's threat surface is Basic
and Scripts containers and off-package `xlink:href` targets, not VBA and `altChunk`. Running the OOXML scan
against an ODF package would pass vacuously, which is worse than not scanning, because it would report clean.

Two channels do not cross over, and saying which is part of the claim. ODF has no custom XML datastore part
and no Markup Compatibility element, so `custom_xml` and `mce` are OOXML-only; ODT payloads ride as ODF
package entries, the unbounded channel. Analogues for the metadata and media channels are plausible and not
yet built.

The sibling profile is a second front door into the same container, which is why it enforces the same intake
ceilings as the OPC reader — entry count, decompression ratio, and rejection of traversal or absolute entry
names. A second entrance that is easier to force is not a portability feature; it is the weakest link, and
[@sec:threat-audit] records the cycles in which this one was found wanting, twice.

# Abstract {.unnumbered}

A `.docx` file is a ZIP archive governed by the Open Packaging Conventions (OPC; ISO/IEC 29500-2 /
ECMA-376-2) [@iso29500], and its OpenDocument counterpart (OASIS ODF v1.3/v1.4) [@oasis_odf] is built the
same way. Both standards document extension points — auxiliary package parts, custom XML datastores,
application property sets, embedded media, markup-compatibility choice blocks — that exist precisely so a
package can carry more than a conforming consumer knows how to read. **docxplus** is an open specification and
reference implementation that takes those affordances seriously. A single archive satisfies two independent
contracts at once: it is a conforming `.docx` or `.odt` that opens unremarkably in Microsoft Word,
LibreOffice, and Google Docs, and it is an authenticated, modular carrier of typed computational payloads
indexed by a signed manifest.

The design turns on one decision: seal payloads, never the package. Whole-package MS-OFFCRYPTO encryption
[@msoffcrypto] buys confidentiality by destroying the artefact — the prose becomes unreadable to anyone
without a credential, and unreadable to archives permanently. Sealing each module instead leaves the surface
document public and openable while confidentiality applies exactly where it is wanted. Modules seal under
memory-hard password derivation (Argon2id [@rfc9106] or Scrypt [@rfc7914], feeding AES-256-GCM),
X25519 multi-recipient key encapsulation [@rfc7748], Shamir $k$-of-$n$ threshold sharing [@shamir1979] with
verifiable-share commitments [@feldman1987], or a decoy frame structurally indistinguishable from an ordinary
sealed one. Payloads are typed (`bytes`, `text`, `json`, a nested `docxplus` container, or a whole
reproducible `project` tree), so a paper can carry the code and data that produced it.

Provenance rests on a signed Merkle tree [@merkle1987] over the module roster together with a composite
digest over every package part, the content-type map, and the relationship graph — excluding only the
manifest that carries the digest — so editing a footnote, a style, or the officeDocument relationship
breaks the signature exactly as editing a payload does. Inclusion proofs let
a third party confirm one module belongs to the signed set without seeing the others, and detached
co-signatures let an institution vouch alongside an author [@rfc8032]. Throughout, a verdict of *authentic*
requires the caller to pin the key they trust; the key travelling inside the manifest is self-asserted, and
we say so wherever the distinction bites. A `project` module may additionally carry a signed **reproduction
attestation** binding its source to an output digest, which a reader checks cryptographically while executing
nothing, or re-runs by explicit opt-in inside a confined, resource-capped sandbox. Attestations chain into an
append-only transparency log whose authenticity comes from a signed tree head, because a hash chain on its
own proves only that a log does not contradict itself.

We implement and evaluate 5 spec-sanctioned transport channels: custom XML parts, auxiliary
package parts, custom document properties, Markup Compatibility and Extensibility (MCE) choice blocks, and
least-significant-bit steganography in a carrier image the document visibly displays. Concealment is
measured, not asserted — a chi-squared detector [@westfeld2000] ships in-tree, with a prefix sweep that
localises the partially-filled carriers whole-image statistics miss, alongside an optional compiled backend
[@fridrich2001]. Across 469 mock-free test functions under a 90% coverage gate we verify
deterministic serialisation, round-trip integrity, openability in mainstream word processors, and the
adversarial boundaries established by 14 red-team cycles closing
88 confirmed findings — a record that includes the occasions when an earlier fix
proved incomplete, and one negative result withdrawn rather than shipped.

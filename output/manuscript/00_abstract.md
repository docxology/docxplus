# Abstract {.unnumbered}

A `.docx` file is a ZIP archive governed by the Open Packaging Conventions (OPC; ISO/IEC 29500-2 /
ECMA-376-2) [@iso29500], and its OpenDocument counterpart (OASIS ODF v1.3/v1.4) [@oasis_odf] is built the
same way. Both standards document extension points — auxiliary package parts, custom XML datastores,
application property sets, embedded media, markup-compatibility choice blocks — that exist precisely so a
package can carry more than a conforming consumer knows how to read. **docxplus** is an open specification and
reference implementation that takes those affordances seriously. A single archive is designed to carry two
contracts: an ordinary public document surface and a modular computational payload layer indexed by a signed
manifest. Structural checks support selected package invariants; they do not establish complete schema
conformance or universal acceptance by Word, LibreOffice or Google Docs.

The design turns on one decision: seal payloads, never the package. Whole-package MS-OFFCRYPTO encryption
[@msoffcrypto] buys confidentiality by destroying the artefact — the prose becomes unreadable to anyone
without a credential, and unreadable to archives permanently. Sealing each module instead leaves the surface
document public and openable while confidentiality applies exactly where it is wanted. Modules seal under
memory-hard password derivation (Argon2id [@rfc9106] or Scrypt [@rfc7914], feeding AES-256-GCM),
classical X25519 or genuine X25519 + ML-KEM-768 multi-recipient encapsulation [@rfc7748; @nist_fips203],
Shamir $k$-of-$n$ sharing [@shamir1979] with signed full-share digests, or two common-policy padded password frames.
The standalone share checksum is not polynomial-verifiable secret sharing. Typed payloads include selected
`project` trees, but carrying code and data does not by itself reproduce a scientific result.

Provenance rests on a signed Merkle tree [@merkle1987] over the module roster and a profile-separated,
typed/count/length/hash commitment to package parts, type/ODF authority and relationship edges including IDs.
Intelligence-manifest bytes are excluded; physical index bytes are represented by their normalized authority.
Ed25519 or genuine Ed25519 + ML-DSA-65 signing authenticates the primary algorithm and declared
co-signer identities/algorithms [@rfc8032; @nist_fips204]. Component standards do not certify the product.
Inclusion proofs support module membership; co-signers can express an author-and-institution policy. Authenticity
requires the caller to pin the key they trust; the key travelling inside the manifest is self-asserted, and
we say so wherever the distinction bites. A `project` module may additionally carry a signed **reproduction
attestation** binding its source to an output digest, which a reader checks cryptographically while executing
nothing, or re-runs by explicit opt-in under available confinement. Missing confinement refuses execution;
readable host files remain exposed. A pinned signed transparency head authenticates inclusion of the complete
claim, not independent execution, trustworthy time, or pre-compromise ordering.
The output-tree-v3 digest scheme is a clean cutover: missing/old schemes refuse before execution,
and local `match` requires both `source_match` and selected-output equality. Linux private PID/proc/session
custody is stronger than macOS process-group cleanup of detached descendants; both require actual platform evidence.

We implement and evaluate 5 spec-sanctioned transport channels: custom XML parts, auxiliary
package parts, custom document properties, Markup Compatibility and Extensibility (MCE) choice blocks, and
least-significant-bit steganography in a carrier image the document visibly displays. A chi-squared heuristic
[@westfeld2000] and prefix sweep inspect selected carriers; neither calibrated detection probabilities nor
general false-positive/sensitivity claims are established. The source inventory contains 705
mock-free test functions under a 90% coverage policy; these are not executed-pass counts.
Historical reports and 14 recorded review cycles with 88
confirmed findings describe selected fixtures and past evidence, not fresh software-release qualification.
The living manuscript demonstrates a dependency-free source hash, not whole-project scientific reproduction.

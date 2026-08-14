# Abstract

DOCX and ODT are ZIP-packaged, XML-vocabulary word-processing formats whose
extension points — additional package parts, custom XML, custom document
properties, embedded media, and markup-compatibility namespaces — are documented
and permissive. We exploit exactly those documented affordances to define **DOCX+**,
a profile of Office Open XML WordprocessingML in which a single file is
simultaneously (a) a conforming `.docx` that opens as an ordinary document in Word,
LibreOffice, and Google Docs, and (b) a carrier of a modular *intelligence layer*:
typed payload modules bound by a signed manifest. Sealing is applied per payload
rather than to the whole package, so the surface document remains openable — a
property whole-package OOXML encryption sacrifices — with lineages spanning
memory-hard password encryption (Argon2id and Scrypt + AES-{{KEY_BITS}}-GCM), X25519 multi-recipient
sealing, Shamir k-of-n threshold with Verifiable Secret Sharing (VSS), and plausible-deniability decoys.

Payloads are typed (`bytes`, `text`, `json`, a whole reproducible `project`, or a
nested DOCX+), so a document can carry the software that produced it. Provenance is
a signed Merkle root over the module set plus a digest of the visible text, with
inclusion proofs and detached co-signatures; authenticity requires a caller-pinned
key. A `project` module can carry a signed **reproduction attestation**: a reader
verifies it cryptographically without executing anything, or opts in to re-run the
attested command in a hermetic sandbox and confirm the outputs. Attestation records
can be verified via an append-only cryptographic transparency log. A hardened intake
path scans untrusted `.docx` for external references, macros, and foreign-content
imports without executing them.

{{CHANNEL_COUNT}} channels are implemented and tested — custom XML parts, additional package
parts, custom document properties, markup compatibility and extensibility (MCE) choice blocks,
and redundancy-capable least-significant-bit steganography in a visibly displayed image
(a zero-setup pure-Python backend and a premium `docxology/steganographer` Rust backend).
An OpenDocument Text (ODT) sibling container profile provides native OASIS ODF compatibility.
The reference implementation is deterministic, dependency-light, and validated by real round-trip
tests with no mocks under a {{COVERAGE_GATE}}% coverage gate, hardened across six versions by adversarial review
with independent verification. Every structural decision traces to primary standards
text collected in an accompanying standards-first research report.

# Abstract

DOCX and ODT are ZIP-packaged, XML-vocabulary word-processing formats whose
extension points — additional package parts, custom XML, custom document
properties, embedded media, and markup-compatibility namespaces — are documented
and permissive. We exploit exactly those documented affordances to define **DOCX+**,
a profile of Office Open XML WordprocessingML in which a single file is
simultaneously (a) a conforming `.docx` that opens as an ordinary document in Word,
LibreOffice, and Google Docs, and (b) a carrier of a modular *intelligence layer*:
typed payload modules bound by an Ed25519-signed manifest, with optional
AES-256-GCM payload encryption whose key derivation follows the MS-OFFCRYPTO agile
lineage. Encryption is applied per payload rather than to the whole package, so the
surface document remains openable — a property whole-package OOXML encryption
sacrifices.

Four channels are implemented and tested: custom XML parts, additional package
parts, custom document properties, and least-significant-bit steganography in an
embedded image the document visibly displays. The media channel offers a
zero-setup pure-Python LSB backend and a premium backend bridging the
`docxology/steganographer` Rust CLI, which BLAKE3-hashes and Ed25519-signs each
embedded packet. The reference implementation is deterministic, dependency-light,
and validated by real round-trip tests with no mocks and a 90% coverage gate; the
steganographer bridge is exercised end-to-end against the built binary. Every
structural decision traces to primary standards text collected in an accompanying
standards-first research report.

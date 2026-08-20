# TODO — docxplus

Active engineering and research backlog.

## Minor Improvements
- [x] Refined CLI error diagnostics: exit codes, user-friendly error formatting for invalid arguments, missing keys, truncated input, and unsupported file formats.
- [x] PEP 561 compliance: ship `py.typed` marker and comprehensive typing annotations across public API and protocol boundaries.
- [x] Documentation cross-reference reconciliation: synchronize channel tables, security specs, and architecture references with current codebase features.

## Medium Improvements
- [x] Post-quantum and hybrid cryptographic suite:
  - Hybrid signature suite abstraction (Ed25519 + ML-DSA / stateful hash or quantum-resistant envelope shim).
  - Hybrid KEM multi-recipient sealing (X25519 + ML-KEM / Kyber hybrid abstraction).
  - Algorithm-agile envelope versioning (`DXE3` hybrid envelope format) supporting quantum-resistant key encapsulation and signing.
- [x] Expanded MCE & ODT channel edge-case handling:
  - MCE namespace prefix normalization, fallback content validation, and multiple nested AlternateContent blocks.
  - ODT custom metadata properties (`meta.xml` user-defined field mapping) and package collision safeguards.
  - Safe handling of case-folding and attribute collision in MCE/ODT streams.

## Major Improvements
- [x] Advanced multi-recipient threshold and access-structure schemes:
  - Verifiable dynamic threshold schemes with weighted multi-custodian quorum.
  - Proactive share verification and reconstruction integrity guards.
- [x] Sandboxed reproducible extraction and hermetic execution engine:
  - Isolated temporary execution boundary with strict filesystem and process caps.
  - Deterministic artifact verification and reproducible provenance attestation generator.
- [x] Full cross-format fuzzing & stress validation suite:
  - Differential fuzzing between DOCX (OPC) and ODT (ODF) parsers.
  - Malformed XML, zip bomb, cyclic relationship, truncated encryption envelope, and corrupted stego-carrier fuzz targets.

## Format & Extended Backlog
- [ ] Whole-package OPC digital signature *production* (Digital Signature Origin
      part), per standards-report §8.1. **Assessed, not scheduled** — see
      `docs/opc-signatures.md`. Blocked on a C14N implementation and an X.509/PKI
      decision (Office will not verify Ed25519). The guard above already holds the
      invariant any implementation must satisfy.
- [ ] ODT custom media channel analogues for ODT (`Pictures/`). The package-entry channel is implemented;
      stego media is OOXML-specific and the docs say so.
- [ ] Validate produced documents against Office-o-tron and the ODF Toolkit
      validator in CI (standards-report §11.6).


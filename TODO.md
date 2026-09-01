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

## Maintenance

- [x] Pin the lint gate: `ruff==0.16.5` in the `dev` extra; CI's unpinned
      `uvx ruff check src scripts tests` had drifted to 53 findings on pristine
      HEAD. All 53 fixed (2026-08-27); `uv run ruff check src scripts tests`
      and CI now judge the same pinned toolchain. Bumps are deliberate.

## Format & Extended Backlog
- [ ] Whole-package OPC digital signature *production* (Digital Signature Origin
      part), per standards-report §8.1. **Assessed, not scheduled** — see
      `docs/opc-signatures.md`. Blocked on a C14N implementation and an X.509/PKI
      decision (Office will not verify Ed25519). The fail-closed coverage guard the
      assessment prescribes is implemented and tested:
      `check_opc_signature_coverage` in `src/docxplus/validate.py` fails any package
      whose OPC signature reference set omits a manifest-named part; verify with
      `.venv/bin/python -m pytest tests/test_validate.py -q`.
      **Acceptance for any future implementation:** (a) reference set derived from
      `manifest.records[*].location`, never a fixed Word-part list; (b) the coverage
      guard stays green against real signed packages; (c) Word/LibreOffice verify a
      signed output without error; (d) dual-key story (Ed25519 manifest +
      RSA/ECDSA OPC) decided by the owner first.
- [x] ODT `stego_media` channel analogue (`Pictures/` carriers), via
      `OdtStegMediaChannel` — a subclass of the OOXML channel sharing the decode path.
      Real round-trip tests in `tests/test_odt_container.py` (`-k stego`); parity figure
      and caption updated (one unbuilt analogue remains: `metadata`).
- [ ] Validate produced documents against Office-o-tron and the ODF Toolkit
      validator in CI (standards-report §11.6). External services; needs an owner
      decision on hosting (neither offers a stable public API today).
      **Acceptance:** (a) a pinned, reproducible validator invocation (container or
      hosted endpoint) runs on a local stage; (b) CI job added only after the
      endpoint is owner-approved (CI configs are outside agent scope); (c) failures
      are blocking, and a service outage skips loudly — never reported as a pass.

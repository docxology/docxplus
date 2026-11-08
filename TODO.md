# TODO — docxplus

Active engineering and research backlog.

## Minor Improvements
- [x] Refined CLI error diagnostics: exit codes, user-friendly error formatting for invalid arguments, missing keys, truncated input, and unsupported file formats.
- [x] PEP 561 compliance: ship `py.typed` marker and comprehensive typing annotations across public API and protocol boundaries.
- [x] Documentation cross-reference reconciliation: synchronize channel tables, security specs, and architecture references with current codebase features.

## Medium Improvements
- [x] Genuine provider-backed hybrid cryptography (`cryptography >= 50`):
  - Ed25519 + ML-DSA-65 dual signatures; both verify under the full composite key pin.
  - X25519 + ML-KEM-768 DXE3 sealing for homogeneous hybrid recipient sets.
  - Portable DXHK signing/recipient private-key suites with exact framing and checked
    derived public halves; both profiles and CLI use them. No simulated shim,
    stateful-hash suite or classical fallback is implemented.
- [x] MCE handling and ODT package collision safeguards.
- [ ] ODT custom metadata channel (`meta.xml` user-defined fields): not implemented;
      package-entry and displayed-image transports are the supported ODF channels.

## Major Improvements
- [x] Shamir k-of-n confidentiality and issued-share integrity:
  - Public tagged-share checksums detect corruption, not polynomial/issuer authenticity.
  - Signed full-share digest commitments authenticate issued bytes under a verified,
    pinned manifest; no weighted/dynamic/proactive VSS scheme is implemented.
- [x] Opt-in confined reproduction with private scratch and versioned output-tree-v3
      comparison; `match` requires source and selected-output equality.
  - Linux private PID/proc/session and reaping controls require actual qualification.
  - macOS detached-descendant custody is weaker; host files remain readable.
    This is not a hermetic execution engine or aggregate resource quota.
- [x] Selected malformed-package, envelope and carrier boundary regressions in both profiles.
      Their existence is not a full differential-fuzzing/stress qualification claim.

## Maintenance

- [x] Pin the lint gate: `ruff==0.16.5` in the `dev` extra, and run it from the
      venv — `.venv/bin/python -m ruff check src scripts tests` — so CI and a local
      checkout judge the same toolchain. The unpinned `uvx ruff check src scripts
      tests` had drifted to 53 findings on pristine HEAD (all 53 fixed 2026-08-27).
      Bumps are deliberate.

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

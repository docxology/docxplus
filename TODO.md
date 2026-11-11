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
- [x] ODT custom metadata channel (`meta.xml` user-defined fields), via
      `OdtMetadataChannel` (`odt_metadata`): base64 in a named `meta:user-defined`
      field, preserving existing fields and refusing collisions. Round-trip,
      capacity, sealing, signature and tamper tests; docs and format spec updated.
- [x] Cross-profile non-decoding batch audit and logical manifest-aware comparison;
      bounded, private, atomic raw payload export with inert project/nested bytes,
      complete key policies and independent threshold-share bundles.

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
      and caption updated (all ODF analogues built; `custom_xml`/`mce` remain
      OOXML-only by design).
- [ ] Validate produced documents against Office-o-tron and the ODF Toolkit
      validator in CI (standards-report §11.6). External services; needs an owner
      decision on hosting (neither offers a stable public API today).
      **Acceptance:** (a) a pinned, reproducible validator invocation (container or
      hosted endpoint) runs on a local stage; (b) CI job added only after the
      endpoint is owner-approved (CI configs are outside agent scope); (c) failures
      are blocking, and a service outage skips loudly — never reported as a pass.

## Verification and release acceptance

Checked items describe implemented contracts, not a fresh passing-gate receipt.
Use the [project gates](AGENTS.md#commands), [CLI contracts](docs/cli.md), and
[source-bound validation workflow](scripts/README.md#release-validation) to exercise
the current source. A bounded review or a historical artifact does not close a
behavioral acceptance criterion.

The unchecked format items remain owner-decision backlog: neither XML-DSig
production nor external validator hosting is implemented by a review or an outage.
Keep them open until their stated real-consumer probes and prerequisites are met.
Local checks are separate from the [explicit tag/release-asset publication
admission](scripts/README.md#release-asset-publication); passing checks do not grant
that admission or replace an exact reviewed plan confirmation.

## Workflowz review — 2026-11-10

Coverage note: no concrete, packet-grounded improvement survived review. The bounded packet covered project guidance, README, existing TODO, runtime/dependency configuration, the pipeline driver, and 22 source files (including 18 marker-focused excerpts), out of 174 files and 110 source candidates; it did not include full source, tests, lockfile, CI configuration, or every line of the excerpted modules. Re-review on a concrete failure or source change.

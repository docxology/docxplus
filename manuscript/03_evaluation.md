# 3. Evaluation

## 3.1 Round-trip integrity across every capability

The showcase build (`scripts/04_dossier.py`) produces one signed `.docx` — a
"self-verifying dossier" — that exercises every sealing lineage in a single file,
then re-reads and verifies each in process. Its five modules recover cleanly:

| Slot | Channel | Sealing | Recovers with |
| --- | --- | --- | --- |
| `source` | package_part (`project` payload) | password | the password → a whole reproducible repo on disk |
| `annex` | package_part (nested `docxplus`) | password | the password → a sealed sub-document |
| `review` | package_part | recipients (X25519) | any recipient's private key |
| `vault` | package_part | threshold | any 3 of 5 Shamir shares |
| `notes` | package_part | password (decoy) | one password → the real payload, another → a cover story |

Every check passes: `opc_valid`, signed `provenance` (Merkle root over the module
set + `surface_digest` over the visible text), the carried project reproduces, the
nested document opens, the multi-recipient and 3-of-5 threshold modules recover, and
both decoy passwords open their own payload. The full suite is **206 real,
mock-free tests at 94.6% line coverage**; the `requires_steganographer` integration
tests pass against the built Rust binary, and the reproduction tests exercise a real
sandboxed re-run with a falsifiable negative control (a tampered source must fail).

## 3.2 The living manuscript

`scripts/05_living_manuscript.py` carries the *real* `template_code_project`
exemplar (≈ 391 KB document) with a signed reproduction attestation. A reader
verifies the attestation cryptographically without executing anything
(`verify_reproduction`), and — opting in — re-runs the attested command in the
hermetic sandbox and confirms the output digest matches (`reproduce`). This is the
format's thesis realised: a document that carries, reproduces, and *proves* the
software that produced it, while opening as an ordinary report (confirmed with the
independent `python-docx` reader).

## 3.3 Capacity

Channel capacity (`scripts/03_capacity_figure.py`) spans four orders of magnitude:
the metadata channel is a short-string carrier (≤ 8 KB by design), custom XML and
package parts are effectively unbounded, and the media channel scales with carrier
pixels — a 256×256 PNG holds ≈ 24 KB — at the standard LSB rate of one payload byte
per eight colour-channel bits minus framing. The media channel's `redundancy=N`
option replicates a payload across N carriers so the document survives losing all
but one.

## 3.4 Conformance, openability, determinism

The surface document passes the OPC validator (mandatory index parts, a typed main
document part, root-anchored reachability, no duplicate or colliding entries).
Because sealing is per-module rather than whole-package, the file never enters the
MS-OFFCRYPTO compound-file envelope and stays a directly openable `.docx` — the
intelligence layer is additive, not substitutive. Unencrypted, unsigned builds are
byte-identical across runs (`test_container.py::test_build_is_deterministic`);
encryption and signing introduce fresh salt/nonce material by design.

## 3.5 Adversarial verification

Every version from v0.2 onward was hardened by an adversarial review with
independent verification (`docs/redteam-audit.md`): v0.3 closed 18 confirmed
findings, v0.4 eleven (including a trust-anchor gap — verification now requires a
pinned `expected_public_key` to claim authenticity), and v0.5 eight (including a
co-signature that did not bind the visible text). Each fix is pinned by a regression
test, so a reintroduced defect fails the suite. Green tests are treated as necessary,
not sufficient: the load-bearing claims were reproduced by an adversary before being
believed.

# 3. Evaluation

> Numbers in this section are tokens filled from the live system by
> `scripts/render_manuscript.py` (values in `output/data/manuscript_variables.json`,
> computed by `src/manuscript_vars.py`). None are hand-typed, so none can drift.

## 3.1 Round-trip integrity across every capability

The reference dossier (`src/reference_docs.py`; the fuller showcase
`scripts/04_dossier.py` adds a carried project and a reproduction attestation)
produces one signed `.docx` — a "self-verifying dossier" — that exercises the sealing
lineages in a single file, then re-reads and verifies each in process. Its
{{DOSSIER_MODULE_COUNT}} modules recover cleanly:

{{DOSSIER_TABLE}}

Every check passes: `opc_valid`, signed `provenance` (a Merkle root over the module
set plus a digest of the visible text), the carried project reproduces, the nested
document opens, the multi-recipient and k-of-n threshold modules recover, and both
decoy passwords open their own payload. The suite is {{TEST_COUNT}} real, mock-free
test functions under a {{COVERAGE_GATE}}% coverage gate; the `requires_steganographer`
integration tests pass against the built Rust binary, and the reproduction tests
exercise a real sandboxed re-run with a falsifiable negative control (a tampered
source must fail).

## 3.2 The living manuscript

`scripts/05_living_manuscript.py` carries the *real* `template_code_project`
exemplar with a signed reproduction attestation. A reader verifies the attestation
cryptographically without executing anything (`verify_reproduction`), and — opting
in — re-runs the attested command in the hermetic sandbox and confirms the output
digest matches (`reproduce`). This is the format's thesis realised: a document that
carries, reproduces, and *proves* the software that produced it, while opening as an
ordinary report (confirmed with the independent `python-docx` reader).

## 3.3 Capacity

Channel capacity (`scripts/03_capacity_figure.py`) spans four orders of magnitude:
the metadata channel is a short-string carrier (≤ {{METADATA_MAX_BYTES}} bytes by
design), custom XML and package parts are effectively unbounded, and the media
channel scales with carrier pixels — a 256×256 PNG holds {{MEDIA_CAP_256}} bytes and
a 512×512 PNG {{MEDIA_CAP_512}} — at the standard LSB rate of one payload byte per
eight colour-channel bits minus framing. The media channel's `redundancy=N` option
replicates a payload across N carriers so the document survives losing all but one.

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
independent verification; every confirmed finding and its fix is recorded in
`docs/redteam-audit.md`, each pinned by a regression test so a reintroduced defect
fails the suite. A trust-anchor review made authenticity require a caller-pinned
`expected_public_key`, and a co-signature review bound co-signatures to the visible
text. Green tests are treated as necessary, not sufficient: the load-bearing claims
were reproduced by an adversary before being believed.

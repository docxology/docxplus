# 3. Evaluation

## 3.1 Round-trip integrity

The reference build (`scripts/01_build_example.py`) produces a single `.docx`
carrying five modules across all four channels, one of them encrypted, under an
Ed25519-signed manifest. Re-reading it (`scripts/02_roundtrip_report.py`) yields:

| Slot | Channel | Encrypted | Recovered | Status |
| --- | --- | --- | --- | --- |
| brief | custom_xml | no | 73 B | ok |
| dossier | package_part | no | 25 B | ok |
| routing | metadata | no | 20 B | ok |
| figure | stego_media (python_lsb) | no | 37 B | ok |
| secret | package_part | yes | 17 B | ok |

`opc_valid: true`, `signature: valid`. Every module's recovered plaintext matches
its manifest digest; the encrypted module recovers only with the correct password.
The full test suite is 101 real, mock-free tests at 95% line coverage; the two
`requires_steganographer` integration tests pass against the built Rust binary,
proving the premium media backend round-trips end-to-end.

## 3.2 Capacity

Channel capacity (`scripts/03_capacity_figure.py`, `output/figures/capacity.png`)
spans four orders of magnitude: the metadata channel is a short-string carrier
(≤ 8 KB by design), custom XML and package parts are effectively unbounded, and the
media channel scales with carrier pixels — a 256×256 PNG holds ≈ 24 KB, a 512×512
PNG ≈ 98 KB, at the standard LSB rate of one payload byte per eight colour-channel
bits minus framing.

## 3.3 Conformance and openability

The surface document passes DOCX+'s OPC validator: mandatory `[Content_Types].xml`
and `_rels/.rels`, a typed main document part, full relationship reachability, no
duplicate entries. Because payload encryption is per-module rather than
whole-package, the file never enters the MS-OFFCRYPTO compound-file envelope and so
remains a directly openable `.docx` — the intelligence layer is additive, not
substitutive.

## 3.4 Determinism

Unencrypted, unsigned builds are byte-identical across runs (verified in
`test_container.py::test_build_is_deterministic`), satisfying the reproducibility
discipline the standards report prescribes for ZIP-based formats. Encryption and
signing introduce fresh salt/nonce material by design.

# RedTeam Audit — v0.2 → v0.3

An adversarial review of DOCX+ v0.2 ran five parallel finder dimensions (crypto,
deniability/metadata-leak, parsing/resource-safety, format-conformance, overclaims)
with an independent verification pass that reproduced each finding against the live
tree. Confirmed findings and their resolution in v0.3:

| # | Sev | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | critical | Manifest announced `mode:"decoy"`, destroying deniability | Decoy is now an ordinary `password` module; every password module carries a chaff second frame, so it is byte-indistinguishable |
| 2 | high | Manifest stored an unkeyed **plaintext** digest of encrypted modules — an offline confirmation oracle | Digest now binds the **stored ciphertext** bytes; plaintext integrity is the GCM tag |
| 3 | high | `recipients` sealing wrote recipient X25519 pubkeys + count into the manifest | Manifest records only `{mode: recipients}`; the DXE2 envelope carries what extraction needs |
| 4 | high | Zip-Slip guard used `str.startswith`, allowing sibling-dir escape | Containment via `Path.is_relative_to` |
| 5 | high | `tar.extractall` unfiltered — symlink escape past the lexical pre-scan | Reject link members + `filter="data"` (3.12+) |
| 6 | high | Project tar.gz had no size/ratio cap (decompression bomb) | Per-total uncompressed cap enforced before extract |
| 7 | high | OPC zip read buffered every entry with no caps (zip bomb) | Per-entry / total / inflate-ratio caps in `read_package` |
| 8 | high | Signature did not bind the visible document text | `surface_digest` of `word/document.xml` folded into the signed body; `verify_provenance` checks it |
| 9 | medium | Unsigned packages are forgeable | Inherent without a signature; validation now emits a loud WARNING and the model documents it |
| 10 | medium | Attacker-controlled KDF work factor → DoS | Scrypt `N ≤ 2^21`, PBKDF2 `≤ 5M` enforced on read |
| 11 | medium | Decoy `DXD1` magic + length betrayed the second envelope | Removed; self-delimiting frames with no magic, uniform 2-frame layout |
| 12 | medium | Nested `docxplus` opening had no depth cap | `MAX_NEST_DEPTH` tracked across the chain |
| 13 | medium | Reachability check was not root-anchored (orphan chains passed) | Root-anchored BFS from package relationships |
| 14 | medium | Docs described PBKDF2/old envelope layout | Spec/security-model/README updated to Scrypt + KDF-tagged envelope |
| 15 | low | Shamir `combine` does no share verification | Fails closed via the AEAD tag (wrong key → GCM failure); VSS is future work |
| 16 | low | Merkle root exposed no inclusion proofs (redundant with signed list) | Added `inclusion_proof` / `verify_inclusion` |
| 17 | low | Stored `merkle_root` was never verified (inert) | Validation recomputes and checks it |
| 18 | low | Cookbook referenced nonexistent API (`extract_threshold`, `redundancy=`) | Cookbook corrected; redundant media marked roadmap |

Each fix is pinned by a regression test in `tests/test_hardening.py`, so a
reintroduced defect fails the suite. The adversarial method — find, then
independently reproduce before believing — is itself the deliverable: green tests
are necessary, not sufficient, and every claim here traces to a reproduced defect.

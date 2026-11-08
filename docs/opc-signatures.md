# Whole-package OPC digital signatures — integration assessment

Status: **assessed, not implemented.** This document answers the roadmap item
"whole-package OPC digital signature alongside the manifest signature (Digital
Signature Origin part), per standards-report §8.1". It states what the feature
would require, how it interacts with the signature docxplus already has, and the one
security question that has to be answered before any of it is worth building.

## What docxplus signs today

`DocxPlusBuilder.sign` produces an Ed25519 signature over
`manifest.canonical_body()`, which binds:

* every module record — slot, channel, payload type, size, and the digest of the
  **stored (sealed) bytes**;
* the Merkle root over the module set, so adding, dropping, or swapping a module
  breaks the root;
* `surface_digest`, a digest over the entire package — every part and its bytes,
  the content-type map, and the relationship graph — so the signature cannot be
  transplanted onto different visible text, nor survive a part being added, retyped,
  or re-pointed.

That is a complete signature over *the intelligence layer plus the package*. What it
is not is an **OPC** signature: it lives in the manifest rather than
`_xmlsignatures`, so no office suite will display or check it.

## What an OPC signature would sign

The OPC digital signature framework ([ISO/IEC 29500-2]; see standards-report
§8.1) stores signatures as package parts:

```text
_xmlsignatures/origin.sigs      # Digital Signature Origin — no markup; the entry point
_xmlsignatures/sig1.xml         # XML-DSig: SignedInfo, references, X.509 certificate
_rels/.rels                     # relationship → the origin part
[Content_Types].xml             # overrides for the signature part content types
```

Each signature enumerates what it covers: `IOpcSignaturePartReference` per signed
part, `IOpcSignatureRelationshipReference` per Relationships part, and the
digest of each. The Digital Signature Origin part "does not contain signature
markup" but "serves as the starting point for locating all signatures in the
package".

Requirements to implement it:

| Requirement | Why it is not free |
| --- | --- |
| Canonical XML (C14N) | XML-DSig digests canonicalized XML, not raw bytes. Python has no C14N implementation in the standard library that covers the exclusive-c14n profile Office emits; this is a real dependency, not a helper function. |
| X.509 certificates | OPC signatures carry a certificate chain, not a raw public key. docxplus currently uses raw Ed25519 keys with no PKI. Signing would mean introducing certificate issuance, validation, and trust-store questions. |
| Algorithm agreement | Word validates a fixed algorithm set (RSA/ECDSA with SHA-2). Ed25519 is not among what Office will verify, so an OPC signature would use a *different key and algorithm* from the manifest signature. |
| Relationship coverage | Signing parts but not `_rels` lets an attacker re-point relationships. Getting the reference set right is where OPC signing implementations usually go wrong. |

## The security question that decides the design

**An OPC signature that does not cover the intelligence parts is worse than no
OPC signature.**

docxplus payloads live in custom XML parts, package parts, media, and inside
`document.xml`. If a package signature enumerates only the conventional Word
parts — which is what a naive integration would do, since that is what Word
itself signs — then:

1. Word displays a valid, trusted signature.
2. An attacker strips or replaces every intelligence part.
3. The document still reports as signed, because the intelligence parts were
   never in the reference set.

The visible trust indicator would then be actively misleading about the
document's actual contents. The manifest signature would still catch the
tampering, but only for a reader that checks it — and the entire point of an OPC
signature is to be checked by readers that know nothing about docxplus.

The two signatures also fail in opposite directions, which is the useful part:

| | Covers intelligence layer | Covers OPC part graph | Verified by Word |
| --- | --- | --- | --- |
| Manifest Ed25519 signature | yes | yes, normalized format-3 commitment including relationship IDs | no |
| OPC XML-DSig (not implemented here) | only if explicitly enumerated | according to signed references/transforms | application-dependent |

## Recommendation

The enforced syntactic gate requires the reachable namespace-qualified SignedInfo/
Manifest reference set to cover the intelligence manifest and every carrier part
(including metadata, MCE and plural media locations). Arbitrary Reference-like
elements do not count. `validate.py` checks this coverage, **not** XML-DSig
cryptography, X.509 trust, transform correctness or a native trusted-signature result.
The future signer must derive coverage from actual manifest locations, not a
fixed list of conventional Word parts. Passing this gate is necessary, not sufficient.

Not scheduled: the C14N and X.509 dependencies are disproportionate to the
research value, and the dual-key story (Ed25519 for intelligence, RSA/ECDSA for
the surface) needs a decision first. Tracked in `TODO.md` under Format.

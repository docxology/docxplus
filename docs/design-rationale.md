# docxplus Design Rationale (First-Principles)

## Deconstruction — what is a docxplus actually made of?

Strip away convention and a docxplus is five irreducible primitives:

1. **Container** — a byte-addressable set of named parts with a reachability graph
   (OPC/ZIP). *Hard constraint*: to stay an openable `.docx`, the surface must be a
   conforming OPC package. Everything else is free.
2. **Channel** — a placement of bytes into the container that a word processor
   ignores. *Soft constraint*: which spec affordance (custom XML, extra part,
   property, media LSB). New channels are pure additions.
3. **Codec** — a reversible transform on a payload before placement (identity,
   compress, encrypt, secret-share, stego-frame). *Assumption to challenge*: "one
   password, one payload." Nothing forces single-recipient or single-secret.
4. **Payload type** — what the bytes *mean* (opaque bytes, JSON, a whole project, a
   nested container). *Assumption to challenge*: "a payload is a blob." A payload can
   be a typed, self-describing, even recursively-containerised object.
5. **Manifest** — the signed binding that says which typed payloads live on which
   channels under which codecs. *Hard constraint*: the manifest must be the single
   source of truth, or readers guess and integrity dies.

## Constraint table

| Constraint | Type | Challenge → consequence |
| --- | --- | --- |
| Surface must be OPC-conforming | Hard | keep; it is the whole value proposition |
| One password / one payload | Assumption | drop → multi-recipient + k-of-n threshold + decoys |
| A payload is opaque bytes | Assumption | drop → typed payloads: project, nested docx, json graph |
| One signer over the manifest | Soft | relax → Merkle root + detached co-signatures |
| Integrity = per-module digest | Soft | strengthen → append-only Merkle chain with a tip seal |
| Concealment = one LSB image | Soft | relax → redundant/spread carriers |

## Reconstruction — the orthogonal axes we scale along

The v0.1 design conflated "payload" with "bytes" and "encryption" with "one
password." Rebuilt from the primitives, complexity grows on **five independent
axes**, each composable with the others:

- **Payload richness** — a typed payload registry: `bytes`, `text`, `json`,
  `project` (a whole reproducible repo packed to a deterministic tar), `docxplus`
  (a nested container). Recursion is free once payloads are typed.
- **Cryptographic depth** — from one-password AES-GCM to X25519 **multi-recipient**
  hybrid sealing (one document, many key-holders) and Shamir **k-of-n threshold**
  (no single holder can open it).
- **Composition** — nesting: a docxplus inside a module of another docxplus. Matryoshka
  sealing, each layer with its own recipients.
- **Provenance** — a **Merkle root** over all module digests, signed, with an
  append-only tip seal, so the *set* of modules is bound, not just each module (an
  attacker cannot drop or add a module without breaking the root).
- **Covert depth** — redundant media carriers and decoy payloads (two secrets, two
  passwords) for plausible deniability.

## Key insight

The limiting assumption was that a docxplus *contains data*. It contains **typed,
independently-sealed, provenance-bound objects** — and one of those object types is
"a whole signed, encrypted, reproducible project," so a document can literally carry
the software that produced it.

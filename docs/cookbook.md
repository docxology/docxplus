# DOCX+ Cookbook — Intelligent Document Concepts

Eight document *kinds* the v0.2 primitives make buildable. Each is a real recipe
against the `DocxPlusBuilder` / `DocxPlusReader` API; see `tests/` for executable
versions.

## 1. The Self-Verifying Dossier
A report that carries the **entire reproducible project** that produced it, signed
and encrypted. A recipient extracts the project, runs its tests, and reproduces the
figures — the paper *is* the software.
```python
builder.add_project("source", "projects/templates/template_code_project", password="review")
reader.extract_project("source", dest, password="review")  # -> runnable repo on disk
```

## 2. The Matryoshka Document
A DOCX+ whose module is itself a sealed DOCX+, recursively. Each layer can target
different recipients — an outer document for the team, an inner one for two people.
```python
inner = DocxPlusBuilder(...).add_module("q4", "package_part", secret).build()
builder.add_nested("sealed", inner)          # a whole container as one module
```

## 3. The Dead-Man's Envelope (k-of-n threshold)
The dossier's content key is Shamir-split into *n* shares; any *k* custodians
together reconstruct it, none alone. Distribute shares to a board; three of five can
open it.
```python
builder.add_threshold("legacy", payload, k=3, n=5)
data = builder.build()
shares = builder.threshold_shares["legacy"]        # the 5 shares to distribute
DocxPlusReader.from_bytes(data).extract("legacy", shares=shares[:3])
```

## 4. The Sealed Referee Packet (multi-recipient)
One file that opens for the author, each reviewer, and the editor — each with their
own X25519 key — without re-encrypting per recipient. The content key is wrapped
once per recipient.
```python
builder.add_module("manuscript", "package_part", pdf, recipients=[author_pub, ref1_pub, editor_pub])
reader.extract("manuscript", private_key=ref1_priv)
```

## 5. The Provenance Ledger Document
Every module is hashed into a **Merkle root** signed into the manifest, with an
append-only tip seal. Dropping, swapping, or injecting a module breaks the root —
tamper-evidence over the *set*, not just each part.
```python
builder.sign(priv)                 # signs the Merkle root over all modules
reader.verify_provenance()         # -> root matches, tip intact
```

## 6. The Polyglot Carrier (redundant media) — *roadmap*
A payload spread across several embedded figures so the document survives losing
one image (crop, re-export). Survivability, not just concealment. Redundant/spread
media carriers are a planned channel option (see `TODO.md`); today the media
channel places one carrier per module.

## 7. The Time-Capsule with a Decoy (plausible deniability)
Two payloads share one module: a benign cover story under one password, the real
content under another. The module is recorded as an ordinary `password` module, and
every password module carries a second (chaff) frame, so nothing in the file
reveals that a hidden payload exists. This is deniability against inspection, not a
proof of non-existence — see `docs/security-model.md`.
```python
builder.add_decoy("notes", real=secret, real_password="a", decoy=cover, decoy_password="b")
reader.extract("notes", password="a")   # the real content
reader.extract("notes", password="b")   # the cover story
```

## 8. The Living Manuscript
Concept #1 + #5: the manuscript carries its own project (self-verifying) under a
signed Merkle provenance root (tamper-evident). Extract, reproduce, and prove the
document and its software are the ones the author sealed.

---

Every recipe keeps the **surface contract**: the file still opens as an ordinary
`.docx`. The intelligence is additive.

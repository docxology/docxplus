# docxplus Cookbook — Intelligent Document Concepts

Eight document *kinds* the v0.2 primitives make buildable. Each is a real recipe
against the `DocxPlusBuilder` / `DocxPlusReader` API; see `tests/` for executable
versions.

## 1. The Self-Verifying Dossier
A report that carries the **entire reproducible project** that produced it, signed
and encrypted, plus a signed **reproduction attestation** binding its source to a
deterministic output digest. A recipient verifies cryptographically (no execution),
or opts in to re-run it in a sandbox and confirm the outputs match — the paper *is*
the software, and it proves so.
```python
builder.add_project("source", "…/template_code_project", password="review", reproduce=True)
reader.verify_reproduction("source")                       # cryptographic, executes nothing
reader.reproduce("source", dest, allow_execution=True, password="review")  # opt-in sandbox re-run
```

## 2. The Matryoshka Document
A docxplus whose module is itself a sealed docxplus, recursively. Each layer can target
different recipients — an outer document for the team, an inner one for two people.
```python
inner = DocxPlusBuilder(...).add_module("q4", "package_part", secret).build()
builder.add_nested("sealed", inner)          # a whole container as one module
```

## 3. The Dead-Man's Envelope (k-of-n threshold & VSS)
The dossier's content key is Shamir-split into *n* shares; any *k* custodians
together reconstruct it, none alone. Optional Verifiable Secret Sharing (`verifiable=True`)
attaches Blake2b integrity tags so corrupted or malicious shares are detected prior to reconstruction.
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

## 6. The Polyglot Carrier (redundant media)
A payload replicated across several embedded figures so the document survives losing
all but one (crop, re-export, a stripped figure). Extraction returns the first
replica whose bytes match the module digest, so a corrupted-but-decodable carrier is
skipped, not returned. Survivability, not just concealment.
```python
builder.add_module("fig", "stego_media", data, backend="python_lsb", redundancy=3)
# lose any two of the three carriers; reader.extract("fig") still recovers the payload
```

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
Concept #1 + #5: the manuscript carries its own project under a signed Merkle
provenance root (tamper-evident) *and* a reproduction attestation. A reader confirms
the document, its software, and its results are the ones the author sealed — and can
re-derive them. Run `scripts/05_living_manuscript.py`, which does exactly this over
the real `template_code_project`.

## 9. The MCE Hidden Channel
Embeds payload modules directly inside the WordprocessingML main document (`word/document.xml`)
using `<mc:Choice>` branches marked with an ignorable namespace (`urn:docxplus:mce:1.0`).
Unaware word processors discard the choice branch and render the empty `<mc:Fallback/>`, so a concealed
module adds no visible paragraph.
```python
builder.add_module("notes", "mce", secret_data)
reader.extract("notes")
```

## 10. The ODT Sibling Container
An OASIS OpenDocument Text archive carrying the same signed intelligence manifest as the
`.docx` profile, in byte-exact ODF 1.3/1.4 conformance. Use `OdtPlusBuilder`: `odt.py`
alone builds only the *surface* package, so `new_base_odt(...).add_part(...)` yields a
conforming `.odt` carrying loose bytes and **no manifest, no sealing, and no signature**.
```python
from odt_container import OdtPlusBuilder, OdtPlusReader

builder = OdtPlusBuilder(paragraphs=["ODF surface text"])
builder.add_module("brief", payload_bytes, password="s3cret").sign(priv)
odt_bytes = builder.build()

reader = OdtPlusReader.from_bytes(odt_bytes)
assert reader.verify_provenance(expected_public_key=pub)
assert reader.extract("brief", password="s3cret") == payload_bytes
```

---

Every recipe keeps the **surface contract**: the file still opens as an ordinary
document (`.docx` or `.odt`). The intelligence is additive.

## 11. The self-carrying project, verified both ways

A report that carries its own source, in either container, with the round trip proved
rather than assumed.

```python
from container import DocxPlusBuilder, DocxPlusReader
from odt_container import OdtPlusBuilder, OdtPlusReader
import crypto

priv, pub = crypto.generate_signing_key()

docx = DocxPlusBuilder(paragraphs=["A report that carries its own source."])
docx.add_project("source", "./myproject", reproduce=True, password="s3cret").sign(priv)

odt = OdtPlusBuilder(paragraphs=["The same, as OpenDocument."])
odt.add_project("source", "./myproject", reproduce=True, password="s3cret").sign(priv)

reader = DocxPlusReader.from_bytes(docx.build())
assert reader.verify_provenance(expected_public_key=pub)      # authenticity needs the pin
assert reader.verify_reproduction("source", expected_public_key=pub)["verified"]
reader.extract_project("source", "./recovered", password="s3cret")
```

From the CLI, including the fidelity check:

```bash
docxplus build report.docx --project source:./myproject --attest \
    --password s3cret --signing-key key.hex
docxplus odt-build report.odt --module notes:notes.txt --signing-key key.hex
docxplus validate report.docx && docxplus odt-validate report.odt
./run.sh roundtrip          # diffs a carried tree against the original, both profiles
```

**What you are relying on.** The tree comes back with contents and the executable bit
intact, empty directories present, and build junk absent. Symlinks are refused rather
than followed — packing one would embed its target's bytes under the link's name — so
a tree containing them needs `follow_symlinks=True` and a moment's thought about what
those links point at. `docs/format-spec.md` §8.1 is the full contract.

## 12. A document inside a document, across containers

Matryoshka nesting does not care which container the inner document uses.

```python
from odt_container import OdtPlusBuilder, OdtPlusReader, open_document

outer = OdtPlusBuilder(paragraphs=["An ODF wrapper."])
outer.add_nested("inner", signed_docx_bytes, password="matryoshka").sign(priv)

reader = OdtPlusReader.from_bytes(outer.build())
inner = reader.open_nested("inner", password="matryoshka")   # returns a DocxPlusReader
assert inner.verify_provenance(expected_public_key=pub)

open_document(some_bytes)   # dispatches on the container's own magic, not a caller flag
```

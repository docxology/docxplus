# docxplus Cookbook — Intelligent Document Concepts

Document kinds built from the `DocxPlusBuilder` / `DocxPlusReader` APIs. Examples
illustrate contracts; source tests and source-bound run receipts establish which
fixtures have actually been exercised.

## 1. The Self-Verifying Dossier
A report can carry a selected project tree, signed and encrypted, plus a signed
claim binding its carried bytes to a recipe and selected output digest. Pinned
verification authenticates the claim without execution; explicit re-execution
compares local outputs. Neither operation proves scientific validity.
```python
builder.add_project("source", "…/template_code_project", password="review", reproduce=True)
reader.verify_reproduction("source", expected_public_key=pub)  # authenticates claim; no execution
reader.reproduce("source", dest, allow_execution=True, password="review")  # opt-in sandbox re-run
```

## 2. The Matryoshka Document
A docxplus whose module is itself a sealed docxplus, recursively. Each layer can target
different recipients — an outer document for the team, an inner one for two people.
```python
inner = DocxPlusBuilder(...).add_module("q4", "package_part", secret).build()
builder.add_nested("sealed", inner)          # a whole container as one module
```

## 3. The Dead-Man's Envelope (k-of-n threshold)
The content key is Shamir-split into *n* shares; any *k* reconstruct it. Container
manifests commit to complete issued-share digests and readers check them before
combine. The standalone tagged-share checksum is unkeyed, not malicious-share
authentication or Feldman/polynomial VSS; authentic commitments require a pinned signer.
```python
builder.add_threshold("legacy", payload, k=3, n=5)
data = builder.build()
shares = builder.threshold_shares["legacy"]        # the 5 shares to distribute
DocxPlusReader.from_bytes(data).extract("legacy", shares=shares[:3])
```

## 4. The Sealed Referee Packet (multi-recipient)
One file opens for each recipient without re-encrypting its body: choose raw X25519
keys (DXE2) or all genuine X25519 + ML-KEM-768 composite keys (DXE3).
The content key is wrapped per recipient; mixed key families refuse.
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
reader.verify_provenance(expected_public_key=pub)  # authenticity needs the trusted pin
```

## 6. The Polyglot Carrier (redundant media)
A payload is replicated across embedded figures; extraction can use a surviving
replica whose stored bytes match the recorded digest. This does not guarantee
survival through crop/re-export or preserve the original signature after package edits.
```python
builder.add_module("fig", "stego_media", data, backend="python_lsb", redundancy=3)
# lose any two of the three carriers; reader.extract("fig") still recovers the payload
```

## 7. The Time-Capsule with a Decoy (limited cover story)
Two payloads share one `password` module under different passwords. Ordinary and
decoy modules use exactly two bounded frames, matching KDF parameters and equal
power-of-two padding buckets. This removes simple framing distinctions, not
distributional/timing attacks or coercion; size ranges and format use remain visible.
See [`security-model.md`](security-model.md).
```python
builder.add_decoy("notes", real=secret, real_password="a", decoy=cover, decoy_password="b")
reader.extract("notes", password="a")   # the real content
reader.extract("notes", password="b")   # the cover story
```

## 8. The Living Manuscript
The manuscript can carry the selected repository tree and a signed reproduction
claim. `scripts/05_living_manuscript.py` demonstrates a dependency-free hash of
selected docxplus Python source, **not** re-execution of tests, figures, rendering
or the full scientific pipeline. Nonselected inputs need not affect that hash.

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
An OpenDocument Text archive carries the same intelligence manifest/sealing as
DOCX over an ODF 1.3-targeted surface. Structural checks are not complete schema
certification or proof about all applications. Use `OdtPlusBuilder`; `odt.py` alone
builds a surface package without an intelligence manifest or signature.
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

A report can carry selected source in either profile; a source-bound round-trip
report provides empirical fixture evidence, not a general project-fidelity proof.

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
# "./recovered" must be new or empty; extraction never merges a nonempty tree.
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

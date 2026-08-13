# DOCX+ — the Intelligent Document Container

> A byte-valid OOXML `.docx` that is **also** a modular, signed, encrypted
> intelligence carrier. It opens as an ordinary document in Word, LibreOffice, and
> Google Docs, while carrying structured payloads through the spec-sanctioned
> side-channels that the OOXML/ODF standards actually permit.

DOCX+ is a standards-first reference implementation. Every channel it uses is
grounded in a documented feature of ISO/IEC 29500 (OOXML) or its ODF cousin —
custom XML parts, additional package parts, custom document properties, embedded
media — layered with an Ed25519-signed manifest and AES-256-GCM payload
encryption. The media channel bridges to
[docxology/steganographer](https://github.com/docxology/steganographer) so the
intelligence can ride inside the least-significant bits of an image the document
visibly displays.

## Why this is not "just a zip trick"

A `.docx` is an Open Packaging Conventions (OPC) ZIP. The standards report this
project is built on (`docs/standards-report.md`) establishes the exact rules:
mandatory `[Content_Types].xml` + `_rels/.rels`, every part reachable by
following relationships, no duplicate entries, deterministic output. DOCX+ obeys
all of them — so the surface document stays *conforming*, not merely openable —
and then uses the standard's own extension points to carry more.

## Channels (modules)

| Channel | Where the payload lives | In-spec basis | Good for |
| --- | --- | --- | --- |
| `custom_xml` | `customXml/itemN.xml` | mapped content-control data is "flat Open XML markup" (§3.1) | structured records |
| `package_part` | `intelligence/payloadN.dxp` | "a package may contain additional files" (§2.2) | bulk / encrypted blobs |
| `metadata` | `docProps/custom.xml` property | custom document properties (§9) | short routing tags |
| `stego_media` | LSBs of `word/media/imageN.png` | embedded image parts (§2.1) + LSB stego | payload hidden in a visible figure |

Every module is described by a signed **manifest** (`intelligence/manifest.json`)
— the authoritative list of what the package carries, playing the role ODF
assigns to `META-INF/manifest.xml`.

## What v0.2 adds

The primitives scale on five orthogonal axes (see `docs/design-rationale.md`):

- **Typed payloads** — `bytes`, `text`, `json`, **`project`** (a whole reproducible
  repo packed to a deterministic tar), **`docxplus`** (a nested container). A
  document can literally carry the software that produced it.
- **Cryptographic depth** — `password` (AES-GCM), **multi-recipient** (X25519, one
  file that opens for many key-holders), **k-of-n threshold** (Shamir; no single
  holder can open it), and **decoy** (two secrets, two passwords).
- **Composition** — nest a sealed DOCX+ inside another (matryoshka).
- **Provenance** — a signed **Merkle root** binds the whole module set; adding,
  dropping, or swapping a module breaks the signature.
- **Covert depth** — the media channel's dual LSB backends.

`docs/cookbook.md` gives eight buildable document kinds (self-verifying dossier,
dead-man's envelope, sealed referee packet, provenance ledger, …). The showcase
`scripts/04_dossier.py` builds and verifies all of them in one file.

## v0.4 — the reproduction attestation (execution as evidence)

Designed through four lenses (FirstPrinciples, Council, Science, RedTeam;
`docs/reproduction-design.md`). A `project` module can carry a **signed
reproduction attestation** binding its source to a deterministic output digest, so
a reader can trust that its results *follow from its code*:

- **`verify_reproduction(slot)`** — cryptographic, **executes nothing** (the default
  trust path; the document is inert data).
- **`reproduce(slot, dest, allow_execution=True)`** — opt-in, re-runs the attested
  command in a best-effort hermetic sandbox (scrubbed env, resource caps, timeout,
  network denied where the platform allows) and compares digests.

`scripts/05_living_manuscript.py` carries the real `template_code_project`, attests
it, verifies cryptographically, and reproduces it in the sandbox — the exemplar a
document carries, reproduces, and proves. The Council's rule is enforced in code: a
document never executes on open; only a deliberately-invoked verifier does, in a
jail. A digest match attests process, not that the science is sound — stated plainly.

## v0.3 — RedTeam-hardened

An adversarial review (`docs/redteam-audit.md`, run as a multi-agent workflow with
independent verification) confirmed and closed 18 findings: memory-hard **Scrypt**
key derivation with capped work factors, **ciphertext-bound** module digests (no
plaintext-confirmation oracle), **AAD** slot binding, recipient-set and decoy
metadata that no longer leak, a signature that also binds the **visible document
text**, **Merkle inclusion proofs**, and untrusted-intake caps (zip/tar
decompression bombs, path-traversal, symlink escape, nesting depth). Each fix is
pinned by a regression test in `tests/test_hardening.py`.

## Quick start

```bash
uv venv && uv pip install -e '.[dev,media]'
./run.sh                      # preflight -> tests -> build example -> roundtrip report

# Or use the CLI directly:
uv run docxplus build report.docx --text "Quarterly summary" \
    --module brief:custom_xml:brief.json --password s3cret
uv run docxplus inspect report.docx
uv run docxplus extract report.docx brief --password s3cret --out brief.json
uv run docxplus validate report.docx
```

## Security posture

Payloads are encrypted at the *payload* level (AES-256-GCM, PBKDF2-HMAC-SHA512 key
derivation — the MS-OFFCRYPTO agile lineage), **not** as whole-package OOXML
encryption, so the document stays a valid, openable Office file. The manifest is
Ed25519-signed for provenance. See `docs/security-model.md` for the full threat
model, grounded in the USENIX 2022/2023 analyses the standards report cites.

## Layout

```
src/            tested domain modules (opc, wordml, crypto, lsb, channels/, manifest, container, validate)
scripts/        thin orchestrators (preflight, build example, roundtrip report, capacity figure)
tests/          real round-trip tests, no mocks (≥90% coverage gate)
manuscript/     the DOCX+ format write-up
docs/           format spec, architecture, security model, standards report
docxplus_cli.py the `docxplus` command-line tool
```

## License

MIT. See `LICENSE`.

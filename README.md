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

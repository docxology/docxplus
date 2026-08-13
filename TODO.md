# TODO — DOCX+

Registered next steps (present-state; no session logs).

## Format
- [ ] Whole-package OPC digital signature alongside the manifest signature
      (Digital Signature Origin part), per standards-report §7.1.
- [ ] MCE `AlternateContent`/`Choice`/`Fallback` channel exercising an Ignorable
      extension namespace inside `document.xml` (standards-report §4.1).
- [ ] ODT sibling profile using `META-INF/manifest.xml` directly (standards-report §2.2).

## Hardening
- [ ] Untrusted-input intake wrapper around the reader: inflate-ratio cap,
      per-entry size cap, Zip-Slip canonicalisation, DTD disabling, sandboxed parse
      (standards-report §14.3). `defusedxml` and no-disk-extraction are already in place.
- [ ] Steganalysis self-check: expose the steganographer `analyze` command through
      `steg_bridge` to report LSB detectability of produced carriers.

## Interop
- [ ] Validate produced documents against Office-o-tron and the ODF Toolkit
      validator in CI (standards-report §11.6).
- [ ] Confirm openability across Word / LibreOffice / Google Docs with a headless
      LibreOffice convert-to-pdf smoke test.

## Packaging
- [ ] CI workflow (uv + pytest + coverage gate). Optional steganographer job.
- [ ] Publish flow (tag → Zenodo DOI) if the repo goes public.

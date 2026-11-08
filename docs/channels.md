# Transport channels

A **channel** is where a module's bytes physically live inside the package. Each
implements one contract — `embed` / `extract` / `capacity` — so a channel can be added
without touching crypto, payload typing, or the container.

[`format-spec.md`](format-spec.md) §3 is normative for the wire format. This page is
the working reference: what each channel costs, what it is good for, and where it
bites.

One rule governs all of them: **the manifest is authoritative.** A reader resolves a
module from its recorded `location`, never by scanning ZIP entries and guessing. That
is what stops an attacker introducing a part the reader treats as intelligence.

---

## Choosing one

| Need | Channel |
| --- | --- |
| Bulk data, code archives, ciphertext | `package_part` |
| Structured records a consumer might map | `custom_xml` |
| A routing tag, identifier, or key share | `metadata` |
| Concealment, not just confidentiality | `stego_media` |
| Payload inside the main story part itself | `mce` |

---

## `custom_xml` — OOXML only

Base64 in `customXml/itemN.xml`, registered via `customXml/itemPropsN.xml` and
referenced from the main document part. Layout engines ignore these parts entirely
while they remain valid against the OOXML custom XML mapping schemas.

**Capacity** has no channel-local limit; package entry/total/count budgets apply.
**Visibility** none. **Cost** base64 inflates by a third.

---

## `package_part` — both profiles

Raw bytes at `intelligence/payloadN.dxp` under a declared content type, referenced by
a package-level relationship. The default and the workhorse.

**Capacity** has no channel-local limit; package entry/total/count budgets apply.
**Visibility** none. **Cost** none — no encoding overhead.

The ODF profile records this package-entry channel as `odt_package_part`, declared
in `META-INF/manifest.xml`; ODT also supports displayed-image `stego_media`.

**Note.** A payload above 1 MiB that compresses extremely well is stored uncompressed,
because deflating it would trip the reader's own inflate-ratio guard and produce a
package this tool would refuse to open. A writer must never emit what it would reject.

---

## `metadata` — OOXML only

Base64 into a named custom document property (`dxplus_<slot>`) in
`docProps/custom.xml`.

**Capacity** bounded — see `channels.metadata.MAX_PAYLOAD`, cited in the manuscript as
a token rather than repeated here. **Visibility** the property name is listed in
document properties dialogs, so the *existence* of a module is visible even though its
contents are not.

**Collision safeguard.** A pre-existing custom property of the same name is refused
with an explicit error rather than silently overwritten or retyped.

---

## `stego_media`

Payload in the least-significant bits of an RGB PNG the document visibly displays —
`word/media/imageN.png` under OOXML, `Pictures/figureN.png` under ODF — inserted into
the visible body (`<w:drawing>` or `<draw:frame>` respectively) so the carrier is a
figure the document actually renders. That is the point: an image nothing renders is a
conspicuously spare part, not cover.

**Capacity** is backend-specific: Python DXL1 uses `floor(w·h·3/8) − 8` when
framing fits; Rust capacity comes from its actual CLI, not that Python formula.
**Visibility** the figure is visible; the payload is not.

Two backends, recorded in `location.backend`:

* `python_lsb` — pure Python, needs only the imaging library. The zero-setup default.
* `steganographer` — the Rust generic-packet CLI with BLAKE3 integrity.
  Default bridge packets are unsigned/non-ECC. An explicit `signing_key` adds
  Ed25519 signing; packet identity pinning is separate. No ECC option is exposed.

The bridge calls the real `capacity` command with actual RGB carrier units, one
bit per unit, stable `payload.bin` filename and `application/octet-stream` MIME
type, using the identical metadata/signing policy for encode. It reports the
maximum legal payload including locator/envelope/signature overhead; a carrier
too small for framing refuses rather than advertising a usable empty payload.
DXL1 likewise refuses truncated/overlength frames and uint32 overflow.

For example, the bridge's unsigned RGB sizing call is:

```bash
steganographer capacity --carrier-units N --stego-type lsb_video --bits 1 \
    --filename payload.bin --mime-type application/octet-stream --format json
```

Add the same `--signing-key FILE` policy to sizing and encode when signing.

The optional backend must provide the generic-packet and capacity CLI contracts;
steganographer 0.9 is the version this release is exercised against. Select a
built binary with `STEGANOGRAPHER_BIN` or PATH. Discovery never searches
implicit sibling checkouts or builds Cargo; invalid explicit configuration fails.
No Rust backend is required for `python_lsb`. `steg_bridge.analyze_carrier` consumes the
`steganographer.cli/v1` success envelope and returns only its analysis `result`
(including `detected` and `analysis_type`).
`steganalysis_report()["external_analysis"]` exposes that same dictionary.
Malformed contracts and nonzero CLI exits raise `StegError`, while an absent
backend is reported as unavailable by the combined report.

`redundancy=N` replicates the payload across N carriers, so the document survives
losing all but one; extraction returns the replica whose bytes match the module digest.

**Concealment is obfuscation, not secrecy.** LSB embedding is statistically detectable,
which is why the chi-squared detector ships in-tree (`docxplus analyze-carrier`). Treat
a concealed module as hidden from casual inspection, never as undiscoverable.

**Detector limits.** The Pearson adjacent-pair statistic reports `p_value`, an
upper-tail probability under pair equality, not an embedding posterior. Each
populated pair contributes a degree of freedom. Sparse/insufficient histograms
return `available=False`, `p_value=None`, not evidence of absence. Balanced untouched
covers can flag. Prefix sweeps reuse samples and are not independently calibrated.
Neither a flag nor a clean result proves presence or absence; no general
sensitivity/false-positive rate or reliable payload-size estimate is established.
RGB/LSB processing has a shared pixel cap, not a total-process memory guarantee.

---

## `mce` — OOXML only

Payload inside `<mc:Choice Requires="dxm">` within an `<mc:AlternateContent>` block in
`word/document.xml`, under an ignorable extension namespace, with an empty
`<mc:Fallback/>`. A consumer that does not recognise the namespace discards the Choice
branch and renders the fallback, with no warning and no error.

**Capacity** has no channel-local bound; XML/base64 and package entry/total/count
budgets apply.
**Visibility** none — the empty fallback means concealing a module adds no paragraph.

**Placement matters.** `CT_Body` is `(EG_BlockLevelElts*, sectPr?)`, so the block is
inserted *before* the body-level `<w:sectPr>`. Appending at `</w:body>` produces
schema-invalid markup that Word offers to repair, which is the loudest possible way to
break the surface contract.

---

## What does not cross to ODF

ODF has no custom XML datastore part and no Markup Compatibility element, so
`custom_xml` and `mce` are OOXML-only by the standards rather than by choice. An
analogue for `metadata` (`meta.xml` user-defined fields) is plausible and not yet
built; `TODO.md` tracks it and the profile-parity figure names it rather than implying
coverage. The `stego_media` analogue is built — the same channel class places carriers
at `Pictures/figureN.png` and renders them through `<draw:frame>`.

---

## Adding one

Implement `embed` / `extract` / `capacity` in `src/docxplus/channels/`, register it in
`channels/__init__.py`, and add a real round-trip test. The manifest records the
channel id; a reader that does not recognise an id fails that module explicitly rather
than silently. Two invariants any new channel must hold:

1. **Preserve profile obligations.** Channel updates must maintain required indexes,
   authority, namespace and markup order. Structural validation checks selected
   invariants; complete schema validation and native application evidence are separate.
2. **The stored digest binds what travels.** Return a `ChannelRecord` whose `digest`
   and `size` describe the bytes actually placed, so the manifest signature covers
   exactly them.

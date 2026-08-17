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

**Capacity** unbounded. **Visibility** none. **Cost** base64 inflates by a third.

---

## `package_part` — both profiles

Raw bytes at `intelligence/payloadN.dxp` under a declared content type, referenced by
a package-level relationship. The default and the workhorse.

**Capacity** unbounded. **Visibility** none. **Cost** none — no encoding overhead.

This is the only channel the ODF profile implements, where it writes ODF package
entries declared in `META-INF/manifest.xml` and is recorded as `odt_package_part`.

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

**Known limitation.** A pre-existing custom property of the same name is retyped to
`vt:lpwstr` rather than refusing the collision (`TODO.md`).

---

## `stego_media` — OOXML only

Payload in the least-significant bits of an RGB PNG at `word/media/imageN.png`, and the
image is inserted into the body as a `<w:drawing>` so the carrier is a figure the
document actually displays. That is the point: an image nothing renders is a
conspicuously spare part, not cover.

**Capacity** scales with carrier pixels: roughly `(w·h·3)/8 − 8` bytes.
**Visibility** the figure is visible; the payload is not.

Two backends, recorded in `location.backend`:

* `python_lsb` — pure Python, needs only the imaging library. The zero-setup default.
* `steganographer` — the docxology/steganographer Rust CLI, adding BLAKE3 hashing,
  Ed25519 payload signatures, and Reed–Solomon error correction.

`redundancy=N` replicates the payload across N carriers, so the document survives
losing all but one; extraction returns the replica whose bytes match the module digest.

**Concealment is obfuscation, not secrecy.** LSB embedding is statistically detectable,
which is why the chi-squared detector ships in-tree (`docxplus analyze-carrier`). Treat
a concealed module as hidden from casual inspection, never as undiscoverable.

**What the shipped detector does not find.** The chi-squared attack keys on the
pairs-of-values flattening that a *uniform* bit stream causes. A sealed module is
ciphertext and so is maximally detectable — a full carrier reports p ≈ 1. An unsealed
low-entropy payload is not detected at any fill rate: plaintext, a constant fill, or a
structured record reports p ≈ 0, the same as a clean carrier. So a clean verdict is
evidence about this attack and not about the carrier. Sealing a module makes it *more*
detectable by this test and less recoverable by everything else, which is the trade the
channel actually offers.

---

## `mce` — OOXML only

Payload inside `<mc:Choice Requires="dxm">` within an `<mc:AlternateContent>` block in
`word/document.xml`, under an ignorable extension namespace, with an empty
`<mc:Fallback/>`. A consumer that does not recognise the namespace discards the Choice
branch and renders the fallback, with no warning and no error.

**Capacity** unbounded in principle; base64 inside the main story part in practice.
**Visibility** none — the empty fallback means concealing a module adds no paragraph.

**Placement matters.** `CT_Body` is `(EG_BlockLevelElts*, sectPr?)`, so the block is
inserted *before* the body-level `<w:sectPr>`. Appending at `</w:body>` produces
schema-invalid markup that Word offers to repair, which is the loudest possible way to
break the surface contract.

---

## What does not cross to ODF

ODF has no custom XML datastore part and no Markup Compatibility element, so
`custom_xml` and `mce` are OOXML-only by the standards rather than by choice. Analogues
for `metadata` (`meta.xml` user-defined fields) and `stego_media` (`Pictures/`) are
plausible and not yet built; `TODO.md` tracks them and the profile-parity figure names
them rather than implying coverage.

---

## Adding one

Implement `embed` / `extract` / `capacity` in `src/channels/`, register it in
`channels/__init__.py`, and add a real round-trip test. The manifest records the
channel id; a reader that does not recognise an id fails that module explicitly rather
than silently. Two invariants any new channel must hold:

1. **Surface validity is invariant.** Adding, sealing, or concealing a module must
   leave the package conforming. Test it by validating a built package, not by
   inspection.
2. **The stored digest binds what travels.** Return a `ChannelRecord` whose `digest`
   and `size` describe the bytes actually placed, so the manifest signature covers
   exactly them.

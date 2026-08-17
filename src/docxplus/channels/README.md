# src/docxplus/channels/ — the side-channels

A *channel* is one spec-sanctioned place inside an otherwise-ordinary package where a
payload can ride. Five are registered. They differ in capacity, visibility, and cost,
and nothing else — the container composes them through one protocol and the manifest
describes them uniformly, so a document can carry five payloads through five channels
without any of them knowing about the others.

| Module | id | Payload lives in | In-spec basis | Capacity |
| --- | --- | --- | --- | --- |
| `custom_xml.py` | `custom_xml` | `customXml/itemN.xml` | mapped content-control data is flat Open XML markup | unbounded |
| `package_part.py` | `package_part` | `intelligence/payloadN.dxp` | a package may contain additional files | unbounded |
| `metadata.py` | `metadata` | a custom document property in `docProps/custom.xml` | custom document properties | bounded — short routing tags only |
| `mce.py` | `mce` | an `<mc:Choice>` inside `word/document.xml` | Markup Compatibility `AlternateContent` | unbounded, but writes into the main story part |
| `stego_media.py` | `stego_media` | the LSBs of `word/media/imageN.png` | embedded image parts plus LSB steganography | bounded by carrier pixels |

`base.py` holds the contract both sides bind to: the `Channel` protocol
(`embed` / `extract` / `capacity`) and `ChannelRecord`, the manifest-facing description
of *where* a payload landed. Extraction is driven by the recorded location, never by
guessing a part name — that is the property that lets a reader open a document it did
not build.

Exact capacity numbers, visibility under each viewer, cost, and caveats are in
[`../../docs/channels.md`](../../../docs/channels.md), which is the reference; the
normative definitions are in
[`../../docs/format-spec.md`](../../../docs/format-spec.md). `tests/test_docs.py` fails
the build if a registered channel is missing from either.

## Two things worth knowing before you pick one

**Not every channel crosses to ODF.** `custom_xml` has no ODF analogue (there is no
custom XML datastore part) and neither does `mce` (there is no Markup Compatibility
element). ODT payloads ride as ODF package entries — the unbounded channel. A recipe
written against `custom_xml` will not port.

**`stego_media` is the only one with an optional dependency.** It needs Pillow, and
optionally the steganographer Rust CLI for the premium backend. `available_channels()`
still lists it; `get_channel` constructs it separately because it takes carrier and
signing configuration the pure channels do not. Absence skips a test, it never turns
into a silent plaintext fallback.

Editing rules: [`AGENTS.md`](AGENTS.md).

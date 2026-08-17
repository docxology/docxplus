# src/docxplus/channels/ — adding and changing a channel

Every channel satisfies the `Channel` protocol in [`base.py`](base.py). The inventory
is in [`README.md`](README.md); the reference is
[`../../docs/channels.md`](../../../docs/channels.md). This file is the recipe and the
traps.

## The contract

```python
embed(pkg, payload, *, slot) -> ChannelRecord   # mutates pkg
extract(pkg, record)         -> bytes
capacity(pkg)                -> int | None      # None = effectively unbounded
```

`embed` receives the payload **already packed and already sealed**. A channel never
encrypts, never packs a type, and never inspects what it is carrying — it places
opaque bytes and reports where they went. Sealing lives in `container.seal_module`
precisely so both container profiles get it from one place.

`extract` must be driven by `record.location` alone. Never scan the package for a part
that looks right: a reader has to open documents it did not build, and a guessed part
name is how a hostile package steers extraction.

## Adding one

1. New module in this directory, one class, a class-level `id` string.
2. Register it in [`__init__.py`](__init__.py) — in `_PURE_CHANNELS` if it needs no
   optional toolchain, otherwise branched in `get_channel` the way `stego_media` is,
   and included in `available_channels()`.
3. A real round-trip test in `tests/test_channels.py`: embed, serialise the package to
   bytes, read it back from bytes, extract, compare. Not an in-memory shortcut — the
   ZIP round trip is where part naming and content types actually get tested.
4. A validation test that the surface document still conforms. `validate.py` is the
   gate.
5. Entries in `docs/channels.md` **and** `docs/format-spec.md`. `tests/test_docs.py`
   fails the build without both.
6. State plainly whether it crosses to ODF. If it does not, say so in
   `docs/channels.md` — two of the five do not, and silence reads as "it does".

An unknown channel id must fail explicitly on read. Do not add a permissive fallback.

## Traps this directory has already hit

- **Writing into the main story part is different from writing beside it.** `mce`
  emitted `<mc:AlternateContent>` after the body-level `<w:sectPr>`, which violates
  `CT_Body`. Word tolerated it; the schema did not. Any channel touching
  `word/document.xml` must be checked against the content model, not against whether a
  viewer opens the file.
- **A concealed module must add nothing visible.** The `mce` fallback is empty for
  that reason. If your channel makes the document render differently, it is not a side
  channel.
- **Determinism is part of the contract.** Fixed part numbering, sorted entries, no
  wall-clock. Two builds of the same input produce the same bytes, and the round-trip
  suite compares bytes.
- **Capacity must be honest.** `capacity` returning a number the channel cannot
  actually hold turns a build into a truncation. Return `None` only when a new part
  can genuinely always be added.
- **The bounded channels are bounded for a reason.** `metadata` caps at a custom
  property's practical length and `stego_media` at carrier pixels; exceeding either
  must raise, never silently spill into a second location.

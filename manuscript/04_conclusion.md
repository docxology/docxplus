# 4. Conclusion

DOCX+ demonstrates that a single file can be an ordinary, standards-conforming
`.docx` and a modular, authenticated, optionally-encrypted, optionally-concealed
intelligence carrier at once, using only documented OOXML affordances. The design
keeps the two contracts cleanly separated — surface conformance and a
signed-manifest intelligence layer — so neither compromises the other: readers that
know nothing of DOCX+ open the document normally, and DOCX+ readers recover exactly
what the manifest attests.

The honest boundaries are stated plainly (`docs/security-model.md`): concealment is
offered only by the media channel and is defeatable by steganalysis; a manifest
signature attests the manifest, not the visible prose; and parsing untrusted `.docx`
input still demands the intake hardening the standards report catalogues. Within
those boundaries, DOCX+ raises the floor from "bytes anyone can read" to
"digest-bound, signed, selectively-encrypted modules that travel inside a document
people already trust to open."

Future work: whole-package OPC digital signatures alongside the manifest signature;
an ODT sibling profile using `META-INF/manifest.xml` directly; an MCE
`AlternateContent` channel exercising ignorable namespaces; and an intake pipeline
wrapping the reader with the report's untrusted-input checklist (inflate-ratio caps,
Zip-Slip canonicalisation, DTD disabling, sandboxed parsing).

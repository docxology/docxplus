# 4. Conclusion

DOCX+ demonstrates that a single file can be an ordinary, standards-conforming
`.docx` and a modular, authenticated, optionally-encrypted, optionally-concealed
intelligence carrier at once, using only documented OOXML affordances. The design
keeps the two contracts cleanly separated — surface conformance and a
signed-manifest intelligence layer — so neither compromises the other: readers that
know nothing of DOCX+ open the document normally, and DOCX+ readers recover exactly
what the manifest attests.

The honest boundaries are stated plainly (`docs/security-model.md`): concealment is
offered only by the media channel and is defeatable by steganalysis; a signature
now binds the visible text (via `surface_digest`) but proves *authenticity* only
against a caller-pinned key, since the embedded signer key is self-asserted; a
reproduction match attests process, not that the science is sound; and deniability
holds against inspection, not proof. The untrusted-input hardening the standards
report catalogues — inflate-ratio and entry caps, traversal and collision guards,
DTD disabling, and a sandboxed, opt-in reproduce path — is implemented, not
promised. Within those boundaries, DOCX+ raises the floor from "bytes anyone can
read" to "digest-bound, signed, selectively-sealed, self-verifying modules that
travel inside a document people already trust to open."

Future work: whole-package OPC digital signatures a word processor recognises
(alongside the manifest signature); an MCE `AlternateContent` channel exercising
ignorable namespaces; an ODT sibling profile using `META-INF/manifest.xml` directly;
and a transparency-log entry so a reproduction attestation is discoverable and
timestamped.

"""The docxplus intelligence layer over an OpenDocument Text package.

`odt.py` builds a conforming ODF package; this module gives that package the
*Intelligence Contract* — typed payloads, the four sealing lineages, a Merkle root
over the module set, a surface digest over the visible ODF content, and an Ed25519
signature binding all of it. Without this, ODT support was a surface-contract
profile that could carry loose bytes, and the "standards parity" claim was wider
than the code.

**Reuse over reimplementation.** Sealing comes from
:func:`container.seal_module`, the manifest and Merkle machinery from
:mod:`manifest` and :mod:`provenance`, and the unsealing path is shared with the
OPC reader. A parallel implementation would be free to drift on precisely the
details that matter — the chaff frame that makes a decoy indistinguishable, the
AAD slot binding, the VSS requirement recorded in the signed manifest — so it is
not written twice.

**Channels.** ODF has no analogue of an OOXML custom XML datastore part, and no
Markup Compatibility `<mc:AlternateContent>` element, so those two channels do not
cross over. Payloads ride as ODF package entries under ``intelligence/``, declared
as file-entries in ``META-INF/manifest.xml`` exactly as the specification requires
for any part of the package. That is the ODF-native analogue of the OPC
``package_part`` channel, and it is the unbounded one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import crypto
from . import payloads
from .container import ContainerError, _Pending, seal_module
from .container import DocxPlusReader as DocxPlusReaderDepth
from .manifest import Manifest
from .odt import MIMETYPE_ODT, OdtPackage, new_base_odt

#: Where the intelligence manifest lives inside an ODT package.
ODT_MANIFEST_PART = "intelligence/manifest.json"
CT_MANIFEST = "application/vnd.docxplus.manifest+json"
CT_PAYLOAD = "application/vnd.docxplus.payload"

#: Excluded from the surface digest. The intelligence manifest carries the digest and
#: cannot contain itself. `mimetype` is a fixed constant the reader checks directly,
#: and `META-INF/manifest.xml` is *derived* from the part set and media types — both
#: of which are digested — so binding it again would add nothing while breaking the
#: build/read symmetry: neither exists in `pkg.parts` until `to_bytes` generates them.
#: `"/"` is the ODF root file-entry, likewise emitted only at serialisation.
_DIGEST_EXCLUDED = frozenset({ODT_MANIFEST_PART, "mimetype", "META-INF/manifest.xml", "/"})

def compute_odt_surface_digest(pkg: OdtPackage) -> str:
    """Digest every part and its declared media type, except the manifest itself.

    Binds the package, not a list of names, for the reason the OOXML profile does
    (`container._compute_surface_digest`): selecting parts by name puts a naming
    convention in the trust path, and a consumer follows declarations rather than
    filenames. Everything except ``intelligence/manifest.json`` — which carries this
    digest and so cannot contain itself — is covered, including the ODF manifest that
    declares what each entry is.
    """
    chunks: list[bytes] = []
    for name in sorted(pkg.parts):
        if name in _DIGEST_EXCLUDED:
            continue
        chunks.append(b"P\x00" + name.encode("utf-8") + b"\x00" + pkg.parts[name])
    for name, media in sorted(pkg.media_types.items()):
        if name in _DIGEST_EXCLUDED:
            continue
        chunks.append(b"M\x00" + name.encode("utf-8") + b"\x00" + media.encode("utf-8"))
    return crypto.digest(b"\x00".join(chunks))


@dataclass
class OdtPlusBuilder:
    """Compose typed, sealed, provenance-bound modules into a conforming .odt."""

    paragraphs: list[str] = field(default_factory=lambda: ["This is an ordinary document."])
    title: str = "Document"
    creator: str = "docxplus"
    _pending: list[_Pending] = field(default_factory=list)
    _private_key: bytes | None = None
    _public_key: bytes | None = None
    _cosigners: list[bytes] = field(default_factory=list)
    #: populated after :meth:`build`; ``{slot: [share_bytes, ...]}``.
    threshold_shares: dict[str, list[bytes]] = field(default_factory=dict)

    def add_module(
        self,
        slot: str,
        obj: object,
        *,
        payload_type: str = "bytes",
        password: str | None = None,
        recipients: list[bytes] | None = None,
        threshold: tuple[int, int] | None = None,
        kdf: str = "scrypt",
    ) -> OdtPlusBuilder:
        """Queue a typed payload under manifest ``slot``."""
        if any(m.slot == slot for m in self._pending):
            raise ContainerError(f"duplicate slot: {slot}")
        if sum(x is not None for x in (password, recipients, threshold)) > 1:
            raise ContainerError("choose at most one of password/recipients/threshold")
        payloads.get_type(payload_type)  # validate early
        self._pending.append(
            _Pending(slot, "odt_package_part", obj, payload_type, password, recipients,
                     threshold, None, {}, kdf=kdf)
        )
        return self

    def add_decoy(
        self, slot: str, *, real: object, real_password: str, decoy: object,
        decoy_password: str, payload_type: str = "bytes", kdf: str = "scrypt",
    ) -> OdtPlusBuilder:
        """Two payloads under two passwords; neither reveals the other."""
        if any(m.slot == slot for m in self._pending):
            raise ContainerError(f"duplicate slot: {slot}")
        payloads.get_type(payload_type)
        self._pending.append(
            _Pending(slot, "odt_package_part", None, payload_type, None, None, None,
                     (real, real_password, decoy, decoy_password), {}, kdf=kdf)
        )
        return self

    def add_threshold(self, slot: str, obj: object, *, k: int, n: int,
                      payload_type: str = "bytes") -> OdtPlusBuilder:
        return self.add_module(slot, obj, payload_type=payload_type, threshold=(k, n))

    def add_project(
        self, slot: str, project_dir: str | Path, *, reproduce: object | bool | None = None,
        follow_symlinks: bool = False, **seal,
    ) -> OdtPlusBuilder:
        """Pack a whole directory tree and carry it as a ``project`` module.

        Mirrors the OOXML profile exactly, including the reproduction attestation:
        an ODF document that carried source but could not attest it would be a
        second-class citizen of the same specification.
        """
        project_dir = Path(project_dir)
        blob = payloads.pack_project(project_dir, follow_symlinks=follow_symlinks)
        self.add_module(slot, blob, payload_type="project", **seal)
        if reproduce is not None and reproduce is not False:
            import tempfile

            from . import reproduce as _repro

            spec = _repro.load_recipe(project_dir) if reproduce is True else reproduce
            if spec is None:
                raise ContainerError(
                    f"{slot!r}: reproduce=True but no {_repro.RECIPE_FILE} in the project"
                )
            # Attest over a clean extraction of the *packed* bytes, so the attested
            # digest matches what a reader reproduces rather than the author's tree.
            with tempfile.TemporaryDirectory() as td:
                clean = payloads.unpack_project(blob, Path(td) / "proj")
                self._pending[-1].reproduction = _repro.attest(clean, spec)
        return self

    def add_nested(self, slot: str, inner_document: bytes, **seal) -> OdtPlusBuilder:
        """Carry a whole docxplus document (either profile) as a nested module."""
        return self.add_module(slot, inner_document, payload_type="docxplus", **seal)

    def sign(self, private_key: bytes) -> OdtPlusBuilder:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private_key = private_key
        self._public_key = (
            Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
        )
        return self

    def add_cosigner(self, private_key: bytes) -> OdtPlusBuilder:
        self._cosigners.append(private_key)
        return self

    def build(self) -> bytes:
        pkg = new_base_odt(self.paragraphs, title=self.title, creator=self.creator)
        manifest = Manifest()
        self.threshold_shares = {}

        for index, m in enumerate(self._pending, start=1):
            sealed, sealing = seal_module(m, self.threshold_shares)
            part = f"intelligence/payload{index}.dxp"
            pkg.add_part(part, sealed, CT_PAYLOAD)

            from .channels.base import ChannelRecord

            record = ChannelRecord(
                channel="odt_package_part",
                slot=m.slot,
                size=len(sealed),
                digest=crypto.digest(sealed),
                content_type=CT_PAYLOAD,
                location={"part": part},
            )
            record.payload_type = m.payload_type
            record.encrypted = sealing["mode"] != "plain"
            record.sealing = sealing
            record.reproduction = m.reproduction or {}
            manifest.add(record)

        manifest.surface_digest = compute_odt_surface_digest(pkg)
        body = manifest.canonical_body()
        if self._private_key is not None and self._public_key is not None:
            manifest.public_key = self._public_key.hex()
            manifest.signature = crypto.sign(body, self._private_key).hex()

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        for priv in self._cosigners:
            pub = Ed25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()
            manifest.cosignatures.append(
                {"public_key": pub.hex(), "value": crypto.sign(body, priv).hex()}
            )

        pkg.add_part(ODT_MANIFEST_PART, manifest.to_bytes(), CT_MANIFEST)
        return pkg.to_bytes()


@dataclass
class OdtPlusReader:
    """Read an .odt back: extract modules, verify provenance, no execution."""

    package: OdtPackage
    manifest: Manifest
    #: How many nested documents deep this reader already is (see `open_nested`).
    _nest_depth: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> OdtPlusReader:
        pkg = OdtPackage.from_bytes(data)
        if pkg.parts.get("mimetype") not in (None, MIMETYPE_ODT):
            raise ContainerError("not an OpenDocument Text package")
        blob = pkg.parts.get(ODT_MANIFEST_PART)
        manifest = Manifest.from_bytes(blob) if blob else Manifest()
        return cls(package=pkg, manifest=manifest)

    def has_intelligence(self) -> bool:
        return ODT_MANIFEST_PART in self.package.parts

    def list_modules(self) -> list[str]:
        return [r.slot for r in self.manifest.records]

    def _record(self, slot: str):
        try:
            return self.manifest.slot(slot)
        except KeyError:
            raise ContainerError(f"no such module: {slot}") from None

    def extract(
        self,
        slot: str,
        *,
        password: str | None = None,
        private_key: bytes | None = None,
        shares: list[bytes] | None = None,
        as_object: bool = False,
    ) -> object:
        """Recover one module's payload, verifying the stored bytes first."""
        from .container import DocxPlusReader

        record = self._record(slot)
        sealed = self._stored_bytes(record)
        if crypto.digest(sealed) != record.digest:
            raise ContainerError(f"digest mismatch for {slot!r} (stored bytes altered)")

        mode = record.sealing.get("mode", "plain")
        aad = slot.encode("utf-8")
        if mode == "plain":
            plaintext = sealed
        else:
            # Shared with the OPC reader on purpose: one unsealing path, one set of
            # failure modes, no chance of the two profiles diverging under attack.
            plaintext = DocxPlusReader._unseal(
                self, slot, mode, sealed, aad, password, private_key, shares,
                require_vss=bool(record.sealing.get("vss", False)),
            )
        if as_object:
            return payloads.get_type(record.payload_type).unpack(plaintext)
        return plaintext

    def extract_project(self, slot: str, dest: str | Path, **creds) -> Path:
        blob = self.extract(slot, **creds)
        return payloads.unpack_project(blob, Path(dest))

    def _stored_bytes(self, record) -> bytes:
        """ODF payloads are package entries, not OPC channel targets."""
        part = record.location.get("part")
        raw = self.package.parts.get(part)
        if raw is None:
            raise ContainerError(f"module {record.slot!r} names a missing part: {part}")
        return raw

    def verify_reproduction(self, slot: str, expected_public_key: bytes | None = None) -> dict:
        """Cryptographically verify a carried attestation. Executes nothing."""
        from .container import DocxPlusReader

        return DocxPlusReader.verify_reproduction(self, slot, expected_public_key)

    def reproduce(self, slot: str, dest: str | Path, *, allow_execution: bool = False, **creds) -> dict:
        """OPT-IN: re-run the attested command in a sandbox and compare digests."""
        from .container import DocxPlusReader

        return DocxPlusReader.reproduce(self, slot, dest, allow_execution=allow_execution, **creds)

    def open_nested(self, slot: str, **creds):
        """Open a carried docxplus document, dispatching on which profile it is.

        A nested module may be either an OPC or an ODF package — matryoshka nesting
        should not care which container the inner document happens to use — so the
        magic is read rather than assumed.
        """
        record = self._record(slot)
        if record.payload_type != "docxplus":
            raise ContainerError(f"module {slot!r} is not a nested document")
        depth = getattr(self, "_nest_depth", 0) + 1
        if depth > DocxPlusReaderDepth.MAX_NEST_DEPTH:
            raise ContainerError(
                f"nesting deeper than {DocxPlusReaderDepth.MAX_NEST_DEPTH} refused "
                "(a matryoshka chain must not be able to exhaust the reader)"
            )
        blob = self.extract(slot, **creds)
        inner = open_document(blob)
        # Carry the budget across the profile boundary: without this, one ODT hop
        # reset a chain that the OPC reader had been counting.
        inner._nest_depth = depth
        return inner

    def merkle_root(self) -> str:
        return self.manifest.merkle_root()

    def signer(self) -> str:
        return self.manifest.public_key or ""

    def _surface_matches(self) -> bool:
        return compute_odt_surface_digest(self.package) == self.manifest.surface_digest

    def signature_status(self, expected_public_key: bytes | None = None) -> str:
        from .container import DocxPlusReader

        return DocxPlusReader.signature_status(self, expected_public_key)

    def verify_provenance(self, expected_public_key: bytes | None = None) -> bool:
        from .container import DocxPlusReader

        return DocxPlusReader.verify_provenance(self, expected_public_key)

    def cosigners(self) -> list[str]:
        from .container import DocxPlusReader

        return DocxPlusReader.cosigners(self)

    def verify_cosigners(self, expected_public_keys: list[bytes]) -> bool:
        from .container import DocxPlusReader

        return DocxPlusReader.verify_cosigners(self, expected_public_keys)

    def inclusion_proof(self, slot: str) -> dict:
        from .container import DocxPlusReader

        return DocxPlusReader.inclusion_proof(self, slot)


def open_document(data: bytes):
    """Open a docxplus document of either profile, dispatching on the container.

    Callers that accept documents from elsewhere should not have to know in advance
    whether they were handed OOXML or ODF. ODF is identified positionally by its
    uncompressed ``mimetype`` first entry, which is exactly the property the format
    guarantees for this purpose; anything else is treated as OPC.
    """
    import io
    import zipfile

    from .container import DocxPlusReader

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            is_odf = bool(names) and names[0] == "mimetype" and zf.read("mimetype").startswith(
                b"application/vnd.oasis.opendocument"
            )
    except zipfile.BadZipFile as exc:
        raise ContainerError(f"not a readable document package: {exc}") from None
    return OdtPlusReader.from_bytes(data) if is_odf else DocxPlusReader.from_bytes(data)

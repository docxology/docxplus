"""The docxplus intelligence layer over an OpenDocument Text package.

`odt.py` builds a conforming ODF package; this module gives that package the
*Intelligence Contract* — typed payloads, the four sealing lineages, a Merkle root
over the module set, a surface digest over the visible ODF content, and a signature
whose actual key family binds all of it. Without this, ODT support was a surface-contract
profile that could carry loose bytes, and the "standards parity" claim was wider
than the code.

**Reuse over reimplementation.** Sealing comes from
:func:`container.seal_module`, the manifest and Merkle machinery from
:mod:`manifest` and :mod:`provenance`, and the unsealing path is shared with the
OPC reader. A parallel implementation could drift on security-relevant details:
the common visible password framing policy, the AAD slot binding, and the
checksum policy and signed full-share commitments — so it is
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
from typing import TYPE_CHECKING

from . import crypto, payloads
from .channels.base import ChannelRecord
from .channels.metadata import OdtMetadataChannel
from .channels.stego_media import OdtStegMediaChannel
from .container import ContainerError, _cosigner_descriptors, _Pending, seal_module

if TYPE_CHECKING:
    from .container import DocxPlusReader
from .container import DocxPlusReader as DocxPlusReaderDepth
from .manifest import Manifest
from .odt import MIMETYPE_ODT, OdtPackage, new_base_odt

#: Where the intelligence manifest lives inside an ODT package.
ODT_MANIFEST_PART = "intelligence/manifest.json"
CT_MANIFEST = "application/vnd.docxplus.manifest+json"
CT_PAYLOAD = "application/vnd.docxplus.payload"

# Physical index bytes are regenerated from bound declarations and supported
# entry attributes. Mimetype is checked directly; the intelligence manifest
# cannot include its own bytes in the digest.
_DIGEST_EXCLUDED = frozenset({ODT_MANIFEST_PART, "mimetype", "META-INF/manifest.xml", "/"})

def compute_odt_surface_digest(pkg: OdtPackage) -> str:
    """Bind ODF parts and declarations in a profile-separated format-3 transcript."""
    import hashlib

    from .opc import _surface_hasher, _surface_record

    h = _surface_hasher(b"ODF")
    _surface_record(h, b"T", MIMETYPE_ODT)
    if pkg.manifest_version is None:
        _surface_record(h, b"V")
    else:
        _surface_record(h, b"V", pkg.manifest_version.encode("utf-8"))
    for name, data in sorted(pkg.parts.items()):
        if name not in _DIGEST_EXCLUDED:
            _surface_record(h, b"P", name.encode(), len(data).to_bytes(8, "big"),
                            hashlib.sha256(data).digest())
    declarations = {name: pkg.media_types.get(name, "application/octet-stream")
                    for name in pkg.parts if name not in _DIGEST_EXCLUDED}
    declarations.update(pkg.media_types)
    declarations.setdefault("/", MIMETYPE_ODT.decode("ascii"))
    for name, media in sorted(declarations.items()):
        _surface_record(h, b"M", name.encode(), media.encode())
    for path, values in sorted(pkg.entry_attributes.items()):
        for key, value in sorted(values.items()):
            _surface_record(h, b"A", path.encode(), key.encode(), value.encode())
    return h.hexdigest()


@dataclass
class OdtPlusBuilder:
    """Compose typed, sealed, provenance-bound modules into a conforming .odt."""

    paragraphs: list[str] = field(default_factory=lambda: ["This is an ordinary document."])
    title: str = "Document"
    creator: str = "docxplus"
    base_package: OdtPackage | None = None
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
        recipient_padding: int = 0,
        channel_id: str = "odt_package_part",
        **channel_kwargs,
    ) -> OdtPlusBuilder:
        """Queue a typed payload under manifest ``slot``.

        ``channel_id`` selects the transport. The default ``odt_package_part`` rides
        as an ordinary intelligence package entry; ``stego_media`` instead conceals
        the payload in the LSBs of a PNG the document visibly displays (see
        :mod:`channels.stego_media`). Unknown channel ids fail here, at authoring
        time, not when some reader meets them.

        ``recipient_padding`` raises the apparent recipient count to a fixed bucket;
        0 leaves it unpadded. It may add recipient slots but cannot remove any.
        """
        if channel_id not in ("odt_package_part", "stego_media", "odt_metadata"):
            raise ContainerError(f"unknown channel: {channel_id}")
        if any(m.slot == slot for m in self._pending):
            raise ContainerError(f"duplicate slot: {slot}")
        if sum(x is not None for x in (password, recipients, threshold)) > 1:
            raise ContainerError("choose at most one of password/recipients/threshold")
        payloads.get_type(payload_type)  # validate early
        self._pending.append(
            _Pending(slot, channel_id, obj, payload_type, password, recipients,
                     threshold, None, channel_kwargs, kdf=kdf, recipient_padding=recipient_padding)
        )
        return self

    def add_decoy(
        self, slot: str, *, real: object, real_password: str, decoy: object,
        decoy_password: str, payload_type: str = "bytes", kdf: str = "scrypt",
    ) -> OdtPlusBuilder:
        """Two encrypted payloads sharing visible KDF/size policy, without a marker."""
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
        follow_symlinks: bool = False, max_uncompressed: int | None = None, **seal,
    ) -> OdtPlusBuilder:
        """Pack a whole directory tree and carry it as a ``project`` module.

        Mirrors the OOXML profile exactly, including the reproduction attestation:
        an ODF document that carried source but could not attest it would be a
        second-class citizen of the same specification. The decompression cap is
        mirrored too: an over-cap tree is refused here at authoring time
        (``max_uncompressed=None`` keeps the format default), not found to be
        unextractable when someone later tries to open it.
        """
        project_dir = Path(project_dir)
        pack_kw: dict[str, object] = {"follow_symlinks": follow_symlinks}
        if max_uncompressed is not None:
            pack_kw["max_uncompressed"] = max_uncompressed
        blob = payloads.pack_project(project_dir, **pack_kw)
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
                clean = payloads.unpack_project(
                    blob, Path(td) / "proj",
                    max_uncompressed=(payloads.MAX_PROJECT_UNCOMPRESSED
                                      if max_uncompressed is None else max_uncompressed),
                )
                self._pending[-1].reproduction = _repro.attest(clean, spec)
        return self

    def add_nested(self, slot: str, inner_document: bytes, **seal: object) -> OdtPlusBuilder:
        """Carry a whole docxplus document (either profile) as a nested module."""
        return self.add_module(slot, inner_document, payload_type="docxplus", **seal)

    def sign(self, private_key: bytes) -> OdtPlusBuilder:
        """Select the signing identity from a strictly framed private key."""
        self._public_key = crypto.signing_public_key(private_key)
        self._private_key = private_key
        return self

    def add_cosigner(self, private_key: bytes) -> OdtPlusBuilder:
        self._cosigners.append(private_key)
        return self

    def build(self) -> bytes:
        cosignatures = _cosigner_descriptors(self._cosigners)
        pkg = self.base_package or new_base_odt(self.paragraphs, title=self.title, creator=self.creator)
        manifest = Manifest()
        self.threshold_shares = {}

        payload_index = 0
        for m in self._pending:
            sealed, sealing = seal_module(m, self.threshold_shares)
            if m.channel_id == "stego_media":
                # Concealment channel: the payload travels inside the carrier's
                # pixels, so no intelligence/payloadN.dxp part is written.
                record = OdtStegMediaChannel(**m.channel_kwargs).embed(pkg, sealed, slot=m.slot)
            elif m.channel_id == "odt_metadata":
                # Short-string transport in meta.xml; still sealed before placement.
                record = OdtMetadataChannel(**m.channel_kwargs).embed(pkg, sealed, slot=m.slot)
            else:
                payload_index += 1
                part = f"intelligence/payload{payload_index}.dxp"
                while part in pkg.parts or part in pkg.media_types:
                    payload_index += 1
                    part = f"intelligence/payload{payload_index}.dxp"
                pkg.add_part(part, sealed, CT_PAYLOAD)
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

        pkg.media_types[ODT_MANIFEST_PART] = CT_MANIFEST
        manifest.surface_digest = compute_odt_surface_digest(pkg)
        if self._public_key is not None:
            manifest.algorithm = crypto.signing_algorithm(self._public_key)
        manifest.cosignatures = cosignatures
        body = manifest.canonical_body()
        if self._private_key is not None and self._public_key is not None:
            manifest.public_key = self._public_key.hex()
            manifest.signature = crypto.sign(body, self._private_key).hex()
        for entry, priv in zip(manifest.cosignatures, self._cosigners, strict=True):
            entry["value"] = crypto.sign(body, priv).hex()

        # Manifest replacement is explicit; generic add_part refuses collisions.
        pkg.parts[ODT_MANIFEST_PART] = manifest.to_bytes()
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
        from .opc import OpcError

        try:
            pkg = OdtPackage.from_bytes(data)
        except OpcError as exc:
            raise ContainerError(f"unreadable ODT package: {exc}") from exc
        blob = pkg.parts.get(ODT_MANIFEST_PART)
        manifest = Manifest.from_bytes(blob) if blob else Manifest()
        for record in manifest.records:
            if record.channel not in ("odt_package_part", "stego_media", "odt_metadata"):
                raise ContainerError(f"unknown ODT channel: {record.channel}")
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
                require_checksum=bool(record.sealing.get("checksummed_shares", False)),
                share_digests=record.sealing.get("share_digests"),
            )
        if as_object:
            return payloads.get_type(record.payload_type).unpack(plaintext)
        return plaintext

    def extract_project(
        self, slot: str, dest: str | Path, *,
        max_uncompressed: int = payloads.MAX_PROJECT_UNCOMPRESSED, **creds: object,
    ) -> Path:
        """Extract a project under an explicit budget independent of credentials."""
        record = self._record(slot)
        if record.payload_type != "project":
            raise ContainerError(f"module {slot!r} is not a project payload")
        blob = self.extract(slot, **creds)
        return payloads.unpack_project(blob, Path(dest), max_uncompressed=max_uncompressed)

    def _stored_bytes(self, record) -> bytes:
        """The bytes a module actually occupies in the package.

        The default is a package entry; a record placed by the stego channel travels
        inside its carrier's pixels, so the channel's own extract — digest-verified
        across replicas — recovers it. Shared with the OOXML profile by inheritance.
        """
        if record.channel == "stego_media":
            return OdtStegMediaChannel().extract(self.package, record)
        if record.channel == "odt_metadata":
            return OdtMetadataChannel().extract(self.package, record)
        if record.channel != "odt_package_part":
            raise ContainerError(f"unknown ODT channel: {record.channel}")
        part = record.location.get("part")
        raw = self.package.parts.get(part)
        if raw is None:
            raise ContainerError(f"module {record.slot!r} names a missing part: {part}")
        return raw

    def verify_reproduction(self, slot: str, expected_public_key: bytes | None = None) -> dict:
        """Cryptographically verify a carried attestation. Executes nothing."""
        from .container import DocxPlusReader

        return DocxPlusReader.verify_reproduction(self, slot, expected_public_key)

    def reproduce(
        self, slot: str, dest: str | Path, *, allow_execution: bool = False, **creds: object,
    ) -> dict[str, object]:
        """OPT-IN: re-run the attested command in a sandbox and compare digests."""
        from .container import DocxPlusReader

        return DocxPlusReader.reproduce(self, slot, dest, allow_execution=allow_execution, **creds)

    def open_nested(
        self, slot: str, **creds: object,
    ) -> DocxPlusReader | OdtPlusReader:
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

    ZIP and package-admission failures raise ``ContainerError``, matching the
    direct profile readers. Manifest-schema failures remain ``ValueError``.
    """
    import io
    import zipfile

    from .container import DocxPlusReader
    from .opc import (
        OpcError,
        _guard_zip_bomb,
        _preflight_zip,
    )

    try:
        expected_entries = _preflight_zip(data)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            from .odt import _guard_mimetype

            infos = zf.infolist()
            _guard_zip_bomb(infos, expected_entries)
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise OpcError("package contains duplicate ZIP entry names")
            is_odf = "mimetype" in names
            if is_odf:
                _guard_mimetype(zf)
    except (zipfile.BadZipFile, OpcError) as exc:
        raise ContainerError(f"not a readable document package: {exc}") from None
    return OdtPlusReader.from_bytes(data) if is_odf else DocxPlusReader.from_bytes(data)


__all__ = [
    "CT_MANIFEST",
    "CT_PAYLOAD",
    "ODT_MANIFEST_PART",
    "OdtPlusBuilder",
    "OdtPlusReader",
    "compute_odt_surface_digest",
    "open_document",
]


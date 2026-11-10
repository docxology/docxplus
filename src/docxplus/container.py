"""docxplus container: compose typed, sealed, provenance-bound modules into a valid
.docx, and read them back.

v0.2 capabilities (see docs/design-rationale.md, docs/cookbook.md):

* **Typed payloads** — bytes / text / json / project (a whole repo) / docxplus
  (a nested container), via the :mod:`payloads` registry.
* **Sealing modes** — plain, ``password`` (AES-GCM/PBKDF2), ``recipients`` (X25519
  multi-recipient), ``threshold`` (Shamir k-of-n over the content key), ``decoy``
  (two secrets under two passwords with a common visible framing policy).
* **Provenance** — a signed Merkle root binds the whole module set.

The surface .docx stays a conforming, openable Office document throughout; sealing
is applied per payload, never to the whole package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from . import channels as channel_registry
from . import crypto, payloads, shamir
from .manifest import Manifest, read_manifest, write_manifest
from .opc import OpcPackage, read_package
from .wordml import new_base_document

if TYPE_CHECKING:
    from .odt_container import OdtPlusReader

#: The sealing lineages a module can use; decoys have no separate manifest marker.
#: Shared framing alone is not a universal plausible-deniability guarantee.
SEALING_LINEAGES = ("plain", "password", "recipients", "threshold")


class ContainerError(RuntimeError):
    """Raised for container-level composition or extraction errors."""


@dataclass
class _Pending:
    slot: str
    channel_id: str
    obj: object
    payload_type: str
    password: str | None
    recipients: list[bytes] | None
    threshold: tuple[int, int] | None
    decoy: tuple[object, str, object, str] | None  # (real, real_pw, decoy, decoy_pw)
    channel_kwargs: dict
    reproduction: dict = None  # type: ignore[assignment]  # attestation for project modules
    #: Password-KDF for this module. Selectable because the format documents three
    #: lineages; before this was threaded through, Argon2id was reachable only by
    #: calling `crypto.encrypt` directly, so no document the tool produced ever used it.
    kdf: str = "scrypt"
    #: Raise the apparent recipient count to this many slots. The envelope carries
    #: one wrap per recipient, so its length reveals how many there are even though
    #: the manifest records neither identities nor count. Padding to a fixed bucket
    #: closes that channel; 0 leaves the true count visible.
    recipient_padding: int = 0


def _compute_surface_digest(pkg: OpcPackage) -> str:
    """Bind the complete OPC graph using the unambiguous format-3 transcript."""
    import hashlib

    from .manifest import MANIFEST_PART
    from .opc import _surface_hasher, _surface_record

    h = _surface_hasher(b"OPC")
    for name, data in sorted(pkg.parts.items()):
        if name != MANIFEST_PART:
            _surface_record(h, b"P", name.encode(), len(data).to_bytes(8, "big"),
                            hashlib.sha256(data).digest())
    for ext, ctype in sorted(pkg.default_types.items()):
        _surface_record(h, b"D", ext.encode(), ctype.encode())
    for part, ctype in sorted(pkg.override_types.items()):
        _surface_record(h, b"O", part.encode(), ctype.encode())
    for source, rels in sorted(pkg.relationships.items()):
        for rel in sorted(rels, key=lambda r: (r.id, r.type, r.target, r.mode)):
            _surface_record(h, b"R", *(v.encode() for v in
                            (source, rel.id, rel.type, rel.target, rel.mode)))
    return h.hexdigest()


@dataclass
class DocxPlusBuilder:
    """Accumulates typed, sealed modules onto a base document, then emits a .docx."""

    paragraphs: list[str] = field(default_factory=lambda: ["This is an ordinary document."])
    title: str = "Document"
    creator: str = "docxplus"
    base_package: OpcPackage | None = None
    _pending: list[_Pending] = field(default_factory=list)
    _private_key: bytes | None = None
    _public_key: bytes | None = None
    _cosigners: list[bytes] = field(default_factory=list)
    #: populated after :meth:`build`; ``{slot: [share_bytes, ...]}`` for threshold modules.
    threshold_shares: dict[str, list[bytes]] = field(default_factory=dict)

    # -- module authoring --------------------------------------------------
    def add_module(
        self,
        slot: str,
        channel_id: str,
        obj: object,
        *,
        payload_type: str = "bytes",
        password: str | None = None,
        recipients: list[bytes] | None = None,
        threshold: tuple[int, int] | None = None,
        kdf: str = "scrypt",
        recipient_padding: int = 0,
        **channel_kwargs,
    ) -> DocxPlusBuilder:
        """Queue a typed payload on ``channel_id`` under manifest ``slot``.

        Exactly one sealing option (``password`` / ``recipients`` / ``threshold``)
        may be given, or none for a plaintext module.
        """
        if channel_id not in channel_registry.available_channels():
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

    def add_project(
        self,
        slot: str,
        project_dir: str | Path,
        *,
        channel_id: str = "package_part",
        reproduce: object | bool | None = None,
        follow_symlinks: bool = False,
        max_uncompressed: int | None = None,
        **seal,
    ) -> DocxPlusBuilder:
        """Pack an entire directory tree and carry it as a ``project`` module.

        ``reproduce`` optionally attests reproduction at build time (author side):
        pass a ``reproduce.ReproSpec``, or ``True`` to load the project's own
        ``.docxplus-reproduce.json`` recipe. The recipe is executed once now and its
        signed attestation travels in the manifest. Nothing is executed on read.

        ``max_uncompressed=None`` uses the format default cap
        (``payloads.MAX_PROJECT_UNCOMPRESSED``); an over-cap tree is refused here,
        at authoring time, rather than discovered to be unextractable at read time.
        Pass a number deliberately to raise the budget for this one document.
        """
        project_dir = Path(project_dir)
        pack_kw: dict[str, object] = {"follow_symlinks": follow_symlinks}
        if max_uncompressed is not None:
            pack_kw["max_uncompressed"] = max_uncompressed
        blob = payloads.pack_project(project_dir, **pack_kw)
        self.add_module(slot, channel_id, blob, payload_type="project", **seal)
        if reproduce is not None and reproduce is not False:
            import tempfile

            from . import reproduce as _repro

            spec = _repro.load_recipe(project_dir) if reproduce is True else reproduce
            if spec is None:
                raise ContainerError(
                    f"{slot!r}: reproduce=True but no {_repro.RECIPE_FILE} in the project"
                )
            # Attest over a clean extraction of the *packed* bytes, not the author's
            # working tree, so the attested digest matches exactly what a reader
            # reproduces (the packed subset — no .venv, output/, caches).
            with tempfile.TemporaryDirectory() as td:
                clean = payloads.unpack_project(
                    blob, Path(td) / "proj",
                    max_uncompressed=(payloads.MAX_PROJECT_UNCOMPRESSED
                                      if max_uncompressed is None else max_uncompressed),
                )
                self._pending[-1].reproduction = _repro.attest(clean, spec)
        return self

    def add_nested(
        self, slot: str, inner_docx: bytes, *, channel_id: str = "package_part", **seal
    ) -> DocxPlusBuilder:
        """Carry a whole docxplus document as a nested ``docxplus`` module."""
        return self.add_module(slot, channel_id, inner_docx, payload_type="docxplus", **seal)

    def add_threshold(
        self, slot: str, obj: object, *, k: int, n: int,
        channel_id: str = "package_part", payload_type: str = "bytes",
    ) -> DocxPlusBuilder:
        """Seal a module so any ``k`` of ``n`` shares (returned after build) open it."""
        return self.add_module(
            slot, channel_id, obj, payload_type=payload_type, threshold=(k, n)
        )

    def add_decoy(
        self, slot: str, *, real: object, real_password: str, decoy: object,
        decoy_password: str, channel_id: str = "package_part", payload_type: str = "bytes",
        kdf: str = "scrypt",
    ) -> DocxPlusBuilder:
        """Two independently encrypted payloads sharing visible KDF/size policy."""
        if channel_id not in channel_registry.available_channels():
            raise ContainerError(f"unknown channel: {channel_id}")
        if any(m.slot == slot for m in self._pending):
            raise ContainerError(f"duplicate slot: {slot}")
        payloads.get_type(payload_type)
        self._pending.append(
            _Pending(slot, channel_id, None, payload_type, None, None, None,
                     (real, real_password, decoy, decoy_password), {}, kdf=kdf)
        )
        return self

    def sign(self, private_key: bytes) -> DocxPlusBuilder:
        """Sign the manifest with the strict key family's actual signature scheme."""
        self._public_key = crypto.signing_public_key(private_key)
        self._private_key = private_key
        return self

    def add_cosigner(self, private_key: bytes) -> DocxPlusBuilder:
        """Add a detached co-signature over the same body (e.g. author + institution)."""
        self._cosigners.append(private_key)
        return self

    # -- build -------------------------------------------------------------
    def build(self) -> bytes:
        cosignatures = _cosigner_descriptors(self._cosigners)
        pkg = self.base_package or new_base_document(
            self.paragraphs, title=self.title, creator=self.creator
        )
        manifest = Manifest()
        self.threshold_shares = {}

        for m in self._pending:
            record = self._place(pkg, m)
            manifest.add(record)

        # Install manifest authority before hashing; exclude only manifest bytes.
        write_manifest(pkg, manifest)
        manifest.surface_digest = _compute_surface_digest(pkg)

        if self._public_key is not None:
            manifest.algorithm = crypto.signing_algorithm(self._public_key)
        manifest.cosignatures = cosignatures
        body = manifest.canonical_body()
        if self._private_key is not None and self._public_key is not None:
            manifest.public_key = self._public_key.hex()
            manifest.signature = crypto.sign(body, self._private_key).hex()
        for entry, priv in zip(manifest.cosignatures, self._cosigners, strict=True):
            entry["value"] = crypto.sign(body, priv).hex()

        write_manifest(pkg, manifest)
        return pkg.to_bytes()

    def _place(self, pkg: OpcPackage, m: _Pending):
        channel = channel_registry.get_channel(m.channel_id, **m.channel_kwargs)
        sealed, sealing = seal_module(m, self.threshold_shares)
        record = channel.embed(pkg, sealed, slot=m.slot)
        record.payload_type = m.payload_type
        record.encrypted = sealing["mode"] != "plain"
        record.sealing = sealing
        record.reproduction = m.reproduction or {}
        # record.digest/size come from the channel = digest/len of the STORED bytes,
        # so the manifest (and its signature) bind exactly what travels; plaintext
        # integrity is the AEAD tag's job, checked on decryption.
        return record


def seal_module(m: _Pending, shares_sink: dict[str, list[bytes]]) -> tuple[bytes, dict]:
    """Pack and seal one pending module → ``(stored_bytes, sealing_metadata)``.

    Deliberately independent of the container format. The sealing lineages are a
    property of docxplus the *specification*, not of OPC the packaging, so the ODT
    profile reuses this verbatim rather than growing a parallel implementation
    that could drift on exactly the security-relevant details below.

    ``shares_sink`` receives threshold shares by slot; the caller owns returning
    them to the user, since only the builder knows how it wants to hand them over.
    """
    ptype = payloads.get_type(m.payload_type)
    aad = m.slot.encode("utf-8")  # bind every ciphertext to its module slot

    if m.decoy is not None:
        # Both frames use one visible KDF and size bucket, as ordinary modules do.
        # This limited policy is not a universal plausible-deniability guarantee.
        real, real_pw, decoy, decoy_pw = m.decoy
        real_bytes, decoy_bytes = ptype.pack(real), ptype.pack(decoy)
        size = _password_bucket(max(len(real_bytes), len(decoy_bytes)))
        sealed = _frame_seq([
            crypto.encrypt(_pad_password(real_bytes, size), real_pw, aad=aad, kdf=m.kdf),
            crypto.encrypt(_pad_password(decoy_bytes, size), decoy_pw, aad=aad, kdf=m.kdf),
        ])
        return sealed, {"mode": "password"}

    plaintext = ptype.pack(m.obj)
    if m.password is not None:
        size = _password_bucket(len(plaintext))
        return _frame_seq([
            crypto.encrypt(_pad_password(plaintext, size), m.password, aad=aad, kdf=m.kdf),
            _chaff(aad, size=size, kdf=m.kdf),
        ]), {"mode": "password"}
    if m.recipients is not None:
        # Record neither identities nor count — the manifest must not leak the
        # recipient set of a blind-review packet. The DXE2 envelope already
        # carries everything extraction needs.
        return (
            crypto.seal_multi(
                plaintext, m.recipients, aad=aad, pad_to=m.recipient_padding
            ),
            {"mode": "recipients"},
        )
    if m.threshold is not None:
        k, n = m.threshold
        content_key = _random_key()
        sealed = crypto.encrypt_with_key(plaintext, content_key, aad=aad)
        # Checksums detect corruption; signed full-share commitments bind issuance.
        shares_sink[m.slot] = shamir.split(content_key, k, n, checksummed=True)
        return sealed, {
            "mode": "threshold", "k": k, "n": n, "checksummed_shares": True,
            "share_digests": [crypto.digest(share) for share in shares_sink[m.slot]],
        }
    return plaintext, {"mode": "plain"}


def _random_key() -> bytes:
    import os

    return os.urandom(crypto.KEY_BYTES)


@dataclass
class DocxPlusReader:
    """Reads typed, sealed modules back out of a docxplus package."""

    package: OpcPackage
    manifest: Manifest
    _nest_depth: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> DocxPlusReader:
        return cls.from_package(read_package(data))

    @classmethod
    def from_package(cls, pkg: OpcPackage) -> DocxPlusReader:
        """Read an admitted package without reparsing ZIP bytes or asserting trust."""
        manifest = read_manifest(pkg)
        if manifest is None:
            raise ContainerError("package carries no intelligence manifest")
        return cls(package=pkg, manifest=manifest)

    def list_modules(self) -> list[str]:
        return [r.slot for r in self.manifest.records]

    def describe(self, slot: str) -> dict[str, object]:
        return self.manifest.slot(slot).to_dict()

    def has_intelligence(self) -> bool:
        return bool(self.manifest.records)

    # -- extraction --------------------------------------------------------
    def extract(
        self,
        slot: str,
        *,
        password: str | None = None,
        private_key: bytes | None = None,
        shares: list[bytes] | None = None,
        as_object: bool = False,
    ) -> object:
        """Recover one module. Provide the credential its sealing mode requires.

        ``as_object`` unpacks per the payload type (e.g. text→str, json→object);
        otherwise raw packed bytes are returned.
        """
        record = self._record(slot)
        sealed = channel_registry.get_channel(record.channel).extract(self.package, record)
        # Integrity of the bytes that actually travelled (uniform across all modes).
        if crypto.digest(sealed) != record.digest:
            raise ContainerError(f"digest mismatch for {slot!r} (stored bytes altered)")

        mode = record.sealing.get("mode", "plain")
        aad = slot.encode("utf-8")
        if mode == "plain":
            plaintext = sealed
        else:
            plaintext = self._unseal(
                slot, mode, sealed, aad, password, private_key, shares,
                require_checksum=bool(record.sealing.get("checksummed_shares", False)),
                share_digests=record.sealing.get("share_digests"),
            )

        if as_object:
            return payloads.get_type(record.payload_type).unpack(plaintext)
        return plaintext

    def _unseal(
        self, slot, mode, sealed, aad, password, private_key, shares, *,
        require_checksum=False, share_digests=None,
    ) -> bytes:
        """Decrypt a sealed module, converting any crypto failure to ContainerError.

        Plaintext integrity comes from the AEAD tag here, not a separate digest.
        """
        if mode == "password" and password is None:
            raise ContainerError(f"module {slot!r} needs a password")
        if mode == "recipients" and private_key is None:
            raise ContainerError(f"module {slot!r} needs a recipient private key")
        if mode == "threshold" and not shares:
            raise ContainerError(f"module {slot!r} needs threshold shares")
        try:
            if mode == "password":
                return _open_password_frames(sealed, password, aad)
            if mode == "recipients":
                return crypto.unseal_multi(sealed, private_key, aad=aad)
            if mode == "threshold":
                if not isinstance(share_digests, list) or not share_digests:
                    raise ContainerError("threshold module missing signed share commitments")
                if any(crypto.digest(share) not in share_digests for share in shares):
                    raise ContainerError("threshold share does not match signed commitment")
                key = shamir.combine(shares, require_checksum=require_checksum)
                return crypto.decrypt_with_key(sealed, key, aad=aad)
        except ContainerError:
            raise
        except Exception as exc:
            raise ContainerError(f"cannot open module {slot!r}: {exc}") from exc
        raise ContainerError(f"unknown sealing mode: {mode}")  # pragma: no cover

    def extract_project(
        self, slot: str, dest: str | Path, *,
        max_uncompressed: int = payloads.MAX_PROJECT_UNCOMPRESSED, **creds: object,
    ) -> Path:
        """Recover a ``project`` module and unpack it into ``dest``."""
        record = self._record(slot)
        if record.payload_type != "project":
            raise ContainerError(f"module {slot!r} is not a project payload")
        blob = self.extract(slot, **creds)
        return payloads.unpack_project(blob, Path(dest), max_uncompressed=max_uncompressed)

    #: Guards against a maliciously deep matryoshka chain exhausting resources.
    MAX_NEST_DEPTH = 32

    def _stored_bytes(self, record) -> bytes:
        """The bytes a module actually occupies in the package.

        A seam, not an abstraction for its own sake: the ODF profile stores payloads
        as package entries rather than through the OPC channel registry, and shares
        the verification logic above. Reaching for the registry directly here would
        make every shared method silently OPC-only.
        """
        return channel_registry.get_channel(record.channel).extract(self.package, record)

    def verify_reproduction(self, slot: str, expected_public_key: bytes | None = None) -> dict:
        """Check an attestation without executing code.

        Self-consistency binds intact carried bytes and the self-asserted signer.
        Authenticity additionally requires a caller-pinned signing key.
        """
        record = self._record(slot)
        att = record.reproduction
        signed = self.verify_provenance()
        # Bind the attestation to the ACTUAL carried bytes: the signature covers
        # record.digest, but the stored bytes could have been swapped post-signing —
        # in which case the signature would already fail, but confirm it here so a
        # "verified" verdict never rides on unread bytes.
        stored_ok = crypto.digest(self._stored_bytes(record)) == record.digest
        self_consistent = bool(att and signed and stored_ok)
        verified = bool(
            self_consistent and expected_public_key is not None
            and _key_matches(self.manifest.public_key, expected_public_key)
        )
        if not att:
            # "verified" must never read as true for a module carrying no attestation:
            # a caller checking that field alone would conclude a reproduction claim
            # was validated when none was ever made.
            return {
                "attested": False, "signed": signed, "self_consistent": False,
                "authentic": False, "verified": False,
            }
        result = {
            "attested": True,
            "signed": signed,
            "self_consistent": self_consistent,
            "authentic": verified,
            "verified": verified,
        }
        # Only surface the attested claim as bound when it is cryptographically
        # verified; otherwise the digest/command are self-asserted and untrusted.
        key = "attestation" if verified else "unverified_attestation"
        result[key] = dict(att)
        return result

    def reproduce(
        self, slot: str, dest: str | Path, *, allow_execution: bool = False, **creds: object,
    ) -> dict[str, object]:
        """OPT-IN, EXECUTES CARRIED CODE. Recover the project and re-run its attested
        command in a best-effort sandbox, comparing output digests.

        This runs code authored by whoever built the document. Call it only with
        ``allow_execution=True`` and only in an environment you are willing to run
        untrusted code in (see docs/security-model.md). Never called on any read,
        validate, or verify path.
        """
        if not allow_execution:
            raise ContainerError(
                "reproduce() executes carried code; pass allow_execution=True and run "
                "only inside a sandbox you trust (see docs/security-model.md)"
            )
        record = self._record(slot)
        att = record.reproduction
        if not att:
            raise ContainerError(f"module {slot!r} carries no reproduction attestation")
        project_dir = self.extract_project(slot, dest, **creds)
        from . import reproduce as _repro

        return _repro.reproduce_and_compare(project_dir, att)

    def open_nested(self, slot: str, **creds: object) -> DocxPlusReader | OdtPlusReader:
        """Recover a nested ``docxplus`` module and return a reader over it.

        Depth is tracked across the chain so a hostile deeply-nested document
        cannot drive unbounded recursion/resource use.
        """
        if self._nest_depth >= self.MAX_NEST_DEPTH:
            raise ContainerError("nested document depth cap exceeded")
        record = self._record(slot)
        if record.payload_type != "docxplus":
            raise ContainerError(f"module {slot!r} is not a nested document")
        from .odt_container import open_document

        child = open_document(self.extract(slot, **creds))
        child._nest_depth = self._nest_depth + 1
        return child

    # -- provenance --------------------------------------------------------
    def merkle_root(self) -> str:
        return self.manifest.merkle_root()

    def signer(self) -> str:
        """The hex signing public key that signed the manifest (``""`` if unsigned).

        This key is *self-asserted* — it is carried inside the manifest. A valid
        signature proves the manifest was signed by whoever holds this key, not that
        the key belongs to anyone you trust. Pin it via ``expected_public_key``.
        """
        return self.manifest.public_key

    def signature_status(self, expected_public_key: bytes | None = None) -> str:
        """``unsigned`` / ``invalid`` / ``valid`` / ``untrusted-signer``.

        Without ``expected_public_key``, ``valid`` means the signature is internally
        consistent (integrity + a *self-asserted* signer) — NOT authenticity. Pass the
        signer's known public key to get ``valid`` only when it matches (constant time),
        else ``untrusted-signer``.
        """
        if not self.manifest.is_signed():
            return "unsigned"
        if not self.manifest.verify_signature():
            return "invalid"
        if expected_public_key is not None and not _key_matches(
            self.manifest.public_key, expected_public_key
        ):
            return "untrusted-signer"
        return "valid"

    def verify_provenance(self, expected_public_key: bytes | None = None) -> bool:
        """True when the manifest signature validates (binding the Merkle root over
        all modules *and* the visible document text) and the surface document matches
        the signed digest.

        Without ``expected_public_key`` this proves integrity + a *self-asserted*
        signer — an attacker can sign a fabricated document with their own key and it
        validates. Pass the signer's known public key to require it (constant-time),
        turning "self-consistent" into "authentic". See docs/security-model.md.
        """
        if not (self.manifest.is_signed() and self.manifest.verify_signature()):
            return False
        if expected_public_key is not None and not _key_matches(
            self.manifest.public_key, expected_public_key
        ):
            return False
        return self._surface_matches()

    def _surface_matches(self) -> bool:
        return _compute_surface_digest(self.package) == self.manifest.surface_digest

    def cosigners(self) -> list[str]:
        """Hex public keys that have added a valid detached co-signature.

        Surface-bound: returns ``[]`` when the visible document no longer matches the
        signed surface digest, so a co-signature can never vouch for text its signer
        did not sign (an edit to the paragraphs invalidates every co-signer here).
        """
        if not self._surface_matches():
            return []
        return [k for k, ok in self.manifest.verify_cosignatures().items() if ok]

    def verify_cosigners(self, expected_public_keys: list[bytes]) -> bool:
        """True when every expected key has a valid signature over *this* document
        (co-signer or the primary signer). Use for 'signed by author AND institution'.

        Binds the visible text (via ``cosigners()`` / ``verify_provenance``) and
        rejects an empty policy, which would otherwise pass vacuously.
        """
        if not expected_public_keys:
            raise ContainerError("verify_cosigners requires at least one expected key")
        valid = {bytes.fromhex(key) for key in self.cosigners()}  # surface-bound
        if self.verify_provenance():  # primary signature valid AND surface/merkle bound
            valid.add(bytes.fromhex(self.manifest.public_key))
        return all(key in valid for key in expected_public_keys)

    def inclusion_proof(self, slot: str) -> dict:
        """A Merkle inclusion proof that ``slot`` belongs to this document's signed
        module set — verifiable by a third party without the other modules."""
        from .provenance import inclusion_proof as _proof

        self._record(slot)  # KeyError→ContainerError if absent
        return _proof([(r.slot, r.digest) for r in self.manifest.records], slot)

    def _record(self, slot: str):
        try:
            return self.manifest.slot(slot)
        except KeyError as exc:
            raise ContainerError(f"no such module: {slot}") from exc


def _key_matches(manifest_key_hex: str, expected_public_key: bytes) -> bool:
    """Constant-time comparison of the manifest's signer key to a trusted key."""
    import hmac

    try:
        return hmac.compare_digest(bytes.fromhex(manifest_key_hex), expected_public_key)
    except ValueError:
        return False


def _cosigner_descriptors(private_keys: list[bytes]) -> list[dict[str, str]]:
    """Validate identities before mutating a base package or publishing bytes."""
    entries, seen = [], set()
    for private_key in private_keys:
        public = crypto.signing_public_key(private_key)
        if public in seen:
            raise ContainerError("duplicate cosigner identity")
        seen.add(public)
        entries.append({"public_key": public.hex(), "algorithm": crypto.signing_algorithm(public)})
    return entries


def _frame_seq(envelopes: list[bytes]) -> bytes:
    """Frame exactly two password envelopes with explicit u32 lengths."""
    if len(envelopes) != 2:
        raise ContainerError("password modules require exactly two frames")
    return b"".join(len(e).to_bytes(4, "big") + e for e in envelopes)


def _password_bucket(length: int) -> int:
    """Common visible power-of-two size policy for ordinary and decoy frames."""
    return max(256, 1 << (length + 7).bit_length())


def _pad_password(plaintext: bytes, size: int) -> bytes:
    import secrets

    return (len(plaintext).to_bytes(8, "big") + plaintext
            + secrets.token_bytes(size - 8 - len(plaintext)))


def _unpad_password(plaintext: bytes) -> bytes:
    if len(plaintext) < 256 or len(plaintext) & (len(plaintext) - 1):
        raise ContainerError("invalid password padding bucket")
    length = int.from_bytes(plaintext[:8], "big")
    if length > len(plaintext) - 8:
        raise ContainerError("invalid password plaintext length")
    return plaintext[8:8 + length]


def _chaff(aad: bytes, *, size: int = 256, kdf: str = "scrypt") -> bytes:
    """Encrypt common-policy padding under a discarded random password."""
    import secrets

    return crypto.encrypt(_pad_password(b"", size), secrets.token_hex(32), aad=aad, kdf=kdf)


def _iter_frames(blob: bytes):
    """Admit all framing and envelopes before yielding anything for KDF work."""
    from .opc import MAX_ENTRY_BYTES

    frames: list[bytes] = []
    envelopes = []
    i = 0
    for _ in range(2):
        if len(blob) - i < 4:
            raise ContainerError("password modules require exactly two complete frames")
        length = int.from_bytes(blob[i:i + 4], "big")
        i += 4
        if not 0 < length <= MAX_ENTRY_BYTES or length > len(blob) - i:
            raise ContainerError("invalid password frame length")
        frame = blob[i:i + length]
        i += length
        try:
            envelope = crypto.validate_password_envelope(frame)
        except ValueError as exc:
            raise ContainerError(f"invalid password envelope: {exc}") from exc
        bucket = len(envelope.ciphertext) - 16
        if bucket < 256 or bucket & (bucket - 1):
            raise ContainerError("invalid password frame padding bucket")
        frames.append(frame)
        envelopes.append(envelope)
    if i != len(blob):
        raise ContainerError("trailing password frame data")
    first, second = envelopes
    if (first.kdf_id, first.params, len(first.ciphertext)) != (
        second.kdf_id, second.params, len(second.ciphertext)
    ):
        raise ContainerError("password frames must share KDF and padding policy")
    yield from frames


def _open_password_frames(sealed: bytes, password: str, aad: bytes) -> bytes:
    """Admit exactly two frames, then attempt both; no universal deniability claim."""
    frames = list(_iter_frames(sealed))
    opened: bytes | None = None
    for env in frames:
        try:
            candidate = crypto.decrypt(env, password, aad=aad)
        except ValueError:
            continue
        if opened is None:
            opened = candidate
    if opened is None:
        raise ContainerError("no envelope opened with this password")
    return _unpad_password(opened)


__all__ = [
    "SEALING_LINEAGES",
    "ContainerError",
    "DocxPlusBuilder",
    "DocxPlusReader",
    "seal_module",
]


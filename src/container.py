"""DOCX+ container: compose typed, sealed, provenance-bound modules into a valid
.docx, and read them back.

v0.2 capabilities (see docs/design-rationale.md, docs/cookbook.md):

* **Typed payloads** — bytes / text / json / project (a whole repo) / docxplus
  (a nested container), via the :mod:`payloads` registry.
* **Sealing modes** — plain, ``password`` (AES-GCM/PBKDF2), ``recipients`` (X25519
  multi-recipient), ``threshold`` (Shamir k-of-n over the content key), ``decoy``
  (two secrets under two passwords for plausible deniability).
* **Provenance** — a signed Merkle root binds the whole module set.

The surface .docx stays a conforming, openable Office document throughout; sealing
is applied per payload, never to the whole package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import channels as channel_registry
import crypto
import payloads
import shamir
from manifest import Manifest, read_manifest, write_manifest
from opc import OpcPackage, read_package
from wordml import new_base_document


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


@dataclass
class DocxPlusBuilder:
    """Accumulates typed, sealed modules onto a base document, then emits a .docx."""

    paragraphs: list[str] = field(default_factory=lambda: ["This is an ordinary document."])
    title: str = "Document"
    creator: str = "DOCX+"
    base_package: OpcPackage | None = None
    _pending: list[_Pending] = field(default_factory=list)
    _private_key: bytes | None = None
    _public_key: bytes | None = None
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
                     threshold, None, channel_kwargs)
        )
        return self

    def add_project(
        self,
        slot: str,
        project_dir: str | Path,
        *,
        channel_id: str = "package_part",
        reproduce: object | bool | None = None,
        **seal,
    ) -> DocxPlusBuilder:
        """Pack an entire directory tree and carry it as a ``project`` module.

        ``reproduce`` optionally attests reproduction at build time (author side):
        pass a ``reproduce.ReproSpec``, or ``True`` to load the project's own
        ``.docxplus-reproduce.json`` recipe. The recipe is executed once now and its
        signed attestation travels in the manifest. Nothing is executed on read.
        """
        project_dir = Path(project_dir)
        blob = payloads.pack_project(project_dir)
        self.add_module(slot, channel_id, blob, payload_type="project", **seal)
        if reproduce is not None and reproduce is not False:
            import tempfile

            import reproduce as _repro

            spec = _repro.load_recipe(project_dir) if reproduce is True else reproduce
            if spec is None:
                raise ContainerError(
                    f"{slot!r}: reproduce=True but no {_repro.RECIPE_FILE} in the project"
                )
            # Attest over a clean extraction of the *packed* bytes, not the author's
            # working tree, so the attested digest matches exactly what a reader
            # reproduces (the packed subset — no .venv, output/, caches).
            with tempfile.TemporaryDirectory() as td:
                clean = payloads.unpack_project(blob, Path(td) / "proj")
                self._pending[-1].reproduction = _repro.attest(clean, spec)
        return self

    def add_nested(
        self, slot: str, inner_docx: bytes, *, channel_id: str = "package_part", **seal
    ) -> DocxPlusBuilder:
        """Carry a whole DOCX+ document as a nested ``docxplus`` module."""
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
    ) -> DocxPlusBuilder:
        """Two payloads under two passwords; neither reveals the other."""
        if channel_id not in channel_registry.available_channels():
            raise ContainerError(f"unknown channel: {channel_id}")
        if any(m.slot == slot for m in self._pending):
            raise ContainerError(f"duplicate slot: {slot}")
        payloads.get_type(payload_type)
        self._pending.append(
            _Pending(slot, channel_id, None, payload_type, None, None, None,
                     (real, real_password, decoy, decoy_password), {})
        )
        return self

    def sign(self, private_key: bytes) -> DocxPlusBuilder:
        """Sign the manifest (its Merkle-bound canonical body) with Ed25519."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private_key = private_key
        self._public_key = Ed25519PrivateKey.from_private_bytes(
            private_key
        ).public_key().public_bytes_raw()
        return self

    # -- build -------------------------------------------------------------
    def build(self) -> bytes:
        pkg = self.base_package or new_base_document(
            self.paragraphs, title=self.title, creator=self.creator
        )
        manifest = Manifest()
        self.threshold_shares = {}

        for m in self._pending:
            record = self._place(pkg, m)
            manifest.add(record)

        # Bind the visible document text into the signed body: a signature over the
        # manifest otherwise says nothing about the paragraphs a reader sees.
        doc_part = pkg.parts.get("word/document.xml", b"")
        manifest.surface_digest = crypto.digest(doc_part)

        if self._private_key is not None and self._public_key is not None:
            manifest.public_key = self._public_key.hex()
            manifest.signature = crypto.sign(
                manifest.canonical_body(), self._private_key
            ).hex()

        write_manifest(pkg, manifest)
        return pkg.to_bytes()

    def _place(self, pkg: OpcPackage, m: _Pending):
        ptype = payloads.get_type(m.payload_type)
        channel = channel_registry.get_channel(m.channel_id, **m.channel_kwargs)
        aad = m.slot.encode("utf-8")  # bind every ciphertext to its module slot

        if m.decoy is not None:
            # A decoy is a password module carrying two envelopes; the manifest
            # records mode "password" so it is indistinguishable from an ordinary
            # encrypted module (the old "decoy" label advertised the hidden payload).
            real, real_pw, decoy, decoy_pw = m.decoy
            sealed = _frame_seq([
                crypto.encrypt(ptype.pack(real), real_pw, aad=aad),
                crypto.encrypt(ptype.pack(decoy), decoy_pw, aad=aad),
            ])
            sealing = {"mode": "password"}
        else:
            plaintext = ptype.pack(m.obj)
            if m.password is not None:
                # Pad with an undecryptable chaff frame so an ordinary password
                # module carries exactly two frames, byte-indistinguishable from a
                # decoy module. An observer cannot prove the second frame is (or is
                # not) a hidden payload — that is the deniability the format offers.
                sealed = _frame_seq([crypto.encrypt(plaintext, m.password, aad=aad), _chaff(aad)])
                sealing = {"mode": "password"}
            elif m.recipients is not None:
                sealed = crypto.seal_multi(plaintext, m.recipients, aad=aad)
                # Record neither identities nor count — the manifest must not leak
                # the recipient set of a blind-review packet. The DXE2 envelope
                # already carries everything extraction needs.
                sealing = {"mode": "recipients"}
            elif m.threshold is not None:
                k, n = m.threshold
                content_key = _random_key()
                sealed = crypto.encrypt_with_key(plaintext, content_key, aad=aad)
                self.threshold_shares[m.slot] = shamir.split(content_key, k, n)
                sealing = {"mode": "threshold", "k": k, "n": n}
            else:
                sealed = plaintext
                sealing = {"mode": "plain"}

        record = channel.embed(pkg, sealed, slot=m.slot)
        record.payload_type = m.payload_type
        record.encrypted = sealing["mode"] != "plain"
        record.sealing = sealing
        record.reproduction = m.reproduction or {}
        # record.digest/size come from the channel = digest/len of the STORED bytes,
        # so the manifest (and its signature) bind exactly what travels; plaintext
        # integrity is the AEAD tag's job, checked on decryption.
        return record


def _random_key() -> bytes:
    import os

    return os.urandom(crypto.KEY_BYTES)


@dataclass
class DocxPlusReader:
    """Reads typed, sealed modules back out of a DOCX+ package."""

    package: OpcPackage
    manifest: Manifest
    _nest_depth: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> DocxPlusReader:
        pkg = read_package(data)
        manifest = read_manifest(pkg)
        if manifest is None:
            raise ContainerError("package carries no intelligence manifest")
        return cls(package=pkg, manifest=manifest)

    def list_modules(self) -> list[str]:
        return [r.slot for r in self.manifest.records]

    def describe(self, slot: str) -> dict:
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
            plaintext = self._unseal(slot, mode, sealed, aad, password, private_key, shares)

        if as_object:
            return payloads.get_type(record.payload_type).unpack(plaintext)
        return plaintext

    def _unseal(self, slot, mode, sealed, aad, password, private_key, shares) -> bytes:
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
                return crypto.decrypt_with_key(sealed, shamir.combine(shares), aad=aad)
        except ContainerError:
            raise
        except Exception as exc:
            raise ContainerError(f"cannot open module {slot!r}: {exc}") from exc
        raise ContainerError(f"unknown sealing mode: {mode}")  # pragma: no cover

    def extract_project(self, slot: str, dest: str | Path, **creds) -> Path:
        """Recover a ``project`` module and unpack it into ``dest``."""
        record = self._record(slot)
        if record.payload_type != "project":
            raise ContainerError(f"module {slot!r} is not a project payload")
        blob = self.extract(slot, **creds)
        return payloads.unpack_project(blob, Path(dest))

    #: Guards against a maliciously deep matryoshka chain exhausting resources.
    MAX_NEST_DEPTH = 32

    def verify_reproduction(self, slot: str, expected_public_key: bytes | None = None) -> dict:
        """Cryptographically verify a project module's reproduction attestation —
        **executing nothing**. Confirms an attestation exists, that the signature
        binds it to exactly these carried bytes and the visible text, and (when
        ``expected_public_key`` is given) that a trusted key signed it.

        Returns ``{attested, signed, verified, attestation|unverified_attestation}``.
        ``verified`` is the load-bearing field: an attested claim is trustworthy only
        when ``verified`` is true. This is the default trust path — the reader relies
        on the signer's attested run without executing anything.
        """
        record = self._record(slot)
        att = record.reproduction
        signed = self.verify_provenance(expected_public_key)
        # Bind the attestation to the ACTUAL carried bytes: the signature covers
        # record.digest, but the stored bytes could have been swapped post-signing —
        # in which case the signature would already fail, but confirm it here so a
        # "verified" verdict never rides on unread bytes.
        stored_ok = crypto.digest(
            channel_registry.get_channel(record.channel).extract(self.package, record)
        ) == record.digest
        verified = bool(signed and stored_ok)
        if not att:
            return {"attested": False, "signed": signed, "verified": verified}
        result = {
            "attested": True,
            "signed": signed,
            "verified": verified,  # signature valid (optionally to a trusted key) AND bytes intact
        }
        # Only surface the attested claim as bound when it is cryptographically
        # verified; otherwise the digest/command are self-asserted and untrusted.
        key = "attestation" if verified else "unverified_attestation"
        result[key] = {
            "output_digest": att.get("output_digest", ""),
            "command": att.get("command", []),
            "toolchain": att.get("toolchain", {}),
        }
        return result

    def reproduce(self, slot: str, dest: str | Path, *, allow_execution: bool = False, **creds) -> dict:
        """OPT-IN, EXECUTES CARRIED CODE. Recover the project and re-run its attested
        command in a best-effort hermetic sandbox, comparing output digests.

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
        import reproduce as _repro

        return _repro.reproduce_and_compare(project_dir, att)

    def open_nested(self, slot: str, **creds) -> DocxPlusReader:
        """Recover a nested ``docxplus`` module and return a reader over it.

        Depth is tracked across the chain so a hostile deeply-nested document
        cannot drive unbounded recursion/resource use.
        """
        if self._nest_depth >= self.MAX_NEST_DEPTH:
            raise ContainerError("nested document depth cap exceeded")
        record = self._record(slot)
        if record.payload_type != "docxplus":
            raise ContainerError(f"module {slot!r} is not a nested document")
        child = DocxPlusReader.from_bytes(self.extract(slot, **creds))
        child._nest_depth = self._nest_depth + 1
        return child

    # -- provenance --------------------------------------------------------
    def merkle_root(self) -> str:
        return self.manifest.merkle_root()

    def signer(self) -> str:
        """The hex Ed25519 public key that signed the manifest (``""`` if unsigned).

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
        doc_part = self.package.parts.get("word/document.xml", b"")
        return crypto.digest(doc_part) == self.manifest.surface_digest

    def inclusion_proof(self, slot: str) -> dict:
        """A Merkle inclusion proof that ``slot`` belongs to this document's signed
        module set — verifiable by a third party without the other modules."""
        from provenance import inclusion_proof as _proof

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


def _frame_seq(envelopes: list[bytes]) -> bytes:
    """Frame one-or-more envelopes as ``[u32 len | envelope]…`` (self-delimiting)."""
    return b"".join(len(e).to_bytes(4, "big") + e for e in envelopes)


def _chaff(aad: bytes) -> bytes:
    """A well-formed but undecryptable envelope: a random payload under a random,
    discarded password. Indistinguishable from a real second envelope."""
    import secrets

    size = 16 + secrets.randbelow(240)
    return crypto.encrypt(secrets.token_bytes(size), secrets.token_hex(16), aad=aad)


def _iter_frames(blob: bytes):
    i = 0
    while i < len(blob):
        length = int.from_bytes(blob[i : i + 4], "big")
        i += 4
        yield blob[i : i + length]
        i += length


def _open_password_frames(sealed: bytes, password: str, aad: bytes) -> bytes:
    """Try each framed envelope with ``password``; return the first that opens.

    A single-secret module has one frame; a decoy has two (a real payload and a
    cover story under different passwords). Both look identical in the manifest.
    """
    for env in _iter_frames(sealed):
        try:
            return crypto.decrypt(env, password, aad=aad)
        except Exception:  # noqa: BLE001,S112 - wrong frame for this password; try next
            continue
    raise ContainerError("no envelope opened with this password")

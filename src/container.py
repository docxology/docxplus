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

_DECOY_MAGIC = b"DXD1"


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
        self, slot: str, project_dir: str | Path, *, channel_id: str = "package_part", **seal
    ) -> DocxPlusBuilder:
        """Pack an entire directory tree and carry it as a ``project`` module."""
        blob = payloads.pack_project(Path(project_dir))
        return self.add_module(slot, channel_id, blob, payload_type="project", **seal)

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

        if m.decoy is not None:
            real, real_pw, decoy, decoy_pw = m.decoy
            env_real = crypto.encrypt(ptype.pack(real), real_pw)
            env_decoy = crypto.encrypt(ptype.pack(decoy), decoy_pw)
            sealed = _DECOY_MAGIC + len(env_real).to_bytes(4, "big") + env_real + env_decoy
            record = channel.embed(pkg, sealed, slot=m.slot)
            record.payload_type = m.payload_type
            record.encrypted = True
            record.sealing = {"mode": "decoy"}
            record.digest = crypto.digest(sealed)  # binds module bytes, not a plaintext
            record.size = len(sealed)
            return record

        plaintext = ptype.pack(m.obj)
        digest = crypto.digest(plaintext)
        size = len(plaintext)

        if m.password is not None:
            sealed, sealing = crypto.encrypt(plaintext, m.password), {"mode": "password"}
        elif m.recipients is not None:
            sealed = crypto.seal_multi(plaintext, m.recipients)
            sealing = {"mode": "recipients", "recipients": [p.hex() for p in m.recipients]}
        elif m.threshold is not None:
            k, n = m.threshold
            content_key = _random_key()
            sealed = crypto.encrypt_with_key(plaintext, content_key)
            self.threshold_shares[m.slot] = shamir.split(content_key, k, n)
            sealing = {"mode": "threshold", "k": k, "n": n}
        else:
            sealed, sealing = plaintext, {"mode": "plain"}

        record = channel.embed(pkg, sealed, slot=m.slot)
        record.payload_type = m.payload_type
        record.encrypted = sealing["mode"] != "plain"
        record.sealing = sealing
        record.digest = digest
        record.size = size
        return record


def _random_key() -> bytes:
    import os

    return os.urandom(crypto.KEY_BYTES)


@dataclass
class DocxPlusReader:
    """Reads typed, sealed modules back out of a DOCX+ package."""

    package: OpcPackage
    manifest: Manifest

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
        mode = record.sealing.get("mode", "plain")

        if mode == "plain":
            plaintext = sealed
        elif mode == "decoy":
            if password is None:
                raise ContainerError(f"module {slot!r} needs a password")
            plaintext = _open_decoy(sealed, password)
        else:
            plaintext = self._unseal(slot, mode, sealed, password, private_key, shares)

        if mode not in ("decoy",):
            computed = crypto.digest(plaintext)
            if computed != record.digest:
                raise ContainerError(
                    f"digest mismatch for {slot!r}: {record.digest} != {computed}"
                )
        if as_object:
            return payloads.get_type(record.payload_type).unpack(plaintext)
        return plaintext

    def _unseal(self, slot, mode, sealed, password, private_key, shares) -> bytes:
        """Decrypt a sealed module, converting any crypto failure to ContainerError."""
        if mode == "password" and password is None:
            raise ContainerError(f"module {slot!r} needs a password")
        if mode == "recipients" and private_key is None:
            raise ContainerError(f"module {slot!r} needs a recipient private key")
        if mode == "threshold" and not shares:
            raise ContainerError(f"module {slot!r} needs threshold shares")
        try:
            if mode == "password":
                return crypto.decrypt(sealed, password)
            if mode == "recipients":
                return crypto.unseal_multi(sealed, private_key)
            if mode == "threshold":
                return crypto.decrypt_with_key(sealed, shamir.combine(shares))
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

    def open_nested(self, slot: str, **creds) -> DocxPlusReader:
        """Recover a nested ``docxplus`` module and return a reader over it."""
        record = self._record(slot)
        if record.payload_type != "docxplus":
            raise ContainerError(f"module {slot!r} is not a nested document")
        return DocxPlusReader.from_bytes(self.extract(slot, **creds))

    # -- provenance --------------------------------------------------------
    def merkle_root(self) -> str:
        return self.manifest.merkle_root()

    def signature_status(self) -> str:
        if not self.manifest.is_signed():
            return "unsigned"
        return "valid" if self.manifest.verify_signature() else "invalid"

    def verify_provenance(self) -> bool:
        """True when the manifest is signed and the signature (which binds the
        Merkle root over all modules) validates."""
        return self.manifest.is_signed() and self.manifest.verify_signature()

    def _record(self, slot: str):
        try:
            return self.manifest.slot(slot)
        except KeyError as exc:
            raise ContainerError(f"no such module: {slot}") from exc


def _open_decoy(sealed: bytes, password: str) -> bytes:
    if sealed[:4] != _DECOY_MAGIC:
        raise ContainerError("not a decoy module")
    i = 4
    a_len = int.from_bytes(sealed[i : i + 4], "big")
    i += 4
    env_real, env_decoy = sealed[i : i + a_len], sealed[i + a_len :]
    for env in (env_real, env_decoy):
        try:
            return crypto.decrypt(env, password)
        except Exception:  # noqa: BLE001,S112 - wrong password for this slot; try the other
            continue
    raise ContainerError("neither decoy slot opened with this password")

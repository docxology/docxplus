"""DOCX+ container: compose channels + manifest into a valid .docx, and read back.

Public API:

    builder = DocxPlusBuilder(paragraphs=["Quarterly report ..."])
    builder.add_module("brief", "custom_xml", b"...structured payload...")
    builder.add_module("secret", "package_part", b"...", password="hunter2")
    builder.sign(private_key)                 # optional Ed25519 over the manifest
    data = builder.build()                    # -> bytes of a valid .docx

    reader = DocxPlusReader.from_bytes(data)
    reader.verify()                           # spec + manifest + signature status
    reader.extract("secret", password="hunter2")

Encryption is applied at the payload level (crypto.encrypt) *before* the channel
places it, so the surface .docx stays openable (report §6.3). The manifest records
which slots are encrypted; extraction refuses an encrypted slot without a
password.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import channels as channel_registry
import crypto
from manifest import Manifest, read_manifest, write_manifest
from opc import OpcPackage, read_package
from wordml import new_base_document


class ContainerError(RuntimeError):
    """Raised for container-level composition or extraction errors."""


@dataclass
class _PendingModule:
    slot: str
    channel_id: str
    payload: bytes
    password: str | None
    channel_kwargs: dict


@dataclass
class DocxPlusBuilder:
    """Accumulates modules onto a base document, then emits a valid .docx."""

    paragraphs: list[str] = field(default_factory=lambda: ["This is an ordinary document."])
    title: str = "Document"
    creator: str = "DOCX+"
    base_package: OpcPackage | None = None
    _pending: list[_PendingModule] = field(default_factory=list)
    _private_key: bytes | None = None
    _public_key: bytes | None = None

    def add_module(
        self,
        slot: str,
        channel_id: str,
        payload: bytes,
        *,
        password: str | None = None,
        **channel_kwargs,
    ) -> "DocxPlusBuilder":
        """Queue a payload to ride on ``channel_id`` under manifest ``slot``."""
        if channel_id not in channel_registry.available_channels():
            raise ContainerError(f"unknown channel: {channel_id}")
        if any(m.slot == slot for m in self._pending):
            raise ContainerError(f"duplicate slot: {slot}")
        self._pending.append(
            _PendingModule(slot, channel_id, payload, password, channel_kwargs)
        )
        return self

    def sign(self, private_key: bytes) -> "DocxPlusBuilder":
        """Sign the manifest with a raw Ed25519 private key at build time."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._private_key = private_key
        self._public_key = Ed25519PrivateKey.from_private_bytes(
            private_key
        ).public_key().public_bytes_raw()
        return self

    def build(self) -> bytes:
        """Compose everything into deterministic .docx bytes."""
        pkg = self.base_package or new_base_document(
            self.paragraphs, title=self.title, creator=self.creator
        )
        manifest = Manifest()
        for module in self._pending:
            payload = module.payload
            encrypted = False
            if module.password is not None:
                payload = crypto.encrypt(payload, module.password)
                encrypted = True
            channel = channel_registry.get_channel(module.channel_id, **module.channel_kwargs)
            record = channel.embed(pkg, payload, slot=module.slot)
            record.encrypted = encrypted
            if encrypted:
                # The manifest digest/size describe the *plaintext* so a reader can
                # verify integrity after decryption; the channel measured the
                # ciphertext envelope, so override with the original payload.
                record.size = len(module.payload)
                record.digest = crypto.digest(module.payload)
            manifest.add(record)

        if self._private_key is not None and self._public_key is not None:
            manifest.public_key = self._public_key.hex()
            manifest.signature = crypto.sign(
                manifest.canonical_body(), self._private_key
            ).hex()

        write_manifest(pkg, manifest)
        return pkg.to_bytes()


@dataclass
class DocxPlusReader:
    """Reads modules back out of a DOCX+ package."""

    package: OpcPackage
    manifest: Manifest

    @classmethod
    def from_bytes(cls, data: bytes) -> "DocxPlusReader":
        pkg = read_package(data)
        manifest = read_manifest(pkg)
        if manifest is None:
            raise ContainerError("package carries no intelligence manifest")
        return cls(package=pkg, manifest=manifest)

    def list_modules(self) -> list[str]:
        return [r.slot for r in self.manifest.records]

    def has_intelligence(self) -> bool:
        return bool(self.manifest.records)

    def extract(self, slot: str, *, password: str | None = None) -> bytes:
        """Extract and (if needed) decrypt one module by slot."""
        try:
            record = self.manifest.slot(slot)
        except KeyError as exc:
            raise ContainerError(f"no such module: {slot}") from exc
        channel = channel_registry.get_channel(record.channel)
        raw = channel.extract(self.package, record)
        if record.encrypted:
            if password is None:
                raise ContainerError(f"module {slot!r} is encrypted; password required")
            raw = crypto.decrypt(raw, password)
        computed = crypto.digest(raw)
        if computed != record.digest:
            raise ContainerError(
                f"digest mismatch for {slot!r}: manifest {record.digest} != {computed}"
            )
        return raw

    def signature_status(self) -> str:
        """One of ``unsigned``, ``valid``, ``invalid``."""
        if not self.manifest.is_signed():
            return "unsigned"
        return "valid" if self.manifest.verify_signature() else "invalid"

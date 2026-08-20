"""The docxplus intelligence manifest.

The manifest is the modular spine of the format: a single JSON part
(``intelligence/manifest.json``, with an Override content type) that enumerates
every payload module, where it lives, its digest and size, whether it is
encrypted, and an optional Ed25519 signature over the canonical manifest body.

It plays the role the report assigns to ``META-INF/manifest.xml`` in ODF (report
§2.2): the authoritative list of what the package carries, so a reader validates
against the manifest, never against guessed bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .channels.base import ChannelRecord
from .crypto import verify as _verify
from .opc import OpcPackage, Relationship

MANIFEST_PART = "intelligence/manifest.json"
CT_MANIFEST = "application/vnd.docxplus.manifest+json"
REL_MANIFEST = "urn:docxplus:intelligence:1.0/manifest"
SIGNATURE_ALGORITHM = "ed25519"

FORMAT_VERSION = "2.0"


@dataclass
class Manifest:
    """In-memory intelligence manifest."""

    records: list[ChannelRecord] = field(default_factory=list)
    version: str = FORMAT_VERSION
    public_key: str = ""  # hex Ed25519 public key, if signed
    signature: str = ""  # hex Ed25519 signature over canonical_body()
    #: Digest of the whole part graph — every part, the content-type map, and every
    #: relationship edge, excluding only this manifest. Not a digest of
    #: word/document.xml: selecting the story part by name put a naming convention
    #: in the trust path, and OPC resolves it through the officeDocument
    #: relationship instead. See container._compute_surface_digest.
    surface_digest: str = ""
    #: Detached co-signatures over the same canonical body: [{public_key, value}, ...].
    cosignatures: list[dict] = field(default_factory=list)
    #: The signature algorithm the manifest declares. Recorded so a disagreement can
    #: be refused; never used to *select* a verifier. Selecting on an attacker-
    #: supplied algorithm field is the JWT `alg` confusion class, and this field is
    #: not inside canonical_body, so it is not authenticated either.
    algorithm: str = SIGNATURE_ALGORITHM

    def add(self, record: ChannelRecord) -> None:
        if any(r.slot == record.slot for r in self.records):
            raise ValueError(f"duplicate manifest slot: {record.slot}")
        self.records.append(record)

    def slot(self, name: str) -> ChannelRecord:
        for r in self.records:
            if r.slot == name:
                return r
        raise KeyError(name)

    def merkle_root(self) -> str:
        """Merkle root over the module set — binds the collection, not just parts."""
        from .provenance import merkle_root as _root

        return _root([(r.slot, r.digest) for r in self.records])

    def canonical_body(self) -> bytes:
        """Deterministic bytes signed/verified: version + modules + Merkle root.

        Including the Merkle root means the signature binds the *set* of modules;
        dropping or injecting a module changes the root and breaks the signature.
        """
        body = {
            "version": self.version,
            "modules": [r.to_dict() for r in sorted(self.records, key=lambda x: x.slot)],
            "merkle_root": self.merkle_root(),
            "surface_digest": self.surface_digest,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_bytes(self) -> bytes:
        doc = {
            "version": self.version,
            "modules": [r.to_dict() for r in sorted(self.records, key=lambda x: x.slot)],
            "merkle_root": self.merkle_root(),
            "surface_digest": self.surface_digest,
            "signature": {
                "algorithm": self.algorithm,
                "public_key": self.public_key,
                "value": self.signature,
            },
            "cosignatures": [dict(c) for c in self.cosignatures],
        }
        return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, blob: bytes) -> Manifest:
        doc = json.loads(blob)
        sig = doc.get("signature", {})
        # `add` refuses a duplicate slot on the write path, but a manifest read from
        # a package never goes through `add`, so a hand-crafted one could carry two
        # records under one name. That is a parser differential: `slot()` returns the
        # first match while a validator iterating `records` sees both, so the module
        # a reader extracts need not be the module a validator checked. Refuse here,
        # where untrusted bytes actually enter.
        records = [ChannelRecord.from_dict(m) for m in doc.get("modules", [])]
        seen: set[str] = set()
        for record in records:
            if record.slot in seen:
                raise ValueError(f"duplicate manifest slot: {record.slot}")
            seen.add(record.slot)
        return cls(
            records=records,
            version=doc.get("version", FORMAT_VERSION),
            public_key=sig.get("public_key", ""),
            signature=sig.get("value", ""),
            surface_digest=doc.get("surface_digest", ""),
            algorithm=str(sig.get("algorithm", SIGNATURE_ALGORITHM)),
            cosignatures=[dict(c) for c in doc.get("cosignatures", [])],
        )

    def verify_cosignatures(self) -> dict[str, bool]:
        """Verify every detached co-signature over the canonical body → {hex_key: ok}.

        Co-signatures are independent attestations by additional parties over the
        same signed content. A verifier checks for the *expected* signer keys; a
        stranger adding their own valid co-signature does not help them.
        """
        body = self.canonical_body()
        out: dict[str, bool] = {}
        for c in self.cosignatures:
            key, value = c.get("public_key", ""), c.get("value", "")
            try:
                out[key] = _verify(body, bytes.fromhex(value), bytes.fromhex(key))
            except ValueError:
                out[key] = False
        return out

    def is_signed(self) -> bool:
        return bool(self.signature and self.public_key)

    def declares_supported_algorithm(self) -> bool:
        """True when the manifest names the signature algorithm this build implements.

        The field was written and never read: a manifest could declare
        ``"algorithm": "rsa-4096"`` and still verify, because verification hard-codes
        Ed25519. Nothing was exploitable — hard-coding is what makes it safe, and
        dispatching on the field instead would be the JWT ``alg``-confusion mistake —
        but a recorded value nobody checks is a claim the format cannot keep, and it
        left no way to notice a document from a future version using something else.

        So the field is checked and never obeyed. Note that it sits outside
        ``canonical_body`` and is therefore unauthenticated: flipping it can turn a
        valid document into a refused one, which is a nuisance rather than a
        compromise, and strictly better than accepting a statement known to be false.
        """
        return self.algorithm == SIGNATURE_ALGORITHM

    def verify_signature(self) -> bool:
        """True when a present signature validates over the canonical body."""
        if not self.declares_supported_algorithm():
            return False
        if not self.is_signed():
            return False
        return _verify(
            self.canonical_body(),
            bytes.fromhex(self.signature),
            bytes.fromhex(self.public_key),
        )


def write_manifest(pkg: OpcPackage, manifest: Manifest) -> None:
    """Serialise ``manifest`` into ``pkg`` (idempotent: replaces if present)."""
    blob = manifest.to_bytes()
    if MANIFEST_PART in pkg.parts:
        pkg.parts[MANIFEST_PART] = blob
        return
    pkg.add_part(MANIFEST_PART, blob, CT_MANIFEST)
    rid = pkg.next_rel_id("")
    pkg.add_relationship(Relationship(rid, REL_MANIFEST, MANIFEST_PART), source_part="")


def read_manifest(pkg: OpcPackage) -> Manifest | None:
    """Load the manifest from ``pkg`` or ``None`` if the package carries none."""
    if MANIFEST_PART not in pkg.parts:
        return None
    return Manifest.from_bytes(pkg.parts[MANIFEST_PART])


__all__ = [
    "CT_MANIFEST",
    "FORMAT_VERSION",
    "MANIFEST_PART",
    "REL_MANIFEST",
    "SIGNATURE_ALGORITHM",
    "Manifest",
    "read_manifest",
    "write_manifest",
]



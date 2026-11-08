"""The docxplus intelligence manifest.

The manifest is the modular spine of the format: a single JSON part
(``intelligence/manifest.json``, with an Override content type) that enumerates
every payload module, where it lives, its digest and size, whether it is
encrypted, and an optional key-family-bound signature over the canonical body.

It plays the role the report assigns to ``META-INF/manifest.xml`` in ODF (report
§2.2): the authoritative list of what the package carries, so a reader validates
against the manifest, never against guessed bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .channels.base import ChannelRecord
from .crypto import signing_algorithm
from .crypto import verify as _verify
from .opc import OpcPackage, Relationship
from .shamir import MAX_X

MANIFEST_PART = "intelligence/manifest.json"
CT_MANIFEST = "application/vnd.docxplus.manifest+json"
REL_MANIFEST = "urn:docxplus:intelligence:1.0/manifest"
SIGNATURE_ALGORITHM = "ed25519"

FORMAT_VERSION = "3.0"


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest JSON key: {key}")
        result[key] = value
    return result


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _validate_document(doc: object) -> None:
    """Validate the single exact format-3 schema before creating records."""
    if not isinstance(doc, dict) or set(doc) != {
        "version", "modules", "merkle_root", "surface_digest", "signature", "cosignatures"
    }:
        raise ValueError("invalid manifest object fields")
    if doc["version"] != FORMAT_VERSION:
        raise ValueError(f"unsupported manifest version: {doc['version']!r}")
    for key in ("merkle_root", "surface_digest"):
        value = doc[key]
        if not isinstance(value, str) or (value and not _is_digest(value)):
            raise ValueError(f"invalid manifest {key}")
    sig = doc["signature"]
    if not isinstance(sig, dict) or set(sig) != {"algorithm", "public_key", "value"}:
        raise ValueError("invalid manifest signature object")
    if any(not isinstance(value, str) for value in sig.values()):
        raise ValueError("manifest signature fields must be strings")
    for key in ("public_key", "value"):
        bytes.fromhex(sig[key])
    if bool(sig["public_key"]) != bool(sig["value"]):
        raise ValueError("signature requires both public_key and value")
    if not isinstance(doc["cosignatures"], list):
        raise TypeError("manifest cosignatures must be a list")
    keys = set()
    for entry in doc["cosignatures"]:
        if (
            not isinstance(entry, dict) or set(entry) != {"public_key", "algorithm", "value"}
            or any(not isinstance(value, str) for value in entry.values())
        ):
            raise ValueError("invalid manifest cosignature")
        public = bytes.fromhex(entry["public_key"])
        bytes.fromhex(entry["value"])
        if public in keys:
            raise ValueError("duplicate manifest cosigner")
        keys.add(public)
    if not isinstance(doc["modules"], list):
        raise TypeError("manifest modules must be a list")
    fields = {
        "channel", "slot", "size", "digest", "encrypted", "content_type",
        "payload_type", "sealing", "location", "reproduction",
    }
    for module in doc["modules"]:
        if not isinstance(module, dict) or set(module) != fields:
            raise ValueError("invalid manifest module fields")
        for key in ("channel", "slot", "digest", "content_type", "payload_type"):
            if not isinstance(module[key], str):
                raise TypeError(f"manifest module {key} must be a string")
            module[key].encode("utf-8")
        if not _is_digest(module["digest"]):
            raise ValueError("module digest must be 32-byte lowercase hex")
        if type(module["size"]) is not int or module["size"] < 0:
            raise ValueError("manifest module size must be a nonnegative integer")
        if type(module["encrypted"]) is not bool:
            raise ValueError("manifest module encrypted must be a boolean")
        if any(not isinstance(module[key], dict) for key in ("sealing", "location", "reproduction")):
            raise ValueError("manifest module metadata must be objects")
        if any(
            not (
                isinstance(value, list) and all(isinstance(part, str) for part in value)
                if key == "parts" else isinstance(value, str)
            )
            for key, value in module["location"].items()
        ):
            raise ValueError("invalid module location values")
        sealing = module["sealing"]
        mode = sealing.get("mode")
        if mode not in ("plain", "password", "recipients", "threshold"):
            raise ValueError("unsupported manifest sealing mode")
        if module["encrypted"] != (mode != "plain"):
            raise ValueError("manifest encrypted flag disagrees with sealing mode")
        if mode == "threshold":
            if set(sealing) != {"mode", "k", "n", "checksummed_shares", "share_digests"}:
                raise ValueError("threshold module requires signed share commitments and checksum policy")
            k, n = sealing["k"], sealing["n"]
            if type(k) is not int or type(n) is not int or not 1 <= k <= n <= MAX_X:
                raise ValueError("invalid threshold parameters")
            if sealing["checksummed_shares"] is not True:
                raise ValueError("threshold module requires checksummed shares")
            digests = sealing["share_digests"]
            if (
                not isinstance(digests, list) or len(digests) != n
                or any(not _is_digest(digest) for digest in digests)
                or len(set(digests)) != n
            ):
                raise ValueError("invalid threshold share commitments")
        elif set(sealing) != {"mode"}:
            raise ValueError("unsupported sealing metadata fields")


@dataclass
class Manifest:
    """In-memory intelligence manifest."""

    records: list[ChannelRecord] = field(default_factory=list)
    version: str = FORMAT_VERSION
    public_key: str = ""  # hex strictly framed signing public key, if signed
    signature: str = ""  # hex signature over canonical_body()
    #: Digest of the whole part graph — every part, the content-type map, and every
    #: relationship edge, excluding only this manifest. Not a digest of
    #: word/document.xml: selecting the story part by name put a naming convention
    #: in the trust path, and OPC resolves it through the officeDocument
    #: relationship instead. See container._compute_surface_digest.
    surface_digest: str = ""
    #: Co-signatures: [{public_key, algorithm, value}, ...]; identities/schemes are signed.
    cosignatures: list[dict] = field(default_factory=list)
    #: Actual primary key family, authenticated by canonical_body().
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
        """Sign version, modules, Merkle root, surface and actual signing schemes.

        Including the Merkle root means the signature binds the *set* of modules;
        dropping or injecting a module changes the root and breaks the signature.
        All co-signer identities and algorithms must be declared before signing;
        only their signature values are excluded from the canonical body.
        """
        body = {
            "version": self.version,
            "modules": [r.to_dict() for r in sorted(self.records, key=lambda x: x.slot)],
            "merkle_root": self.merkle_root(),
            "surface_digest": self.surface_digest,
            "signature_algorithm": self.algorithm,
            "cosigners": sorted(
                ({"public_key": c["public_key"], "algorithm": c["algorithm"]}
                 for c in self.cosignatures),
                key=lambda c: (c["public_key"], c["algorithm"]),
            ),
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
        try:
            doc = json.loads(blob, object_pairs_hook=_unique_object)
            _validate_document(doc)
            sig = doc["signature"]
            records = [ChannelRecord.from_dict(module) for module in doc["modules"]]
        except (KeyError, TypeError, UnicodeError, RecursionError) as exc:
            raise ValueError(f"malformed manifest: {exc}") from exc
        seen: set[str] = set()
        for record in records:
            if record.slot in seen:
                raise ValueError(f"duplicate manifest slot: {record.slot}")
            seen.add(record.slot)
        return cls(
            records=records,
            version=doc["version"],
            public_key=sig["public_key"],
            signature=sig["value"],
            surface_digest=doc["surface_digest"],
            algorithm=sig["algorithm"],
            cosignatures=[dict(c) for c in doc["cosignatures"]],
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
                public = bytes.fromhex(key)
                out[key] = (self.version == FORMAT_VERSION
                            and c.get("algorithm") == signing_algorithm(public)
                            and _verify(body, bytes.fromhex(value), public))
            except ValueError:
                out[key] = False
        return out

    def is_signed(self) -> bool:
        return bool(self.signature and self.public_key)

    def declares_supported_algorithm(self) -> bool:
        """Check the authenticated scheme against the strictly parsed key family."""
        if self.version != FORMAT_VERSION:
            return False
        if not self.public_key:
            return self.algorithm == SIGNATURE_ALGORITHM
        try:
            return self.algorithm == signing_algorithm(bytes.fromhex(self.public_key))
        except ValueError:
            return False

    def verify_signature(self) -> bool:
        """True when a present signature validates over the canonical body."""
        if not self.declares_supported_algorithm():
            return False
        if not self.is_signed():
            return False
        try:
            return _verify(
                self.canonical_body(),
                bytes.fromhex(self.signature),
                bytes.fromhex(self.public_key),
            )
        except ValueError:
            return False


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



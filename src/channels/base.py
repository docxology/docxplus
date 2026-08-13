"""Channel interface for the DOCX+ intelligence layer.

A *channel* is one spec-sanctioned side-channel through which a payload can ride
inside an otherwise-ordinary OOXML package. Every channel implements the same
contract so the container can compose them modularly and the manifest can
describe them uniformly:

    embed(pkg, payload, slot)   -> ChannelRecord   (mutates pkg)
    extract(pkg, record)        -> bytes

``ChannelRecord`` is the manifest-facing description of *where* a payload landed,
so extraction is driven by the recorded location, never by guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from opc import OpcPackage


@dataclass
class ChannelRecord:
    """One entry in the intelligence manifest describing a placed payload."""

    channel: str
    slot: str
    size: int
    digest: str
    encrypted: bool = False
    content_type: str = "application/octet-stream"
    location: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "slot": self.slot,
            "size": self.size,
            "digest": self.digest,
            "encrypted": self.encrypted,
            "content_type": self.content_type,
            "location": dict(self.location),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChannelRecord":
        return cls(
            channel=data["channel"],
            slot=data["slot"],
            size=int(data["size"]),
            digest=data["digest"],
            encrypted=bool(data.get("encrypted", False)),
            content_type=data.get("content_type", "application/octet-stream"),
            location=dict(data.get("location", {})),
        )


@runtime_checkable
class Channel(Protocol):
    """Structural type every concrete channel satisfies."""

    id: str

    def embed(self, pkg: OpcPackage, payload: bytes, *, slot: str) -> ChannelRecord: ...

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes: ...

    def capacity(self, pkg: OpcPackage) -> int | None:
        """Bytes this channel can still hold in ``pkg``; ``None`` = effectively
        unbounded (a new part can always be added)."""
        ...

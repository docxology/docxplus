"""Cryptographic transparency log for reproduction attestations.

Produces an append-only, tamper-evident hash chain and Merkle inclusion proofs
for reproduction attestations, enabling distributed zero-knowledge verification
and auditability across independent verification nodes.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from provenance import inclusion_proof, merkle_root


@dataclass(frozen=True)
class LogEntry:
    index: int
    timestamp: int
    attestation_digest: str
    toolchain_hash: str
    prev_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def entry_hash(self) -> str:
        body = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "attestation_digest": self.attestation_digest,
                "toolchain_hash": self.toolchain_hash,
                "prev_hash": self.prev_hash,
                "metadata": self.metadata,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.blake2b(body, digest_size=32).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "attestation_digest": self.attestation_digest,
            "toolchain_hash": self.toolchain_hash,
            "prev_hash": self.prev_hash,
            "metadata": dict(self.metadata),
            "hash": self.entry_hash(),
        }


class TransparencyLog:
    """An append-only log binding attestations into a verified Merkle-backed chain."""

    def __init__(self, entries: list[LogEntry] | None = None) -> None:
        self.entries: list[LogEntry] = list(entries or [])

    def append(self, attestation: dict, metadata: dict[str, Any] | None = None) -> LogEntry:
        idx = len(self.entries)
        prev_h = self.entries[-1].entry_hash() if self.entries else "0" * 64
        att_digest = attestation.get("output_digest", "")
        tc_raw = json.dumps(attestation.get("toolchain", {}), sort_keys=True).encode("utf-8")
        tc_hash = hashlib.blake2b(tc_raw, digest_size=32).hexdigest()

        entry = LogEntry(
            index=idx,
            timestamp=int(time.time()),
            attestation_digest=att_digest,
            toolchain_hash=tc_hash,
            prev_hash=prev_h,
            metadata=dict(metadata or {}),
        )
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """Verify hash-chain integrity from root to tip."""
        for i, entry in enumerate(self.entries):
            if entry.index != i:
                return False
            expected_prev = self.entries[i - 1].entry_hash() if i > 0 else "0" * 64
            if entry.prev_hash != expected_prev:
                return False
        return True

    def merkle_tree_root(self) -> str:
        """Compute the Merkle root over all log entry hashes."""
        leaves = [(f"entry_{e.index:06d}", e.entry_hash()) for e in self.entries]
        return merkle_root(leaves)

    def inclusion_proof(self, index: int) -> dict:
        leaves = [(f"entry_{e.index:06d}", e.entry_hash()) for e in self.entries]
        slot = f"entry_{index:06d}"
        return inclusion_proof(leaves, slot)

    def to_json(self) -> str:
        return json.dumps([e.to_dict() for e in self.entries], indent=2)

    @classmethod
    def from_json(cls, data: str) -> TransparencyLog:
        raw = json.loads(data)
        entries = [
            LogEntry(
                index=d["index"],
                timestamp=d["timestamp"],
                attestation_digest=d["attestation_digest"],
                toolchain_hash=d["toolchain_hash"],
                prev_hash=d["prev_hash"],
                metadata=d.get("metadata", {}),
            )
            for d in raw
        ]
        log = cls(entries)
        if not log.verify_chain():
            raise ValueError("loaded transparency log fails chain integrity check")
        return log

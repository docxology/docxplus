"""Cryptographic transparency log for reproduction attestations.

Produces an append-only, tamper-evident hash chain and Merkle inclusion proofs
for reproduction attestations, enabling distributed zero-knowledge verification
and auditability across independent verification nodes.

**A hash chain alone proves nothing about authenticity.** ``verify_chain`` only
establishes that the log is *self-consistent*: every entry's ``prev_hash`` equals
the recomputed hash of its predecessor. An adversary who rewrites the whole log
from index 0 produces a different-but-equally-self-consistent chain, and — because
no entry references the tip — the *last* entry's body can be edited in place
without breaking any linkage at all. Self-consistency is therefore necessary and
nowhere near sufficient.

The trust anchor is the **signed tree head** (STH): an Ed25519 signature over
``(log_size, root_hash)``. Pinning a signer's public key and checking the STH is
what upgrades "this log does not contradict itself" into "this log is the one that
signer published, at this exact length". Verifiers that skip the STH are running an
integrity check, not an authenticity check, and the CLI says so out loud.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

import crypto
from provenance import inclusion_proof, merkle_root

# Domain-separation prefix so an STH signature can never be replayed as a
# manifest signature (or vice versa) under the same Ed25519 key.
STH_DOMAIN = b"docxplus-transparency-sth-v1\x00"


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


def _resolve_timestamp(timestamp: int | None) -> int:
    """Resolve an explicit timestamp, else ``SOURCE_DATE_EPOCH``, else wall clock.

    Reproducible builds need the log to be a pure function of its inputs, so an
    explicit value wins and ``SOURCE_DATE_EPOCH`` is honoured before the clock.
    """
    import os

    if timestamp is not None:
        return int(timestamp)
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is not None:
        try:
            return int(raw)
        except ValueError:
            return int(time.time())
    return int(time.time())


class TransparencyLog:
    """An append-only log binding attestations into a verified Merkle-backed chain."""

    def __init__(self, entries: list[LogEntry] | None = None) -> None:
        self.entries: list[LogEntry] = list(entries or [])

    def append(
        self,
        attestation: dict,
        metadata: dict[str, Any] | None = None,
        *,
        timestamp: int | None = None,
    ) -> LogEntry:
        idx = len(self.entries)
        prev_h = self.entries[-1].entry_hash() if self.entries else "0" * 64
        att_digest = attestation.get("output_digest", "")
        tc_raw = json.dumps(attestation.get("toolchain", {}), sort_keys=True).encode("utf-8")
        tc_hash = hashlib.blake2b(tc_raw, digest_size=32).hexdigest()
        ts = _resolve_timestamp(timestamp)

        entry = LogEntry(
            index=idx,
            timestamp=ts,
            attestation_digest=att_digest,
            toolchain_hash=tc_hash,
            prev_hash=prev_h,
            metadata=dict(metadata or {}),
        )
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """Verify hash-chain *self-consistency* from root to tip.

        Necessary, not sufficient: see the module docstring. A wholly rewritten log
        passes this check, and so does a log whose tip entry was edited in place.
        Authenticity requires :meth:`verify_signed_tree_head`.
        """
        for i, entry in enumerate(self.entries):
            if entry.index != i:
                return False
            expected_prev = self.entries[i - 1].entry_hash() if i > 0 else "0" * 64
            if entry.prev_hash != expected_prev:
                return False
        return True

    # -- signed tree head (the trust anchor) --------------------------------
    def _sth_body(self, timestamp: int) -> bytes:
        """Canonical, domain-separated bytes an STH signature commits to."""
        return STH_DOMAIN + json.dumps(
            {
                "log_size": len(self.entries),
                "root_hash": self.merkle_tree_root(),
                "timestamp": int(timestamp),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def signed_tree_head(
        self, private_key: bytes, *, timestamp: int | None = None
    ) -> dict[str, Any]:
        """Sign the current tip, binding log length *and* Merkle root.

        Binding ``log_size`` alongside ``root_hash`` is what stops a truncation
        replay: an old STH cannot be presented as a description of a longer log,
        because the size it commits to would not match.
        """
        ts = _resolve_timestamp(timestamp)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pub = Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
        return {
            "log_size": len(self.entries),
            "root_hash": self.merkle_tree_root(),
            "timestamp": ts,
            "public_key": pub.hex(),
            "signature": crypto.sign(self._sth_body(ts), private_key).hex(),
        }

    def verify_signed_tree_head(
        self, sth: dict, *, expected_public_key: bytes | None = None
    ) -> bool:
        """True only when ``sth`` authentically describes *this* log.

        Fails closed on every step: a malformed STH, a signature that does not
        verify, a signer other than the pinned ``expected_public_key``, or a
        size/root that disagrees with the log in hand all return ``False``.
        """
        try:
            claimed_pub = bytes.fromhex(sth["public_key"])
            signature = bytes.fromhex(sth["signature"])
            log_size = int(sth["log_size"])
            root_hash = str(sth["root_hash"])
            timestamp = int(sth["timestamp"])
        except (KeyError, TypeError, ValueError):
            return False

        if expected_public_key is not None and claimed_pub != expected_public_key:
            return False
        # The STH must describe the log we actually hold, not merely be well-formed.
        if log_size != len(self.entries) or root_hash != self.merkle_tree_root():
            return False
        body = STH_DOMAIN + json.dumps(
            {"log_size": log_size, "root_hash": root_hash, "timestamp": timestamp},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return crypto.verify(body, signature, claimed_pub)

    def merkle_tree_root(self) -> str:
        """Compute the Merkle root over all log entry hashes."""
        leaves = [(f"entry_{e.index:06d}", e.entry_hash()) for e in self.entries]
        return merkle_root(leaves)

    def inclusion_proof(self, index: int) -> dict:
        leaves = [(f"entry_{e.index:06d}", e.entry_hash()) for e in self.entries]
        slot = f"entry_{index:06d}"
        return inclusion_proof(leaves, slot)

    # -- append-only consistency -------------------------------------------
    def consistency_proof(self, old_size: int | None = None) -> dict:
        """Evidence that this log *extends* a log of ``old_size`` rather than replacing it.

        A signed tree head proves a log is authentic at one moment. It cannot show
        that yesterday's log and today's are the same log: an operator who drops or
        rewrites an entry and re-signs produces a perfectly valid newer head. Without
        a consistency check, "append-only" is a promise rather than a property.

        The proof here is the prefix's entry hashes, which a verifier recomputes the
        old root from and then confirms every retained entry still occupies the same
        index with the same content. That is O(n) rather than the O(log n) a Merkle
        consistency proof achieves; it is chosen because the log's own hash chain
        already makes the prefix relationship explicit, and an honest linear proof is
        worth more than a subtle logarithmic one nobody audits.
        """
        size = len(self.entries) if old_size is None else old_size
        if not 0 <= size <= len(self.entries):
            raise ValueError(f"old_size {size} outside 0..{len(self.entries)}")
        prefix = self.entries[:size]
        # The proof describes the state being *committed to*, and is handed to a
        # later, longer log. It must therefore say nothing about the future size.
        return {
            "old_size": size,
            "old_root": merkle_root([(f"entry_{e.index:06d}", e.entry_hash()) for e in prefix]),
            "prefix_hashes": [e.entry_hash() for e in prefix],
        }

    def verify_consistency(self, proof: dict) -> bool:
        """True when ``proof`` shows this log is an append-only extension of the older one.

        Fails closed: a shrunk log, a changed entry, a reordered index, or a root that
        does not recompute all return ``False``.
        """
        try:
            old_size = int(proof["old_size"])
            old_root = str(proof["old_root"])
            prefix_hashes = list(proof["prefix_hashes"])
        except (KeyError, TypeError, ValueError):
            return False

        # An append-only log may only grow. A shorter log is a truncation, which is
        # exactly the event this check exists to catch.
        if old_size > len(self.entries) or len(prefix_hashes) != old_size:
            return False
        # Every retained entry must still sit at the same index with the same content.
        for index, expected in enumerate(prefix_hashes):
            if self.entries[index].entry_hash() != expected:
                return False
        recomputed = merkle_root(
            [(f"entry_{i:06d}", h) for i, h in enumerate(prefix_hashes)]
        )
        return recomputed == old_root and self.verify_chain()

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
        # `to_dict` publishes a `hash` field that downstream consumers may index on,
        # and nothing in the chain references the *tip*'s hash. Recomputing from the
        # body alone would silently bless a log whose published hashes disagree with
        # their own contents, so check any that are present.
        for d, entry in zip(raw, log.entries):
            if "hash" in d and d["hash"] != entry.entry_hash():
                raise ValueError(
                    f"transparency log entry {entry.index} publishes a hash that does "
                    "not match its contents"
                )
        return log

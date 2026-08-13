"""Merkle provenance over the module set.

Per-module digests bind each payload individually, but not the *set*: without more,
an attacker could drop or inject a module. A Merkle root over all module leaves, in
a fixed order, binds the whole collection; storing it in the (signed) manifest means
adding, removing, or swapping any module breaks the root and therefore the
signature. This is the tamper-evident "provenance ledger" property, and it closes
the append-only-chain-tip gap: the tip (root) is sealed.

Leaves are ``blake2b(slot || 0x00 || module_digest)``; internal nodes are
``blake2b(left || right)`` with an odd node promoted (duplicated) — the standard
binary Merkle construction. Domain-separation bytes prevent second-preimage tricks
across leaf/node levels.
"""

from __future__ import annotations

import hashlib

_LEAF = b"\x00"
_NODE = b"\x01"


def _h(*parts: bytes) -> bytes:
    d = hashlib.blake2b(digest_size=32)
    for p in parts:
        d.update(p)
    return d.digest()


def leaf_hash(slot: str, module_digest: str) -> bytes:
    # module_digest is an opaque digest string; hash its bytes directly so the
    # Merkle construction does not assume a particular digest encoding.
    return _h(_LEAF, slot.encode("utf-8"), b"\x00", module_digest.encode("utf-8"))


def merkle_root(leaves: list[tuple[str, str]]) -> str:
    """Compute the Merkle root hex over ``(slot, digest)`` pairs.

    Ordering is by slot, so the root is independent of insertion order. Returns the
    empty-string sentinel for an empty module set.
    """
    if not leaves:
        return ""
    level = [leaf_hash(slot, dg) for slot, dg in sorted(leaves, key=lambda x: x[0])]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # promote the odd node
        level = [_h(_NODE, level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def verify_root(leaves: list[tuple[str, str]], root: str) -> bool:
    """True when the recomputed root matches ``root`` (both empty is vacuously ok)."""
    return merkle_root(leaves) == root


def inclusion_proof(leaves: list[tuple[str, str]], slot: str) -> dict:
    """Return a compact proof that ``slot`` is a leaf of the tree over ``leaves``.

    The proof — ``{slot, digest, siblings: [[hex, is_right], ...], root}`` — lets a
    third party confirm one module belongs to the signed set without seeing the
    other modules' digests. This is the capability that makes the Merkle root more
    than a redundant re-hash of the signed manifest.
    """
    ordered = sorted(leaves, key=lambda x: x[0])
    slots = [s for s, _ in ordered]
    if slot not in slots:
        raise KeyError(slot)
    digest = dict(ordered)[slot]
    level = [leaf_hash(s, d) for s, d in ordered]
    idx = slots.index(slot)
    siblings: list[list] = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sib = idx + 1 if idx % 2 == 0 else idx - 1
        siblings.append([level[sib].hex(), idx % 2 == 0])
        idx //= 2
        level = [_h(_NODE, level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return {"slot": slot, "digest": digest, "siblings": siblings, "root": level[0].hex()}


def verify_inclusion(proof: dict) -> bool:
    """Verify an :func:`inclusion_proof` self-consistently (leaf folds to root)."""
    cur = leaf_hash(proof["slot"], proof["digest"])
    for sib_hex, is_right in proof["siblings"]:
        sib = bytes.fromhex(sib_hex)
        cur = _h(_NODE, cur, sib) if is_right else _h(_NODE, sib, cur)
    return cur.hex() == proof["root"]

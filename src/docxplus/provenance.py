"""Merkle provenance over the module set.

Per-module digests bind each payload individually, but not the *set*: without more,
an attacker could drop or inject a module. A Merkle root over all module leaves, in
a fixed order, binds the whole collection; storing it in the (signed) manifest means
adding, removing, or swapping any module breaks the root and therefore the
signature. This is the tamper-evident "provenance ledger" property, and it closes
the append-only-chain-tip gap: the tip (root) is sealed.

Leaves are ``blake2b(0x00 || slot || 0x00 || module_digest)``; internal nodes are
``blake2b(0x01 || left || right)``. The domain-separation bytes stop a leaf being
reinterpreted as an interior node.

**Tree shape follows RFC 6962**, splitting at the largest power of two below the
node count, rather than the more common approach of duplicating a trailing odd node
to pad each level to an even width. That difference is a security property, not a
style preference. Under duplicate-promotion the tree over ``[A, B, C]`` pads to
``[A, B, C, C]`` and therefore has *the same root* as a genuine four-leaf tree whose
last two leaves are equal — the second-preimage ambiguity found in Bitcoin as
CVE-2012-2459. This implementation had it: ``merkle_root([a, b, c])`` equalled
``merkle_root([a, b, c, c])``, so the documented guarantee that adding a module
always changes the root was false in exactly that case.

Slot uniqueness alone would have prevented the collision being reachable through a
well-formed manifest, and ``Manifest.add`` does enforce it — but ``from_bytes`` did
not, and a guarantee that holds only because a *different* module happens to check
something is not a guarantee. The splitting rule removes the ambiguity from the
construction itself, so it no longer depends on any caller.
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


def _split(n: int) -> int:
    """Largest power of two strictly less than ``n`` (RFC 6962 §2.1, ``k``)."""
    return 1 << (n - 1).bit_length() - 1


def _root_of(level: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-computed leaf hashes."""
    if len(level) == 1:
        return level[0]
    k = _split(len(level))
    return _h(_NODE, _root_of(level[:k]), _root_of(level[k:]))


def _ordered(leaves: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Leaves in canonical order, with duplicate slots refused.

    Ordering by slot makes the root independent of insertion order. Rejecting a
    repeated slot keeps the tree a faithful image of a module *set*: two leaves
    under one name make ``inclusion_proof`` ambiguous about which one it proved,
    and no legitimate manifest can contain them.
    """
    seen: set[str] = set()
    for slot, _ in leaves:
        if slot in seen:
            raise ValueError(f"duplicate slot in module set: {slot}")
        seen.add(slot)
    return sorted(leaves, key=lambda x: x[0])


def merkle_root(leaves: list[tuple[str, str]]) -> str:
    """Compute the Merkle root hex over ``(slot, digest)`` pairs.

    Ordering is by slot, so the root is independent of insertion order. Returns the
    empty-string sentinel for an empty module set. Raises ``ValueError`` if a slot
    appears twice.
    """
    if not leaves:
        return ""
    return _root_of([leaf_hash(slot, dg) for slot, dg in _ordered(leaves)]).hex()


def verify_root(leaves: list[tuple[str, str]], root: str) -> bool:
    """True when the recomputed root matches ``root`` (both empty is vacuously ok)."""
    try:
        return merkle_root(leaves) == root
    except ValueError:
        return False


def _path(level: list[bytes], index: int) -> list[list]:
    """Audit path for ``index``: ``[[sibling_hex, sibling_is_right], ...]``.

    Built bottom-up, so the caller folds the leaf toward the root in list order.
    """
    if len(level) == 1:
        return []
    k = _split(len(level))
    if index < k:
        return _path(level[:k], index) + [[_root_of(level[k:]).hex(), True]]
    return _path(level[k:], index - k) + [[_root_of(level[:k]).hex(), False]]


def inclusion_proof(leaves: list[tuple[str, str]], slot: str) -> dict:
    """Return a compact proof that ``slot`` is a leaf of the tree over ``leaves``.

    The proof — ``{slot, digest, siblings: [[hex, is_right], ...], root}`` — lets a
    third party confirm one module belongs to the signed set without seeing the
    other modules' digests. This is the capability that makes the Merkle root more
    than a redundant re-hash of the signed manifest.

    The ``root`` field is a convenience for the prover's own bookkeeping, and is
    **not** evidence of anything on its own: an attacker writes it. Verification
    must supply the root it independently trusts, which is why
    :func:`verify_inclusion` requires one.
    """
    ordered = _ordered(leaves)
    slots = [s for s, _ in ordered]
    if slot not in slots:
        raise KeyError(slot)
    digest = dict(ordered)[slot]
    level = [leaf_hash(s, d) for s, d in ordered]
    index = slots.index(slot)
    return {
        "slot": slot,
        "digest": digest,
        "siblings": _path(level, index),
        "root": _root_of(level).hex(),
    }


def verify_inclusion(proof: dict, expected_root: str) -> bool:
    """Verify ``proof`` folds to ``expected_root``.

    ``expected_root`` is required rather than optional, and defaults to nothing,
    because the alternative is the shape of a real vulnerability. Folding a proof to
    the root it carries only establishes internal consistency, and an attacker who
    supplies the proof supplies that root too: they can build a tree containing any
    module they like and hand over a self-consistent proof for it. Membership is a
    claim about a *specific* set, so the root has to come from the party doing the
    verifying — the signed manifest, or a pinned signed tree head.
    """
    if not expected_root:
        return False
    try:
        current = leaf_hash(proof["slot"], proof["digest"])
        for sibling_hex, sibling_is_right in proof["siblings"]:
            sibling = bytes.fromhex(sibling_hex)
            current = (
                _h(_NODE, current, sibling)
                if sibling_is_right
                else _h(_NODE, sibling, current)
            )
    except (KeyError, TypeError, ValueError):
        return False
    return current.hex() == expected_root


__all__ = [
    "inclusion_proof",
    "leaf_hash",
    "merkle_root",
    "verify_inclusion",
    "verify_root",
]


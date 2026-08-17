"""Merkle provenance over the module set."""

from __future__ import annotations

from docxplus import provenance


def test_empty_root_is_sentinel():
    assert provenance.merkle_root([]) == ""


def test_single_leaf():
    root = provenance.merkle_root([("a", "d1")])
    assert root and len(root) == 64


def test_order_independence():
    a = provenance.merkle_root([("a", "d1"), ("b", "d2"), ("c", "d3")])
    b = provenance.merkle_root([("c", "d3"), ("a", "d1"), ("b", "d2")])
    assert a == b


def test_odd_leaf_count_handled():
    root = provenance.merkle_root([("a", "1"), ("b", "2"), ("c", "3")])
    assert len(root) == 64


def test_changing_a_digest_changes_root():
    base = provenance.merkle_root([("a", "d1"), ("b", "d2")])
    changed = provenance.merkle_root([("a", "d1"), ("b", "d2-tampered")])
    assert base != changed


def test_adding_a_module_changes_root():
    base = provenance.merkle_root([("a", "d1")])
    added = provenance.merkle_root([("a", "d1"), ("b", "d2")])
    assert base != added


def test_verify_root():
    leaves = [("a", "d1"), ("b", "d2")]
    root = provenance.merkle_root(leaves)
    assert provenance.verify_root(leaves, root)
    assert not provenance.verify_root(leaves, "deadbeef")

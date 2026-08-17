"""Regressions for the round-12 adversarial review.

Four findings, each reproduced against a running build before its fix was written,
and each pinned here. They share a shape worth naming: every one was a guarantee
that held only because some *other* component happened to check something. The
Merkle root was unambiguous only because slots were unique; slots were unique only
because the write path checked them; the visible document was protected only if the
reader ran `verify` rather than `validate`; and part names were sane only because
the traversal check happened to reject the shapes anyone had thought to try.

A guarantee delegated to a neighbour is not a guarantee, so each fix moves the check
into the component that owns the property.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from docxplus import crypto
from docxplus import provenance
from docxplus.container import DocxPlusBuilder, DocxPlusReader
from docxplus.manifest import Manifest
from docxplus.validate import validate_bytes


# -- Finding 1: Merkle second preimage (CVE-2012-2459 shape) ------------------


def test_a_duplicated_trailing_leaf_does_not_collide_with_the_shorter_tree():
    """The structural property, tested below the slot-uniqueness guard.

    Padding an odd level by duplicating its last node made the tree over three
    leaves hash identically to a four-leaf tree whose last two leaves were equal,
    so the documented promise that adding a module always changes the root was
    false in exactly that case. RFC 6962 splitting removes the ambiguity from the
    construction, which is why this asserts on leaf *hashes* rather than on slots:
    the property must not depend on any caller enforcing uniqueness.
    """
    leaves = [provenance.leaf_hash(s, d) for s, d in [("a", "d1"), ("b", "d2"), ("c", "d3")]]
    assert provenance._root_of(leaves) != provenance._root_of(leaves + [leaves[-1]])


def test_merkle_root_refuses_a_duplicate_slot():
    with pytest.raises(ValueError, match="duplicate slot"):
        provenance.merkle_root([("a", "d1"), ("b", "d2"), ("a", "d3")])


@pytest.mark.parametrize("size", range(1, 18))
def test_every_leaf_of_every_tree_size_produces_a_verifiable_proof(size):
    """Sizes 1..17 cross several power-of-two boundaries, where splitting bugs live."""
    leaves = [(f"s{i:03d}", f"d{i}") for i in range(size)]
    root = provenance.merkle_root(leaves)
    for slot, _ in leaves:
        assert provenance.verify_inclusion(provenance.inclusion_proof(leaves, slot), root)


def test_merkle_root_is_independent_of_insertion_order():
    assert provenance.merkle_root([("a", "1"), ("b", "2"), ("c", "3")]) == provenance.merkle_root(
        [("c", "3"), ("a", "1"), ("b", "2")]
    )


# -- Finding 2: inclusion proofs must bind to a root the verifier trusts ------


def test_a_forged_proof_does_not_verify_against_the_real_root():
    """The attacker supplies the proof, so they supply the root inside it.

    Folding a proof to its own `root` field establishes internal consistency and
    nothing else: an attacker builds a tree containing whatever module they like and
    hands over a perfectly self-consistent proof of its membership. Requiring the
    expected root as an argument makes that misuse unspellable.
    """
    real = [("a", "d1"), ("b", "d2"), ("c", "d3")]
    signed_root = provenance.merkle_root(real)
    forged = provenance.inclusion_proof(real + [("payload", "attacker-digest")], "payload")

    assert provenance.verify_inclusion(forged, forged["root"]), "should be self-consistent"
    assert not provenance.verify_inclusion(forged, signed_root)


def test_verification_without_a_root_is_refused_rather_than_assumed():
    leaves = [("a", "d1"), ("b", "d2")]
    proof = provenance.inclusion_proof(leaves, "a")
    assert not provenance.verify_inclusion(proof, "")
    assert not provenance.verify_inclusion(proof, None)


def test_a_malformed_proof_is_refused_rather_than_raising():
    root = provenance.merkle_root([("a", "d1"), ("b", "d2")])
    for bad in ({}, {"slot": "a"}, {"slot": "a", "digest": "d1", "siblings": [["zz", True]]}):
        assert not provenance.verify_inclusion(bad, root)


# -- Finding 3: duplicate slots on the manifest read path ---------------------


def test_manifest_from_bytes_refuses_duplicate_slots():
    """`add` guarded the write path; untrusted bytes never go through `add`.

    Two records under one name is a parser differential: `slot()` returns the first
    while a validator iterating `records` sees both, so the module a reader extracts
    need not be the module a validator checked.
    """
    builder = DocxPlusBuilder(paragraphs=["cover"], title="t")
    builder.add_module("notes", "package_part", b"benign", payload_type="bytes")
    with zipfile.ZipFile(io.BytesIO(builder.build())) as archive:
        doc = json.loads(archive.read("intelligence/manifest.json"))
    doc["modules"].append(json.loads(json.dumps(doc["modules"][0])))

    with pytest.raises(ValueError, match="duplicate manifest slot"):
        Manifest.from_bytes(json.dumps(doc).encode())


# -- Finding 4: validate must recompute the surface digest --------------------


def _signed_document():
    private_key, public_key = crypto.generate_signing_key()
    builder = DocxPlusBuilder(paragraphs=["the original visible text"], title="t")
    builder.add_module("notes", "package_part", b"benign", payload_type="bytes")
    builder.sign(private_key)
    return builder.build(), public_key


def _repack(blob: bytes, mutate) -> bytes:
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    mutate(entries)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return out.getvalue()


@pytest.mark.parametrize(
    "label,mutate",
    [
        (
            "visible text",
            lambda e: e.__setitem__(
                "word/document.xml",
                e["word/document.xml"].replace(b"the original visible text", b"a different claim"),
            ),
        ),
        (
            "content type",
            lambda e: e.__setitem__(
                "[Content_Types].xml",
                e["[Content_Types].xml"].replace(b"application/xml", b"text/plain"),
            ),
        ),
        ("added part", lambda e: e.__setitem__("word/extra.xml", b"<x/>")),
    ],
)
def test_validate_detects_tampering_the_signature_alone_does_not(label, mutate):
    """`verify` caught these; `validate` reported no findings whatsoever.

    The signature covers `surface_digest` as a *stored field*, so a package whose
    visible prose had been rewritten still had a self-consistent signature. Only
    recomputing the digest from the package in hand closes it — the same treatment
    the Merkle root already received. This matters because `validate` is the command
    a release process runs.
    """
    blob, _ = _signed_document()
    tampered = _repack(blob, mutate)
    report = validate_bytes(tampered)
    assert not report.ok, f"validator accepted a package with altered {label}"
    assert any("surface_digest" in error for error in report.intelligence_errors), (
        f"{label} was caught, but not by the surface-digest check: {report.intelligence_errors}"
    )


def test_an_untampered_signed_document_still_validates():
    """The gate has to stay closed on the honest case, or it is just noise."""
    blob, public_key = _signed_document()
    assert validate_bytes(blob).ok
    assert DocxPlusReader.from_bytes(blob).verify_provenance(expected_public_key=public_key)

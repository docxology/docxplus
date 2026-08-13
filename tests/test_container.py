"""End-to-end container: build a valid .docx carrying intelligence, read it back."""

from __future__ import annotations

import pytest

from container import ContainerError, DocxPlusBuilder, DocxPlusReader
from crypto import generate_signing_key
from validate import validate_bytes


def test_build_and_read_single_module(sample_payload):
    data = (
        DocxPlusBuilder(paragraphs=["A perfectly ordinary memo."])
        .add_module("brief", "custom_xml", sample_payload)
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.list_modules() == ["brief"]
    assert reader.extract("brief") == sample_payload


def test_surface_document_is_valid_docx(sample_payload):
    data = (
        DocxPlusBuilder(paragraphs=["Surface."])
        .add_module("brief", "package_part", sample_payload)
        .build()
    )
    report = validate_bytes(data)
    assert report.ok, report.to_dict()


def test_multiple_channels_compose(sample_payload):
    data = (
        DocxPlusBuilder(paragraphs=["x"])
        .add_module("a", "custom_xml", b"alpha")
        .add_module("b", "package_part", b"bravo")
        .add_module("c", "metadata", b"charlie")
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert set(reader.list_modules()) == {"a", "b", "c"}
    assert reader.extract("a") == b"alpha"
    assert reader.extract("b") == b"bravo"
    assert reader.extract("c") == b"charlie"


def test_encrypted_module_roundtrip(sample_payload):
    data = (
        DocxPlusBuilder(paragraphs=["x"])
        .add_module("secret", "package_part", sample_payload, password="hunter2")
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.manifest.slot("secret").encrypted is True
    assert reader.extract("secret", password="hunter2") == sample_payload


def test_encrypted_module_requires_password(sample_payload):
    data = (
        DocxPlusBuilder(paragraphs=["x"])
        .add_module("secret", "package_part", sample_payload, password="pw")
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    with pytest.raises(ContainerError, match="password"):
        reader.extract("secret")


def test_signed_manifest_verifies():
    priv, _ = generate_signing_key()
    data = (
        DocxPlusBuilder(paragraphs=["x"])
        .add_module("a", "custom_xml", b"payload")
        .sign(priv)
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.signature_status() == "valid"


def test_unsigned_reports_unsigned():
    data = DocxPlusBuilder(paragraphs=["x"]).add_module("a", "custom_xml", b"p").build()
    assert DocxPlusReader.from_bytes(data).signature_status() == "unsigned"


def test_duplicate_slot_rejected():
    b = DocxPlusBuilder(paragraphs=["x"]).add_module("a", "custom_xml", b"1")
    with pytest.raises(ContainerError, match="duplicate slot"):
        b.add_module("a", "package_part", b"2")


def test_unknown_channel_rejected():
    with pytest.raises(ContainerError, match="unknown channel"):
        DocxPlusBuilder().add_module("a", "nope", b"x")


def test_reader_requires_manifest():
    from wordml import new_base_document

    plain = new_base_document(["just a document"]).to_bytes()
    with pytest.raises(ContainerError, match="no intelligence manifest"):
        DocxPlusReader.from_bytes(plain)


def test_extract_unknown_slot():
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"p").build()
    reader = DocxPlusReader.from_bytes(data)
    with pytest.raises(ContainerError, match="no such module"):
        reader.extract("zzz")


def test_build_is_deterministic():
    def make():
        return (
            DocxPlusBuilder(paragraphs=["x"])
            .add_module("a", "custom_xml", b"payload")
            .build()
        )

    # Encryption/signature use randomness; a plain custom_xml module must be stable.
    assert make() == make()

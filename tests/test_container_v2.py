"""docxplus v0.2: typed payloads, advanced sealing, nesting, provenance."""

from __future__ import annotations

import pytest

from docxplus.container import ContainerError, DocxPlusBuilder, DocxPlusReader
from docxplus.crypto import generate_recipient_key, generate_signing_key
from docxplus.validate import validate_bytes


# -- typed payloads --------------------------------------------------------
def test_json_payload_as_object():
    obj = {"priority": 3, "tags": ["a", "b"]}
    data = DocxPlusBuilder().add_module("meta", "custom_xml", obj, payload_type="json").build()
    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("meta", as_object=True) == obj
    assert reader.describe("meta")["payload_type"] == "json"


def test_text_payload():
    data = DocxPlusBuilder().add_module("note", "package_part", "hello", payload_type="text").build()
    assert DocxPlusReader.from_bytes(data).extract("note", as_object=True) == "hello"


# -- the self-verifying dossier: a whole project inside a .docx -------------
def test_project_payload_roundtrip(tmp_path):
    proj = tmp_path / "miniproject"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "core.py").write_text("VALUE = 42\n")
    (proj / "README.md").write_text("# mini\n")

    data = (
        DocxPlusBuilder(paragraphs=["A report carrying its own source."])
        .add_project("source", proj, password="reproduce")
        .build()
    )
    assert validate_bytes(data).ok
    reader = DocxPlusReader.from_bytes(data)
    dest = tmp_path / "extracted"
    reader.extract_project("source", dest, password="reproduce")
    assert (dest / "src" / "core.py").read_text() == "VALUE = 42\n"
    assert (dest / "README.md").read_text() == "# mini\n"


# -- matryoshka: a nested docxplus inside a docxplus ------------------------------
def test_nested_document():
    inner = (
        DocxPlusBuilder(paragraphs=["Inner sealed memo."])
        .add_module("q4", "package_part", b"inner secret")
        .build()
    )
    outer = (
        DocxPlusBuilder(paragraphs=["Outer cover document."])
        .add_nested("sealed", inner, password="open-sesame")
        .build()
    )
    reader = DocxPlusReader.from_bytes(outer)
    inner_reader = reader.open_nested("sealed", password="open-sesame")
    assert inner_reader.extract("q4") == b"inner secret"


def test_open_nested_type_guard():
    data = DocxPlusBuilder().add_module("x", "package_part", b"y").build()
    with pytest.raises(ContainerError, match="not a nested document"):
        DocxPlusReader.from_bytes(data).open_nested("x")


# -- sealed referee packet: multi-recipient --------------------------------
def test_multi_recipient_module():
    priv_a, pub_a = generate_recipient_key()
    priv_b, pub_b = generate_recipient_key()
    priv_x, _ = generate_recipient_key()

    data = (
        DocxPlusBuilder()
        .add_module("manuscript", "package_part", b"draft pdf bytes", recipients=[pub_a, pub_b])
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("manuscript", private_key=priv_a) == b"draft pdf bytes"
    assert reader.extract("manuscript", private_key=priv_b) == b"draft pdf bytes"
    with pytest.raises(ContainerError):
        reader.extract("manuscript", private_key=priv_x)
    assert reader.describe("manuscript")["sealing"]["mode"] == "recipients"


# -- dead-man's envelope: k-of-n threshold ---------------------------------
def test_threshold_module():
    builder = DocxPlusBuilder().add_threshold("legacy", b"the vault combination", k=3, n=5)
    data = builder.build()
    shares = builder.threshold_shares["legacy"]
    assert len(shares) == 5

    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("legacy", shares=shares[:3]) == b"the vault combination"
    # Below quorum must not recover the secret.
    with pytest.raises(Exception):
        reader.extract("legacy", shares=shares[:2])


def test_threshold_requires_shares():
    builder = DocxPlusBuilder().add_threshold("x", b"secret", k=2, n=3)
    reader = DocxPlusReader.from_bytes(builder.build())
    with pytest.raises(ContainerError, match="threshold shares"):
        reader.extract("x")


# -- plausible deniability: decoy ------------------------------------------
def test_decoy_module():
    data = (
        DocxPlusBuilder()
        .add_decoy(
            "notes",
            real=b"the real coordinates",
            real_password="secret-a",
            decoy=b"a grocery list",
            decoy_password="secret-b",
        )
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("notes", password="secret-a") == b"the real coordinates"
    assert reader.extract("notes", password="secret-b") == b"a grocery list"
    with pytest.raises(ContainerError):
        reader.extract("notes", password="wrong")


# -- provenance ------------------------------------------------------------
def test_signed_provenance_binds_module_set():
    priv, _ = generate_signing_key()
    data = (
        DocxPlusBuilder()
        .add_module("a", "custom_xml", b"one")
        .add_module("b", "package_part", b"two")
        .sign(priv)
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.verify_provenance()
    assert len(reader.merkle_root()) == 64


def test_tampering_a_module_digest_breaks_signature():
    priv, _ = generate_signing_key()
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"one").sign(priv).build()
    from docxplus.opc import read_package

    pkg = read_package(data)
    manifest = pkg.parts["intelligence/manifest.json"].replace(b'"one"', b'"one"')
    # Flip the recorded digest; recomputed Merkle root then mismatches the signature.
    import re

    manifest = re.sub(rb'"digest": "[0-9a-f]+"', b'"digest": "00"', manifest, count=1)
    pkg.parts["intelligence/manifest.json"] = manifest
    reader = DocxPlusReader(package=pkg, manifest=__import__("docxplus.manifest", fromlist=["x"]).read_manifest(pkg))
    assert reader.verify_provenance() is False


def test_choose_one_sealing_mode():
    _, pub = generate_recipient_key()
    with pytest.raises(ContainerError, match="at most one"):
        DocxPlusBuilder().add_module("x", "package_part", b"y", password="p", recipients=[pub])


def test_container_error_branches():
    """Verify various ContainerError conditions in DocxPlusBuilder and DocxPlusReader."""
    # Unknown channel
    with pytest.raises(ContainerError, match="unknown channel"):
        DocxPlusBuilder().add_module("x", "nonexistent_channel", b"data")

    # Add decoy with unknown channel
    with pytest.raises(ContainerError, match="unknown channel"):
        DocxPlusBuilder().add_decoy("d", real=b"r", real_password="rp", decoy=b"d", decoy_password="dp", channel_id="invalid")

    # Add decoy with duplicate slot
    b = DocxPlusBuilder().add_module("dup", "package_part", b"data")
    with pytest.raises(ContainerError, match="duplicate slot"):
        b.add_decoy("dup", real=b"r", real_password="rp", decoy=b"d", decoy_password="dp")

    # Missing intelligence manifest on read
    from docxplus.wordml import new_base_document
    plain_docx = new_base_document(["plain"]).to_bytes()
    with pytest.raises(ContainerError, match="no intelligence manifest"):
        DocxPlusReader.from_bytes(plain_docx)

    # Missing credentials on unseal
    b = DocxPlusBuilder()
    priv, pub = generate_recipient_key()
    b.add_module("recip", "package_part", b"secret", recipients=[pub])
    b.add_module("pass", "package_part", b"secret", password="pw")
    reader = DocxPlusReader.from_bytes(b.build())

    with pytest.raises(ContainerError, match="needs a password"):
        reader.extract("pass")
    with pytest.raises(ContainerError, match="needs a recipient private key"):
        reader.extract("recip")


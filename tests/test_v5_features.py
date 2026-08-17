"""v0.5: detached co-signatures, hardened intake, redundant media carriers."""

from __future__ import annotations

import pytest

from container import DocxPlusBuilder, DocxPlusReader
from crypto import generate_signing_key
from opc import OpcPackage, Relationship, read_package
from wordml import CT_DOCUMENT, new_base_document


# -- detached co-signatures ------------------------------------------------
def test_cosignatures_author_and_institution():
    author_priv, author_pub = generate_signing_key()
    inst_priv, inst_pub = generate_signing_key()
    stranger_priv, stranger_pub = generate_signing_key()

    data = (
        DocxPlusBuilder(paragraphs=["Jointly attested."])
        .add_module("claim", "custom_xml", b"result")
        .sign(author_priv)
        .add_cosigner(inst_priv)
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert inst_pub.hex() in reader.cosigners()
    # Author (primary) + institution (co-signer) policy holds.
    assert reader.verify_cosigners([author_pub, inst_pub]) is True
    # A stranger who never signed fails the policy.
    assert reader.verify_cosigners([author_pub, stranger_pub]) is False


def test_cosignatures_bind_the_visible_document():
    """RedTeam v0.5: editing the visible paragraphs must invalidate co-signers, even
    though the manifest bytes are untouched."""
    author_priv, author_pub = generate_signing_key()
    inst_priv, inst_pub = generate_signing_key()
    data = (
        DocxPlusBuilder(paragraphs=["Approved budget: $1,000,000"])
        .add_module("m", "custom_xml", b"x")
        .sign(author_priv)
        .add_cosigner(inst_priv)
        .build()
    )
    pkg = read_package(data)
    manifest_before = pkg.parts["intelligence/manifest.json"]
    pkg.parts["word/document.xml"] = pkg.parts["word/document.xml"].replace(
        b"1,000,000", b"10,000,000"
    )
    assert pkg.parts["intelligence/manifest.json"] == manifest_before  # manifest untouched
    reader = DocxPlusReader(package=pkg, manifest=__import__("manifest").read_manifest(pkg))
    # The institution must NOT be shown as vouching for text it never signed.
    assert reader.cosigners() == []
    assert reader.verify_cosigners([author_pub, inst_pub]) is False


def test_verify_cosigners_rejects_empty_policy():
    a_priv, _ = generate_signing_key()
    data = DocxPlusBuilder().add_module("m", "custom_xml", b"x").sign(a_priv).build()
    reader = DocxPlusReader.from_bytes(data)
    with pytest.raises(Exception, match="at least one expected key"):
        reader.verify_cosigners([])


def test_cosignature_survives_manifest_roundtrip():
    a_priv, _ = generate_signing_key()
    b_priv, b_pub = generate_signing_key()
    data = DocxPlusBuilder().add_module("m", "custom_xml", b"x").sign(a_priv).add_cosigner(b_priv).build()
    reader = DocxPlusReader.from_bytes(data)
    assert reader.manifest.verify_cosignatures()[b_pub.hex()] is True


def test_tampered_cosignature_rejected():
    a_priv, _ = generate_signing_key()
    b_priv, b_pub = generate_signing_key()
    data = DocxPlusBuilder().add_module("m", "custom_xml", b"x").sign(a_priv).add_cosigner(b_priv).build()
    pkg = read_package(data)
    blob = pkg.parts["intelligence/manifest.json"].replace(b_pub.hex().encode(), b_pub.hex().encode())
    import re

    blob = re.sub(rb'"value": "[0-9a-f]{128}"', b'"value": "' + b"0" * 128 + b'"', blob)
    pkg.parts["intelligence/manifest.json"] = blob
    reader = DocxPlusReader(package=pkg, manifest=__import__("manifest").read_manifest(pkg))
    assert all(not ok for ok in reader.manifest.verify_cosignatures().values())


# -- hardened intake -------------------------------------------------------
def test_intake_clean_document():
    import intake

    data = DocxPlusBuilder().add_module("a", "custom_xml", b"x").build()
    report, reader = intake.safe_open(data)
    assert report.ok
    assert reader is not None and reader.list_modules() == ["a"]


def test_intake_flags_external_relationship():
    import intake

    pkg = new_base_document(["surface"])
    pkg.add_relationship(
        Relationship("rIdX", "urn:ext", "https://evil.example/x", mode="External"),
        source_part="",
    )
    report = intake.scan(pkg)
    assert not report.ok
    assert any("evil.example" in e for e in report.external_relationships)


def test_intake_flags_macro_part():
    import intake

    pkg = new_base_document(["surface"])
    pkg.set_default_type("bin", "application/vnd.ms-office.vbaProject")
    pkg.add_part("word/vbaProject.bin", b"\x00macro", "application/vnd.ms-office.vbaProject")
    report = intake.scan(pkg)
    assert "word/vbaProject.bin" in report.macro_parts
    assert not report.ok


_NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _doc_with_altchunk(part_name="word/document.xml"):
    pkg = OpcPackage()
    pkg.set_default_type("xml", "application/xml")
    pkg.set_default_type("rels", "application/xml")
    body = f'<w:document xmlns:w="{_NS_W}"><w:body><w:altChunk/></w:body></w:document>'.encode()
    pkg.add_part(part_name, body, CT_DOCUMENT)
    pkg.add_relationship(Relationship("rId1", "urn:doc", part_name), source_part="")
    return pkg


def test_intake_flags_altchunk_import():
    import intake

    report = intake.scan(_doc_with_altchunk())
    assert "word/document.xml" in report.altchunk_imports


def test_intake_altchunk_not_evadable_by_non_xml_part_name():
    """A main document part named .dat (typed as WordprocessingML) must still be
    caught — detection is by content type + parsing, not filename extension."""
    import intake

    report = intake.scan(_doc_with_altchunk("word/document.dat"))
    assert "word/document.dat" in report.altchunk_imports


def test_intake_altchunk_no_false_positive_on_prose():
    """Benign text mentioning altChunk must not be flagged (parse, not substring)."""
    import intake

    pkg = OpcPackage()
    pkg.set_default_type("xml", "application/xml")
    pkg.set_default_type("rels", "application/xml")
    body = f'<w:document xmlns:w="{_NS_W}"><w:body><w:p><w:r><w:t>This paper documents the altChunk element.</w:t></w:r></w:p></w:body></w:document>'.encode()
    pkg.add_part("word/document.xml", body, CT_DOCUMENT)
    pkg.add_relationship(Relationship("rId1", "urn:doc", "word/document.xml"), source_part="")
    report = intake.scan(pkg)
    assert report.altchunk_imports == []


def test_intake_macro_detection_is_case_insensitive():
    import intake

    pkg = new_base_document(["x"])
    pkg.set_default_type("bin", "application/octet-stream")
    pkg.add_part("word/vbaproject.bin", b"\x00", "application/octet-stream")  # lowercase
    report = intake.scan(pkg)
    assert "word/vbaproject.bin" in report.macro_parts


def test_intake_strict_raises():
    import intake

    pkg = new_base_document(["x"])
    pkg.add_relationship(
        Relationship("rIdX", "urn:ext", "http://x", mode="External"), source_part=""
    )
    data = pkg.to_bytes()
    with pytest.raises(intake.IntakeError):
        intake.safe_open(data, policy=intake.IntakePolicy(strict=True))


def test_intake_policy_can_allow():
    import intake

    pkg = new_base_document(["x"])
    pkg.add_relationship(
        Relationship("rIdX", "urn:ext", "http://x", mode="External"), source_part=""
    )
    report = intake.scan(pkg, intake.IntakePolicy(allow_external_relationships=True))
    assert report.ok


# -- OPC intake caps (RedTeam v0.5) ----------------------------------------
def test_opc_rejects_too_many_entries():
    import io
    import zipfile

    import opc

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        for i in range(opc.MAX_ENTRIES + 2):
            zf.writestr(f"p{i}.dat", b"")
    with pytest.raises(opc.OpcError, match="too many entries"):
        opc.read_package(buf.getvalue())


def _package_with(*entries: tuple[str, bytes]) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def test_opc_rejects_a_noncanonical_entry_name_outright():
    """Refused on its own, without needing a colliding partner to give it away.

    ``word//document.xml`` denotes ``word/document.xml``, so a reader that
    normalises it silently operates on a part whose name no other consumer agrees
    with. Refusing only the *pair* left the single smuggled entry admissible.
    """
    import opc

    with pytest.raises(opc.OpcError, match="non-canonical entry name"):
        opc.read_package(_package_with(("word//document.xml", b"smuggled")))


@pytest.mark.parametrize(
    "name",
    [
        "/word/document.xml",       # absolute
        "//srv/share/document.xml",  # UNC-shaped
        "C:/word/document.xml",      # drive-qualified
        "word/./document.xml",       # normalises away
        "a/../word/document.xml",    # traversal that resolves inside
        "word\\document.xml",        # backslash separator
        "word/doc\tument.xml",       # control character
    ],
)
def test_opc_refuses_every_shape_of_noncanonical_name(name):
    """One rule — canonical form or refusal — rather than a list of bad prefixes.

    An earlier check named ``..`` and left the absolute, UNC, drive-letter and
    control-character forms admissible, each silently rewritten into some other
    part name on the way in.
    """
    import opc

    with pytest.raises(opc.OpcError):
        opc.read_package(_package_with((name, b"x")))


def test_opc_still_rejects_a_case_folding_collision():
    """Two individually canonical names that collapse to one part.

    Canonical-form checking cannot catch this pair — both names are already
    canonical — so the collision check remains load-bearing and is exercised here.
    """
    import opc

    with pytest.raises(opc.OpcError, match="colliding part names"):
        opc.read_package(
            _package_with(("word/document.xml", b"FIRST"), ("word/Document.xml", b"SECOND"))
        )


# -- redundant media carrier -----------------------------------------------
def test_redundant_media_survives_losing_carriers():
    pytest.importorskip("PIL")
    data = (
        DocxPlusBuilder(paragraphs=["Doc with 3 figures."])
        .add_module("fig", "stego_media", b"resilient payload", backend="python_lsb",
                    redundancy=3, carrier_size=(96, 96))
        .build()
    )
    pkg = read_package(data)
    record = __import__("manifest").read_manifest(pkg).slot("fig")
    parts = record.location["parts"]
    assert len(parts) == 3

    # Destroy two of the three carriers; the payload must still recover.
    for p in parts[:2]:
        del pkg.parts[p]
    reader = DocxPlusReader(package=pkg, manifest=__import__("manifest").read_manifest(pkg))
    assert reader.extract("fig") == b"resilient payload"


def test_redundant_media_skips_corrupted_replica(tmp_path):
    """A replica that still decodes but to the wrong bytes must be skipped in favour
    of an intact one — never returned silently."""
    pytest.importorskip("PIL")
    import lsb

    data = DocxPlusBuilder().add_module(
        "fig", "stego_media", b"the true payload", redundancy=2, carrier_size=(96, 96)
    ).build()
    pkg = read_package(data)
    record = __import__("manifest").read_manifest(pkg).slot("fig")
    parts = record.location["parts"]
    # Overwrite the FIRST replica with a carrier holding different (decodable) bytes.
    carrier = lsb.make_carrier(tmp_path / "c.png", (96, 96))
    bad = lsb.embed(carrier, b"attacker-swapped bytes", tmp_path / "bad.png")
    pkg.parts[parts[0]] = bad.read_bytes()
    reader = DocxPlusReader(package=pkg, manifest=__import__("manifest").read_manifest(pkg))
    assert reader.extract("fig") == b"the true payload"  # recovered from the intact replica


def test_redundant_media_all_lost_fails():
    pytest.importorskip("PIL")
    data = DocxPlusBuilder().add_module(
        "fig", "stego_media", b"x", redundancy=2, carrier_size=(64, 64)
    ).build()
    pkg = read_package(data)
    record = __import__("manifest").read_manifest(pkg).slot("fig")
    for p in record.location["parts"]:
        del pkg.parts[p]
    reader = DocxPlusReader(package=pkg, manifest=__import__("manifest").read_manifest(pkg))
    with pytest.raises(Exception, match="no surviving"):
        reader.extract("fig")

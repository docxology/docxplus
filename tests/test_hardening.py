"""RedTeam regression suite — each test pins a fixed defect so it cannot return."""

from __future__ import annotations

import json

import pytest

from docxplus import crypto
from docxplus.container import ContainerError, DocxPlusBuilder, DocxPlusReader
from docxplus.crypto import generate_recipient_key, generate_signing_key
from docxplus.opc import read_package
from docxplus.provenance import verify_inclusion


# -- deniability: the manifest must not advertise a decoy ------------------
def test_decoy_is_indistinguishable_from_password_module():
    decoy_doc = (
        DocxPlusBuilder()
        .add_decoy("notes", real=b"real", real_password="a", decoy=b"cover", decoy_password="b")
        .build()
    )
    plain_pw_doc = DocxPlusBuilder().add_module("notes", "package_part", b"x", password="a").build()

    d_rec = DocxPlusReader.from_bytes(decoy_doc).describe("notes")
    p_rec = DocxPlusReader.from_bytes(plain_pw_doc).describe("notes")
    # Same sealing shape and same manifest keys — no "decoy" tell anywhere.
    assert d_rec["sealing"] == {"mode": "password"}
    assert p_rec["sealing"] == {"mode": "password"}
    assert set(d_rec) == set(p_rec)
    assert b"decoy" not in read_package(decoy_doc).parts["intelligence/manifest.json"].lower()


def test_password_and_decoy_have_the_same_frame_count():
    """A password module and a decoy module must both carry two envelope frames,
    so frame-counting cannot distinguish 'has a hidden payload' from 'does not'."""
    from docxplus.container import _iter_frames

    pw_doc = DocxPlusBuilder().add_module("s", "package_part", b"only", password="a").build()
    decoy_doc = (
        DocxPlusBuilder()
        .add_decoy("s", real=b"real", real_password="a", decoy=b"cover", decoy_password="b")
        .build()
    )
    pw_reader = DocxPlusReader.from_bytes(pw_doc)
    decoy_reader = DocxPlusReader.from_bytes(decoy_doc)
    from docxplus import channels as reg

    pw_bytes = reg.get_channel("package_part").extract(pw_reader.package, pw_reader.manifest.slot("s"))
    decoy_bytes = reg.get_channel("package_part").extract(decoy_reader.package, decoy_reader.manifest.slot("s"))
    assert len(list(_iter_frames(pw_bytes))) == len(list(_iter_frames(decoy_bytes))) == 2


def test_decoy_still_opens_both_ways():
    data = (
        DocxPlusBuilder()
        .add_decoy("notes", real=b"real", real_password="a", decoy=b"cover", decoy_password="b")
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("notes", password="a") == b"real"
    assert reader.extract("notes", password="b") == b"cover"


# -- privacy: recipient identities must not leak ---------------------------
def test_recipient_public_keys_not_in_manifest():
    _, pub_a = generate_recipient_key()
    _, pub_b = generate_recipient_key()
    data = (
        DocxPlusBuilder()
        .add_module("m", "package_part", b"draft", recipients=[pub_a, pub_b])
        .build()
    )
    manifest = read_package(data).parts["intelligence/manifest.json"]
    assert pub_a.hex().encode() not in manifest
    assert pub_b.hex().encode() not in manifest
    sealing = DocxPlusReader.from_bytes(data).describe("m")["sealing"]
    # Neither identities nor count — the manifest reveals nothing about who/how many.
    assert sealing == {"mode": "recipients"}


# -- AAD context binding ---------------------------------------------------
def test_aad_binds_ciphertext_to_context():
    env = crypto.encrypt(b"secret", "pw", aad=b"slot-a")
    assert crypto.decrypt(env, "pw", aad=b"slot-a") == b"secret"
    with pytest.raises(Exception):
        crypto.decrypt(env, "pw", aad=b"slot-b")  # wrong context fails the tag


# -- uniform digest: tampering an ENCRYPTED module's bytes is caught -------
def test_tampered_encrypted_bytes_detected_without_key():
    data = DocxPlusBuilder().add_module("s", "package_part", b"secret", password="pw").build()
    pkg = read_package(data)
    part = next(p for p in pkg.parts if p.startswith("intelligence/payload"))
    pkg.parts[part] = pkg.parts[part][:-1] + bytes([pkg.parts[part][-1] ^ 0xFF])
    reader = DocxPlusReader(package=pkg, manifest=__import__("docxplus.manifest", fromlist=["x"]).read_manifest(pkg))
    with pytest.raises(ContainerError, match="stored bytes altered"):
        reader.extract("s", password="pw")


# -- surface binding: the signature covers the visible text ----------------
def test_signature_binds_visible_document_text():
    priv, _ = generate_signing_key()
    data = DocxPlusBuilder(paragraphs=["Genuine text."]).add_module(
        "a", "custom_xml", b"p"
    ).sign(priv).build()
    pkg = read_package(data)
    # Manifest signature is untouched, but the visible paragraph is rewritten.
    pkg.parts["word/document.xml"] = pkg.parts["word/document.xml"].replace(
        b"Genuine text.", b"Forged text!!"
    )
    reader = DocxPlusReader(package=pkg, manifest=__import__("docxplus.manifest", fromlist=["x"]).read_manifest(pkg))
    assert reader.manifest.verify_signature() is True  # manifest itself intact
    assert reader.verify_provenance() is False  # but the surface no longer matches


# -- KDF: memory-hard scrypt is the default --------------------------------
def test_default_kdf_is_scrypt():
    env = crypto.encrypt(b"x", "pw")
    assert crypto.EncryptedPayload.from_bytes(env).kdf_id == crypto.KDF_SCRYPT


def test_pbkdf2_mode_available():
    env = crypto.encrypt(b"x", "pw", kdf="pbkdf2")
    assert crypto.EncryptedPayload.from_bytes(env).kdf_id == crypto.KDF_PBKDF2
    assert crypto.decrypt(env, "pw") == b"x"


# -- Merkle inclusion proofs -----------------------------------------------
def test_inclusion_proof_verifies_and_rejects_tamper():
    data = (
        DocxPlusBuilder()
        .add_module("a", "custom_xml", b"one")
        .add_module("b", "package_part", b"two")
        .add_module("c", "metadata", b"three")
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    proof = reader.inclusion_proof("b")
    assert verify_inclusion(proof, reader.merkle_root())
    proof["digest"] = "deadbeef"
    assert not verify_inclusion(proof, reader.merkle_root())


# -- resource safety -------------------------------------------------------
def test_project_decompression_bomb_capped(tmp_path):
    from docxplus import payloads

    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "big.bin").write_bytes(b"\x00" * 2_000_000)
    blob = payloads.pack_project(proj)
    with pytest.raises(ValueError, match="decompression cap"):
        payloads.unpack_project(blob, tmp_path / "out", max_uncompressed=1_000_000)


def test_project_rejects_symlink_member(tmp_path):
    import io
    import tarfile

    from docxplus import payloads

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        info = tarfile.TarInfo("evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(ValueError, match="only plain files and directories"):
        payloads.unpack_project(raw.getvalue(), tmp_path / "dest")


def test_unsigned_document_warns():
    from docxplus.validate import validate_bytes

    data = DocxPlusBuilder().add_module("a", "custom_xml", b"x").build()
    report = validate_bytes(data)
    assert report.ok
    assert any("unsigned" in n for n in report.notes)


def test_signed_document_no_unsigned_warning():
    priv, _ = generate_signing_key()
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"x").sign(priv).build()
    from docxplus.validate import validate_bytes

    report = validate_bytes(data)
    assert not any("unsigned" in n for n in report.notes)
    assert json.loads(read_package(data).parts["intelligence/manifest.json"])["surface_digest"]


# -- trust anchor: a forged signature must not read as "authentic" ---------
def test_forged_signature_is_not_authentic_without_pinned_key():
    author_priv, author_pub = generate_signing_key()
    attacker_priv, attacker_pub = generate_signing_key()

    # An attacker fabricates a whole document and signs it with THEIR OWN key.
    forged = (
        DocxPlusBuilder(paragraphs=["Fabricated results by attacker."])
        .add_module("claim", "custom_xml", b"fake")
        .sign(attacker_priv)
        .build()
    )
    reader = DocxPlusReader.from_bytes(forged)

    # Without a pinned key it is only self-consistent — the signer is the forger.
    assert reader.signature_status() == "valid"          # internal consistency only
    assert reader.signer() == attacker_pub.hex()
    # Pinned to the real author's key, the forgery is rejected.
    assert reader.signature_status(expected_public_key=author_pub) == "untrusted-signer"
    assert reader.verify_provenance(expected_public_key=author_pub) is False
    # The attacker's own key of course matches itself (that is the point of pinning).
    assert reader.verify_provenance(expected_public_key=attacker_pub) is True


def test_verify_reproduction_marks_unsigned_attestation_unverified(tmp_path):
    import json as _json

    from docxplus import reproduce
    (tmp_path / "p" / "src").mkdir(parents=True)
    (tmp_path / "p" / "src" / "c.py").write_text(
        "import json,os;os.makedirs('output',exist_ok=True);json.dump({'x':1},open('output/r.json','w'))\n"
    )
    (tmp_path / "p" / reproduce.RECIPE_FILE).write_text(
        _json.dumps({"command": [__import__("sys").executable, "src/c.py"], "outputs": ["output/r.json"]})
    )
    data = DocxPlusBuilder().add_project("s", tmp_path / "p", reproduce=True).build()  # unsigned
    info = DocxPlusReader.from_bytes(data).verify_reproduction("s")
    assert info["attested"] and not info["signed"] and not info["verified"]
    # The digest/command are surfaced under the UNVERIFIED key, not as a bound claim.
    assert "unverified_attestation" in info and "attestation" not in info


# -- OPC zip-bomb intake caps ----------------------------------------------
def test_opc_zip_bomb_guard_rejects_high_ratio():
    import zipfile

    from docxplus import opc

    info = zipfile.ZipInfo("word/document.xml")
    info.file_size = 500_000_000
    info.compress_size = 1000  # 500000:1 inflate ratio
    with pytest.raises(opc.OpcError, match="inflate ratio|too large"):
        opc._guard_zip_bomb([info], compressed_len=2000)


def test_opc_zip_bomb_guard_rejects_total():
    import zipfile

    from docxplus import opc

    infos = []
    for i in range(6):
        z = zipfile.ZipInfo(f"p{i}.bin")
        z.file_size = 200 * 1024 * 1024
        z.compress_size = 200 * 1024 * 1024
        infos.append(z)
    with pytest.raises(opc.OpcError, match="total-size cap"):
        opc._guard_zip_bomb(infos, compressed_len=10)


# -- KDF work-factor DoS cap -----------------------------------------------
def test_hostile_scrypt_workfactor_rejected():
    env = crypto.EncryptedPayload(
        kdf_id=crypto.KDF_SCRYPT, salt=b"s" * 16, nonce=b"n" * 12,
        params=bytes([30, 8, 1]), ciphertext=b"whatever",
    ).to_bytes()
    with pytest.raises(ValueError, match="scrypt parameters outside"):
        crypto.decrypt(env, "pw")


def test_hostile_pbkdf2_iterations_rejected():
    env = crypto.EncryptedPayload(
        kdf_id=crypto.KDF_PBKDF2, salt=b"s" * 16, nonce=b"n" * 12,
        params=(999_000_000).to_bytes(4, "big"), ciphertext=b"x",
    ).to_bytes()
    with pytest.raises(ValueError, match="iteration count outside"):
        crypto.decrypt(env, "pw")


# -- root-anchored reachability: an orphan chain must not pass --------------
def test_orphan_relationship_chain_is_unreachable():
    from docxplus.opc import OpcPackage, Relationship
    from docxplus.validate import validate_package
    from docxplus.wordml import CT_DOCUMENT

    pkg = OpcPackage()
    pkg.set_default_type("xml", "application/xml")
    pkg.set_default_type("rels", "application/xml")
    pkg.add_part("word/document.xml", b"<w:document/>", CT_DOCUMENT)
    pkg.add_relationship(Relationship("rId1", "urn:doc", "word/document.xml"), source_part="")
    # Two parts that only reference each other — reachable from neither root nor doc.
    pkg.add_part("orphanA.xml", b"<a/>", "application/xml")
    pkg.add_part("orphanB.xml", b"<b/>", "application/xml")
    pkg.add_relationship(Relationship("rId1", "urn:x", "../orphanB.xml"), source_part="orphanA.xml")
    pkg.add_relationship(Relationship("rId1", "urn:x", "../orphanA.xml"), source_part="orphanB.xml")
    report = validate_package(pkg)
    assert not report.ok
    assert any("reachable" in e for e in report.opc_errors)


# -- nested depth cap ------------------------------------------------------
def test_nested_depth_cap_enforced():
    inner = DocxPlusBuilder().add_module("x", "package_part", b"y").build()
    data = DocxPlusBuilder().add_nested("n", inner).build()
    reader = DocxPlusReader.from_bytes(data)
    reader._nest_depth = reader.MAX_NEST_DEPTH  # simulate a deep chain
    with pytest.raises(ContainerError, match="depth cap"):
        reader.open_nested("n")


# -- stored merkle_root is live --------------------------------------------
def test_tampered_stored_merkle_root_detected():
    from docxplus.validate import validate_bytes

    data = DocxPlusBuilder().add_module("a", "custom_xml", b"one").build()
    pkg = read_package(data)
    raw = pkg.parts["intelligence/manifest.json"]
    doc = json.loads(raw)
    doc["merkle_root"] = "0" * 64
    pkg.parts["intelligence/manifest.json"] = json.dumps(doc, indent=2, sort_keys=True).encode()
    report = validate_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("merkle_root" in e for e in report.intelligence_errors)


# -- Surface digest binds headers, footers, footnotes, endnotes, comments --
def test_surface_digest_binds_headers_and_footers():
    priv, _ = generate_signing_key()
    b = DocxPlusBuilder(paragraphs=["Main body text."]).sign(priv)
    # Manually add a header part to base_package
    pkg = b.base_package or __import__("docxplus.wordml", fromlist=["x"]).new_base_document(b.paragraphs, title=b.title, creator=b.creator)
    pkg.add_part("word/header1.xml", b"<w:hdr><w:p><w:r><w:t>Confidential Disclaimer</w:t></w:r></w:p></w:hdr>", "application/xml")
    b.base_package = pkg
    data = b.add_module("m1", "custom_xml", b"payload").build()

    reader = DocxPlusReader.from_bytes(data)
    assert reader.verify_provenance() is True

    # Tampering with header invalidates provenance
    pkg_tampered = read_package(data)
    pkg_tampered.parts["word/header1.xml"] = b"<w:hdr><w:p><w:r><w:t>Forged Disclaimer</w:t></w:r></w:p></w:hdr>"
    reader_tampered = DocxPlusReader(package=pkg_tampered, manifest=__import__("docxplus.manifest", fromlist=["x"]).read_manifest(pkg_tampered))
    assert reader_tampered.verify_provenance() is False


# -- ODT zip bomb defense --
def test_odt_zip_bomb_guard_rejects_high_ratio():
    import io
    import zipfile
    from docxplus.odt import OdtPackage
    from docxplus import opc

    large_zeros = b"\x00" * (5 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("content.xml", large_zeros)

    with pytest.raises(opc.OpcError, match="inflate ratio|too large"):
        OdtPackage.from_bytes(buf.getvalue())


# -- TransparencyLog deterministic timestamp and SOURCE_DATE_EPOCH --
def test_transparency_log_source_date_epoch_and_explicit_timestamp(monkeypatch):
    from docxplus.transparency import TransparencyLog

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    log1 = TransparencyLog()
    e1 = log1.append({"output_digest": "d1", "toolchain": {}})
    assert e1.timestamp == 1700000000

    log2 = TransparencyLog()
    e2 = log2.append({"output_digest": "d1", "toolchain": {}}, timestamp=1234567890)
    assert e2.timestamp == 1234567890


# -- Reproduce scrubbed env includes python and temp isolation --
def test_reproduce_scrubbed_env_isolation():
    from docxplus.reproduce import _scrubbed_env
    env = _scrubbed_env()
    assert env["PYTHONPATH"] == ""
    assert env["PYTHONHOME"] == ""
    assert env["TMPDIR"] == "/tmp"
    assert env["LD_PRELOAD"] == ""
    assert env["DYLD_INSERT_LIBRARIES"] == ""


def test_xml_attribute_values_are_escaped_and_round_trip():
    from docxplus.channels.custom_xml import CustomXmlChannel
    from docxplus.channels.metadata import MetadataChannel
    from docxplus.channels.mce import MceChannel
    from defusedxml.ElementTree import fromstring
    from docxplus.wordml import new_base_document

    slot = 'q" & < >'
    pkg = new_base_document()
    record = CustomXmlChannel().embed(pkg, b'custom', slot=slot)
    assert CustomXmlChannel().extract(pkg, record) == b'custom'
    MetadataChannel().embed(pkg, b'meta', slot=slot)
    fromstring(pkg.parts['docProps/custom.xml'])
    record = MceChannel().embed(pkg, b'mce', slot=slot)
    assert MceChannel().extract(pkg, record) == b'mce'


def test_kdf_rejects_malformed_and_excessive_scrypt_parameters():
    with pytest.raises(ValueError, match='malformed scrypt'):
        crypto._derive('pw', b's' * 16, crypto.KDF_SCRYPT, b'')
    with pytest.raises(ValueError, match='outside accepted'):
        crypto._derive('pw', b's' * 16, crypto.KDF_SCRYPT, bytes([15, 65, 1]))
    with pytest.raises(ValueError, match='malformed PBKDF2'):
        crypto._derive('pw', b's' * 16, crypto.KDF_PBKDF2, b'')


def test_truncated_multi_recipient_envelope_fails_closed():
    _, pub = generate_recipient_key()
    envelope = crypto.seal_multi(b'x', [pub])
    with pytest.raises(ValueError, match='truncated'):
        crypto.unseal_multi(envelope[:8], generate_recipient_key()[0])


# -- v0.7.0: the signature binds the part graph, not a list of filenames ------
#
# The signed surface used to be selected by name prefix. OPC decides which part a
# consumer renders through the officeDocument *relationship*, so an attacker could
# add a second document part, repoint that relationship, leave every signed byte
# untouched, and still get verify_provenance(pinned_key) == True.


def _signed_docx():
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder

    priv, pub = crypto.generate_signing_key()
    builder = DocxPlusBuilder(paragraphs=["Alice agrees to pay Bob 100 USD."])
    builder.add_module("data", "package_part", b"payload").sign(priv)
    return builder.build(), pub


def _reverifies(mutate) -> bool:
    from docxplus.container import DocxPlusReader
    from docxplus.opc import read_package

    signed, pub = _signed_docx()
    pkg = read_package(signed)
    mutate(pkg)
    return DocxPlusReader.from_bytes(pkg.to_bytes()).verify_provenance(expected_public_key=pub)


def test_honest_document_still_verifies():
    from docxplus.container import DocxPlusReader

    signed, pub = _signed_docx()
    assert DocxPlusReader.from_bytes(signed).verify_provenance(expected_public_key=pub) is True


def test_document_swap_via_relationship_is_caught():
    """The forgery that motivated the fix: repoint the main story, touch no signed byte."""
    from docxplus import wordml
    from docxplus.opc import Relationship

    def mutate(pkg):
        evil = pkg.parts["word/document.xml"].replace(b"100 USD", b"100000 USD")
        pkg.add_part("word/document2.xml", evil, wordml.CT_DOCUMENT)
        pkg.override_types["word/document.xml"] = "application/xml"
        for rels in pkg.relationships.values():
            for i, r in enumerate(rels):
                if r.target.endswith("document.xml") and "officeDocument" in r.type:
                    rels[i] = Relationship(r.id, r.type, "word/document2.xml")

    assert _reverifies(mutate) is False


def test_adding_an_unsigned_part_is_caught():
    assert _reverifies(lambda p: p.add_part("word/extra.xml", b"<x/>", "application/xml")) is False


def test_retyping_a_part_is_caught():
    """Content types decide what a part *is*, so they are inside the signature."""
    assert _reverifies(
        lambda p: p.override_types.__setitem__("word/document.xml", "application/xml")
    ) is False


def test_adding_a_default_content_type_is_caught():
    assert _reverifies(lambda p: p.default_types.__setitem__("bin", "application/octet-stream")) is False


def test_adding_a_stray_relationship_is_caught():
    """The relationship graph decides what a consumer follows, so it is signed too."""
    from docxplus.opc import Relationship

    assert _reverifies(
        lambda p: p.add_relationship(
            Relationship("rIdX", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                         "word/document.xml"),
            source_part="",
        )
    ) is False


def test_adding_a_header_part_is_caught():
    assert _reverifies(lambda p: p.add_part("word/header1.xml", b"<h/>", "application/xml")) is False


def test_odt_surface_digest_also_binds_the_whole_package():
    from docxplus import crypto
    from docxplus.odt import OdtPackage
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    priv, pub = crypto.generate_signing_key()
    builder = OdtPlusBuilder(paragraphs=["Amount: $10,000."])
    builder.add_module("m", b"payload").sign(priv)
    signed = builder.build()
    assert OdtPlusReader.from_bytes(signed).verify_provenance(expected_public_key=pub) is True

    pkg = OdtPackage.from_bytes(signed)
    pkg.add_part("Pictures/extra.png", b"\x89PNG", "image/png")
    assert OdtPlusReader.from_bytes(pkg.to_bytes()).verify_provenance(expected_public_key=pub) is False


def test_odt_rejects_duplicate_and_colliding_entry_names():
    """A second content.xml stream lets a signed .odt render bytes it never signed."""
    import io
    import zipfile

    import pytest as _pytest
    from docxplus.odt import MIMETYPE_ODT
    from docxplus.opc import OpcError

    def build(names_and_data):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("mimetype", MIMETYPE_ODT)
            for name, data in names_and_data:
                zf.writestr(name, data)
        return buf.getvalue()

    from docxplus.odt import OdtPackage

    with _pytest.raises(OpcError, match="duplicate ZIP entry names"):
        OdtPackage.from_bytes(build([("content.xml", b"<a/>"), ("content.xml", b"<b/>")]))

    with _pytest.raises(OpcError, match="colliding ODT entry names"):
        OdtPackage.from_bytes(build([("content.xml", b"<a/>"), ("./content.xml", b"<b/>")]))


# -- v1.0.0 release-gate fixes ------------------------------------------------


def test_argon2id_is_reachable_from_the_builder():
    """The docs list three KDF lineages; before this, only one could be produced.

    `crypto.encrypt` took a `kdf=` argument that nothing above it ever passed, so no
    document the tool emitted had ever used Argon2id.
    """
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder, DocxPlusReader, _iter_frames

    expected = {"scrypt": crypto.KDF_SCRYPT, "argon2id": crypto.KDF_ARGON2ID,
                "pbkdf2": crypto.KDF_PBKDF2}
    for name, kdf_id in expected.items():
        builder = DocxPlusBuilder(paragraphs=["x"])
        builder.add_module("m", "package_part", b"secret", password="pw", kdf=name)
        reader = DocxPlusReader.from_bytes(builder.build())
        frame = next(_iter_frames(reader.package.parts["intelligence/payload1.dxp"]))
        assert crypto.EncryptedPayload.from_bytes(frame).kdf_id == kdf_id, name
        assert reader.extract("m", password="pw") == b"secret"


def test_argon2id_is_reachable_from_the_odt_builder():
    from docxplus import crypto
    from docxplus.container import _iter_frames
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    builder = OdtPlusBuilder(paragraphs=["x"])
    builder.add_module("m", b"secret", password="pw", kdf="argon2id")
    reader = OdtPlusReader.from_bytes(builder.build())
    frame = next(_iter_frames(reader.package.parts["intelligence/payload1.dxp"]))
    assert crypto.EncryptedPayload.from_bytes(frame).kdf_id == crypto.KDF_ARGON2ID
    assert reader.extract("m", password="pw") == b"secret"


def test_builder_never_emits_a_package_its_own_reader_rejects():
    """A highly compressible payload used to trip the reader's inflate-ratio guard."""
    from docxplus import validate
    from docxplus.container import DocxPlusBuilder, DocxPlusReader

    for payload in (b"\x00" * (2 * 1024 * 1024), b'{"seq":1,"v":"x"}' * 200_000):
        builder = DocxPlusBuilder(paragraphs=["x"])
        builder.add_module("d", "package_part", payload)
        data = builder.build()
        assert validate.validate_bytes(data).ok, "builder emitted an unreadable package"
        assert DocxPlusReader.from_bytes(data).extract("d") == payload


def test_stego_carrier_is_actually_displayed():
    """The channel's premise is a figure the document *shows*, not a spare part."""
    import re

    import pytest as _pytest

    _pytest.importorskip("PIL")
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.opc import read_package

    builder = DocxPlusBuilder(paragraphs=["visible prose"])
    builder.add_module("fig", "stego_media", b"hidden payload", backend="python_lsb")
    data = builder.build()

    doc = read_package(data).parts["word/document.xml"].decode("utf-8")
    assert "<w:drawing>" in doc
    embed = re.search(r'r:embed="(rId\d+)"', doc)
    assert embed, "the drawing must reference the carrier by relationship id"
    rels = read_package(data).relationships.get("word/document.xml", [])
    assert any(r.id == embed.group(1) and "image" in r.type for r in rels)
    assert DocxPlusReader.from_bytes(data).extract("fig") == b"hidden payload"


def test_verify_reproduction_is_not_verified_without_an_attestation():
    """A module carrying no attestation must not report `verified: True`."""
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder, DocxPlusReader

    priv, pub = crypto.generate_signing_key()
    builder = DocxPlusBuilder(paragraphs=["x"])
    builder.add_module("plain", "package_part", b"no attestation here").sign(priv)
    reader = DocxPlusReader.from_bytes(builder.build())

    info = reader.verify_reproduction("plain", expected_public_key=pub)
    assert info["attested"] is False
    assert info["verified"] is False


def test_nesting_depth_is_carried_across_the_profile_boundary():
    """One ODT hop must not reset a matryoshka budget the OPC reader was counting."""
    from docxplus import crypto
    from docxplus.container import ContainerError, DocxPlusBuilder
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    priv, _pub = crypto.generate_signing_key()
    inner = DocxPlusBuilder(paragraphs=["inner"])
    inner.add_module("m", "package_part", b"x").sign(priv)

    outer = OdtPlusBuilder(paragraphs=["outer"])
    outer.add_nested("inner", inner.build())
    reader = OdtPlusReader.from_bytes(outer.build())

    nested = reader.open_nested("inner")
    assert nested._nest_depth == 1

    reader._nest_depth = reader.MAX_NEST_DEPTH if hasattr(reader, "MAX_NEST_DEPTH") else 32
    with pytest.raises(ContainerError, match="nesting deeper"):
        reader.open_nested("inner")


def test_open_nested_refuses_a_module_that_is_not_a_document():
    from docxplus.container import ContainerError
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    builder = OdtPlusBuilder(paragraphs=["x"]).add_module("notadoc", b"just bytes")
    reader = OdtPlusReader.from_bytes(builder.build())
    with pytest.raises(ContainerError, match="not a nested document"):
        reader.open_nested("notadoc")


def test_chaff_is_randomly_sized_so_module_size_implies_no_payload_length():
    """Deniability has a size dimension the frame-count tests do not cover.

    Two frames of fixed overhead would make a module's stored size a direct readout
    of its payload length, and an adversary who can read the payload length off the
    package can test a guess about what is in it. The chaff frame is randomly sized
    to break that link. Measured rather than assumed, because a chaff generator that
    silently became fixed-length would leave every other deniability test passing.
    """
    sizes = set()
    for _ in range(12):
        doc = DocxPlusBuilder().add_module("s", "package_part", b"P" * 64, password="a").build()
        sizes.add(DocxPlusReader.from_bytes(doc).describe("s")["size"])
    assert len(sizes) > 1, f"chaff is fixed-length; module size now leaks payload length: {sizes}"


def test_a_decoy_module_size_falls_inside_the_ordinary_module_range():
    """The size distributions must overlap, or size alone separates the two cases.

    A decoy carries two real payloads, so its size is deterministic given their
    lengths; an ordinary module's is randomised by chaff. What deniability needs is
    that an observed decoy size is one an ordinary module could equally have
    produced, which is what this asserts. The scope documented in
    `docs/security-model.md` is exactly this — one document, payload lengths unknown
    — and not indistinguishability under a distributional attack.
    """
    payload = b"X" * 64
    ordinary = [
        DocxPlusReader.from_bytes(
            DocxPlusBuilder().add_module("s", "package_part", payload, password="a").build()
        ).describe("s")["size"]
        for _ in range(24)
    ]
    decoy_doc = (
        DocxPlusBuilder()
        .add_decoy("s", real=payload, real_password="a", decoy=payload, decoy_password="b")
        .build()
    )
    decoy_size = DocxPlusReader.from_bytes(decoy_doc).describe("s")["size"]
    assert min(ordinary) <= decoy_size <= max(ordinary), (
        f"decoy size {decoy_size} sits outside the ordinary-module range "
        f"[{min(ordinary)}, {max(ordinary)}]; size alone would separate the two cases"
    )

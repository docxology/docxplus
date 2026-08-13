"""RedTeam regression suite — each test pins a fixed defect so it cannot return."""

from __future__ import annotations

import json

import pytest

import crypto
from container import ContainerError, DocxPlusBuilder, DocxPlusReader
from crypto import generate_recipient_key, generate_signing_key
from opc import read_package
from provenance import verify_inclusion


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
    from container import _iter_frames

    pw_doc = DocxPlusBuilder().add_module("s", "package_part", b"only", password="a").build()
    decoy_doc = (
        DocxPlusBuilder()
        .add_decoy("s", real=b"real", real_password="a", decoy=b"cover", decoy_password="b")
        .build()
    )
    pw_reader = DocxPlusReader.from_bytes(pw_doc)
    decoy_reader = DocxPlusReader.from_bytes(decoy_doc)
    import channels as reg

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
    reader = DocxPlusReader(package=pkg, manifest=__import__("manifest").read_manifest(pkg))
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
    reader = DocxPlusReader(package=pkg, manifest=__import__("manifest").read_manifest(pkg))
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
    assert verify_inclusion(proof)
    proof["digest"] = "deadbeef"
    assert not verify_inclusion(proof)


# -- resource safety -------------------------------------------------------
def test_project_decompression_bomb_capped(tmp_path):
    import payloads

    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "big.bin").write_bytes(b"\x00" * 2_000_000)
    blob = payloads.pack_project(proj)
    with pytest.raises(ValueError, match="decompression cap"):
        payloads.unpack_project(blob, tmp_path / "out", max_uncompressed=1_000_000)


def test_project_rejects_symlink_member(tmp_path):
    import io
    import tarfile

    import payloads

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        info = tarfile.TarInfo("evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(ValueError, match="link member"):
        payloads.unpack_project(raw.getvalue(), tmp_path / "dest")


def test_unsigned_document_warns():
    from validate import validate_bytes

    data = DocxPlusBuilder().add_module("a", "custom_xml", b"x").build()
    report = validate_bytes(data)
    assert report.ok
    assert any("unsigned" in n for n in report.notes)


def test_signed_document_no_unsigned_warning():
    priv, _ = generate_signing_key()
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"x").sign(priv).build()
    from validate import validate_bytes

    report = validate_bytes(data)
    assert not any("unsigned" in n for n in report.notes)
    assert json.loads(read_package(data).parts["intelligence/manifest.json"])["surface_digest"]


# -- OPC zip-bomb intake caps ----------------------------------------------
def test_opc_zip_bomb_guard_rejects_high_ratio():
    import zipfile

    import opc

    info = zipfile.ZipInfo("word/document.xml")
    info.file_size = 500_000_000
    info.compress_size = 1000  # 500000:1 inflate ratio
    with pytest.raises(opc.OpcError, match="inflate ratio|too large"):
        opc._guard_zip_bomb([info], compressed_len=2000)


def test_opc_zip_bomb_guard_rejects_total():
    import zipfile

    import opc

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
    from opc import OpcPackage, Relationship
    from validate import validate_package
    from wordml import CT_DOCUMENT

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
    from validate import validate_bytes

    data = DocxPlusBuilder().add_module("a", "custom_xml", b"one").build()
    pkg = read_package(data)
    raw = pkg.parts["intelligence/manifest.json"]
    doc = json.loads(raw)
    doc["merkle_root"] = "0" * 64
    pkg.parts["intelligence/manifest.json"] = json.dumps(doc, indent=2, sort_keys=True).encode()
    report = validate_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("merkle_root" in e for e in report.intelligence_errors)

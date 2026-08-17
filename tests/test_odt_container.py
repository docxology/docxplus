"""The intelligence layer over an ODT package.

Before v0.6.3 `odt.py` could carry loose bytes but had no manifest, no sealing and
no signature, while the docs claimed standards parity with the OOXML profile.
These tests hold the profile to that claim: both contracts, every sealing lineage,
and the same tamper detection.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from docxplus import crypto
from docxplus.container import ContainerError
from docxplus.odt import MIMETYPE_ODT
from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader
from docxplus.validate import validate_odt_bytes


def _signed(**kw):
    priv, pub = crypto.generate_signing_key()
    builder = OdtPlusBuilder(paragraphs=["An ordinary ODF document."], **kw)
    return builder, priv, pub


# -- surface contract ---------------------------------------------------------


def test_odt_with_intelligence_is_still_a_conforming_odf_package():
    builder, priv, _pub = _signed()
    builder.add_module("brief", b"payload").sign(priv)
    data = builder.build()

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        assert infos[0].filename == "mimetype"
        assert infos[0].compress_type == zipfile.ZIP_STORED
        assert zf.read("mimetype") == MIMETYPE_ODT
        manifest = zf.read("META-INF/manifest.xml").decode("utf-8")

    # Intelligence parts must be declared, or a conforming consumer cannot see them.
    assert "intelligence/manifest.json" in manifest
    assert "intelligence/payload1.dxp" in manifest


def test_odt_build_is_deterministic_when_unsealed():
    assert (
        OdtPlusBuilder(paragraphs=["fixed"]).add_module("m", b"bytes").build()
        == OdtPlusBuilder(paragraphs=["fixed"]).add_module("m", b"bytes").build()
    )


def test_validator_accepts_a_well_formed_odt():
    builder, priv, _pub = _signed()
    builder.add_module("m", b"payload", password="pw").sign(priv)
    report = validate_odt_bytes(builder.build())
    assert report.ok, report.to_dict()
    assert any("intelligence modules: 1" in n for n in report.notes)


def test_validator_reports_a_plain_odt_without_failing():
    from docxplus.odt import new_base_odt

    report = validate_odt_bytes(new_base_odt(["just text"]).to_bytes())
    assert report.ok
    assert any("plain ODT document" in n for n in report.notes)


def test_validator_warns_loudly_about_an_unsigned_manifest():
    data = OdtPlusBuilder(paragraphs=["x"]).add_module("m", b"p").build()
    report = validate_odt_bytes(data)
    assert report.ok
    assert any("WARNING" in n and "unsigned" in n for n in report.notes)


def test_validator_rejects_a_package_whose_mimetype_is_not_first():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("content.xml", b"<a/>")
        zf.writestr("mimetype", MIMETYPE_ODT)
        zf.writestr("META-INF/manifest.xml", b"<m/>")
    report = validate_odt_bytes(buf.getvalue())
    assert not report.ok
    assert any("not 'mimetype'" in e for e in report.opc_errors)


# -- intelligence contract: every sealing lineage -----------------------------


def test_typed_payload_round_trip():
    builder, priv, pub = _signed()
    builder.add_module("brief", {"kind": "brief", "n": 3}, payload_type="json").sign(priv)
    reader = OdtPlusReader.from_bytes(builder.build())
    assert reader.extract("brief", as_object=True) == {"kind": "brief", "n": 3}
    assert reader.verify_provenance(expected_public_key=pub) is True


def test_password_sealing_round_trip():
    builder, _priv, _pub = _signed()
    builder.add_module("secret", b"classified", password="pw")
    reader = OdtPlusReader.from_bytes(builder.build())
    assert reader.extract("secret", password="pw") == b"classified"
    with pytest.raises(ContainerError):
        reader.extract("secret", password="wrong")


def test_multi_recipient_sealing_round_trip():
    a_priv, a_pub = crypto.generate_recipient_key()
    b_priv, b_pub = crypto.generate_recipient_key()
    builder = OdtPlusBuilder().add_module("packet", b"for two", recipients=[a_pub, b_pub])
    reader = OdtPlusReader.from_bytes(builder.build())
    assert reader.extract("packet", private_key=a_priv) == b"for two"
    assert reader.extract("packet", private_key=b_priv) == b"for two"


def test_threshold_sealing_requires_quorum_and_verifiable_shares():
    from docxplus import shamir

    builder = OdtPlusBuilder().add_threshold("quorum", b"dead-man payload", k=2, n=3)
    data = builder.build()
    shares = builder.threshold_shares["quorum"]
    assert all(shamir.is_verifiable(s) for s in shares)

    reader = OdtPlusReader.from_bytes(data)
    assert reader.extract("quorum", shares=shares[:2]) == b"dead-man payload"

    # The downgrade the OPC profile refuses must be refused here too.
    downgraded = bytes([shares[0][1]]) + bytes(shares[0][shamir._VSS_HEADER:])
    with pytest.raises(ContainerError):
        reader.extract("quorum", shares=[downgraded, shares[1]])


def test_decoy_yields_two_plaintexts_under_two_passwords():
    builder = OdtPlusBuilder().add_decoy(
        "plausible", real=b"REAL", real_password="r", decoy=b"COVER", decoy_password="d"
    )
    reader = OdtPlusReader.from_bytes(builder.build())
    assert reader.extract("plausible", password="r") == b"REAL"
    assert reader.extract("plausible", password="d") == b"COVER"
    # The manifest must not label it a decoy; that would advertise the hidden payload.
    assert reader.manifest.slot("plausible").sealing["mode"] == "password"


# -- provenance and tampering -------------------------------------------------


def test_surface_tampering_breaks_provenance():
    builder, priv, pub = _signed()
    builder.add_module("m", b"payload").sign(priv)
    reader = OdtPlusReader.from_bytes(builder.build())
    assert reader.verify_provenance(expected_public_key=pub) is True

    reader.package.parts["content.xml"] = reader.package.parts["content.xml"].replace(
        b"ordinary", b"tampered"
    )
    assert reader.verify_provenance(expected_public_key=pub) is False


def test_payload_tampering_is_caught_before_decryption():
    builder, priv, _pub = _signed()
    builder.add_module("m", b"payload", password="pw").sign(priv)
    reader = OdtPlusReader.from_bytes(builder.build())
    part = reader.manifest.slot("m").location["part"]
    raw = bytearray(reader.package.parts[part])
    raw[0] ^= 0xFF  # flip, never assign — assigning a byte it already held is a no-op
    reader.package.parts[part] = bytes(raw)
    with pytest.raises(ContainerError, match="digest mismatch"):
        reader.extract("m", password="pw")


def test_authenticity_requires_a_pinned_key():
    builder, priv, pub = _signed()
    builder.add_module("m", b"payload").sign(priv)
    reader = OdtPlusReader.from_bytes(builder.build())
    _other_priv, other_pub = crypto.generate_signing_key()

    assert reader.signature_status(expected_public_key=pub) == "valid"
    assert reader.signature_status(expected_public_key=other_pub) != "valid"
    assert reader.verify_provenance(expected_public_key=other_pub) is False


def test_cosignatures_follow_the_opc_policy():
    priv_a, pub_a = crypto.generate_signing_key()
    priv_b, pub_b = crypto.generate_signing_key()
    _priv_c, pub_c = crypto.generate_signing_key()

    builder = OdtPlusBuilder().add_module("m", b"payload")
    builder.sign(priv_a).add_cosigner(priv_b)
    reader = OdtPlusReader.from_bytes(builder.build())

    assert reader.verify_cosigners([pub_a, pub_b]) is True
    assert reader.verify_cosigners([pub_a, pub_c]) is False


def test_merkle_inclusion_proof_over_the_odt_module_set():
    from docxplus.provenance import verify_inclusion

    builder = OdtPlusBuilder()
    for i in range(4):
        builder.add_module(f"m{i}", f"payload {i}".encode())
    reader = OdtPlusReader.from_bytes(builder.build())

    proof = reader.inclusion_proof("m2")
    assert verify_inclusion(proof, reader.merkle_root()) is True
    assert proof["root"] == reader.merkle_root()


def test_dropping_a_module_breaks_the_signature():
    """The Merkle root binds the module set, not merely each module."""
    builder, priv, pub = _signed()
    builder.add_module("keep", b"a").add_module("drop", b"b").sign(priv)
    reader = OdtPlusReader.from_bytes(builder.build())
    assert reader.verify_provenance(expected_public_key=pub) is True

    reader.manifest.records = [r for r in reader.manifest.records if r.slot != "drop"]
    assert reader.verify_provenance(expected_public_key=pub) is False


def test_duplicate_slot_is_refused():
    builder = OdtPlusBuilder().add_module("m", b"a")
    with pytest.raises(ContainerError, match="duplicate slot"):
        builder.add_module("m", b"b")


def test_conflicting_sealing_options_are_refused():
    _priv, pub = crypto.generate_recipient_key()
    with pytest.raises(ContainerError, match="at most one"):
        OdtPlusBuilder().add_module("m", b"a", password="pw", recipients=[pub])


def test_missing_module_names_the_slot():
    reader = OdtPlusReader.from_bytes(OdtPlusBuilder().add_module("m", b"a").build())
    with pytest.raises(ContainerError, match="no such module"):
        reader.extract("absent")


def test_project_payload_round_trips_through_odt(tmp_path):
    from docxplus import payloads

    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.py").write_text("X = 1\n")

    builder = OdtPlusBuilder()
    builder.add_module("source", payloads.pack_project(proj), payload_type="project")
    reader = OdtPlusReader.from_bytes(builder.build())

    dest = reader.extract_project("source", tmp_path / "out")
    assert (dest / "src" / "m.py").read_text() == "X = 1\n"


# -- validator failure paths --------------------------------------------------


def _raw_odt(entries, mimetype=MIMETYPE_ODT, mimetype_first=True, stored=True):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if mimetype_first and mimetype is not None:
            info = zipfile.ZipInfo("mimetype")
            info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            zf.writestr(info, mimetype)
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_validator_reports_unreadable_bytes_without_crashing():
    report = validate_odt_bytes(b"not a zip at all")
    assert not report.ok
    assert any("unreadable ODT package" in e for e in report.opc_errors)


def test_validator_rejects_a_compressed_mimetype():
    data = _raw_odt(
        {"META-INF/manifest.xml": b"<m/>", "content.xml": b"<c/>"}, stored=False
    )
    report = validate_odt_bytes(data)
    assert not report.ok
    assert any("must be STORED" in e for e in report.opc_errors)


def test_validator_rejects_a_wrong_mimetype_payload():
    data = _raw_odt(
        {"META-INF/manifest.xml": b"<m/>", "content.xml": b"<c/>"},
        mimetype=b"application/zip",
    )
    report = validate_odt_bytes(data)
    assert not report.ok
    assert any("not the OpenDocument Text media type" in e for e in report.opc_errors)


def test_validator_reports_missing_structural_parts():
    report = validate_odt_bytes(_raw_odt({}))
    assert not report.ok
    joined = " ".join(report.opc_errors)
    assert "missing META-INF/manifest.xml" in joined
    assert "missing content.xml" in joined


def test_validator_reports_a_part_absent_from_the_odf_manifest():
    """An undeclared entry is unreachable to a conforming consumer."""
    from docxplus.odt import build_manifest_xml

    data = _raw_odt({
        "META-INF/manifest.xml": build_manifest_xml([("content.xml", "text/xml")]),
        "content.xml": b"<c/>",
        "Pictures/stray.png": b"\x89PNG",
    })
    report = validate_odt_bytes(data)
    assert not report.ok
    assert any("not declared in META-INF/manifest.xml" in e for e in report.opc_errors)


def test_validator_reports_a_module_whose_part_is_missing():
    builder = OdtPlusBuilder(paragraphs=["x"]).add_module("m", b"payload")
    from docxplus.odt import OdtPackage

    pkg = OdtPackage.from_bytes(builder.build())
    del pkg.parts["intelligence/payload1.dxp"]
    report = validate_odt_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("missing part" in e for e in report.intelligence_errors)


def test_validator_reports_a_tampered_module_digest():
    from docxplus.odt import OdtPackage

    pkg = OdtPackage.from_bytes(OdtPlusBuilder(paragraphs=["x"]).add_module("m", b"payload").build())
    raw = bytearray(pkg.parts["intelligence/payload1.dxp"])
    raw[0] ^= 0xFF
    pkg.parts["intelligence/payload1.dxp"] = bytes(raw)
    report = validate_odt_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("digest mismatch" in e for e in report.intelligence_errors)


def test_validator_reports_an_invalid_signature():
    import json as _json

    from docxplus.odt import OdtPackage
    from docxplus.odt_container import ODT_MANIFEST_PART

    builder, priv, _pub = _signed()
    builder.add_module("m", b"payload").sign(priv)
    pkg = OdtPackage.from_bytes(builder.build())

    doc = _json.loads(pkg.parts[ODT_MANIFEST_PART])
    doc["signature"]["value"] = "00" * 64
    pkg.parts[ODT_MANIFEST_PART] = _json.dumps(doc).encode("utf-8")

    report = validate_odt_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("signature is invalid" in e for e in report.intelligence_errors)


def test_validator_reports_a_merkle_root_that_disagrees_with_the_module_set():
    import json as _json

    from docxplus.odt import OdtPackage
    from docxplus.odt_container import ODT_MANIFEST_PART

    pkg = OdtPackage.from_bytes(OdtPlusBuilder(paragraphs=["x"]).add_module("m", b"p").build())
    doc = _json.loads(pkg.parts[ODT_MANIFEST_PART])
    doc["merkle_root"] = "de" * 32
    pkg.parts[ODT_MANIFEST_PART] = _json.dumps(doc).encode("utf-8")

    report = validate_odt_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("merkle_root" in e for e in report.intelligence_errors)


def test_reader_refuses_a_package_that_is_not_opendocument_text():
    """`to_bytes` always writes the ODT media type, so build the hostile ZIP directly."""
    data = _raw_odt(
        {"META-INF/manifest.xml": b"<m/>", "content.xml": b"<c/>"},
        mimetype=b"application/vnd.oasis.opendocument.spreadsheet",
    )
    with pytest.raises(ContainerError, match="not an OpenDocument Text"):
        OdtPlusReader.from_bytes(data)


def test_reader_reports_absence_of_an_intelligence_layer():
    from docxplus.odt import new_base_odt

    reader = OdtPlusReader.from_bytes(new_base_odt(["plain"]).to_bytes())
    assert reader.has_intelligence() is False
    assert reader.list_modules() == []


# -- ODF threat intake --------------------------------------------------------


def _hostile_odt(**extra_parts):
    from docxplus.odt import OdtPackage

    pkg = OdtPackage.from_bytes(OdtPlusBuilder(paragraphs=["ordinary"]).add_module("m", b"p").build())
    for name, data in extra_parts.items():
        pkg.add_part(name.replace("__", "/"), data, "text/xml")
    return pkg


def test_clean_odt_scans_clean():
    from docxplus import intake

    data = OdtPlusBuilder(paragraphs=["ordinary"]).add_module("m", b"payload").build()
    report, reader = intake.safe_open_odt(data)
    assert report.ok is True
    assert isinstance(reader, OdtPlusReader)


def test_plain_odt_yields_no_reader():
    """Absence of an intelligence layer is a fact about the document, not a failure."""
    from docxplus import intake

    from docxplus.odt import new_base_odt

    report, reader = intake.safe_open_odt(new_base_odt(["plain"]).to_bytes())
    assert report.ok is True
    assert reader is None


def test_scan_flags_odf_basic_macro_containers():
    from docxplus import intake

    pkg = _hostile_odt(Basic__Standard__Module1_xml=b"<m/>")
    report, _ = intake.safe_open_odt(pkg.to_bytes())
    assert not report.ok
    assert any("Basic/" in m for m in report.macro_parts)


def test_scan_flags_off_package_xlink_targets():
    from docxplus import intake

    pkg = _hostile_odt()
    pkg.parts["content.xml"] = pkg.parts["content.xml"].replace(
        b"<office:body>",
        b'<office:body><text:a xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
        b'xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="http://evil.example/x">t</text:a>',
    )
    report, _ = intake.safe_open_odt(pkg.to_bytes())
    assert not report.ok
    assert any("evil.example" in r for r in report.external_relationships)


def test_scan_ignores_ordinary_in_package_links():
    """A relative or same-document href is normal; only a scheme means it dials out."""
    from docxplus import intake

    pkg = _hostile_odt()
    pkg.parts["content.xml"] = pkg.parts["content.xml"].replace(
        b"<office:body>",
        b'<office:body><text:a xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
        b'xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#anchor">t</text:a>',
    )
    report, _ = intake.safe_open_odt(pkg.to_bytes())
    assert report.external_relationships == []


def test_strict_policy_refuses_a_dirty_odt():
    from docxplus import intake
    import pytest as _pytest

    pkg = _hostile_odt(Scripts__script_xml=b"<s/>")
    with _pytest.raises(intake.IntakeError, match="intake rejected"):
        intake.safe_open_odt(pkg.to_bytes(), policy=intake.IntakePolicy(strict=True))


def test_scan_caps_part_count():
    from docxplus import intake

    data = OdtPlusBuilder(paragraphs=["x"]).add_module("m", b"p").build()
    report, _ = intake.safe_open_odt(data, policy=intake.IntakePolicy(max_parts=2))
    assert report.oversized is True
    assert not report.ok

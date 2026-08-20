"""Validation: OPC conformance + intelligence conformance, incl. tamper detection."""

from __future__ import annotations

import io
import zipfile

from docxplus.container import DocxPlusBuilder
from docxplus.crypto import generate_signing_key
from docxplus.opc import OpcPackage, Relationship, read_package
from docxplus.validate import assert_valid, validate_bytes, validate_package
from docxplus.wordml import new_base_document
from docxplus.channels.mce import MceChannel


def test_plain_document_validates_with_note():
    data = new_base_document(["plain"]).to_bytes()
    report = validate_bytes(data)
    assert report.ok
    assert any("plain document" in n for n in report.notes)


def test_intelligent_document_validates():
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"payload").build()
    report = validate_bytes(data)
    assert report.ok
    assert any("intelligence modules: 1" in n for n in report.notes)


def test_unreachable_part_flagged():
    pkg = new_base_document(["x"])
    # Add an orphan part with no relationship pointing at it.
    pkg.set_default_type("bin", "application/octet-stream")
    pkg.add_part("orphan/data.bin", b"orphan")
    report = validate_package(pkg)
    assert not report.ok
    assert any("reachable" in e for e in report.opc_errors)


def test_missing_main_document_flagged():
    pkg = OpcPackage()
    pkg.set_default_type("xml", "application/xml")
    pkg.set_default_type("rels", "application/xml")
    pkg.add_part("stuff/x.xml", b"<x/>", "application/xml")
    pkg.add_relationship(Relationship("rId1", "urn:x", "stuff/x.xml"), source_part="")
    report = validate_package(pkg)
    assert any("main document" in e for e in report.opc_errors)


def test_tampered_custom_xml_digest_mismatch():
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"payload").build()
    pkg = read_package(data)
    # Corrupt the payload part bytes but keep it well-formed XML.
    part = pkg.parts["customXml/item1.xml"]
    pkg.parts["customXml/item1.xml"] = part.replace(b"base64", b"base64")  # locate then swap
    # Force a real change: replace the encoded body with a different valid base64.
    import re

    pkg.parts["customXml/item1.xml"] = re.sub(
        rb">([A-Za-z0-9+/=]+)<", b">QUJD<", pkg.parts["customXml/item1.xml"]
    )
    report = validate_package(pkg)
    assert not report.ok
    assert any("digest mismatch" in e for e in report.intelligence_errors)


def test_invalid_signature_flagged():
    priv, pub = generate_signing_key()
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"payload").sign(priv).build()
    pkg = read_package(data)
    # Corrupt the signature in the manifest part.
    manifest = pkg.parts["intelligence/manifest.json"].replace(
        pub.hex().encode(), pub.hex().encode()
    )
    manifest = manifest.replace(b'"value": "', b'"value": "00', 1)
    pkg.parts["intelligence/manifest.json"] = manifest
    report = validate_package(pkg)
    assert not report.ok
    assert any("signature is invalid" in e for e in report.intelligence_errors)


def test_assert_valid_raises_on_corrupt():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
    try:
        assert_valid(buf.getvalue())
    except AssertionError as exc:
        assert "validation failed" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected AssertionError")


def test_assert_valid_passes_good_document():
    data = DocxPlusBuilder().add_module("a", "custom_xml", b"payload").build()
    assert_valid(data)  # must not raise


def test_unreadable_bytes_report():
    report = validate_bytes(b"not a zip at all")
    assert not report.ok
    assert report.opc_errors


def test_validate_mce_channel():
    pkg = new_base_document(["Testing validation of MCE."])
    chan = MceChannel()
    rec = chan.embed(pkg, b"sample mce data", slot="slot_mce")

    # Check valid MCE channel in package
    from docxplus.manifest import Manifest, write_manifest
    m = Manifest()
    m.add(rec)
    write_manifest(pkg, m)

    report = validate_package(pkg)
    assert report.ok is True


# -- OPC whole-package signature coverage (docs/opc-signatures.md) -------------
#
# The rule exists before any signing support does, on purpose: a package signature
# that covers only the conventional Word parts would render as valid in a desktop
# office suite over a document whose intelligence layer had been stripped.


_SIG_NS = "http://www.w3.org/2000/09/xmldsig#"


def _signature_part(uris: list[str]) -> bytes:
    refs = "".join(f'<Reference URI="{u}"/>' for u in uris)
    return (
        f'<Signature xmlns="{_SIG_NS}"><SignedInfo>{refs}</SignedInfo></Signature>'
    ).encode("utf-8")


def _docx_with_signature(uris: list[str]) -> tuple:
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder
    from docxplus.opc import read_package
    from docxplus.validate import ValidationReport, check_opc_signature_coverage

    priv, _pub = crypto.generate_signing_key()
    builder = DocxPlusBuilder(paragraphs=["surface"])
    builder.add_module("brief", "package_part", b"payload")
    builder.sign(priv)
    pkg = read_package(builder.build())
    pkg.parts["_xmlsignatures/origin.sigs"] = b""
    pkg.parts["_xmlsignatures/sig1.xml"] = _signature_part(uris)
    report = ValidationReport()
    check_opc_signature_coverage(pkg, report)
    return pkg, report


def test_opc_signature_covering_only_word_parts_is_rejected():
    """The trust-laundering case: a valid-looking signature over a stripped payload set."""
    _pkg, report = _docx_with_signature(["/word/document.xml", "/[Content_Types].xml"])
    assert not report.ok
    joined = " ".join(report.intelligence_errors)
    assert "does not cover intelligence parts" in joined
    assert "intelligence/manifest.json" in joined


def test_opc_signature_covering_every_manifest_part_is_accepted():
    from docxplus.manifest import MANIFEST_PART

    _pkg, report = _docx_with_signature(
        [f"/{MANIFEST_PART}", "/intelligence/payload1.dxp", "/word/document.xml"]
    )
    assert report.ok, report.to_dict()


def test_signature_reference_uris_are_matched_ignoring_the_content_type_query():
    """OPC references carry ?ContentType=…; stripping it is required, not cosmetic."""
    from docxplus.manifest import MANIFEST_PART

    _pkg, report = _docx_with_signature([
        f"/{MANIFEST_PART}?ContentType=application/vnd.docxplus.manifest%2Bjson",
        "/intelligence/payload1.dxp?ContentType=application/vnd.docxplus.payload",
    ])
    assert report.ok, report.to_dict()


def test_package_without_an_opc_signature_is_unaffected():
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder
    from docxplus.opc import read_package
    from docxplus.validate import ValidationReport, check_opc_signature_coverage

    priv, _pub = crypto.generate_signing_key()
    builder = DocxPlusBuilder(paragraphs=["surface"])
    builder.add_module("brief", "package_part", b"payload")
    builder.sign(priv)
    report = ValidationReport()
    check_opc_signature_coverage(read_package(builder.build()), report)
    assert report.ok


def test_malformed_signature_part_covers_nothing_and_fails_closed():
    _pkg, report = _docx_with_signature([])
    # An unparseable or empty signature must not be read as covering everything.
    assert not report.ok


def test_validation_report_notes_and_failures():
    """Cover ValidationReport note appending and failure handling."""
    from docxplus.validate import ValidationReport

    rep = ValidationReport()
    rep.notes.append("test note")
    assert rep.to_dict()["notes"] == ["test note"]
    rep.fail(rep.opc_errors, "opc failure")
    assert rep.ok is False
    assert "opc failure" in rep.to_dict()["opc_errors"]


"""Serialized regressions for validation topology and untrusted-input reports."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import zipfile

import pytest

from docxplus.container import DocxPlusBuilder
from docxplus.manifest import MANIFEST_PART, REL_MANIFEST
from docxplus.odt import OdtPackage, new_base_odt
from docxplus.odt_container import OdtPlusBuilder
from docxplus.opc import Relationship, read_package
from docxplus.validate import (
    ValidationReport,
    check_opc_signature_coverage,
    validate_bytes,
    validate_odt_bytes,
)
from docxplus.wordml import REL_OFFICE_DOCUMENT, new_base_document

_DS = "http://www.w3.org/2000/09/xmldsig#"


def _replace_entries(data: bytes, replacements: dict[str, bytes | None]) -> bytes:
    """Preserve serialized index and mimetype metadata while mutating real bytes."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, "w") as target:
        for info in source.infolist():
            blob = replacements.get(info.filename, source.read(info))
            if blob is not None:
                target.writestr(info, blob)
    return out.getvalue()


def _profile(profile: str):
    if profile == "docx":
        return DocxPlusBuilder().add_module("brief", "package_part", b"payload").build(), validate_bytes
    return OdtPlusBuilder().add_module("brief", b"payload").build(), validate_odt_bytes


def _refs(parts: list[str], *, prefix: str = "ds") -> str:
    return "".join(f'<{prefix}:Reference URI="/{part}"/>' for part in parts)


def _signature(signed_info: str, objects: str = "") -> bytes:
    return (
        f'<ds:Signature xmlns:ds="{_DS}"><ds:SignedInfo>{signed_info}'
        f'</ds:SignedInfo>{objects}</ds:Signature>'
    ).encode()


def _coverage(data: bytes, signature: bytes) -> ValidationReport:
    pkg = read_package(data)
    pkg.add_part("_xmlsignatures/origin.sigs", b"", "application/vnd.openxmlformats-package.digital-signature-origin")
    pkg.add_part("_xmlsignatures/sig1.xml", signature, "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml")
    report = ValidationReport()
    check_opc_signature_coverage(read_package(pkg.to_bytes()), report)
    return report


@pytest.mark.parametrize("channel,carriers,options", [
    ("metadata", ["docProps/custom.xml"], {}),
    ("mce", ["word/document.xml"], {}),
    ("custom_xml", ["customXml/item1.xml"], {}),
    ("package_part", ["intelligence/payload1.dxp"], {}),
    pytest.param("stego_media", ["word/media/image1.png", "word/media/image2.png"],
                 {"redundancy": 2}, marks=pytest.mark.requires_pillow),
])
def test_opc_coverage_requires_every_actual_carrier(channel, carriers, options):
    """A4: fixed metadata, singular/MCE and every stego replica must be covered."""
    data = DocxPlusBuilder().add_module("brief", channel, b"payload", **options).build()
    assert validate_bytes(data).ok
    for omitted in carriers:
        refs = [MANIFEST_PART] + [part for part in carriers if part != omitted]
        report = _coverage(data, _signature(_refs(refs)))
        assert not report.ok
        assert omitted in " ".join(report.intelligence_errors)
    report = _coverage(data, _signature(_refs([MANIFEST_PART, *carriers])))
    assert report.ok, report.to_dict()
    assert any("syntactic only" in note for note in report.notes)


@pytest.mark.parametrize("placement", ["wrong_namespace", "unsigned_object", "unsigned_manifest", "nested_reference"])
def test_opc_coverage_ignores_unsigned_or_non_dsig_references(placement):
    """A5: arbitrary descendant Reference-like elements are not signed coverage."""
    data, _ = _profile("docx")
    parts = [MANIFEST_PART, "intelligence/payload1.dxp"]
    proper = _refs(parts)
    signed_info = _refs(["word/document.xml"])
    if placement == "wrong_namespace":
        signed_info += "".join(f'<x:Reference xmlns:x="urn:unsigned" URI="/{part}"/>' for part in parts)
        objects = ""
    elif placement == "unsigned_object":
        objects = f'<ds:Object>{proper}</ds:Object>'
    elif placement == "unsigned_manifest":
        objects = f'<ds:Object><ds:Manifest Id="unreferenced">{proper}</ds:Manifest></ds:Object>'
    else:
        signed_info += f'<ds:Extension>{proper}</ds:Extension>'
        objects = ""
    report = _coverage(data, _signature(signed_info, objects))
    assert not report.ok
    assert "does not cover intelligence parts" in " ".join(report.intelligence_errors)


@pytest.mark.parametrize("target", ["object", "manifest", "chained_manifest"])
def test_opc_coverage_follows_signed_manifest_topology(target):
    """A5 positive: genuine SignedInfo to Object/Manifest chains contribute coverage."""
    data, _ = _profile("docx")
    proper = _refs([MANIFEST_PART, "intelligence/payload1.dxp"])
    objects = f'<ds:Object Id="object"><ds:Manifest Id="manifest">{proper}</ds:Manifest></ds:Object>'
    if target == "chained_manifest":
        objects += '<ds:Object><ds:Manifest Id="chained_manifest"><ds:Reference URI="#manifest"/></ds:Manifest></ds:Object>'
    report = _coverage(data, _signature(f'<ds:Reference URI="#{target}"/>', objects))
    assert report.ok, report.to_dict()


@pytest.mark.parametrize("signature", [
    b"not XML",
    b'<Signature><SignedInfo/></Signature>',
    _signature('<ds:Reference URI="#missing"/>'),
    _signature('<ds:Reference URI="#duplicate"/>', '<ds:Object Id="duplicate"/><ds:Object Id="duplicate"/>'),
])
def test_malformed_opc_signature_yields_report(signature):
    """A7: malformed signature XML/topology fails structurally without a traceback."""
    data, _ = _profile("docx")
    report = _coverage(data, signature)
    assert not report.ok
    assert any("malformed OPC signature" in error for error in report.intelligence_errors)


@pytest.mark.parametrize("profile,part", [("docx", "word/document.xml"), ("odt", "content.xml")])
@pytest.mark.parametrize("blob", [b"not XML", b"<wrong/>", b'<document xmlns="urn:wrong"/>'])
def test_bad_serialized_surface_root_fails(profile, part, blob):
    """A6: existence and a plausible content type never substitute for surface XML."""
    if profile == "docx":
        data, validate = new_base_document(["surface"]).to_bytes(), validate_bytes
    else:
        data, validate = new_base_odt(["surface"]).to_bytes(), validate_odt_bytes
    report = validate(_replace_entries(data, {part: blob}))
    assert not report.ok
    assert any(part in error and "XML" in error for error in report.opc_errors)


@pytest.mark.parametrize("mutation", ["missing", "wrong_type", "external", "wrong_target"])
def test_main_document_requires_genuine_root_office_document_edge(mutation):
    """A6: a reachable correctly typed part is not itself an officeDocument edge."""
    pkg = new_base_document(["surface"])
    edges = []
    for rel in pkg.relationships[""]:
        if rel.type != REL_OFFICE_DOCUMENT:
            edges.append(rel)
        elif mutation != "missing":
            edges.append(Relationship(rel.id, "urn:unrelated" if mutation == "wrong_type" else rel.type,
                                      "docProps/core.xml" if mutation == "wrong_target" else rel.target,
                                      "External" if mutation == "external" else rel.mode))
    pkg.relationships[""] = edges
    report = validate_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("officeDocument" in error for error in report.opc_errors)


@pytest.mark.parametrize("mutation", ["content_type", "missing", "wrong_type", "external", "wrong_target", "missing_part"])
def test_docx_manifest_authority_is_enforced(mutation):
    """A6: fixed manifest bytes need the prescribed type and package-root authority."""
    data, _ = _profile("docx")
    pkg = read_package(data)
    if mutation == "content_type":
        pkg.override_types[MANIFEST_PART] = "text/plain"
    elif mutation == "missing_part":
        del pkg.parts[MANIFEST_PART]
    else:
        edges = []
        for rel in pkg.relationships[""]:
            if rel.type != REL_MANIFEST:
                edges.append(rel)
            elif mutation != "missing":
                edges.append(Relationship(rel.id, "urn:unrelated" if mutation == "wrong_type" else rel.type,
                                          "word/document.xml" if mutation == "wrong_target" else rel.target,
                                          "External" if mutation == "external" else rel.mode))
        pkg.relationships[""] = edges
    report = validate_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("manifest" in error and ("content type" in error or "authority" in error)
               for error in report.intelligence_errors)


@pytest.mark.parametrize("declaration", ["wrong", "missing"])
def test_odt_manifest_authority_media_type_is_enforced(declaration):
    """A6: the ODF file-entry must declare the intelligence authority's exact type."""
    from xml.etree import ElementTree as ET

    from docxplus.odt import NS_MANIFEST

    data, _ = _profile("odt")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        root = ET.fromstring(zf.read("META-INF/manifest.xml"))
    for entry in list(root):
        if entry.get(f"{{{NS_MANIFEST}}}full-path") == MANIFEST_PART:
            if declaration == "missing":
                root.remove(entry)
            else:
                entry.set(f"{{{NS_MANIFEST}}}media-type", "text/plain")
    report = validate_odt_bytes(_replace_entries(data, {"META-INF/manifest.xml": ET.tostring(root)}))
    assert not report.ok
    assert any("media-type declaration" in error for error in report.intelligence_errors)


@pytest.mark.parametrize("channel", ["future_channel", "package_part", "custom_xml", "metadata", "mce"])
def test_odt_unknown_channels_are_not_package_parts(channel):
    """A8: only the explicit ODT transport allowlist has package-entry semantics."""
    data, _ = _profile("odt")
    pkg = OdtPackage.from_bytes(data)
    manifest = json.loads(pkg.parts[MANIFEST_PART])
    manifest["modules"][0]["channel"] = channel
    pkg.parts[MANIFEST_PART] = json.dumps(manifest).encode()
    report = validate_odt_bytes(pkg.to_bytes())
    assert not report.ok
    assert any("unsupported ODT channel" in error for error in report.intelligence_errors)


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("mutation", ["json", "root", "modules", "duplicate", "location", "signature", "partial_signature", "version"])
def test_malformed_manifest_returns_structured_failure(profile, mutation):
    """A7: JSON, schema, duplicate slots and signature decoding stay inside reports."""
    data, validate = _profile(profile)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        manifest = json.loads(zf.read(MANIFEST_PART))
    if mutation == "json":
        blob = b"{"
    elif mutation == "root":
        blob = b"[]"
    else:
        if mutation == "modules":
            manifest["modules"] = [None]
        elif mutation == "duplicate":
            manifest["modules"].append(dict(manifest["modules"][0]))
        elif mutation == "location":
            manifest["modules"][0]["location"] = []
        elif mutation == "signature":
            manifest["signature"]["value"] = "zz"
            manifest["signature"]["public_key"] = "00" * 32
        elif mutation == "partial_signature":
            manifest["signature"]["value"] = "00" * 64
        else:
            manifest["version"] = "999.0"
        blob = json.dumps(manifest).encode()
    report = validate(_replace_entries(data, {MANIFEST_PART: blob}))
    assert not report.ok
    assert report.intelligence_errors
    assert json.loads(json.dumps(report.to_dict()))["ok"] is False


@pytest.mark.parametrize("profile,part", [
    ("docx", "[Content_Types].xml"), ("docx", "_rels/.rels"),
    ("odt", "META-INF/manifest.xml"),
])
def test_malformed_xml_indexes_return_package_errors(profile, part):
    """A7: malformed package-index XML is a surface failure, not an escaped parser error."""
    data, validate = _profile(profile)
    report = validate(_replace_entries(data, {part: b"<"}))
    assert not report.ok
    assert report.opc_errors


@pytest.mark.parametrize("profile,command", [("docx", "validate"), ("odt", "odt-validate")])
def test_cli_malformed_manifest_still_emits_json(tmp_path, profile, command):
    """A7: the real CLI keeps its JSON/failed-exit contract for hostile manifest bytes."""
    data, _ = _profile(profile)
    path = tmp_path / f"malformed.{profile}"
    path.write_bytes(_replace_entries(data, {MANIFEST_PART: b"{"}))
    result = subprocess.run([sys.executable, "-m", "docxplus.cli", command, str(path)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert json.loads(result.stdout)["ok"] is False
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_valid_serialized_profiles_pass(profile):
    """Positive controls retain supported DOCX and ODT package-entry validation."""
    data, validate = _profile(profile)
    assert validate(data).ok


@pytest.mark.parametrize("profile,part", [("docx", "word/document.xml"), ("odt", "content.xml")])
def test_unknown_surface_xml_encoding_is_reported(profile, part):
    """A7: unsupported XML encodings are known untrusted-input failures."""
    data, validate = _profile(profile)
    blob = b'<?xml version="1.0" encoding="not-a-real-codec"?><document/>'
    report = validate(_replace_entries(data, {part: blob}))
    assert not report.ok
    assert any(part in error for error in report.opc_errors)


@pytest.mark.parametrize("location", [{"part": []}, {"parts": [{}]}, {"parts": "not-a-list"}])
def test_malformed_opc_carrier_locations_return_failed_reports(location):
    """A7: malformed carrier field values cannot escape the coverage report API."""
    data, _ = _profile("docx")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        manifest = json.loads(zf.read(MANIFEST_PART))
    signature = _signature(_refs([MANIFEST_PART, manifest["modules"][0]["location"]["part"]]))
    assert _coverage(data, signature).ok
    manifest["modules"][0]["location"] = location
    data = _replace_entries(data, {MANIFEST_PART: json.dumps(manifest).encode()})
    report = _coverage(data, signature)
    assert not report.ok

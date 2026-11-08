"""Format-3 regressions cross real ZIP, signature, frame and share boundaries."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import replace
from xml.etree import ElementTree as ET

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from docxplus import crypto, shamir
from docxplus.container import (
    ContainerError,
    DocxPlusBuilder,
    DocxPlusReader,
    _iter_frames,
    _open_password_frames,
)
from docxplus.manifest import MANIFEST_PART, Manifest
from docxplus.odt import MIMETYPE_ODT, NS_MANIFEST, OdtPackage, new_base_odt
from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader, open_document
from docxplus.opc import (
    CONTENT_TYPES_PART,
    NS_CONTENT_TYPES,
    NS_RELATIONSHIPS,
    ROOT_RELS_PART,
    OpcError,
    Relationship,
    read_package,
)
from docxplus.validate import validate_bytes, validate_odt_bytes
from docxplus.wordml import NS_OFFICE_REL, NS_WORDML, new_base_document

_PRIVATE = bytes(range(32))
_PUBLIC = Ed25519PrivateKey.from_private_bytes(_PRIVATE).public_key().public_bytes_raw()


def _builder(profile, **kwargs):
    return DocxPlusBuilder(**kwargs) if profile == "docx" else OdtPlusBuilder(**kwargs)


def _add(builder, slot, data, **kwargs):
    if isinstance(builder, DocxPlusBuilder):
        builder.add_module(slot, "package_part", data, **kwargs)
    else:
        builder.add_module(slot, data, **kwargs)
    return builder


def _package(profile, data):
    return read_package(data) if profile == "docx" else OdtPackage.from_bytes(data)


def _validate(profile, data):
    return validate_bytes(data) if profile == "docx" else validate_odt_bytes(data)


def _rewrite(data, replacements=None, extras=(), deflate=()):
    """Change real ZIP entries without passing through a normalizing serializer."""
    replacements = replacements or {}
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, "w") as target:
        for entry in source.infolist():
            info = zipfile.ZipInfo(entry.filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED if entry.filename in deflate else entry.compress_type
            target.writestr(info, replacements.get(entry.filename, source.read(entry)))
        for name, payload in extras:
            target.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), payload)
    return out.getvalue()


def test_relationship_id_permutation_changes_pinned_rendered_graph():
    """A1: unchanged headerReference resolves differently after an ID-only swap."""
    base = new_base_document(["visible"])
    header_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"
    for label in ("A", "B"):
        base.add_part(
            f"word/header{label}.xml",
            f'<w:hdr xmlns:w="{NS_WORDML}"><w:p><w:r><w:t>{label}</w:t></w:r></w:p></w:hdr>'.encode(),
            header_type,
        )
    for rid, label in (("rId10", "A"), ("rId11", "B")):
        base.add_relationship(Relationship(rid, f"{NS_OFFICE_REL}/header", f"header{label}.xml"), "word/document.xml")
    base.parts["word/document.xml"] = base.parts["word/document.xml"].replace(
        b"<w:sectPr>",
        f'<w:sectPr><w:headerReference xmlns:r="{NS_OFFICE_REL}" w:type="default" r:id="rId10"/>'.encode(),
    )
    builder = _add(DocxPlusBuilder(base_package=base), "m", b"payload")
    signed = builder.sign(_PRIVATE).add_cosigner(_PRIVATE).build()
    assert DocxPlusReader.from_bytes(signed).verify_provenance(_PUBLIC)
    pkg = read_package(signed)
    document = pkg.parts["word/document.xml"]
    rid = ET.fromstring(document).find(f".//{{{NS_WORDML}}}headerReference").attrib[f"{{{NS_OFFICE_REL}}}id"]
    assert next(r.target for r in pkg.relationships["word/document.xml"] if r.id == rid) == "headerA.xml"
    pkg.relationships["word/document.xml"] = [
        replace(r, id="rId11" if r.id == "rId10" else "rId10")
        for r in pkg.relationships["word/document.xml"]
    ]
    changed = pkg.to_bytes()
    reader = DocxPlusReader.from_bytes(changed)
    assert reader.package.parts["word/document.xml"] == document
    assert next(r.target for r in reader.package.relationships["word/document.xml"] if r.id == rid) == "headerB.xml"
    assert reader.manifest.verify_signature()
    assert not reader.verify_provenance(_PUBLIC)
    assert not reader.verify_cosigners([_PUBLIC])
    assert not validate_bytes(changed).ok


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_binary_delimiter_collision_is_not_a_surface_digest_collision(profile):
    """A2: the exact former two-part NUL collision now invalidates a pinned package."""
    base = new_base_document() if profile == "docx" else new_base_odt()
    separator = b"\x00P\x00b.bin\x00"
    base.add_part("a.bin", b"A", "application/octet-stream")
    base.add_part("b.bin", b"B" + separator + b"C", "application/octet-stream")
    if profile == "docx":
        for index, name in enumerate(("a.bin", "b.bin"), 20):
            base.add_relationship(Relationship(f"rId{index}", "urn:attachment", name))
    signed = _add(_builder(profile, base_package=base), "m", b"kept").sign(_PRIVATE).build()
    original = open_document(signed)
    assert original.verify_provenance(_PUBLIC)
    assert _validate(profile, signed).ok
    pkg = _package(profile, signed)
    pkg.parts["a.bin"], pkg.parts["b.bin"] = b"A" + separator + b"B", b"C"
    changed = pkg.to_bytes()
    reader = open_document(changed)
    assert reader.manifest.verify_signature()
    assert not reader.verify_provenance(_PUBLIC)
    assert not _validate(profile, changed).ok


@pytest.mark.parametrize("field", ["id", "type", "target", "mode", "content_type"])
def test_manifest_authority_metadata_is_not_self_excluded(field):
    """A1/A6: only manifest bytes, not arbitrary authority declarations, are excluded."""
    data = _add(DocxPlusBuilder(), "m", b"x").sign(_PRIVATE).build()
    pkg = read_package(data)
    if field == "content_type":
        pkg.override_types[MANIFEST_PART] = "text/plain"
    else:
        pkg.relationships[""] = [
            replace(rel, **{field: {"id": "rIdChanged", "type": "urn:changed", "target": "/" + MANIFEST_PART, "mode": "External"}[field]})
            if rel.target == MANIFEST_PART else rel for rel in pkg.relationships[""]
        ]
    assert not DocxPlusReader.from_bytes(pkg.to_bytes()).verify_provenance(_PUBLIC)


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("alias", ["content.xml/", "word/document.xml/", "[Content_Types].xml/", "_rels/.rels/"])
def test_directory_zip_entries_cannot_alias_parsed_parts(profile, alias):
    """F1: directory names never normalize onto a file or an authority index."""
    data = _add(_builder(profile), "m", b"x").sign(_PRIVATE).build()
    with pytest.raises((OpcError, ContainerError), match="directory|colliding"):
        open_document(_rewrite(data, extras=[(alias, b"attacker")]))
    assert not _validate(profile, _rewrite(data, extras=[(alias, b"attacker")])).ok


@pytest.mark.parametrize("kind", ["oversized", "compressed", "duplicate"])
def test_generic_mimetype_dispatch_refuses_before_unbounded_inflate(kind):
    """A3: the public discriminator accepts only one exact short STORED stream."""
    data = _add(OdtPlusBuilder(), "m", b"x").build()
    if kind == "oversized":
        data = _rewrite(data, {"mimetype": MIMETYPE_ODT + b"\x00" * (2 * 1024 * 1024)}, deflate=["mimetype"])
    elif kind == "compressed":
        data = _rewrite(data, deflate=["mimetype"])
    else:
        data = _rewrite(data, extras=[("mimetype", MIMETYPE_ODT)])
    with pytest.raises(ContainerError):
        open_document(data)


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_unknown_serialized_channel_is_rejected(profile):
    """A8: a future transport never silently enters ODT's raw-part branch."""
    data = _add(_builder(profile), "m", b"x").build()
    pkg = _package(profile, data)
    manifest = json.loads(pkg.parts[MANIFEST_PART])
    manifest["modules"][0]["channel"] = "future_transport"
    pkg.parts[MANIFEST_PART] = json.dumps(manifest).encode()
    changed = pkg.to_bytes()
    with pytest.raises((ContainerError, ValueError)):
        open_document(changed).extract("m")
    assert not _validate(profile, changed).ok


@pytest.mark.parametrize("payload", [b"\x00" * (2 * 1024 * 1024), b'{"v":"x"}' * 200_000])
def test_odt_compression_writer_reader_symmetry(payload):
    """A9: compressible signed output reads, but hostile DEFLATED ratios still fail."""
    data = _add(OdtPlusBuilder(), "m", payload).sign(_PRIVATE).build()
    reader = open_document(data)
    assert reader.extract("m") == payload
    assert reader.verify_provenance(_PUBLIC)
    assert validate_odt_bytes(data).ok
    part = reader.manifest.slot("m").location["part"]
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.getinfo(part).compress_type == zipfile.ZIP_STORED
    with pytest.raises(OpcError, match="inflate ratio"):
        OdtPackage.from_bytes(_rewrite(data, deflate=[part]))


def test_odt_allocation_preserves_existing_parts_and_is_deterministic():
    """A10: allocation fills free indexes without replacing either occupied base part."""
    base = new_base_odt(["KEEP VISIBLE"])
    base.add_part("intelligence/payload1.dxp", b"KEEP ONE", "application/octet-stream")
    base.add_part("intelligence/payload3.dxp", b"KEEP THREE", "application/octet-stream")
    original = base.to_bytes()
    outputs = []
    for _ in range(2):
        builder = OdtPlusBuilder(base_package=OdtPackage.from_bytes(original))
        outputs.append(_add(_add(builder, "a", b"NEW A"), "b", b"NEW B").sign(_PRIVATE).build())
    assert outputs[0] == outputs[1]
    reader = open_document(outputs[0])
    assert reader.package.parts["intelligence/payload1.dxp"] == b"KEEP ONE"
    assert reader.package.parts["intelligence/payload3.dxp"] == b"KEEP THREE"
    assert b"KEEP VISIBLE" in reader.package.parts["content.xml"]
    assert reader.manifest.slot("a").location["part"] == "intelligence/payload2.dxp"
    assert reader.manifest.slot("b").location["part"] == "intelligence/payload4.dxp"
    assert reader.extract("a") == b"NEW A"
    assert reader.extract("b") == b"NEW B"
    assert reader.verify_provenance(_PUBLIC)
    with pytest.raises(OpcError, match="duplicate ODT part"):
        reader.package.add_part("intelligence/payload1.dxp", b"REPLACE")


@pytest.mark.parametrize("outer_profile", ["docx", "odt"])
@pytest.mark.parametrize("inner_profile", ["docx", "odt"])
def test_nesting_dispatches_both_profiles_with_one_shared_depth(outer_profile, inner_profile):
    """Both nested front doors preserve the same depth budget across profiles."""
    leaf = _add(_builder(outer_profile), "leaf", b"contents").build()
    inner = _builder(inner_profile).add_nested("child", leaf).build()
    outer = _builder(outer_profile).add_nested("child", inner).build()
    reader = open_document(outer)
    child = reader.open_nested("child")
    assert isinstance(child, DocxPlusReader if inner_profile == "docx" else OdtPlusReader)
    assert child._nest_depth == 1
    grandchild = child.open_nested("child")
    assert grandchild._nest_depth == 2
    assert grandchild.extract("leaf") == b"contents"
    reader._nest_depth = DocxPlusReader.MAX_NEST_DEPTH - 1
    child = reader.open_nested("child")
    assert child._nest_depth == DocxPlusReader.MAX_NEST_DEPTH
    with pytest.raises(ContainerError, match="depth|nesting deeper"):
        child.open_nested("child")


def _wire_frames(envelopes):
    """Craft hostile wire shapes independently of the deliberately strict writer."""
    return b"".join(len(envelope).to_bytes(4, "big") + envelope for envelope in envelopes)


def _structural_envelope(**changes):
    fields = {
        "kdf_id": crypto.KDF_PBKDF2, "salt": b"s" * 16, "nonce": b"n" * 12,
        "params": (1).to_bytes(4, "big"), "ciphertext": b"t" * (256 + 16),
    }
    fields.update(changes)
    return crypto.EncryptedPayload(**fields).to_bytes()


@pytest.mark.parametrize("kind", ["extra", "many", "missing", "truncated", "bad_second", "bad_kdf"])
def test_password_frame_preflight_finishes_before_yield_or_derivation(kind):
    """CE06: even the first frame is unavailable until exactly two frames validate."""
    valid = _structural_envelope()
    cases = {
        "extra": _wire_frames([valid, valid, valid]),
        "many": _wire_frames([valid] * 100),
        "missing": _wire_frames([valid]),
        "truncated": _wire_frames([valid, valid])[:-1],
        "bad_second": _wire_frames([valid, b"DXE1"]),
        "bad_kdf": _wire_frames([valid, _structural_envelope(params=(crypto.MAX_PBKDF2_ITERATIONS + 1).to_bytes(4, "big"))]),
    }
    with pytest.raises(ContainerError):
        next(_iter_frames(cases[kind]))
    # Empty password would cause the first derivation to fail for a different
    # reason; structural preflight instead rejects malformed input on every path.
    with pytest.raises(ContainerError):
        _open_password_frames(cases[kind], "", b"m")


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("kdf", ["pbkdf2", "scrypt", "argon2id"])
def test_ordinary_and_decoy_frames_record_the_same_selected_kdf(profile, kdf):
    """CE07: chaff never advertises the default KDF beside a nondefault real frame."""
    ordinary = _add(_builder(profile), "m", b"secret", password="real", kdf=kdf).build()
    decoy = _builder(profile).add_decoy("m", real=b"secret", real_password="real",
                                      decoy=b"cover", decoy_password="cover", kdf=kdf).build()
    headers = []
    for data in (ordinary, decoy):
        reader = open_document(data)
        stored = reader._stored_bytes(reader.manifest.slot("m"))
        frames = [crypto.validate_password_envelope(frame) for frame in _iter_frames(stored)]
        headers.append([(frame.kdf_id, frame.params) for frame in frames])
        assert reader.extract("m", password="real") == b"secret"
    assert headers[0] == headers[1]


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_recomputed_share_checksum_cannot_replace_signed_full_share_digest(profile):
    """Threshold headers are checksums; every supplied share needs a signed commitment."""
    builder = _add(_builder(profile), "m", b"classified", threshold=(2, 3)).sign(_PRIVATE)
    reader = open_document(builder.build())
    shares = builder.threshold_shares["m"]
    assert reader.verify_provenance(expected_public_key=crypto.signing_public_key(_PRIVATE))
    assert reader.extract("m", shares=shares[:2]) == b"classified"
    forged = bytearray(shares[2])
    forged[-1] ^= 1
    forged[2:34] = hashlib.blake2b(bytes(forged[1:2]) + bytes(forged[34:]), digest_size=32).digest()
    forged = bytes(forged)
    assert shamir.verify_share_checksum(forged)
    # Include two genuine shares first: checking only the minimum prefix is unsafe.
    with pytest.raises(ContainerError):
        reader.extract("m", shares=[*shares[:2], forged])
    pkg = reader.package
    doc = json.loads(pkg.parts[MANIFEST_PART])
    del doc["modules"][0]["sealing"]["share_digests"]
    pkg.parts[MANIFEST_PART] = json.dumps(doc).encode()
    with pytest.raises(ValueError):
        open_document(pkg.to_bytes())


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_reproduction_api_distinguishes_self_consistency_from_pinned_authenticity(profile, tmp_path):
    """CE09: a self-signed authored claim is explicitly unauthenticated without a pin."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "input.txt").write_bytes(b"carried input")
    builder = _builder(profile).add_project("source", project)
    # Author-controlled metadata is a signed claim, not evidence of local execution.
    builder._pending[-1].reproduction = {
        "output_digest": "0" * 128, "command": ["python", "build.py"], "toolchain": {},
    }
    reader = open_document(builder.sign(_PRIVATE).build())
    unpinned = reader.verify_reproduction("source")
    assert unpinned["attested"] and unpinned["signed"] and unpinned["self_consistent"]
    assert not unpinned["authentic"] and not unpinned["verified"]
    assert "unverified_attestation" in unpinned and "attestation" not in unpinned
    pinned = reader.verify_reproduction("source", _PUBLIC)
    assert pinned["authentic"] and pinned["verified"] and pinned["self_consistent"]
    assert "attestation" in pinned
    wrong = reader.verify_reproduction("source", b"x" * 32)
    assert wrong["self_consistent"] and not wrong["authentic"] and not wrong["verified"]


@pytest.mark.parametrize("index", [CONTENT_TYPES_PART, ROOT_RELS_PART])
@pytest.mark.parametrize("fault", ["root_namespace", "child_namespace", "duplicate"])
def test_opc_index_namespace_and_declaration_uniqueness(index, fault):
    """A6: wrong-namespace or duplicate index declarations never project lossily."""
    data = _add(DocxPlusBuilder(), "m", b"x").build()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        root = ET.fromstring(archive.read(index))
    namespace = NS_CONTENT_TYPES if index == CONTENT_TYPES_PART else NS_RELATIONSHIPS
    if fault == "root_namespace":
        root.tag = "{urn:wrong}" + root.tag.split("}")[-1]
    elif fault == "child_namespace":
        root[0].tag = "{urn:wrong}" + root[0].tag.split("}")[-1]
    else:
        root.append(ET.fromstring(ET.tostring(root[0])))
    assert namespace in ET.tostring(root).decode() or fault == "root_namespace"
    with pytest.raises(OpcError, match="namespace|duplicate|unknown"):
        read_package(_rewrite(data, {index: ET.tostring(root)}))


@pytest.mark.parametrize("fault", ["root_namespace", "child_namespace", "duplicate"])
def test_odf_index_namespace_and_declaration_uniqueness(fault):
    """A6: ODF index declarations are exact namespace-qualified unique entries."""
    data = _add(OdtPlusBuilder(), "m", b"x").build()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        root = ET.fromstring(archive.read("META-INF/manifest.xml"))
    if fault == "root_namespace":
        root.tag = "{urn:wrong}manifest"
    elif fault == "child_namespace":
        root[0].tag = "{urn:wrong}file-entry"
    else:
        root.append(ET.fromstring(ET.tostring(root[0])))
    assert root[0].get(f"{{{NS_MANIFEST}}}full-path") == "/"
    with pytest.raises(OpcError, match="namespace|duplicate"):
        OdtPackage.from_bytes(_rewrite(data, {"META-INF/manifest.xml": ET.tostring(root)}))


@pytest.mark.parametrize("version", ["2.0", "1.0", "99.0", None])
def test_manifest_clean_cutover_rejects_unsupported_or_missing_version(version):
    """Format-3 signatures are never interpreted under an old or implicit version."""
    doc = json.loads(Manifest().to_bytes())
    if version is None:
        del doc["version"]
    else:
        doc["version"] = version
    with pytest.raises(ValueError, match="version|fields"):
        Manifest.from_bytes(json.dumps(doc).encode())


@pytest.mark.parametrize("nested", [False, True])
def test_manifest_rejects_duplicate_json_keys_at_every_depth(nested):
    """Duplicate keys cannot select different signed data in different JSON consumers."""
    raw = Manifest().to_bytes()
    if nested:
        raw = raw.replace(b'"algorithm": "ed25519"', b'"algorithm":"ed25519","algorithm":"ed25519"')
    else:
        raw = raw.replace(b'"version": "3.0"', b'"version":"3.0","version":"3.0"')
    with pytest.raises(ValueError, match="duplicate manifest JSON key"):
        Manifest.from_bytes(raw)


@pytest.mark.parametrize("field,value", [("size", "1"), ("encrypted", "false"), ("sealing", []), ("location", [])])
def test_manifest_rejects_coercible_but_wrong_module_field_types(field, value):
    """Schema checks occur before ChannelRecord's historical int/bool coercions."""
    data = _add(DocxPlusBuilder(), "m", b"x").build()
    doc = json.loads(read_package(data).parts[MANIFEST_PART])
    doc["modules"][0][field] = value
    with pytest.raises(ValueError, match="manifest module"):
        Manifest.from_bytes(json.dumps(doc).encode())


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("fault", ["extra", "malformed", "work"])
def test_serialized_password_modules_preflight_every_frame(profile, fault):
    """CE06 reaches shared unsealing through both real package reader boundaries."""
    valid = _structural_envelope()
    malformed = {
        "extra": _wire_frames([valid] * 3),
        "malformed": _wire_frames([valid, b"DXE1"]),
        "work": _wire_frames([
            valid,
            _structural_envelope(kdf_id=crypto.KDF_SCRYPT, params=bytes([15, 8, 64])),
        ]),
    }[fault]
    data = _add(_builder(profile), "m", malformed).build()
    pkg = _package(profile, data)
    doc = json.loads(pkg.parts[MANIFEST_PART])
    doc["modules"][0]["encrypted"] = True
    doc["modules"][0]["sealing"] = {"mode": "password"}
    pkg.parts[MANIFEST_PART] = json.dumps(doc).encode()
    reader = open_document(pkg.to_bytes())
    with pytest.raises(ContainerError):
        reader.extract("m", password="unused")


@pytest.mark.parametrize("version", [None, "1.2", "1.3", "1.4"])
def test_odf_root_index_version_is_preserved_and_authenticated(version):
    """ODF index authority is bound rather than discarded or silently regenerated."""
    base = new_base_odt()
    base.manifest_version = version
    data = _add(OdtPlusBuilder(base_package=base), "m", b"payload").sign(_PRIVATE).build()
    reader = open_document(data)
    assert reader.package.manifest_version == version
    assert reader.verify_provenance(_PUBLIC)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        root = ET.fromstring(archive.read("META-INF/manifest.xml"))
    root.set(f"{{{NS_MANIFEST}}}version", "1.2" if version == "1.3" else "1.3")
    altered = _rewrite(data, {"META-INF/manifest.xml": ET.tostring(root)})
    assert not open_document(altered).verify_provenance(_PUBLIC)


@pytest.mark.parametrize("path", ["mimetype", "META-INF/manifest.xml"])
def test_odf_reserved_index_declarations_are_not_silently_discarded(path):
    """Reserved index entries cannot disappear during a parse/serialize cycle."""
    data = _add(OdtPlusBuilder(), "m", b"x").build()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        root = ET.fromstring(archive.read("META-INF/manifest.xml"))
    ET.SubElement(root, f"{{{NS_MANIFEST}}}file-entry", {
        f"{{{NS_MANIFEST}}}full-path": path,
        f"{{{NS_MANIFEST}}}media-type": "text/plain",
    })
    with pytest.raises(OpcError, match="reserved ODF file-entry"):
        OdtPackage.from_bytes(_rewrite(data, {"META-INF/manifest.xml": ET.tostring(root)}))


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("hybrid", [False, True])
def test_duplicate_cosigners_refuse_before_mutating_base(profile, hybrid):
    key = crypto.generate_hybrid_signing_key().private_bytes if hybrid else _PRIVATE
    base = new_base_document(["preserved"]) if profile == "docx" else new_base_odt(["preserved"])
    before = base.to_bytes()
    builder = _add(_builder(profile, base_package=base), "m", b"payload")
    builder.add_cosigner(key).add_cosigner(key)
    with pytest.raises(ContainerError):
        builder.build()
    assert base.to_bytes() == before


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_empty_directory_markers_preserve_signed_logical_surface(profile):
    original = _add(_builder(profile), "m", b"payload").sign(_PRIVATE).build()
    reader = open_document(_rewrite(original, extras=[("Unused/", b""), ("Unused/Nested/", b"")]))
    assert reader.verify_provenance(_PUBLIC)
    assert reader.extract("m") == b"payload"


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_zip_directory_count_must_match_actual_records(profile):
    data = _add(_builder(profile), "m", b"payload").build()
    forged = bytearray(data)
    end = data.rfind(b"PK\x05\x06")
    forged[end + 8:end + 12] = b"\x01\x00\x01\x00"
    with pytest.raises(ContainerError):
        open_document(bytes(forged))


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_valid_zip_metadata_cannot_bypass_directory_allocation_budget(profile):
    data = _add(_builder(profile), "m", b"payload").build()
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, "w") as target:
        for entry in source.infolist():
            target.writestr(entry, source.read(entry))
        for index in range(129):
            entry = zipfile.ZipInfo(f"unused/{index}.bin")
            entry.comment = b"x" * 65535
            target.writestr(entry, b"")
    with pytest.raises(ContainerError):
        open_document(out.getvalue())


def test_noncanonical_physical_relationship_index_cannot_keep_signed_projection():
    base = new_base_document(["visible"])
    base.add_part("word/header.xml", f'<w:hdr xmlns:w="{NS_WORDML}"/>'.encode(),
                  "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml")
    base.add_relationship(Relationship("header", f"{NS_OFFICE_REL}/header", "header.xml"),
                          "word/document.xml")
    data = _add(DocxPlusBuilder(base_package=base), "m", b"payload").sign(_PRIVATE).build()
    assert open_document(data).verify_provenance(_PUBLIC)
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(out, "w") as target:
        for entry in source.infolist():
            name = ("word/document.xml/_rels/.rels" if entry.filename == "word/_rels/document.xml.rels"
                    else entry.filename)
            target.writestr(name, source.read(entry))
    with pytest.raises(OpcError):
        open_document(out.getvalue())


@pytest.mark.parametrize("attribute", ["version", "preferred-view-mode", "size"])
def test_odf_standard_entry_attributes_roundtrip_and_bind(attribute):
    base = new_base_odt(["visible"])
    path = "content.xml" if attribute == "size" else "/"
    value = {"version": "1.3", "preferred-view-mode": "read-only",
             "size": str(len(base.parts["content.xml"]))}[attribute]
    base.entry_attributes[path] = {attribute: value}
    data = _add(OdtPlusBuilder(base_package=base), "m", b"payload").sign(_PRIVATE).build()
    reader = open_document(data)
    assert reader.package.entry_attributes == {path: {attribute: value}}
    assert reader.verify_provenance(_PUBLIC)
    assert open_document(reader.package.to_bytes()).verify_provenance(_PUBLIC)
    del reader.package.entry_attributes[path]
    assert not open_document(reader.package.to_bytes()).verify_provenance(_PUBLIC)


def test_odf_case_sensitive_parts_and_subdocument_index_survive_serialization():
    base = new_base_odt(["visible"])
    base.add_part("Object 1/content.xml", base.parts["content.xml"], "text/xml")
    base.add_part("data/A.bin", b"upper")
    base.add_part("data/a.bin", b"lower")
    base.media_types["Object 1/"] = MIMETYPE_ODT.decode()
    base.entry_attributes["Object 1/"] = {"version": "1.3"}
    data = _add(OdtPlusBuilder(base_package=base), "m", b"payload").sign(_PRIVATE).build()
    reader = open_document(data)
    assert reader.package.parts["data/A.bin"] == b"upper"
    assert reader.package.parts["data/a.bin"] == b"lower"
    assert reader.package.entry_attributes["Object 1/"] == {"version": "1.3"}
    assert reader.verify_provenance(_PUBLIC)
    assert validate_odt_bytes(data).ok


@pytest.mark.parametrize("attributes", [{"preferred-view-mode": "vendor:view"}, {"size": "-1"}])
def test_odf_unsupported_or_invalid_entry_semantics_refuse(attributes):
    base = new_base_odt()
    base.entry_attributes["/"] = attributes
    with pytest.raises(OpcError):
        base.to_bytes()

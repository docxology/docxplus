"""Media channel over the pure-Python backend, plus the optional Rust backend."""

from __future__ import annotations

import pytest

from docxplus.channels import get_channel
from docxplus.opc import read_package
from docxplus.wordml import new_base_document

pytest.importorskip("PIL")


def test_python_lsb_channel_roundtrip(sample_payload):
    pkg = new_base_document(["A report with an embedded figure."])
    ch = get_channel("stego_media", backend="python_lsb", carrier_size=(128, 128))
    record = ch.embed(pkg, sample_payload, slot="hidden")
    assert record.location["backend"] == "python_lsb"
    # The carrier is a real, valid image part in word/media/.
    assert record.location["parts"][0].startswith("word/media/image")
    reparsed = read_package(pkg.to_bytes())
    assert ch.extract(reparsed, record) == sample_payload


def test_full_container_with_media_channel(sample_payload):
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.validate import validate_bytes

    data = (
        DocxPlusBuilder(paragraphs=["Quarterly summary."])
        .add_module("figure", "stego_media", sample_payload, backend="python_lsb")
        .build()
    )
    assert validate_bytes(data).ok
    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("figure") == sample_payload


def test_encrypted_media_channel(sample_payload):
    from docxplus.container import DocxPlusBuilder, DocxPlusReader

    data = (
        DocxPlusBuilder(paragraphs=["x"])
        .add_module("figure", "stego_media", sample_payload, password="pw", backend="python_lsb")
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("figure", password="pw") == sample_payload


def test_unknown_backend_rejected():
    with pytest.raises(ValueError, match="unknown stego backend"):
        get_channel("stego_media", backend="nope")


def test_capacity_reports_lsb_bound():
    ch = get_channel("stego_media", carrier_size=(64, 64))
    assert ch.capacity() == (64 * 64 * 3) // 8 - 8


def test_stego_media_error_paths():
    """A missing carrier refuses instead of returning unverifiable bytes."""
    channel = get_channel("stego_media", carrier_size=(128, 128))
    pkg = new_base_document(["visible"])
    record = channel.embed(pkg, b"payload", slot="s")
    assert channel.extract(pkg, record) == b"payload"
    del pkg.parts[record.location["parts"][0]]
    with pytest.raises(RuntimeError):
        channel.extract(pkg, record)



@pytest.mark.requires_steganographer
@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_steganographer_backend_roundtrip(sample_payload, profile):
    """Both serialized document profiles preserve real generic-packet bytes."""
    from docxplus import steg_bridge

    if not steg_bridge.available():
        pytest.skip("steganographer CLI not built")
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader
    from docxplus.validate import validate_bytes, validate_odt_bytes

    if profile == "docx":
        builder = DocxPlusBuilder(paragraphs=["Unsigned carrier."]).add_module(
            "packet", "stego_media", sample_payload,
            backend="steganographer", carrier_size=(128, 128),
        )
        reader_type, validate = DocxPlusReader, validate_bytes
    else:
        builder = OdtPlusBuilder(paragraphs=["Unsigned carrier."]).add_module(
            "packet", sample_payload, channel_id="stego_media",
            backend="steganographer", carrier_size=(128, 128),
        )
        reader_type, validate = OdtPlusReader, validate_odt_bytes
    data = builder.build()
    assert validate(data).ok
    reader = reader_type.from_bytes(data)
    assert reader.extract("packet") == sample_payload


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_supplied_png_capacity_and_display_use_actual_dimensions(tmp_path, profile):
    """C22: supplied carrier pixels, not the generated-size default, bound payloads."""
    from docxplus import lsb
    from docxplus.channels.stego_media import OdtStegMediaChannel, StegMediaChannel
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader
    from docxplus.validate import validate_bytes, validate_odt_bytes

    carrier = lsb.make_carrier(tmp_path / "actual.png", (37, 19))
    channel_type = StegMediaChannel if profile == "docx" else OdtStegMediaChannel
    channel = channel_type(carrier_png=carrier, carrier_size=(2, 2))
    assert channel.capacity() == lsb.capacity_bytes(37, 19)
    payload = b"x" * channel.capacity()
    options = {"carrier_png": carrier, "carrier_size": (2, 2)}
    if profile == "docx":
        builder = DocxPlusBuilder().add_module("s", "stego_media", payload, **options)
        reader_type, validate = DocxPlusReader, validate_bytes
    else:
        builder = OdtPlusBuilder().add_module("s", payload, channel_id="stego_media", **options)
        reader_type, validate = OdtPlusReader, validate_odt_bytes
    data = builder.build()
    assert validate(data).ok
    reader = reader_type.from_bytes(data)
    assert reader.extract("s") == payload
    if profile == "docx":
        xml = reader.package.parts["word/document.xml"].decode()
        assert 'cx="352425" cy="180975"' in xml
    else:
        xml = reader.package.parts["content.xml"].decode()
        assert 'svg:width="0.979cm" svg:height="0.503cm"' in xml
    with pytest.raises(ValueError, match="too large"):
        lsb.embed(carrier, payload + b"x", tmp_path / "too-large.png")


@pytest.mark.requires_steganographer
@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("supplied", [False, True])
def test_rust_media_capacity_is_exact_for_both_carrier_sources(tmp_path, profile, supplied):
    """C22: media-channel capacity is executable Rust capacity, not DXL1 sizing."""
    from docxplus import lsb, steg_bridge
    from docxplus.channels.stego_media import OdtStegMediaChannel, StegMediaChannel
    from docxplus.container import DocxPlusBuilder, DocxPlusReader
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    if not steg_bridge.available():
        pytest.skip("steganographer CLI not built")
    carrier = lsb.make_carrier(tmp_path / "actual.png", (64, 48)) if supplied else None
    options = {
        "backend": "steganographer", "carrier_png": carrier,
        "carrier_size": (2, 2) if supplied else (64, 48),
    }
    channel_type = StegMediaChannel if profile == "docx" else OdtStegMediaChannel
    capacity = channel_type(**options).capacity()
    assert capacity == steg_bridge.capacity(64 * 48 * 3)["max_payload_bytes"]
    assert capacity < lsb.capacity_bytes(64, 48)
    payload = b"x" * capacity
    if profile == "docx":
        builder = DocxPlusBuilder().add_module("s", "stego_media", payload, **options)
        reader_type = DocxPlusReader
    else:
        builder = OdtPlusBuilder().add_module("s", payload, channel_id="stego_media", **options)
        reader_type = OdtPlusReader
    reader = reader_type.from_bytes(builder.build())
    assert reader.extract("s") == payload
    with pytest.raises(steg_bridge.StegError):
        if profile == "docx":
            DocxPlusBuilder().add_module(
                "s", "stego_media", payload + b"x", **options
            ).build()
        else:
            OdtPlusBuilder().add_module(
                "s", payload + b"x", channel_id="stego_media", **options
            ).build()


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("fault", ["missing_backend", "obsolete_part_alias", "empty_parts"])
def test_serialized_media_location_has_no_implicit_decoder_or_part_alias(profile, fault):
    from docxplus.container import DocxPlusBuilder
    from docxplus.manifest import MANIFEST_PART
    from docxplus.odt_container import OdtPlusBuilder, open_document

    if profile == "docx":
        builder = DocxPlusBuilder().add_module("m", "stego_media", b"payload", carrier_size=(128, 128))
    else:
        builder = OdtPlusBuilder().add_module("m", b"payload", channel_id="stego_media",
                                             carrier_size=(128, 128))
    reader = open_document(builder.build())
    assert reader.extract("m") == b"payload"
    location = reader.manifest.slot("m").location
    if fault == "missing_backend":
        del location["backend"]
    elif fault == "obsolete_part_alias":
        location["part"] = location.pop("parts")[0]
    else:
        location["parts"] = []
    reader.package.parts[MANIFEST_PART] = reader.manifest.to_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        open_document(reader.package.to_bytes()).extract("m")


@pytest.mark.requires_steganographer
@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_unknown_decoder_cannot_extract_a_real_rust_packet(profile):
    from docxplus import steg_bridge
    from docxplus.container import DocxPlusBuilder
    from docxplus.manifest import MANIFEST_PART
    from docxplus.odt_container import OdtPlusBuilder, open_document

    if not steg_bridge.available():
        pytest.skip("steganographer CLI not available")
    options = {"backend": "steganographer", "carrier_size": (128, 128)}
    if profile == "docx":
        builder = DocxPlusBuilder().add_module("m", "stego_media", b"real packet", **options)
    else:
        builder = OdtPlusBuilder().add_module("m", b"real packet", channel_id="stego_media", **options)
    reader = open_document(builder.build())
    assert reader.extract("m") == b"real packet"
    reader.manifest.slot("m").location["backend"] = "undeclared-decoder"
    reader.package.parts[MANIFEST_PART] = reader.manifest.to_bytes()
    with pytest.raises((ValueError, RuntimeError)):
        open_document(reader.package.to_bytes()).extract("m")


@pytest.mark.parametrize("existing_id", ["2", "02", "+2"])
def test_drawing_ids_are_unique_across_body_and_header_without_renumbering(existing_id):
    import copy
    import xml.etree.ElementTree as ET

    from docxplus.channels.stego_media import REL_IMAGE
    from docxplus.opc import Relationship

    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    wp = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
    a = "http://schemas.openxmlformats.org/drawingml/2006/main"
    r = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg = new_base_document(["visible"])
    channel = get_channel("stego_media", carrier_size=(128, 128))
    first = channel.embed(pkg, b"first", slot="first")
    root = ET.fromstring(pkg.parts["word/document.xml"])
    root.find(f".//{{{wp}}}docPr").set("id", existing_id)
    header = ET.Element(f"{{{w}}}hdr")
    paragraph = ET.SubElement(header, f"{{{w}}}p")
    run = ET.SubElement(paragraph, f"{{{w}}}r")
    run.append(copy.deepcopy(root.find(f".//{{{w}}}drawing")))
    header.find(f".//{{{wp}}}docPr").set("id", "1")
    header.find(f".//{{{a}}}blip").set(f"{{{r}}}embed", "image")
    pkg.add_part("word/header.xml", ET.tostring(header),
                 "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml")
    pkg.add_relationship(Relationship("image", REL_IMAGE, first.location["parts"][0][len("word/"):]),
                         source_part="word/header.xml")
    header_id = pkg.next_rel_id("word/document.xml")
    pkg.add_relationship(Relationship(header_id, f"{r}/header", "header.xml"),
                         source_part="word/document.xml")
    body = root.find(f"{{{w}}}body")
    section = body.find(f"{{{w}}}sectPr")
    if section is None:
        section = ET.SubElement(body, f"{{{w}}}sectPr")
    section.insert(0, ET.Element(f"{{{w}}}headerReference",
                                {f"{{{r}}}id": header_id, f"{{{w}}}type": "default"}))
    pkg.parts["word/document.xml"] = ET.tostring(root)
    second = channel.embed(pkg, b"second", slot="second")
    reparsed = read_package(pkg.to_bytes())
    main_ids = [node.attrib["id"] for node in ET.fromstring(
        reparsed.parts["word/document.xml"]).iter(f"{{{wp}}}docPr")]
    header_ids = [node.attrib["id"] for node in ET.fromstring(
        reparsed.parts["word/header.xml"]).iter(f"{{{wp}}}docPr")]
    assert main_ids[0] == existing_id and header_ids == ["1"]
    all_ids = [int(value) for value in main_ids + header_ids]
    assert len(all_ids) == 3 and len(set(all_ids)) == 3
    assert channel.extract(reparsed, first) == b"first"
    assert channel.extract(reparsed, second) == b"second"


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("empty", [False, True])
def test_media_authoring_accepts_namespace_aliases_and_self_closing_bodies(profile, empty):
    import xml.etree.ElementTree as ET

    from docxplus.channels.stego_media import OdtStegMediaChannel, StegMediaChannel
    from docxplus.odt import OdtPackage, new_base_odt

    if profile == "docx":
        pkg = new_base_document(["visible"])
        part = "word/document.xml"
        text_tag = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}body"
        channel = StegMediaChannel(carrier_size=(128, 128))
    else:
        pkg = new_base_odt(["visible"])
        part = "content.xml"
        text_tag = "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}text"
        channel = OdtStegMediaChannel(carrier_size=(128, 128))
    root = ET.fromstring(pkg.parts[part])
    if empty:
        root.find(f".//{text_tag}").clear()
    pkg.parts[part] = ET.tostring(root, encoding="utf-8")
    record = channel.embed(pkg, b"namespace-safe payload", slot="m")
    reparsed = read_package(pkg.to_bytes()) if profile == "docx" else OdtPackage.from_bytes(pkg.to_bytes())
    assert channel.extract(reparsed, record) == b"namespace-safe payload"
    body = ET.fromstring(reparsed.parts[part]).find(f".//{text_tag}")
    if profile == "docx":
        assert body.find(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}drawing") is not None
    else:
        assert body.find(".//{urn:oasis:names:tc:opendocument:xmlns:drawing:1.0}frame") is not None

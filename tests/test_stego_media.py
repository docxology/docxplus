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
    """Verify error handling on stego_media extraction."""
    ch = get_channel("stego_media")
    from docxplus.channels.base import ChannelRecord

    # Missing parts in package
    pkg = new_base_document(["x"])
    rec = ChannelRecord.from_dict({
        "channel": "stego_media",
        "slot": "s",
        "size": 10,
        "digest": "d",
        "location": {"parts": ["word/media/nonexistent.png"]},
    })
    with pytest.raises(RuntimeError, match="no surviving media carrier"):
        ch.extract(pkg, rec)



@pytest.mark.requires_steganographer
def test_steganographer_backend_roundtrip(sample_payload):
    from docxplus import steg_bridge

    if not steg_bridge.available():
        pytest.skip("steganographer CLI not built")
    from docxplus.container import DocxPlusBuilder, DocxPlusReader

    data = (
        DocxPlusBuilder(paragraphs=["Signed carrier."])
        .add_module(
            "signed", "stego_media", sample_payload,
            backend="steganographer", carrier_size=(128, 128),
        )
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)
    assert reader.extract("signed") == sample_payload

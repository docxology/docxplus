"""Pure (toolchain-free) channels: embed/extract round-trips and limits."""

from __future__ import annotations

import pytest

from docxplus.channels import available_channels, get_channel
from docxplus.channels.metadata import MAX_PAYLOAD
from docxplus.wordml import new_base_document


@pytest.mark.parametrize("channel_id", ["custom_xml", "package_part", "metadata"])
def test_channel_roundtrip(channel_id, sample_payload):
    pkg = new_base_document(["surface text"])
    channel = get_channel(channel_id)
    record = channel.embed(pkg, sample_payload, slot="brief")
    assert record.channel == channel_id
    assert record.size == len(sample_payload)
    # Serialise + re-read so extraction works against parsed bytes, not the live obj.
    from docxplus.opc import read_package

    reparsed = read_package(pkg.to_bytes())
    assert channel.extract(reparsed, record) == sample_payload


def test_custom_xml_multiple_items_get_distinct_parts(sample_payload):
    pkg = new_base_document(["x"])
    ch = get_channel("custom_xml")
    r1 = ch.embed(pkg, b"one", slot="a")
    r2 = ch.embed(pkg, b"two", slot="b")
    assert r1.location["part"] != r2.location["part"]


def test_package_part_registers_default_type():
    pkg = new_base_document(["x"])
    ch = get_channel("package_part")
    rec = ch.embed(pkg, b"blob", slot="s")
    assert pkg.content_type_for(rec.location["part"]) == "application/vnd.docxplus.payload"


def test_metadata_rejects_oversized_payload():
    pkg = new_base_document(["x"])
    ch = get_channel("metadata")
    with pytest.raises(ValueError, match="at most"):
        ch.embed(pkg, b"A" * (MAX_PAYLOAD + 1), slot="big")


def test_metadata_multiple_properties_coexist():
    pkg = new_base_document(["x"])
    ch = get_channel("metadata")
    ch.embed(pkg, b"first", slot="a")
    r2 = ch.embed(pkg, b"second", slot="b")
    from docxplus.opc import read_package

    reparsed = read_package(pkg.to_bytes())
    assert ch.extract(reparsed, r2) == b"second"


def test_metadata_collision_refused():
    pkg = new_base_document(["x"])
    ch = get_channel("metadata")
    ch.embed(pkg, b"first", slot="collision_test")
    with pytest.raises(ValueError, match="metadata property collision"):
        ch.embed(pkg, b"second", slot="collision_test")



def test_capacity_reports():
    pkg = new_base_document(["x"])
    assert get_channel("custom_xml").capacity(pkg) is None
    assert get_channel("package_part").capacity(pkg) is None
    assert get_channel("metadata").capacity(pkg) == MAX_PAYLOAD


def test_unknown_channel_raises():
    with pytest.raises(ValueError, match="unknown channel"):
        get_channel("does_not_exist")


def test_available_channels_lists_media_toggle():
    assert "stego_media" in available_channels(include_media=True)
    assert "stego_media" not in available_channels(include_media=False)


def test_channel_record_roundtrip():
    """Cover ChannelRecord to_dict and from_dict mapping."""
    from docxplus.channels.base import ChannelRecord

    rec = ChannelRecord(
        channel="custom_xml",
        slot="test_slot",
        size=42,
        digest="abcd",
        encrypted=True,
        content_type="application/xml",
        payload_type="text",
        sealing={"mode": "password"},
        location={"part": "customXml/item1.xml"},
        reproduction={"command": ["python"]},
    )
    d = rec.to_dict()
    assert d["slot"] == "test_slot"
    assert d["encrypted"] is True

    rec2 = ChannelRecord.from_dict(d)
    assert rec2.slot == rec.slot
    assert rec2.digest == rec.digest
    assert rec2.encrypted == rec.encrypted
    assert rec2.sealing == rec.sealing
    assert rec2.reproduction == rec.reproduction


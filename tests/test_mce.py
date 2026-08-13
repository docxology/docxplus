"""Tests for the MCE AlternateContent channel."""

import pytest

from channels.mce import NS_DXP_MCE, NS_MC, MceChannel
from container import DocxPlusBuilder, DocxPlusReader
from wordml import new_base_document


def test_mce_channel_embed_and_extract_direct():
    pkg = new_base_document(["Hello from base document."])
    chan = MceChannel()
    payload = b"secret payload in MCE Choice branch"
    rec = chan.embed(pkg, payload, slot="mce_slot")

    assert rec.channel == "mce"
    assert rec.slot == "mce_slot"
    assert rec.size == len(payload)
    assert chan.capacity(pkg) is None

    extracted = chan.extract(pkg, rec)
    assert extracted == payload


def test_mce_channel_in_container_roundtrip():
    b = DocxPlusBuilder(paragraphs=["Testing MCE channel in full container."])
    b.add_module("intel", "mce", "Confidential Strategy Document", payload_type="text")
    b.add_module("cfg", "mce", {"key": "val", "count": 42}, payload_type="json")
    b.add_module("sec", "mce", b"Encrypted MCE Payload", password="pass")

    docx_bytes = b.build()
    reader = DocxPlusReader.from_bytes(docx_bytes)

    assert set(reader.list_modules()) == {"intel", "cfg", "sec"}
    assert reader.extract("intel", as_object=True) == "Confidential Strategy Document"
    assert reader.extract("cfg", as_object=True) == {"key": "val", "count": 42}
    assert reader.extract("sec", password="pass") == b"Encrypted MCE Payload"


def test_mce_markup_preserves_ignorable_choice():
    pkg = new_base_document(["Main text."])
    chan = MceChannel()
    chan.embed(pkg, b"data", slot="s1")
    doc_xml = pkg.parts["word/document.xml"].decode("utf-8")
    assert f'xmlns:mc="{NS_MC}"' in doc_xml
    assert f'xmlns:dxm="{NS_DXP_MCE}"' in doc_xml
    assert 'mc:Ignorable="dxm"' in doc_xml or 'mc:Ignorable=' in doc_xml
    assert "<mc:AlternateContent" in doc_xml
    assert '<mc:Choice Requires="dxm">' in doc_xml
    assert "<mc:Fallback>" in doc_xml


def test_mce_missing_part_or_slot_raises():
    pkg = new_base_document(["Main text."])
    chan = MceChannel()
    rec = chan.embed(pkg, b"data", slot="s1")

    # Tamper with slot in record
    rec_tampered = type(rec)(**{**rec.to_dict(), "slot": "nonexistent"})
    with pytest.raises(ValueError, match="not found"):
        chan.extract(pkg, rec_tampered)

    # Empty parts
    pkg_empty = new_base_document()
    pkg_empty.parts.clear()
    with pytest.raises(ValueError, match="missing from package"):
        chan.embed(pkg_empty, b"data", slot="s1")

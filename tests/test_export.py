"""Real cross-profile inert exports and descriptor-safe publication boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import stat

import pytest

from docxplus import crypto, payloads
from docxplus.container import DocxPlusBuilder, DocxPlusReader, _compute_surface_digest
from docxplus.export import _rename_noreplace, export_modules
from docxplus.manifest import MANIFEST_PART
from docxplus.odt import new_base_odt
from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader, compute_odt_surface_digest
from docxplus.wordml import new_base_document


@pytest.fixture(params=["docx", "odt"])
def profile(request):
    return request.param


def _builder(profile):
    return (DocxPlusBuilder(paragraphs=["export sentinel"]) if profile == "docx"
            else OdtPlusBuilder(paragraphs=["export sentinel"]))


def _add(builder, slot, obj, **kwargs):
    if isinstance(builder, DocxPlusBuilder):
        return builder.add_module(slot, "package_part", obj, **kwargs)
    return builder.add_module(slot, obj, **kwargs)


def _reader(profile, data):
    return (DocxPlusReader if profile == "docx" else OdtPlusReader).from_bytes(data)


def _refresh_unsigned(reader, profile):
    """Create a genuinely valid unsigned declaration for adversarial payload bytes."""
    reader.manifest.surface_digest = (
        _compute_surface_digest(reader.package)
        if profile == "docx" else compute_odt_surface_digest(reader.package)
    )
    reader.package.parts[MANIFEST_PART] = reader.manifest.to_bytes()
    return reader.package.to_bytes()


def _check_export(result, data, destination, expected, profile):
    assert result["schema"] == "docxplus.payload-export.v1"
    index = result["index"]
    assert index == json.loads((destination / "index.json").read_bytes())
    assert index["schema"] == "docxplus.payload-export-index.v1"
    assert index["profile"] == profile
    assert index["source_sha256"] == hashlib.sha256(data).hexdigest()
    assert [entry["slot"] for entry in index["modules"]] == sorted(expected)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    names = {"index.json"}
    reader = _reader(profile, data)
    for ordinal, entry in enumerate(index["modules"], 1):
        raw = expected[entry["slot"]]
        assert entry["file"] == f"module-{ordinal:06d}.bin"
        assert (destination / entry["file"]).read_bytes() == raw
        assert entry["bytes"] == len(raw)
        assert entry["sha256"] == hashlib.sha256(raw).hexdigest()
        assert entry["payload_type"] == reader.manifest.slot(entry["slot"]).payload_type
        assert entry["content_type"] == reader.manifest.slot(entry["slot"]).content_type
        names.add(entry["file"])
    assert {path.name for path in destination.iterdir()} == names
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in destination.iterdir())


@pytest.mark.parametrize("mode", ["plain", "password", "recipient", "threshold"])
def test_export_actual_sealing_modes(profile, mode, tmp_path):
    """Every sealing lineage exports exact packed bytes without claiming identity."""
    builder = _builder(profile)
    credentials = {}
    sealing = {}
    if mode == "password":
        sealing = {"password": "private export passphrase"}
        credentials = dict(sealing)
    elif mode == "recipient":
        private, public = crypto.generate_recipient_key()
        sealing = {"recipients": [public]}
        credentials = {"private_key": private}
    elif mode == "threshold":
        sealing = {"threshold": (2, 3)}
    _add(builder, "payload", b"\x00exact\xffpacked\n", **sealing)
    data = builder.build()
    if mode == "threshold":
        credentials = {"shares": builder.threshold_shares["payload"][:2]}
    source = tmp_path / f"source.{profile}"
    source.write_bytes(data)
    destination = tmp_path / "new" / "private" / "export"
    result = export_modules(source.read_bytes(), destination, **credentials)
    _check_export(result, data, destination, {"payload": b"\x00exact\xffpacked\n"}, profile)
    assert result["index"]["signature"]["authentic"] is None
    assert source.read_bytes() == data
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    encoded = (destination / "index.json").read_bytes()
    assert b"private export passphrase" not in encoded
    if "private_key" in credentials:
        assert credentials["private_key"].hex().encode() not in encoded
    if "shares" in credentials:
        assert all(share.hex().encode() not in encoded for share in credentials["shares"])


def test_export_types_slots_and_inert_recipes(profile, tmp_path):
    """Hostile aliases become ordinal files; custom codecs and carried code stay inert."""
    def refuse_unpack(blob):
        raise RuntimeError("this type is deliberately not decodable")

    payloads.register_type(payloads.PayloadType(
        "export-inert-custom", "application/x-inert", bytes, refuse_unpack
    ))
    builder = _builder(profile)
    expected = {}
    for slot in ("../escape", "/absolute", "A", "a", "é", "e\u0301", "x\\y", "line\nbreak"):
        raw = slot.encode("utf-8") + b"\x00"
        _add(builder, slot, raw)
        expected[slot] = raw
    objects = [
        ("text", "text", "Unicode λ\n"),
        ("json", "json", {"z": [1, 2], "a": "λ"}),
        ("custom", "export-inert-custom", b"\xffcustom\x00"),
        ("nested", "docxplus", b"not even an inner ZIP; never open me"),
        ("project", "project", b"not even a tarball; never unpack me"),
    ]
    for slot, kind, obj in objects:
        _add(builder, slot, obj, payload_type=kind)
        expected[slot] = payloads.get_type(kind).pack(obj)
    builder._pending[-1].reproduction = {
        "command": ["/bin/sh", "-c", f"touch {tmp_path / 'executed'}"]
    }
    data = builder.build()
    destination = tmp_path / "export"
    result = export_modules(data, destination)
    _check_export(result, data, destination, expected, profile)
    assert not (tmp_path / "executed").exists()
    assert not (tmp_path / "escape").exists()
    subset = tmp_path / "subset"
    chosen = ["project", "../escape", "A"]
    result = export_modules(data, subset, slots=chosen)
    _check_export(result, data, subset, {slot: expected[slot] for slot in chosen}, profile)


def test_noncanonical_json_and_unregistered_type_are_raw(profile, tmp_path):
    """Raw JSON whitespace and unknown custom ids survive without a codec lookup."""
    builder = _builder(profile)
    _add(builder, "json", {"a": 1}, payload_type="json")
    _add(builder, "unknown", b"opaque custom")
    reader = _reader(profile, builder.build())
    record = reader.manifest.slot("json")
    raw = b'{ "a" : 1, "z": [ 2 ] }\n'
    reader.package.parts[record.location["part"]] = raw
    record.size = len(raw)
    record.digest = crypto.digest(raw)
    reader.manifest.slot("unknown").payload_type = "not-registered-export-type"
    data = _refresh_unsigned(reader, profile)
    destination = tmp_path / "export"
    result = export_modules(data, destination)
    _check_export(result, data, destination, {"json": raw, "unknown": b"opaque custom"}, profile)


@pytest.mark.parametrize("selection", [[], ["a", "a"], ["missing"], "a", [1]])
def test_invalid_selection_precedes_output(profile, selection, tmp_path):
    """Empty, duplicate, absent or non-slot selections never create output parents."""
    data = _add(_builder(profile), "a", b"one").build()
    destination = tmp_path / "absent" / "export"
    with pytest.raises(ValueError):
        export_modules(data, destination, slots=selection)
    assert list(tmp_path.iterdir()) == []


def test_empty_manifest_exports_empty_index(profile, tmp_path):
    """An actual empty intelligence declaration differs from no intelligence."""
    data = _builder(profile).build()
    destination = tmp_path / "export"
    result = export_modules(data, destination)
    _check_export(result, data, destination, {}, profile)
    index_size = (destination / "index.json").stat().st_size
    export_modules(data, tmp_path / "exact", max_bytes=index_size)
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / "too-small", max_bytes=index_size - 1)
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / "explicit-empty", slots=[])
    assert not (tmp_path / "explicit-empty").exists()
    assert not (tmp_path / "too-small").exists()


@pytest.mark.parametrize("ordinary", [False, True])
def test_invalid_or_ordinary_document_refuses(profile, ordinary, tmp_path):
    """Neither malformed packages nor ordinary office files qualify as payload exports."""
    if ordinary:
        data = (new_base_document() if profile == "docx" else new_base_odt()).to_bytes()
    else:
        data = b"not an office ZIP"
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / "export")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("damage", ["root", "surface", "payload", "cosignature"])
def test_tampered_declaration_and_surface_refuse(profile, damage, tmp_path):
    """Serialized roots and every declared signature remain evidence, not reconstructed truth."""
    primary, _ = crypto.generate_signing_key()
    cosigner, _ = crypto.generate_signing_key()
    builder = _add(_builder(profile), "a", b"one").sign(primary).add_cosigner(cosigner)
    reader = _reader(profile, builder.build())
    if damage == "surface":
        part = "word/document.xml" if profile == "docx" else "content.xml"
        reader.package.parts[part] = reader.package.parts[part].replace(b"export sentinel", b"altered surface")
    elif damage == "payload":
        reader.package.parts[reader.manifest.slot("a").location["part"]] = b"altered"
    else:
        raw = json.loads(reader.package.parts[MANIFEST_PART])
        if damage == "root":
            raw["merkle_root"] = "0" * 64
        else:
            raw["cosignatures"][0]["value"] = "0" * 128
        reader.package.parts[MANIFEST_PART] = json.dumps(raw).encode()
    with pytest.raises(ValueError):
        export_modules(reader.package.to_bytes(), tmp_path / "export")
    assert list(tmp_path.iterdir()) == []


def test_primary_and_cosigner_pins_are_and_policy(profile, tmp_path):
    """Only complete pinned primary plus all required cosigners authorizes identity."""
    primary, public = crypto.generate_signing_key()
    cosigner, cosigner_public = crypto.generate_signing_key()
    _, other = crypto.generate_signing_key()
    data = _add(_builder(profile), "a", b"one").sign(primary).add_cosigner(cosigner).build()
    result = export_modules(
        data, tmp_path / "authentic", expected_public_key=public,
        require_cosigners=[cosigner_public],
    )
    assert result["index"]["signature"]["authentic"] is True
    assert result["index"]["signature"]["required_cosigners_verified"] is True
    policies = [
        {"expected_public_key": other},
        {"expected_public_key": public, "require_cosigners": [other]},
        {"require_cosigners": [cosigner_public]},
        {"expected_public_key": b"incomplete-key"},
    ]
    for ordinal, policy in enumerate(policies):
        destination = tmp_path / f"refuse-{ordinal}"
        with pytest.raises(ValueError):
            export_modules(data, destination, **policy)
        assert not destination.exists()
    unsigned = _add(_builder(profile), "a", b"one").build()
    with pytest.raises(ValueError):
        export_modules(unsigned, tmp_path / "unsigned", expected_public_key=public)
    assert not (tmp_path / "unsigned").exists()


def test_complete_hybrid_primary_pin(profile, tmp_path):
    """A hybrid signer authenticates only against its complete two-family identity."""
    key = crypto.generate_hybrid_signing_key()
    data = _add(_builder(profile), "a", b"one").sign(key.private_bytes).build()
    result = export_modules(data, tmp_path / "full", expected_public_key=key.public_bytes)
    assert result["index"]["signature"]["authentic"] is True
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / "partial", expected_public_key=key.public_bytes[:32])
    assert not (tmp_path / "partial").exists()


@pytest.mark.parametrize("mode", ["password", "recipient", "threshold", "tampered-envelope"])
def test_later_extraction_failure_removes_stage(profile, mode, tmp_path):
    """A later credential/AEAD failure removes already-staged earlier plaintext."""
    builder = _add(_builder(profile), "a-plain", b"already extracted")
    credentials = {}
    if mode in ("password", "tampered-envelope"):
        _add(builder, "z-sealed", b"secret", password="correct")
        credentials = {"password": "wrong credential not for errors"}
    elif mode == "recipient":
        _, public = crypto.generate_recipient_key()
        wrong_private, _ = crypto.generate_recipient_key()
        _add(builder, "z-sealed", b"secret", recipients=[public])
        credentials = {"private_key": wrong_private}
    else:
        _add(builder, "z-sealed", b"secret", threshold=(2, 3))
    data = builder.build()
    if mode == "threshold":
        credentials = {"shares": builder.threshold_shares["z-sealed"][:1]}
    if mode == "tampered-envelope":
        reader = _reader(profile, data)
        record = reader.manifest.slot("z-sealed")
        changed = bytearray(reader.package.parts[record.location["part"]])
        first_frame_end = 4 + int.from_bytes(changed[:4], "big")
        changed[first_frame_end - 1] ^= 1
        changed = bytes(changed)
        reader.package.parts[record.location["part"]] = changed
        record.digest = crypto.digest(changed)
        data = _refresh_unsigned(reader, profile)
        credentials = {"password": "correct"}
    with pytest.raises(ValueError) as error:
        export_modules(data, tmp_path / "export", **credentials)
    assert "wrong credential not for errors" not in str(error.value)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("encrypted", [False, True])
def test_payload_plus_index_exact_byte_boundary(profile, encrypted, tmp_path):
    """The limit includes the actual index, not just plaintext or envelope sizes."""
    sealing = {"password": "pass"} if encrypted else {}
    data = _add(_builder(profile), "payload", b"x" * 1234, **sealing).build()
    baseline = tmp_path / "baseline"
    export_modules(data, baseline, **sealing)
    size = sum(path.stat().st_size for path in baseline.iterdir())
    export_modules(data, tmp_path / "exact", max_bytes=size, max_modules=1, **sealing)
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / "short", max_bytes=size - 1, **sealing)
    assert not (tmp_path / "short").exists()
    assert not list(tmp_path.glob(".docxplus-export-*"))
    if encrypted:
        assert _reader(profile, data).manifest.slot("payload").size > size


def test_module_count_selection_and_preflight(profile, tmp_path):
    """Count limits apply to selected modules, and declarations can refuse pre-output."""
    builder = _add(_builder(profile), "a", b"x" * 4096)
    data = _add(builder, "b", b"y").build()
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / "count", max_modules=1)
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / "parent" / "size", max_bytes=4096)
    assert list(tmp_path.iterdir()) == []
    result = export_modules(data, tmp_path / "selected", slots=["b"], max_modules=1)
    assert [entry["slot"] for entry in result["index"]["modules"]] == ["b"]
    assert (tmp_path / "selected" / result["index"]["modules"][0]["file"]).read_bytes() == b"y"


@pytest.mark.parametrize("name", ["max_bytes", "max_modules"])
@pytest.mark.parametrize("value", [0, -1, True, False, 1.5, "1", None])
def test_limits_require_positive_nonbool_integers(name, value, tmp_path):
    """Invalid limit types cannot reach inspection or output creation."""
    with pytest.raises(ValueError):
        export_modules(b"", tmp_path / "export", **{name: value})
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("kind", ["empty", "nonempty", "file", "symlink", "dangling"])
def test_occupied_destination_is_preserved(profile, kind, tmp_path):
    """Absent means absent: empty folders and dangling symlinks are never replaced."""
    data = _add(_builder(profile), "a", b"one").build()
    destination = tmp_path / "destination"
    if kind in ("empty", "nonempty"):
        destination.mkdir()
        if kind == "nonempty":
            (destination / "keep").write_bytes(b"preserve")
    elif kind == "file":
        destination.write_bytes(b"preserve")
    else:
        target = tmp_path / "target"
        if kind == "symlink":
            target.mkdir()
            (target / "keep").write_bytes(b"preserve")
        destination.symlink_to(target, target_is_directory=True)
    before = destination.lstat()
    with pytest.raises(FileExistsError):
        export_modules(data, destination)
    after = destination.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev, before.st_ino, before.st_mode
    )
    if kind == "nonempty":
        assert (destination / "keep").read_bytes() == b"preserve"
    elif kind == "file":
        assert destination.read_bytes() == b"preserve"
    elif kind == "empty":
        assert list(destination.iterdir()) == []
    elif kind == "symlink":
        assert (tmp_path / "target" / "keep").read_bytes() == b"preserve"
    assert not list(tmp_path.glob(".docxplus-export-*"))


def test_symlink_ancestor_refuses(profile, tmp_path):
    """Parent traversal never follows a link, including an intermediate ancestor."""
    data = _add(_builder(profile), "a", b"one").build()
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        export_modules(data, link / "new" / "export")
    assert link.is_symlink()
    assert list(target.iterdir()) == []
    assert not list(tmp_path.glob(".docxplus-export-*"))


@pytest.mark.parametrize("kind", ["empty", "nonempty", "file", "dangling"])
def test_native_no_replace_refuses_late_occupation(kind, tmp_path):
    """The genuine native primitive refuses occupation after an earlier absence check."""
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    (stage / "payload.bin").write_bytes(b"complete stage")
    destination = tmp_path / "destination"
    assert not destination.exists()
    # Deliberately occupy after the check; no race timing or mocked syscall.
    if kind in ("empty", "nonempty"):
        destination.mkdir()
        if kind == "nonempty":
            (destination / "keep").write_bytes(b"preserve")
    elif kind == "file":
        destination.write_bytes(b"preserve")
    else:
        destination.symlink_to(tmp_path / "absent")
    inode = destination.lstat().st_ino
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(FileExistsError):
            _rename_noreplace(parent, "stage", parent, "destination")
        assert destination.lstat().st_ino == inode
        assert (stage / "payload.bin").read_bytes() == b"complete stage"
        _rename_noreplace(parent, "stage", parent, "published")
    finally:
        os.close(parent)
    assert (tmp_path / "published" / "payload.bin").read_bytes() == b"complete stage"
    assert not stage.exists()


def test_native_publication_uses_pinned_parent(tmp_path):
    """Ancestor substitution cannot redirect the native descriptor-relative publish."""
    original = tmp_path / "parent"
    original.mkdir()
    (original / "stage").mkdir()
    (original / "stage" / "payload.bin").write_bytes(b"pinned")
    other = tmp_path / "other"
    other.mkdir()
    parent = os.open(original, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    retained = tmp_path / "retained"
    original.rename(retained)
    original.symlink_to(other, target_is_directory=True)
    try:
        _rename_noreplace(parent, "stage", parent, "published")
    finally:
        os.close(parent)
    assert (retained / "published" / "payload.bin").read_bytes() == b"pinned"
    assert list(other.iterdir()) == []


@pytest.mark.parametrize('selection', [None, ['a']])
def test_multiple_threshold_modules_accept_one_committed_share_bundle(profile, selection, tmp_path):
    """Independent signed share sets can recover all modules or a selected subset."""
    builder = _builder(profile)
    for slot in ('a', 'b'):
        _add(builder, slot, slot.encode(), threshold=(2, 3))
    primary = bytes(range(32))
    data = builder.sign(primary).build()
    bundle = builder.threshold_shares['a'][:2] + builder.threshold_shares['b'][:2]
    destination = tmp_path / 'export'
    result = export_modules(data, destination, slots=selection, shares=bundle,
                            expected_public_key=crypto.signing_public_key(primary))
    expected = {slot: slot.encode() for slot in (selection or ('a', 'b'))}
    _check_export(result, data, destination, expected, profile)
    with pytest.raises(ValueError):
        export_modules(data, tmp_path / 'unknown', slots=selection, shares=[*bundle, b'unknown'])
    assert not (tmp_path / 'unknown').exists()


@pytest.mark.parametrize('mode', [0o770, 0o707, 0o777])
def test_export_refuses_peer_writable_publication_parent(profile, mode, tmp_path):
    """An unrelated UID must not control staging or the published entry's parent."""
    parent = tmp_path / 'unsafe'
    parent.mkdir()
    parent.chmod(mode)
    sentinel = parent / 'unrelated'
    sentinel.write_bytes(b'preserve')
    data = _add(_builder(profile), 'a', b'private').build()
    with pytest.raises(PermissionError):
        export_modules(data, parent / 'export')
    assert sentinel.read_bytes() == b'preserve'
    assert set(parent.iterdir()) == {sentinel}
    assert stat.S_IMODE(parent.stat().st_mode) == mode


def test_native_publication_retains_source_when_holder_name_is_substituted(tmp_path):
    """Publication resolves the private child through its held source descriptor."""
    parent = tmp_path / 'parent'
    parent.mkdir()
    holder = parent / 'holder'
    holder.mkdir(mode=0o700)
    (holder / 'payloads').mkdir(mode=0o700)
    (holder / 'payloads' / 'private.bin').write_bytes(b'actual payload')
    source_fd = os.open(holder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    holder.rename(parent / 'displaced')
    (holder / 'payloads').mkdir(parents=True)
    marker = holder / 'payloads' / 'marker'
    marker.write_bytes(b'substitution')
    try:
        _rename_noreplace(source_fd, 'payloads', parent_fd, 'published')
    finally:
        os.close(source_fd)
        os.close(parent_fd)
    assert (parent / 'published' / 'private.bin').read_bytes() == b'actual payload'
    assert marker.read_bytes() == b'substitution'
    assert not (parent / 'published' / 'marker').exists()

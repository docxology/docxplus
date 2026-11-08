"""Real I/O regressions for decoder discovery, XML intake and typed CLI inputs."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from docxplus import intake, lsb, steg_bridge
from docxplus.odt_container import open_document


def _cli(args):
    return subprocess.run(
        [sys.executable, "-m", "docxplus.cli", *args],
        capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
    )


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("payload_type", ["bytes", "text", "json"])
@pytest.mark.parametrize("threshold", [False, True])
def test_cli_typed_files_roundtrip(tmp_path, profile, payload_type, threshold):
    """F7: files become semantic objects before ordinary or threshold packing."""
    values = {
        "bytes": (b"\x00\xffbinary\r\n", b"\x00\xffbinary\r\n"),
        "text": ("héllo\r\n世界\n".encode(), "héllo\r\n世界\n"),
        "json": (' {"z": [1, true, null], "é": {"x": "世界"}}\n'.encode(),
                 {"z": [1, True, None], "é": {"x": "世界"}}),
    }
    encoded, expected = values[payload_type]
    src = tmp_path / "input"
    src.write_bytes(encoded)
    document = tmp_path / f"typed.{profile}"
    module = f"m:package_part:{src}" if profile == "docx" else f"m:{src}"
    command = "build" if profile == "docx" else "odt-build"
    args = [command, str(document), "--module", module, "--payload-type", payload_type]
    shares = tmp_path / "shares"
    if threshold:
        args += ["--threshold", "2:3", "--shares-dir", str(shares)]
    result = _cli(args)
    assert result.returncode == 0, result.stderr
    reader = open_document(document.read_bytes())
    assert reader.manifest.slot("m").payload_type == payload_type
    creds = {}
    if threshold:
        creds["shares"] = [p.read_bytes() for p in sorted(shares.glob("m.share*.bin"))[:2]]
    assert reader.extract("m", as_object=True, **creds) == expected
    expected_bytes = (
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
        if payload_type == "json" else encoded
    )
    assert reader.extract("m", **creds) == expected_bytes


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("payload_type,encoded", [
    ("json", b'{"unfinished":'), ("text", b"\xff"), ("json", b"\xff"),
    ("project", b"not a packed project"), ("docxplus", b"not a document"),
])
def test_cli_bad_typed_input_preserves_outputs(tmp_path, profile, payload_type, encoded):
    """Input errors refuse cleanly before replacing either output spelling."""
    src = tmp_path / "bad"
    src.write_bytes(encoded)
    document = tmp_path / f"existing.{profile}"
    plus = document.with_suffix(f".{profile}plus")
    document.write_bytes(b"previous document")
    plus.write_bytes(b"previous plus document")
    module = f"m:package_part:{src}" if profile == "docx" else f"m:{src}"
    command = "build" if profile == "docx" else "odt-build"
    rejected = _cli([command, str(document), "--module", module,
                     "--payload-type", payload_type, "--threshold", "2:3"])
    assert rejected.returncode == 2
    assert "error:" in rejected.stderr and "Traceback" not in rejected.stderr
    assert document.read_bytes() == b"previous document"
    assert plus.read_bytes() == b"previous plus document"


def test_installed_layout_ignores_hostile_cwd_sibling(tmp_path):
    """F2: relocatable installed-layout imports never select a carried decoder."""
    import docxplus

    site = tmp_path / "site"
    shutil.copytree(Path(docxplus.__file__).parent, site / "docxplus",
                    ignore=shutil.ignore_patterns("__pycache__"))
    reader_dir = tmp_path / "carried" / "reader"
    reader_dir.mkdir(parents=True)
    executable = reader_dir.parent / "steganographer/target/release/steganographer"
    executable.parent.mkdir(parents=True)
    marker = tmp_path / "executed"
    executable.write_text(f"#!/bin/sh\nprintf executed > '{marker}'\nexit 3\n")
    executable.chmod(0o755)
    env = dict(os.environ, PYTHONPATH=str(site), PATH=str(tmp_path / "empty-path"))
    env.pop("STEGANOGRAPHER_BIN", None)
    result = subprocess.run([
        sys.executable, "-c",
        (
            "from pathlib import Path; from docxplus import steg_bridge as s; "
            "s.extract_payload(Path('carrier.png'), Path('out.bin'))"
        ),
    ], cwd=reader_dir, env=env, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "CLI not available" in result.stderr
    assert not marker.exists()


@pytest.mark.parametrize("invalid", ["missing", "directory", "nonexecuting", "empty"])
def test_explicit_invalid_backend_never_falls_through(tmp_path, monkeypatch, invalid):
    """Explicit bad configuration is a failure even with a usable PATH candidate."""
    on_path = tmp_path / "bin"
    on_path.mkdir()
    (on_path / "steganographer").symlink_to(sys.executable)
    monkeypatch.setenv("PATH", str(on_path))
    configured = tmp_path / invalid
    if invalid == "directory":
        configured.mkdir()
    elif invalid == "nonexecuting":
        configured.write_text("not executable")
        configured.chmod(0o600)
    monkeypatch.setenv("STEGANOGRAPHER_BIN", "" if invalid == "empty" else str(configured))
    with pytest.raises(steg_bridge.StegError, match="STEGANOGRAPHER_BIN"):
        steg_bridge.available()


def test_explicit_repo_requires_built_binary_without_cargo(tmp_path, monkeypatch):
    """Dependency checkouts never compile; explicit already-built tools still work."""
    monkeypatch.delenv("STEGANOGRAPHER_BIN", raising=False)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "cargo-ran"
    cargo = bindir / "cargo"
    cargo.write_text(f"#!/bin/sh\nprintf cargo > '{marker}'\nexit 4\n")
    cargo.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    repo = tmp_path / "dependency"
    repo.mkdir()
    (repo / "Cargo.toml").write_text("[workspace]\n")
    assert steg_bridge.locate() is None
    with pytest.raises(steg_bridge.StegError, match="no built"):
        steg_bridge.locate(repo)
    assert not marker.exists()
    binary = repo / "target/release/steganographer"
    binary.parent.mkdir(parents=True)
    binary.symlink_to(sys.executable)
    tool = steg_bridge.locate(repo)
    assert steg_bridge._run(tool, ["-c", "print('explicit backend')"]).stdout == b"explicit backend\n"
    monkeypatch.setenv("STEGANOGRAPHER_BIN", str(binary))
    assert steg_bridge.locate() == tool


def test_backend_deadline_and_closed_stdin():
    """Real subprocess timeout is StegError, and decoder stdin cannot prompt."""
    tool = steg_bridge.StegTool((sys.executable,), None, "binary")
    with pytest.raises(steg_bridge.StegError, match="timed out"):
        steg_bridge._run(tool, ["-c", "import time; time.sleep(10)"], timeout=0.05)
    result = steg_bridge._run(tool, ["-c", "import sys; assert sys.stdin.buffer.read() == b''"])
    assert result.returncode == 0


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"])
def test_declared_xml_encodings_cannot_hide_altchunk(encoding):
    """F3: the XML parser, not an ASCII prefilter, identifies actual imports."""
    from docxplus.opc import OpcPackage, Relationship

    pkg = OpcPackage()
    pkg.set_default_type("rels", "application/xml")
    namespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    relationship_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    xml = (f'<?xml version="1.0" encoding="{encoding}"?>'
           f'<w:document xmlns:w="{namespace}" xmlns:r="{relationship_ns}">'
           '<w:body><w:altChunk r:id="import"/></w:body></w:document>')
    pkg.add_part("word/document.xml", xml.encode(encoding),
                 "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")
    pkg.add_part("word/chunk.html", b"<html><body>Imported</body></html>", "text/html")
    pkg.add_relationship(Relationship("main", relationship_ns + "/officeDocument", "word/document.xml"))
    pkg.add_relationship(Relationship("import", relationship_ns + "/aFChunk", "chunk.html"),
                         source_part="word/document.xml")
    data = pkg.to_bytes()
    report, _ = intake.safe_open(data)
    assert report.altchunk_imports == ["word/document.xml"]
    with pytest.raises(intake.IntakeError):
        intake.safe_open(data, policy=intake.IntakePolicy(strict=True))
    report, _ = intake.safe_open(data, policy=intake.IntakePolicy(strict=True, allow_altchunk=True))
    assert report.ok


@pytest.mark.parametrize("href", ["//outside.invalid/a", "custom+transport:target", "mailto:a@example.invalid", "file:/tmp/resource"])
def test_odf_nested_xml_honors_allow_policy_and_reports_uris(href):
    """ODF allow flags match DOCX and nested declared XML is not a scan blind spot."""
    from docxplus.odt import OdtPackage

    pkg = OdtPackage()
    pkg.add_part("content.xml", b'<root/>', "text/xml")
    pkg.add_part("Basic/module.bin", b"macro", "application/octet-stream")
    xml = (f'<root xmlns:xlink="http://www.w3.org/1999/xlink">'
           f'<image xlink:href="{href}"/><scripts/></root>').encode()
    pkg.add_part("Object 1/custom.dat", xml, "application/example+xml")
    data = pkg.to_bytes()
    report, _ = intake.safe_open_odt(data)
    assert report.external_relationships == [f"Object 1/custom.dat -> {href}"]
    assert set(report.macro_parts) == {"Basic/module.bin", "Object 1/custom.dat (script declarations)"}
    with pytest.raises(intake.IntakeError):
        intake.safe_open_odt(data, policy=intake.IntakePolicy(strict=True))
    allowed, _ = intake.safe_open_odt(data, policy=intake.IntakePolicy(
        strict=True, allow_macros=True, allow_external_relationships=True))
    assert allowed.ok
    macros_allowed, _ = intake.safe_open_odt(data, policy=intake.IntakePolicy(allow_macros=True))
    assert not macros_allowed.macro_parts and macros_allowed.external_relationships
    links_allowed, _ = intake.safe_open_odt(data, policy=intake.IntakePolicy(allow_external_relationships=True))
    assert not links_allowed.external_relationships and links_allowed.macro_parts


def test_odf_local_references_remain_local():
    """Ordinary relative paths and fragments must not be called external links."""
    from docxplus.odt import OdtPackage

    pkg = OdtPackage()
    pkg.add_part("content.xml", b'<root xmlns:xlink="http://www.w3.org/1999/xlink">'
                 b'<a xlink:href="#fragment"/><a xlink:href="Pictures/image.png"/></root>', "text/xml")
    report, _ = intake.safe_open_odt(pkg.to_bytes(), policy=intake.IntakePolicy(strict=True))
    assert report.ok


def _frame_carrier(path, size, frame):
    from PIL import Image

    with Image.new("RGB", size) as image:
        px = image.load()
        for i in range(min(len(frame) * 8, size[0] * size[1] * 3)):
            pixel, channel = divmod(i, 3)
            x, y = pixel % size[0], pixel // size[0]
            channels = list(px[x, y])
            channels[channel] = (frame[i // 8] >> (7 - i % 8)) & 1
            px[x, y] = tuple(channels)
        image.save(path, "PNG")
    return path


def test_lsb_refuses_short_header_and_impossible_length(tmp_path):
    """F6: truncated frames fail before payload allocation rather than returning prefixes."""
    pytest.importorskip("PIL")
    tiny = _frame_carrier(tmp_path / "tiny.png", (4, 4), b"DXL1" + b"\x00" * 4)
    with pytest.raises(ValueError):
        lsb.extract(tiny)
    forged = _frame_carrier(tmp_path / "forged.png", (32, 32), b"DXL1" + b"\xff" * 4)
    with pytest.raises(ValueError):
        lsb.extract(forged)
    with pytest.raises(ValueError):
        lsb.embed(tiny, b"", tmp_path / "out.png")
    assert not (tmp_path / "out.png").exists()


@pytest.mark.parametrize("size", [(8, 8), (17, 19)])
def test_lsb_exact_capacity_and_empty_payload(tmp_path, size):
    """Every complete byte fits, residual sub-byte RGB samples do not change framing."""
    pytest.importorskip("PIL")
    carrier = lsb.make_carrier(tmp_path / "carrier.png", size)
    for payload in (b"", hashlib.shake_256(b"fixed payload").digest(lsb.capacity_bytes(*size))):
        encoded = lsb.embed(carrier, payload, tmp_path / "encoded.png")
        assert lsb.extract(encoded) == payload


def test_carrier_pixel_budget_precedes_decode_and_analysis(tmp_path):
    """A small compressed PNG cannot demand unbounded decoded RGB/sample storage."""
    Image = pytest.importorskip("PIL.Image")
    path = tmp_path / "oversized.png"
    with Image.new("1", (4001, 4000)) as image:
        image.save(path, "PNG")
    for operation in (lsb.extract, steg_bridge.chi_square_lsb, steg_bridge.chi_square_sweep):
        with pytest.raises(ValueError, match="pixel count"):
            operation(path)


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_malformed_lsb_media_refused_after_serialization(tmp_path, profile):
    """Both media consumers propagate malformed framing instead of decoded prefixes."""
    pytest.importorskip("PIL")
    from docxplus.container import DocxPlusBuilder
    from docxplus.odt_container import OdtPlusBuilder

    if profile == "docx":
        builder = DocxPlusBuilder().add_module("m", "stego_media", b"real payload",
                                              backend="python_lsb", carrier_size=(32, 32))
    else:
        builder = OdtPlusBuilder().add_module("m", b"real payload", channel_id="stego_media",
                                             backend="python_lsb", carrier_size=(32, 32))
    reader = open_document(builder.build())
    assert reader.extract("m") == b"real payload"
    forged = _frame_carrier(tmp_path / "forged.png", (32, 32), b"DXL1" + b"\xff" * 4)
    for part in reader.manifest.slot("m").location["parts"]:
        reader.package.parts[part] = forged.read_bytes()
    reparsed = open_document(reader.package.to_bytes())
    with pytest.raises((ValueError, RuntimeError), match="carrier|capacity"):
        reparsed.extract("m")


def test_configured_backend_runtime_failure_is_not_absence(tmp_path, monkeypatch):
    """A configured executable's real exit error propagates through media embedding."""
    monkeypatch.setenv("STEGANOGRAPHER_BIN", sys.executable)
    with pytest.raises(steg_bridge.StegError, match="failed \\(exit"):
        steg_bridge.embed_payload(tmp_path / "input.png", b"payload", tmp_path / "output.png")
    assert not (tmp_path / "output.png").exists()


def test_reproduction_cli_labels_unpinned_claim_self_consistent(tmp_path):
    """A real signed claim is not authentic until the CLI pins the author's key."""
    from docxplus import crypto
    from docxplus.container import DocxPlusBuilder

    source = tmp_path / "project"
    source.mkdir()
    (source / "input.txt").write_text("carried source")
    private, public = crypto.generate_signing_key()
    builder = DocxPlusBuilder().add_project("source", source)
    # Construct an author's claim, not a receipt from an executed experiment.
    # Verification authenticates the signed assertion, not its factual truth.
    builder._pending[-1].reproduction = {
        "output_digest": "author-asserted-output", "command": ["never-execute-me"],
        "toolchain": {"python": "author-asserted"},
    }
    document = tmp_path / "signed.docx"
    document.write_bytes(builder.sign(private).build())
    unpinned = _cli(["verify-reproduction", str(document), "source"])
    assert unpinned.returncode == 0, unpinned.stderr
    report = json.loads(unpinned.stdout)
    assert report["self_consistent"] is True
    assert report["verified"] is False and report["authentic"] is False
    assert "self-consistency is not authenticity" in report["_warning"]
    assert "attestation" not in report and "unverified_attestation" in report
    key = tmp_path / "author.pub"
    key.write_text(public.hex())
    pinned = _cli(["verify-reproduction", str(document), "source", "--expected-key", str(key)])
    assert pinned.returncode == 0, pinned.stderr
    assert json.loads(pinned.stdout)["verified"] is True
    _, outsider = crypto.generate_signing_key()
    key.write_text(outsider.hex())
    rejected = _cli(["verify-reproduction", str(document), "source", "--expected-key", str(key)])
    assert rejected.returncode == 1
    assert json.loads(rejected.stdout)["verified"] is False


def test_prefix_pair_statistics_match_independent_reference_distributions(tmp_path):
    """Prefix boundaries change the populated pairs, statistic and reference tail."""
    import math

    Image = pytest.importorskip("PIL.Image")
    carrier = tmp_path / "samples.png"
    pixels = bytes([40, 41, 40]) * 24 + bytes([80, 81, 81]) * 24
    with Image.frombytes("RGB", (48, 1), pixels) as image:
        image.save(carrier, "PNG")
    half, whole = steg_bridge.chi_square_sweep(carrier, steps=2)["steps"]
    assert half["available"] and whole["available"]
    assert half["fraction"] == 0.5 and whole["fraction"] == 1.0
    assert half["dof"] == 1 and whole["dof"] == 2
    assert half["chi2"] == pytest.approx(8.0)
    assert whole["chi2"] == pytest.approx(16.0)
    assert half["p_value"] == pytest.approx(math.erfc(2.0))
    assert whole["p_value"] == pytest.approx(math.exp(-8.0))


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_unscannable_xml_is_not_a_clean_intake_observation(profile):
    from docxplus.odt import new_base_odt
    from docxplus.wordml import new_base_document

    pkg = new_base_document(["visible"]) if profile == "docx" else new_base_odt(["visible"])
    part = "word/document.xml" if profile == "docx" else "content.xml"
    pkg.parts[part] = b'<!DOCTYPE root [<!ENTITY forbidden "value">]><root/>'
    scanner = intake.safe_open if profile == "docx" else intake.safe_open_odt
    data = pkg.to_bytes()
    report, _ = scanner(data)
    assert not report.ok and report.parse_errors == [part]
    with pytest.raises(intake.IntakeError):
        scanner(data, policy=intake.IntakePolicy(strict=True, allow_altchunk=True,
                                                allow_macros=True, allow_external_relationships=True))


@pytest.mark.parametrize("part,href,external", [
    ("content.xml", "../outside.svg", True),
    ("content.xml", "%2e%2e%2foutside.svg", True),
    ("Object 1/content.xml", "../../outside.svg", True),
    ("Object 1/content.xml", "../Pictures/image.png", False),
    ("Object 1/content.xml", "#local", False),
])
def test_odf_hrefs_resolve_against_their_containing_part(part, href, external):
    from docxplus.odt import new_base_odt

    pkg = new_base_odt()
    xml = (f'<root xmlns:xlink="http://www.w3.org/1999/xlink">'
           f'<image xlink:href="{href}"/></root>').encode()
    if part in pkg.parts:
        pkg.parts[part] = xml
    else:
        pkg.add_part(part, xml, "text/xml")
    report, _ = intake.safe_open_odt(pkg.to_bytes())
    assert bool(report.external_relationships) is external
    if external:
        with pytest.raises(intake.IntakeError):
            intake.safe_open_odt(pkg.to_bytes(), policy=intake.IntakePolicy(strict=True))


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_cli_duplicate_cosigner_identity_preserves_both_outputs(tmp_path, profile):
    private = bytes(range(32)).hex()
    keys = [tmp_path / "first.key", tmp_path / "same-identity.key"]
    for key in keys:
        key.write_text(private, encoding="ascii")
    payload = tmp_path / "payload"
    payload.write_bytes(b"consumer data")
    command = "build" if profile == "docx" else "odt-build"
    module = f"m:package_part:{payload}" if profile == "docx" else f"m:{payload}"
    control = tmp_path / f"control.{profile}"
    args = ["--module", module, "--cosign", str(keys[0])]
    accepted = _cli([command, str(control), *args])
    assert accepted.returncode == 0, accepted.stderr
    assert open_document(control.read_bytes()).extract("m") == b"consumer data"
    destination = tmp_path / f"existing.{profile}"
    plus = destination.with_suffix(f".{profile}plus")
    destination.write_bytes(b"previous document")
    plus.write_bytes(b"previous plus document")
    rejected = _cli([command, str(destination), *args, "--cosign", str(keys[1])])
    assert rejected.returncode != 0
    assert destination.read_bytes() == b"previous document"
    assert plus.read_bytes() == b"previous plus document"

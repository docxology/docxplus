"""Consumer regressions for typed authoring, seal policy and output admission."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from docxplus import crypto
from docxplus.container import ContainerError
from docxplus.odt_container import open_document
from docxplus.secure_io import is_secret_mode


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "docxplus.cli", *map(str, args)],
        capture_output=True, text=True, check=False,
    )


def _module(profile, slot, source):
    return f"{slot}:package_part:{source}" if profile == "docx" else f"{slot}:{source}"


def _build(profile):
    return "build" if profile == "docx" else "odt-build"


def _extract(profile):
    return "extract" if profile == "docx" else "odt-extract"


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("threshold", [False, True])
@pytest.mark.parametrize("payload_type,raw,obj", [
    ("text", "Crème brûlée 🍮\n".encode(), "Crème brûlée 🍮\n"),
    ("json", '{"z": [1, true, null], "é": "雪"}'.encode(),
     {"z": [1, True, None], "é": "雪"}),
    ("json", b'"a JSON scalar"', "a JSON scalar"),
    ("bytes", b"\x00\xff\x80not UTF-8", b"\x00\xff\x80not UTF-8"),
])
def test_typed_files_cross_cli_and_serialized_package(tmp_path, profile, threshold,
                                                     payload_type, raw, obj):
    """C12: typed files must not become bytes reprs or lose type under threshold sealing."""
    source = tmp_path / "input"
    source.write_bytes(raw)
    document = tmp_path / f"typed.{profile}"
    shares = tmp_path / "shares"
    args = [_build(profile), document, "--module", _module(profile, "m", source),
            "--payload-type", payload_type]
    if threshold:
        args += ["--threshold", "2:3", "--shares-dir", shares]
    built = _run(*args)
    assert built.returncode == 0, built.stderr
    reader = open_document(document.read_bytes())
    assert reader.manifest.slot("m").payload_type == payload_type
    creds = {}
    extraction = [_extract(profile), document, "m", "--out", tmp_path / "recovered"]
    if threshold:
        paths = sorted(shares.glob("m.share*.bin"))
        assert len(paths) == 3
        assert all(is_secret_mode(path) for path in paths)
        creds["shares"] = [path.read_bytes() for path in paths[:2]]
        for path in paths[:2]:
            extraction += ["--share", path]
        with pytest.raises(ContainerError):
            reader.extract("m")
    assert reader.extract("m", as_object=True, **creds) == obj
    extracted = _run(*extraction)
    assert extracted.returncode == 0, extracted.stderr
    recovered = (tmp_path / "recovered").read_bytes()
    assert recovered == reader.extract("m", **creds)
    if payload_type == "json":
        assert json.loads(recovered) == obj
    else:
        assert recovered == raw


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("payload_type,raw", [
    ("text", b"\xff"), ("json", b"\xff"), ("json", b"{broken"),
    ("json", b"NaN"), ("json", b"{} trailing"), ("unknown", b"data"),
    ("json", b"1e999"),
    ("project", b"PK\x03\x04not a project file codec"),
    ("docxplus", b"not an add_nested invocation"),
])
def test_invalid_typed_input_preserves_both_document_names(tmp_path, profile,
                                                         payload_type, raw):
    """C12: invalid encoding/type/JSON is refused before replacing either document."""
    source = tmp_path / "input"
    source.write_bytes(raw)
    document = tmp_path / f"prior.{profile}"
    plus = document.with_suffix(f".{profile}plus")
    document.write_bytes(b"approved surface")
    plus.write_bytes(b"approved intelligence")
    shares = tmp_path / "shares"
    rejected = _run(_build(profile), document, "--module", _module(profile, "m", source),
                    "--payload-type", payload_type, "--threshold", "2:3", "--shares-dir", shares)
    assert rejected.returncode != 0
    assert document.read_bytes() == b"approved surface"
    assert plus.read_bytes() == b"approved intelligence"
    assert not shares.exists()


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_threshold_policy_seals_projects_and_modules_together(tmp_path, profile):
    """C13: --project must apply the same threshold policy as an ordinary module."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.txt").write_text("private project source\n", encoding="utf-8")
    source = tmp_path / "module"
    source.write_bytes(b"private module")
    document = tmp_path / f"project.{profile}"
    shares = tmp_path / "shares"
    built = _run(_build(profile), document, "--project", f"source:{project}",
                 "--module", _module(profile, "m", source),
                 "--threshold", "2:3", "--shares-dir", shares)
    assert built.returncode == 0, built.stderr
    reader = open_document(document.read_bytes())
    for slot in ("source", "m"):
        record = reader.manifest.slot(slot)
        assert record.encrypted
        assert record.sealing["mode"] == "threshold"
        assert record.sealing["checksummed_shares"] is True
        assert record.sealing["k"] == 2
        assert record.sealing["n"] == 3
        assert record.sealing["share_digests"] == [
            crypto.digest((shares / f"{slot}.share{i}.bin").read_bytes())
            for i in range(1, 4)
        ]
        with pytest.raises(ContainerError):
            reader.extract(slot)
    assert reader.manifest.slot("source").payload_type == "project"
    dest = tmp_path / "recovered"
    denied = _run("unpack-project", document, "source", dest)
    assert denied.returncode != 0
    assert not dest.exists()
    share_args = ["--share", shares / "source.share1.bin",
                  "--share", shares / "source.share3.bin"]
    over_budget = _run("unpack-project", document, "source", dest,
                       "--max-uncompressed", "1", *share_args)
    assert over_budget.returncode != 0
    assert not dest.exists()
    opened = _run("unpack-project", document, "source", dest, *share_args)
    assert opened.returncode == 0, opened.stderr
    assert (dest / "source.txt").read_bytes() == (project / "source.txt").read_bytes()


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("policies", [
    ("--password", "pw", "--threshold", "2:3"),
    ("--recipient", "PUBLIC", "--threshold", "2:3"),
    ("--password", "pw", "--recipient", "PUBLIC"),
    ("--pad-recipients", "2"), ("--shares-dir", "unused"),
    ("--threshold", "0:3"), ("--threshold", "3:2"),
    ("--threshold", "2:3:4"), ("--threshold", "2:255"),
])
def test_invalid_seal_policies_publish_nothing(tmp_path, profile, policies):
    """C13: conflicting or malformed global seal policies cannot silently pick plaintext."""
    public = crypto.generate_recipient_key()[1].hex()
    policies = [public if value == "PUBLIC" else value for value in policies]
    source = tmp_path / "source"
    source.write_bytes(b"secret")
    document = tmp_path / f"refused.{profile}"
    rejected = _run(_build(profile), document, "--module", _module(profile, "m", source), *policies)
    assert rejected.returncode != 0
    assert not document.exists()
    assert not document.with_suffix(f".{profile}plus").exists()


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("collision", ["existing-share", "share-document", "plus-directory",
                                        "share-parent-file", "unsafe-slot", "key-output"])
def test_all_related_outputs_are_admitted_before_publication(tmp_path, profile, collision):
    """C14: one bad output must not replace a prior document or publish earlier shares."""
    source = tmp_path / "source"
    source.write_bytes(b"secret")
    document = tmp_path / f"approved.{profile}"
    plus = document.with_suffix(f".{profile}plus")
    document.write_bytes(b"approved surface")
    plus.write_bytes(b"approved intelligence")
    shares = tmp_path / "shares"
    slot = "m"
    extra = []
    if collision == "existing-share":
        shares.mkdir()
        (shares / "m.share3.bin").write_bytes(b"retained share")
    elif collision == "share-document":
        document = tmp_path / "m.share1.bin"
        document.write_bytes(b"approved surface")
        shares = tmp_path
    elif collision == "plus-directory":
        plus.unlink()
        plus.mkdir()
    elif collision == "share-parent-file":
        shares.write_bytes(b"not a directory")
    elif collision == "unsafe-slot":
        slot = "../escape"
    elif collision == "key-output":
        private, _ = crypto.generate_signing_key()
        document.write_text(private.hex())
        extra = ["--signing-key", document]
    original = document.read_bytes()
    rejected = _run(_build(profile), document, "--module", _module(profile, slot, source),
                    "--threshold", "2:3", "--shares-dir", shares, *extra)
    assert rejected.returncode != 0
    assert document.read_bytes() == original
    if collision == "plus-directory":
        assert plus.is_dir()
    else:
        assert plus.read_bytes() == b"approved intelligence"
    if collision == "existing-share":
        assert (shares / "m.share3.bin").read_bytes() == b"retained share"
        assert sorted(path.name for path in shares.iterdir()) == ["m.share3.bin"]
    elif collision == "share-parent-file":
        assert shares.read_bytes() == b"not a directory"
    elif collision not in ("share-document",):
        assert not shares.exists()


@pytest.mark.parametrize("family", ["ed25519", "x25519", "hybrid-signing", "hybrid-recipient"])
def test_keygen_refuses_existing_public_sidecar_without_creating_private_key(tmp_path, family):
    """C14: exclusive key creation includes the matching public sidecar, not only the secret."""
    private = tmp_path / "identity"
    public = Path(str(private) + ".pub")
    public.write_bytes(b"retain pinned identity")
    rejected = _run("keygen", private, "--type", family)
    assert rejected.returncode != 0
    assert not private.exists()
    assert public.read_bytes() == b"retain pinned identity"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["identity.pub"]


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("hybrid", [False, True])
def test_keygen_build_verify_extract_use_the_actual_key_families(tmp_path, profile, hybrid):
    """C14: portable CLI keys must compose for pinned signing, cosigning and recipient opening."""
    signing_type = "hybrid-signing" if hybrid else "ed25519"
    recipient_type = "hybrid-recipient" if hybrid else "x25519"
    author, institution, recipient, stranger = [tmp_path / name for name in
                                               ("author", "institution", "recipient", "stranger")]
    for key, family in ((author, signing_type), (institution, signing_type),
                        (recipient, recipient_type), (stranger, signing_type)):
        generated = _run("keygen", key, "--type", family)
        assert generated.returncode == 0, generated.stderr
        assert is_secret_mode(key)
    if hybrid:
        for key in (author, institution, recipient, stranger):
            parsed = crypto.HybridKeyPair.from_private_bytes(bytes.fromhex(key.read_text()))
            assert parsed.public_bytes == bytes.fromhex(Path(str(key) + ".pub").read_text())
            assert parsed.private_bytes == bytes.fromhex(key.read_text())
    source = tmp_path / "payload"
    source.write_bytes(b"recipient-only bytes\x00\xff")
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.txt").write_bytes(b"recipient-only project")
    document = tmp_path / f"signed.{profile}"
    recipient_public = Path(str(recipient) + ".pub").read_text()
    built = _run(_build(profile), document, "--module", _module(profile, "m", source),
                 "--project", f"source:{project}", "--recipient", recipient_public,
                 "--pad-recipients", "3", "--signing-key", author, "--cosign", institution)
    assert built.returncode == 0, built.stderr
    verified = _run("verify", document, "--expected-key", str(author) + ".pub",
                    "--require-cosigner", str(institution) + ".pub")
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["provenance_verified"] is True
    wrong_pin = _run("verify", document, "--expected-key", str(stranger) + ".pub")
    assert wrong_pin.returncode != 0
    recovered = tmp_path / "recovered"
    opened = _run(_extract(profile), document, "m", "--private-key", recipient, "--out", recovered)
    assert opened.returncode == 0, opened.stderr
    assert recovered.read_bytes() == source.read_bytes()
    dest = tmp_path / "unpacked"
    unpacked = _run("unpack-project", document, "source", dest, "--private-key", recipient)
    assert unpacked.returncode == 0, unpacked.stderr
    assert (dest / "source.txt").read_bytes() == b"recipient-only project"
    refused = _run(_extract(profile), document, "m", "--private-key", stranger, "--out", recovered)
    assert refused.returncode != 0
    assert recovered.read_bytes() == source.read_bytes()


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_extract_output_cannot_replace_its_document_or_credentials(tmp_path, profile):
    """C14: a valid extraction must not overwrite either document alias, a share, or a key."""
    source = tmp_path / "payload"
    source.write_bytes(b"classified")
    document = tmp_path / f"document.{profile}"
    shares = tmp_path / "shares"
    built = _run(_build(profile), document, "--module", _module(profile, "m", source),
                 "--threshold", "2:3", "--shares-dir", shares)
    assert built.returncode == 0, built.stderr
    share1, share2 = shares / "m.share1.bin", shares / "m.share2.bin"
    private, public = crypto.generate_recipient_key()
    key, pin = tmp_path / "recipient", tmp_path / "recipient.pub"
    key.write_text(private.hex())
    pin.write_text(public.hex())
    alias = tmp_path / "document-alias"
    alias.hardlink_to(document)
    for output in (document, document.with_suffix(f".{profile}plus"), alias, share1, key, pin):
        original = output.read_bytes()
        rejected = _run(_extract(profile), document, "m", "--share", share1,
                        "--share", share2, "--private-key", key, "--out", output)
        assert rejected.returncode != 0
        assert output.read_bytes() == original


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("option", ["--signing-key", "--cosign", "--recipient"])
@pytest.mark.parametrize("material", ["nonhex", "short", "wrong-hybrid-family"])
def test_malformed_or_wrong_family_key_material_never_publishes(
    tmp_path, profile, option, material,
):
    """C14: hexadecimal syntax alone is not admission of signing or recipient keys."""
    if material == "nonhex":
        encoded = "not hexadecimal"
    elif material == "short":
        encoded = "ab" * 31
    elif option == "--recipient":
        encoded = crypto.generate_hybrid_signing_key().public_bytes.hex()
    else:
        encoded = crypto.generate_hybrid_recipient_key().private_bytes.hex()
    key = tmp_path / "invalid.key"
    key.write_text(encoded)
    source = tmp_path / "source"
    source.write_bytes(b"secret")
    document = tmp_path / f"approved.{profile}"
    plus = document.with_suffix(f".{profile}plus")
    document.write_bytes(b"approved surface")
    plus.write_bytes(b"approved intelligence")
    argument = encoded if option == "--recipient" else str(key)
    rejected = _run(_build(profile), document, "--module", _module(profile, "m", source),
                    option, argument)
    assert rejected.returncode != 0
    assert document.read_bytes() == b"approved surface"
    assert plus.read_bytes() == b"approved intelligence"
    assert key.read_text() == encoded


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_hardlinked_document_and_share_outputs_are_rejected(tmp_path, profile):
    """C14: distinct spellings do not make two names for the same output inode safe."""
    source = tmp_path / "source"
    source.write_bytes(b"secret")
    document = tmp_path / f"approved.{profile}"
    document.write_bytes(b"approved")
    shares = tmp_path / "shares"
    shares.mkdir()
    share = shares / "m.share2.bin"
    share.hardlink_to(document)
    rejected = _run(_build(profile), document, "--module", _module(profile, "m", source),
                    "--threshold", "2:3", "--shares-dir", shares)
    assert rejected.returncode != 0
    assert document.read_bytes() == b"approved"
    assert share.read_bytes() == b"approved"
    assert sorted(path.name for path in shares.iterdir()) == ["m.share2.bin"]


@pytest.mark.parametrize("collision", ["directory", "symlink"])
def test_keygen_refuses_nonregular_public_sidecar(tmp_path, collision):
    """C14: a bad public destination must not leave a newly generated private identity."""
    private = tmp_path / "identity"
    public = Path(str(private) + ".pub")
    if collision == "directory":
        public.mkdir()
    else:
        victim = tmp_path / "victim"
        victim.write_bytes(b"retain")
        public.symlink_to(victim)
    rejected = _run("keygen", private)
    assert rejected.returncode != 0
    assert not private.exists()
    if collision == "directory":
        assert public.is_dir()
    else:
        assert public.is_symlink()
        assert victim.read_bytes() == b"retain"


def test_transparency_outputs_validate_signing_and_collisions_before_replacement(tmp_path):
    """C14: malformed signing or colliding log/STH targets cannot overwrite a prior log."""
    from docxplus.transparency import TransparencyLog

    log = tmp_path / "log.json"
    original = TransparencyLog().to_json()
    log.write_text(original)
    key = tmp_path / "key"
    key.write_text("aa" * 31)
    sth = tmp_path / "sth.json"
    rejected = _run("transparency-append", log, "--signing-key", key, "--sth-out", sth)
    assert rejected.returncode != 0
    assert log.read_text() == original
    assert not sth.exists()
    generated = _run("keygen", key.parent / "valid")
    assert generated.returncode == 0, generated.stderr
    collided = _run("transparency-append", log, "--signing-key", key.parent / "valid",
                    "--sth-out", log)
    assert collided.returncode != 0
    assert log.read_text() == original


@pytest.mark.requires_pillow
@pytest.mark.parametrize("kind,expected_exit,available,flagged", [
    ("tiny", 2, False, False),
    ("balanced", 1, True, True),
    ("unbalanced", 0, True, False),
])
def test_carrier_cli_keeps_unavailable_and_partial_statistics_explicit(
    tmp_path, monkeypatch, capsys, kind, expected_exit, available, flagged,
):
    """Unavailable histograms are inconclusive; available flags mean compatibility only."""
    from docxplus.cli import main

    image = pytest.importorskip("PIL.Image")
    # Isolate optional tool discovery without replacing any analysis behavior.
    monkeypatch.delenv("STEGANOGRAPHER_BIN", raising=False)
    monkeypatch.setenv("PATH", "")
    carrier = tmp_path / "carrier.png"
    if kind == "tiny":
        image.new("RGB", (1, 1), (0, 0, 0)).save(carrier)
    else:
        values = bytes(i % 2 for i in range(192)) if kind == "balanced" else bytes(192)
        image.frombytes("RGB", (8, 8), values).save(carrier)
    assert main(["analyze-carrier", str(carrier)]) == expected_exit
    report = json.loads(capsys.readouterr().out)
    assert report["available"] is available
    assert report["suspicious"] is flagged
    assert report["external_available"] is False
    assert report["chi_square"]["available"] is available
    steps = report["chi_square_sweep"]["steps"]
    assert any(not step["available"] for step in steps)
    assert all(step["p_value"] is None for step in steps if not step["available"])
    if available:
        assert any(step["available"] for step in steps)
    else:
        assert report["chi_square"]["p_value"] is None
    if kind == "balanced":
        assert report["chi_square"]["p_value"] == 1.0


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_single_share_threshold_remains_a_supported_explicit_policy(tmp_path, profile):
    """CLI admission must preserve the Shamir API's legal 1-of-1 boundary."""
    source = tmp_path / "source"
    source.write_bytes(b"secret")
    document = tmp_path / f"document.{profile}"
    shares = tmp_path / "shares"
    built = _run(_build(profile), document, "--module", _module(profile, "m", source),
                 "--threshold", "1:1", "--shares-dir", shares)
    assert built.returncode == 0, built.stderr
    reader = open_document(document.read_bytes())
    with pytest.raises(ContainerError):
        reader.extract("m")
    assert reader.extract("m", shares=[(shares / "m.share1.bin").read_bytes()]) == b"secret"


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_project_authoring_budget_refuses_before_replacing_documents(tmp_path, profile):
    """The chosen author-side project budget applies before either document is published."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.txt").write_bytes(b"more than one byte")
    document = tmp_path / f"approved.{profile}"
    plus = document.with_suffix(f".{profile}plus")
    document.write_bytes(b"approved surface")
    plus.write_bytes(b"approved intelligence")
    shares = tmp_path / "shares"
    refused = _run(_build(profile), document, "--project", f"source:{project}",
                   "--max-uncompressed", "1", "--threshold", "2:3", "--shares-dir", shares)
    assert refused.returncode != 0
    assert document.read_bytes() == b"approved surface"
    assert plus.read_bytes() == b"approved intelligence"
    assert not shares.exists()


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("output_kind", ["document", "share"])
def test_project_inputs_cannot_be_replaced_by_related_outputs(tmp_path, profile, output_kind):
    """Publication cannot silently replace a carried project member or add shares to its tree."""
    project = tmp_path / "project"
    project.mkdir()
    member = project / f"approved.{profile}"
    member.write_bytes(b"retain project source")
    document = member if output_kind == "document" else tmp_path / f"document.{profile}"
    shares = project / "shares" if output_kind == "share" else tmp_path / "shares"
    refused = _run(_build(profile), document, "--project", f"source:{project}",
                   "--threshold", "2:3", "--shares-dir", shares)
    assert refused.returncode != 0
    assert member.read_bytes() == b"retain project source"
    assert not shares.exists()
    assert not document.with_suffix(f".{profile}plus").exists()
    if output_kind == "share":
        assert not document.exists()


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("hybrid", [False, True])
def test_reproduction_cli_preserves_full_attestation_and_pinned_trust(tmp_path, profile, hybrid):
    """Real sandboxed attest/replay composes with typed signing and threshold project recovery."""
    from docxplus.reproduce import OUTPUT_DIGEST_SCHEME

    author, stranger = tmp_path / "author", tmp_path / "stranger"
    for key in (author, stranger):
        generated = _run("keygen", key, "--type", "hybrid-signing" if hybrid else "ed25519")
        assert generated.returncode == 0, generated.stderr
    project = tmp_path / "project"
    project.mkdir()
    (project / "run.py").write_text(
        "from pathlib import Path\nPath('result.txt').write_bytes(b'reproduced bytes')\n",
        encoding="utf-8",
    )
    (project / ".docxplus-reproduce.json").write_text(json.dumps({
        "command": ["{python}", "run.py"], "outputs": ["result.txt"], "timeout": 30,
    }), encoding="utf-8")
    document = tmp_path / f"reproduction.{profile}"
    shares = tmp_path / "shares"
    built = _run(_build(profile), document, "--project", f"source:{project}",
                 "--attest", "--signing-key", author, "--threshold", "2:3",
                 "--shares-dir", shares, "--max-uncompressed", "4096")
    assert built.returncode == 0, built.stderr
    assert not (project / "result.txt").exists()
    reader = open_document(document.read_bytes())
    attestation = reader.manifest.slot("source").reproduction
    assert attestation["output_digest_scheme"] == OUTPUT_DIGEST_SCHEME
    assert attestation["command"] == ["{python}", "run.py"]
    assert attestation["source_digest"]
    assert attestation["toolchain"]
    for pin, exit_code, authenticated in ((None, 0, False), (author, 0, True),
                                           (stranger, 1, False)):
        args = ["verify-reproduction", document, "source"]
        if pin is not None:
            args += ["--expected-key", str(pin) + ".pub"]
        checked = _run(*args)
        assert checked.returncode == exit_code, checked.stderr
        info = json.loads(checked.stdout)
        assert info["verified"] is authenticated
        assert info["self_consistent"] is True
        claim = info.get("attestation", info.get("unverified_attestation"))
        assert claim == attestation
        if pin is None:
            assert "self-consistency is not authenticity" in info["_warning"]
    credentials = ["--share", shares / "source.share1.bin",
                   "--share", shares / "source.share3.bin"]
    for budget, destination in (("1", tmp_path / "denied"), ("4096", tmp_path / "replay")):
        replayed = _run("reproduce", document, "source", destination, "--allow-execution",
                        "--max-uncompressed", budget, *credentials)
        if budget == "1":
            assert replayed.returncode != 0
            assert not destination.exists()
        else:
            assert replayed.returncode == 0, replayed.stderr
            report = json.loads(replayed.stdout)
            assert report["output_digest_scheme"] == OUTPUT_DIGEST_SCHEME
            assert report["match"] is True
            assert report["source_match"] is True
            assert (destination / "result.txt").read_bytes() == b"reproduced bytes"

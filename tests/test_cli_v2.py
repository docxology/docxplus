"""CLI integration: profile round trips, signer policy and append-only logs."""

from __future__ import annotations

import subprocess
import sys

import pytest

#: The CLI is a module inside the package, so it is invoked with -m. Run by
#: file path it would have no parent package and every relative import in it
#: would fail — which is exactly how this broke when the module moved.
CLI_MODULE = "docxplus.cli"


def _run(args, **kw):
    return subprocess.run([sys.executable, "-m", CLI_MODULE, *args], capture_output=True, text=True, check=False, **kw)


def test_project_build_and_unpack(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.py").write_text("X = 1\n")
    docx = tmp_path / "out.docx"

    built = _run(["build", str(docx), "--project", f"source:{proj}", "--password", "pw"])
    assert built.returncode == 0, built.stderr

    graph = _run(["graph", str(docx)])
    assert graph.returncode == 0
    assert "source" in graph.stdout and "project" in graph.stdout

    dest = tmp_path / "unpacked"
    up = _run(["unpack-project", str(docx), "source", str(dest), "--password", "pw"])
    assert up.returncode == 0, up.stderr
    assert (dest / "src" / "m.py").read_text() == "X = 1\n"


def test_keygen_x25519_and_multi_recipient(tmp_path):
    key = tmp_path / "rk.hex"
    assert _run(["keygen", str(key), "--type", "x25519"]).returncode == 0
    pub = (tmp_path / "rk.hex.pub").read_text().strip()

    # Hybrid keygen smoke
    hk_recip = tmp_path / "hk_recip.hex"
    assert _run(["keygen", str(hk_recip), "--type", "hybrid-recipient"]).returncode == 0
    assert hk_recip.exists() and (tmp_path / "hk_recip.hex.pub").exists()

    hk_sign = tmp_path / "hk_sign.hex"
    assert _run(["keygen", str(hk_sign), "--type", "hybrid-signing"]).returncode == 0
    assert hk_sign.exists() and (tmp_path / "hk_sign.hex.pub").exists()

    payload = tmp_path / "p.bin"
    payload.write_bytes(b"referee draft")
    docx = tmp_path / "r.docx"
    built = _run(["build", str(docx), "--module", f"m:package_part:{payload}", "--recipient", pub])
    assert built.returncode == 0, built.stderr

    out = tmp_path / "got.bin"
    got = _run(["extract", str(docx), "m", "--private-key", str(key), "--out", str(out)])
    assert got.returncode == 0, got.stderr
    assert out.read_bytes() == b"referee draft"


def test_threshold_build_writes_shares_and_extracts(tmp_path):
    payload = tmp_path / "s.bin"
    payload.write_bytes(b"vault code")
    docx = tmp_path / "t.docx"
    shares_dir = tmp_path / "shares"
    built = _run([
        "build", str(docx), "--module", f"vault:package_part:{payload}",
        "--threshold", "2:3", "--shares-dir", str(shares_dir),
    ])
    assert built.returncode == 0, built.stderr
    shares = sorted(shares_dir.glob("vault.share*.bin"))
    assert len(shares) == 3

    out = tmp_path / "v.bin"
    got = _run([
        "extract", str(docx), "vault", "--out", str(out),
        "--share", str(shares[0]), "--share", str(shares[1]),
    ])
    assert got.returncode == 0, got.stderr
    assert out.read_bytes() == b"vault code"


def test_graph_shows_signature_and_merkle(tmp_path):
    key = tmp_path / "sk.hex"
    _run(["keygen", str(key)])
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    docx = tmp_path / "g.docx"
    _run(["build", str(docx), "--module", f"a:custom_xml:{payload}", "--signing-key", str(key)])
    graph = _run(["graph", str(docx)])
    assert "signature: valid" in graph.stdout
    assert "merkle_root" in graph.stdout


# -- verify-transparency: distributed verification of the attestation log -----


def _write_log(tmp_path, entries=5, *, sign=True):
    """Produce a real transparency log (and STH) on disk for the CLI to read."""
    import json as _json

    from docxplus import crypto
    from docxplus.transparency import TransparencyLog

    log = TransparencyLog()
    for i in range(entries):
        log.append({"output_digest": f"digest_{i}", "toolchain": {"python": "3.12"}}, timestamp=100 + i)
    log_path = tmp_path / "log.json"
    log_path.write_text(log.to_json())

    if not sign:
        return log_path, log, None, None
    priv, pub = crypto.generate_signing_key()
    sth_path = tmp_path / "sth.json"
    sth_path.write_text(_json.dumps(log.signed_tree_head(priv, timestamp=999)))
    key_path = tmp_path / "signer.pub"
    key_path.write_text(pub.hex())
    return log_path, log, sth_path, key_path


def test_verify_transparency_reports_unauthenticated_without_an_sth(tmp_path):
    import json as _json

    log_path, log, _, _ = _write_log(tmp_path, sign=False)
    res = _run(["verify-transparency", str(log_path)])
    assert res.returncode == 0, res.stderr
    report = _json.loads(res.stdout)
    assert report["chain_verified"] is True
    assert report["entries"] == 5
    assert report["merkle_root"] == log.merkle_tree_root()
    assert report["sth_verified"] is None
    # A clean chain must not be allowed to read as an authenticity result.
    assert "UNAUTHENTICATED" in report["_warning"]


def test_verify_transparency_full_verification_passes(tmp_path):
    import json as _json

    log_path, log, sth_path, key_path = _write_log(tmp_path)
    res = _run([
        "verify-transparency", str(log_path),
        "--sth", str(sth_path),
        "--expected-key", str(key_path),
        "--expected-root", log.merkle_tree_root(),
        "--prove", "2",
    ])
    assert res.returncode == 0, res.stderr
    report = _json.loads(res.stdout)
    assert report["chain_verified"] is True
    assert report["root_matches"] is True
    assert report["sth_verified"] is True
    assert report["inclusion"]["verified"] is True
    assert report["inclusion"]["attestation_digest"] == "digest_2"
    assert "_warning" not in report


def test_verify_transparency_fails_closed_on_a_wrong_pinned_signer(tmp_path):
    import json as _json

    from docxplus import crypto

    log_path, _log, sth_path, _key = _write_log(tmp_path)
    wrong = tmp_path / "wrong.pub"
    wrong.write_text(crypto.generate_signing_key()[1].hex())

    res = _run(["verify-transparency", str(log_path), "--sth", str(sth_path), "--expected-key", str(wrong)])
    assert res.returncode == 1
    assert _json.loads(res.stdout)["sth_verified"] is False


def test_verify_transparency_fails_closed_on_a_wrong_pinned_root(tmp_path):
    import json as _json

    log_path, _log, _sth, _key = _write_log(tmp_path, sign=False)
    res = _run(["verify-transparency", str(log_path), "--expected-root", "de" * 32])
    assert res.returncode == 1
    report = _json.loads(res.stdout)
    assert report["root_matches"] is False
    assert report["chain_verified"] is True  # self-consistent, but not the pinned log


def test_verify_transparency_rejects_a_tampered_log(tmp_path):
    import json as _json

    log_path, _log, _sth, _key = _write_log(tmp_path, sign=False)
    log_path.write_text(log_path.read_text().replace("digest_0", "forged_0"))

    res = _run(["verify-transparency", str(log_path)])
    assert res.returncode == 1
    report = _json.loads(res.stdout)
    assert report["chain_verified"] is False
    assert "error" in report


def test_verify_transparency_rejects_an_out_of_range_inclusion_proof(tmp_path):
    import json as _json

    log_path, _log, _sth, _key = _write_log(tmp_path, sign=False)
    res = _run(["verify-transparency", str(log_path), "--prove", "99"])
    assert res.returncode == 1
    assert _json.loads(res.stdout)["inclusion"]["verified"] is False


# -- v0.6.3 commands: ODT profile, steganalysis, transparency producer ---------


def _keypair(tmp_path):
    key = tmp_path / "k.hex"
    assert _run(["keygen", str(key)]).returncode == 0
    return key, tmp_path / "k.hex.pub"


def test_odt_build_validate_extract_round_trip(tmp_path):
    import json as _json

    key, _pub = _keypair(tmp_path)
    payload = tmp_path / "brief.json"
    payload.write_text('{"kind":"brief"}')
    odt = tmp_path / "r.odt"

    built = _run([
        "odt-build", str(odt), "--text", "Ordinary ODF",
        "--module", f"brief:{payload}", "--password", "pw", "--signing-key", str(key),
    ])
    assert built.returncode == 0, built.stderr

    valid = _run(["odt-validate", str(odt)])
    assert valid.returncode == 0, valid.stdout
    assert _json.loads(valid.stdout)["ok"] is True

    inspected = _run(["odt-inspect", str(odt)])
    assert inspected.returncode == 0
    assert _json.loads(inspected.stdout)["signature"] in {"valid", "self-asserted"}

    got = _run(["odt-extract", str(odt), "brief", "--password", "pw"])
    assert got.returncode == 0
    assert got.stdout.strip() == '{"kind":"brief"}'


def test_odt_threshold_shares_written_and_accepted(tmp_path):
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"quorum payload")
    odt = tmp_path / "t.odt"
    shares = tmp_path / "shares"

    built = _run([
        "odt-build", str(odt), "--module", f"q:{payload}",
        "--threshold", "2:3", "--shares-dir", str(shares),
    ])
    assert built.returncode == 0, built.stderr
    files = sorted(shares.glob("q.share*.bin"))
    assert len(files) == 3

    out = tmp_path / "out.bin"
    got = _run([
        "odt-extract", str(odt), "q", "--out", str(out),
        "--share", str(files[0]), "--share", str(files[1]),
    ])
    assert got.returncode == 0, got.stderr
    assert out.read_bytes() == b"quorum payload"


def _carrier(path, size=(96, 96)):
    import math

    from PIL import Image

    w, h = size
    img = Image.new("RGB", size)
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = (
                max(0, min(255, int(127 + 100 * math.sin(x / 23.0) * math.cos(y / 31.0)))),
                max(0, min(255, int(127 + 90 * math.sin((x + y) / 19.0)))),
                max(0, min(255, int(127 + 80 * math.cos((x - y) / 27.0)))),
            )
    img.save(path, format="PNG")
    return path


def test_analyze_carrier_exit_code_distinguishes_clean_from_embedded(tmp_path):
    import json as _json
    import os

    pytest.importorskip("PIL")
    from docxplus import lsb

    clean = _carrier(tmp_path / "clean.png")
    stego = lsb.embed(clean, os.urandom(lsb.capacity_bytes(96, 96)), tmp_path / "stego.png")

    ok = _run(["analyze-carrier", str(clean)])
    assert ok.returncode == 0
    assert _json.loads(ok.stdout)["suspicious"] is False

    flagged = _run(["analyze-carrier", str(stego)])
    # Nonzero on a suspicious carrier so the check is usable as a gate in a script.
    assert flagged.returncode == 1
    assert _json.loads(flagged.stdout)["suspicious"] is True


def test_transparency_append_then_verify_round_trip(tmp_path):
    import json as _json

    key, pub = _keypair(tmp_path)
    att = tmp_path / "att.json"
    att.write_text('{"output_digest":"abc123","toolchain":{"python":"3.12"}}')
    log = tmp_path / "log.json"
    sth = tmp_path / "sth.json"

    first = _run(["transparency-append", str(log), "--attestation", str(att), "--timestamp", "1000"])
    assert first.returncode == 0
    # An unsigned append must say out loud that the log is unanchored.
    assert "UNANCHORED" in _json.loads(first.stdout)["_warning"]

    second = _run([
        "transparency-append", str(log), "--attestation", str(att), "--timestamp", "1001",
        "--signing-key", str(key), "--sth-out", str(sth),
    ])
    assert second.returncode == 0
    assert _json.loads(second.stdout)["entries"] == 2

    verified = _run([
        "verify-transparency", str(log), "--sth", str(sth),
        "--expected-key", str(pub), "--prove", "1",
    ])
    assert verified.returncode == 0, verified.stdout
    report = _json.loads(verified.stdout)
    assert report["sth_verified"] is True
    assert report["inclusion"]["verified"] is True
    assert report["inclusion"]["attestation_digest"] == "abc123"


def test_transparency_append_is_reproducible_under_a_pinned_timestamp(tmp_path):
    """Same inputs, same timestamp, same root — the log must be a function of its entries."""
    import json as _json

    att = tmp_path / "att.json"
    att.write_text('{"output_digest":"d","toolchain":{}}')
    roots = []
    for name in ("a.json", "b.json"):
        log = tmp_path / name
        out = _run(["transparency-append", str(log), "--attestation", str(att), "--timestamp", "7"])
        roots.append(_json.loads(out.stdout)["root"])
    assert roots[0] == roots[1]


def test_cli_error_diagnostics_on_invalid_args(tmp_path):
    # Invalid module syntax
    res = _run(["build", str(tmp_path / "bad.docx"), "--module", "invalid_module_spec"])
    assert res.returncode == 2
    assert "expected SLOT:CHANNEL:FILE" in res.stderr

    # Non-existent module file
    res = _run(["build", str(tmp_path / "bad.docx"), "--module", "m:package_part:/non/existent/file.bin"])
    assert res.returncode == 2
    assert "module file not found" in res.stderr

    # Invalid ODT module spec
    res = _run(["odt-build", str(tmp_path / "bad.odt"), "--module", "invalid_odt_spec:too:many:colons"])
    assert res.returncode == 2
    assert "expected SLOT:FILE" in res.stderr

    # Extraction with missing private key file
    docx = tmp_path / "sample.docx"
    _run(["build", str(docx), "--text", "hello"])
    res = _run(["extract", str(docx), "slot", "--private-key", "/non/existent/key.hex"])
    assert res.returncode == 2
    assert "private key file not found" in res.stderr

    # Invalid project format
    res = _run(["build", str(tmp_path / "bad_proj.docx"), "--project", "invalid_proj_spec:too:many:colons"])
    assert res.returncode == 2
    assert "expected SLOT:DIR" in res.stderr

    # Nonexistent project directory
    res = _run(["build", str(tmp_path / "bad_proj.docx"), "--project", "s:/non/existent/dir"])
    assert res.returncode == 2
    assert "project directory not found" in res.stderr

    # Keygen collision safeguard (secret exists)
    k_path = tmp_path / "existing_key.hex"
    k_path.write_text("dummy")
    res = _run(["keygen", str(k_path)])
    assert res.returncode == 1
    assert "refusing to overwrite" in res.stdout or "refusing to overwrite" in res.stderr


def test_reproduce_consent_gate_does_not_execute_carried_code(tmp_path):
    """Declining execution must leave both the carried program and destination untouched."""
    import json

    sentinel = tmp_path / "executed"
    proj = tmp_path / "repro_proj"
    proj.mkdir()
    (proj / "run.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n"
    )
    (proj / ".docxplus-reproduce.json").write_text(json.dumps({
        "command": [sys.executable, "run.py"], "outputs": ["result.txt"],
    }))
    docx = tmp_path / "repro.docx"
    built = _run(["build", str(docx), "--project", f"p:{proj}"])
    assert built.returncode == 0, built.stderr
    dest = tmp_path / "out_rep"
    no_opt_in = _run(["reproduce", str(docx), "p", str(dest)])
    assert no_opt_in.returncode == 2
    assert not sentinel.exists()
    assert not dest.exists()



@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_cli_cosigner_policy_binds_the_serialized_surface(tmp_path, profile):
    """A required institution must sign these document bytes, not just its manifest."""
    import json

    from docxplus import crypto
    from docxplus.odt_container import open_document
    from docxplus.secure_io import write_secret

    keys = {}
    for name in ("author", "institution", "stranger"):
        private, public = crypto.generate_signing_key()
        secret = write_secret(tmp_path / f"{name}.key", private.hex())
        pin = tmp_path / f"{name}.pub"
        pin.write_text(public.hex())
        keys[name] = (secret, pin)

    document = tmp_path / f"signed.{profile}"
    build_command = "build" if profile == "docx" else "odt-build"
    built = _run([
        build_command, str(document), "--text", "Approved budget 100",
        "--signing-key", str(keys["author"][0]),
        "--cosign", str(keys["institution"][0]),
    ])
    assert built.returncode == 0, built.stderr
    verify = [
        "verify", str(document), "--expected-key", str(keys["author"][1]),
        "--require-cosigner", str(keys["author"][1]),
        "--require-cosigner", str(keys["institution"][1]),
    ]
    accepted = _run(verify)
    assert accepted.returncode == 0, accepted.stderr
    report = json.loads(accepted.stdout)
    assert report["profile"] == profile
    assert report["provenance_verified"] is True
    assert report["cosigners_verified"] is True

    missing = _run([*verify, "--require-cosigner", str(keys["stranger"][1])])
    assert missing.returncode == 1
    missing_report = json.loads(missing.stdout)
    assert missing_report["provenance_verified"] is True
    assert missing_report["cosigners_verified"] is False

    reader = open_document(document.read_bytes())
    part = "word/document.xml" if profile == "docx" else "content.xml"
    reader.package.parts[part] = reader.package.parts[part].replace(
        b"Approved budget 100", b"Approved budget 900"
    )
    document.write_bytes(reader.package.to_bytes())
    tampered = _run(verify)
    assert tampered.returncode == 1
    tampered_report = json.loads(tampered.stdout)
    assert tampered_report["provenance_verified"] is False
    assert tampered_report["cosigners_verified"] is False


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("key_option", ["--signing-key", "--cosign"])
@pytest.mark.parametrize("key_failure", ["missing", "nonhex"])
def test_cli_invalid_signing_material_preserves_existing_document(
    tmp_path, profile, key_option, key_failure,
):
    """A failed signing request must not replace the caller's previous document."""
    document = tmp_path / f"existing.{profile}"
    build_command = "build" if profile == "docx" else "odt-build"
    built = _run([build_command, str(document), "--text", "Keep this signed-off draft"])
    assert built.returncode == 0, built.stderr
    original = document.read_bytes()
    key = tmp_path / "invalid.key"
    if key_failure == "nonhex":
        key.write_text("not a serialized signing key")

    rejected = _run([
        build_command, str(document), "--text", "Unapproved replacement",
        key_option, str(key),
    ])
    assert rejected.returncode == 2
    assert document.read_bytes() == original


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_cli_padded_recipients_hide_count_without_losing_access(tmp_path, profile):
    """CLI padding must reach the envelope, not only the argument parser."""
    from docxplus import crypto
    from docxplus.odt_container import open_document
    from docxplus.secure_io import is_secret_mode, write_secret

    recipients = [crypto.generate_recipient_key() for _ in range(2)]
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"Confidential review\x00\xff\n")
    module = f"review:package_part:{payload}" if profile == "docx" else f"review:{payload}"
    build_command = "build" if profile == "docx" else "odt-build"
    extract_command = "extract" if profile == "docx" else "odt-extract"
    sizes = []
    for count in (1, 2):
        document = tmp_path / f"recipients-{count}.{profile}"
        recipient_args = [
            arg for _, public in recipients[:count] for arg in ("--recipient", public.hex())
        ]
        built = _run([
            build_command, str(document), "--module", module,
            "--pad-recipients", "4", *recipient_args,
        ])
        assert built.returncode == 0, built.stderr
        record = open_document(document.read_bytes()).manifest.slot("review")
        sizes.append(record.size)
        assert record.sealing == {"mode": "recipients"}

    assert sizes[0] == sizes[1]
    for index, (private, _) in enumerate(recipients):
        key = write_secret(tmp_path / f"recipient-{index}.key", private.hex())
        out = tmp_path / f"recipient-{index}.bin"
        extracted = _run([
            extract_command, str(document), "review", "--private-key", str(key), "--out", str(out),
        ])
        assert extracted.returncode == 0, extracted.stderr
        assert out.read_bytes() == payload.read_bytes()
        assert is_secret_mode(out)

    outsider, _ = crypto.generate_recipient_key()
    key = write_secret(tmp_path / "outsider.key", outsider.hex())
    out = tmp_path / "outsider.bin"
    out.write_bytes(b"previously recovered bytes")
    rejected = _run([
        extract_command, str(document), "review", "--private-key", str(key), "--out", str(out),
    ])
    assert rejected.returncode == 1
    assert out.read_bytes() == b"previously recovered bytes"
    assert rejected.stdout == ""


@pytest.mark.parametrize("profile", ["docx", "odt"])
def test_cli_recipient_padding_cannot_discard_recipients(tmp_path, profile):
    """An undersized recipient bucket must fail without replacing the document."""
    from docxplus import crypto

    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"Confidential review\x00\xff\n")
    document = tmp_path / f"existing.{profile}"
    original = b"Previously approved document"
    document.write_bytes(original)
    module = f"review:package_part:{payload}" if profile == "docx" else f"review:{payload}"
    build_command = "build" if profile == "docx" else "odt-build"
    recipients = [crypto.generate_recipient_key() for _ in range(2)]
    recipient_args = [
        arg for _, public in recipients for arg in ("--recipient", public.hex())
    ]

    rejected = _run([
        build_command, str(document), "--module", module,
        "--pad-recipients", "1", *recipient_args,
    ])

    assert rejected.returncode != 0
    assert document.read_bytes() == original


def test_cli_consistency_proof_survives_growth_and_rejects_a_resigned_fork(tmp_path):
    """A newly valid STH cannot excuse rewriting the history pinned by an old proof."""
    import json

    from docxplus import crypto
    from docxplus.transparency import TransparencyLog

    log_path, log, sth, key = _write_log(tmp_path)
    proof = tmp_path / "earlier-proof.json"
    first = _run([
        "verify-transparency", str(log_path), "--sth", str(sth),
        "--expected-key", str(key), "--emit-proof", str(proof),
    ])
    assert first.returncode == 0, first.stderr
    assert json.loads(proof.read_text())["old_root"] == log.merkle_tree_root()

    private, public = crypto.generate_signing_key()
    key.write_text(public.hex())
    log.append({"output_digest": "new-result", "toolchain": {}}, timestamp=200)
    log_path.write_text(log.to_json())
    sth.write_text(json.dumps(log.signed_tree_head(private, timestamp=300)))
    verify = [
        "verify-transparency", str(log_path), "--sth", str(sth),
        "--expected-key", str(key), "--consistent-with", str(proof),
    ]
    extended = _run(verify)
    assert extended.returncode == 0, extended.stderr
    assert json.loads(extended.stdout)["append_only_verified"] is True

    fork = TransparencyLog()
    for index in range(len(log.entries)):
        fork.append(
            {"output_digest": f"rewritten-history-{index}", "toolchain": {}},
            timestamp=100 + index,
        )
    log_path.write_text(fork.to_json())
    sth.write_text(json.dumps(fork.signed_tree_head(private, timestamp=301)))
    rejected = _run(verify)
    assert rejected.returncode == 1
    report = json.loads(rejected.stdout)
    assert report["chain_verified"] is True
    assert report["sth_verified"] is True
    assert report["append_only_verified"] is False


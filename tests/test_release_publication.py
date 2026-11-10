"""Real staged-file boundaries for release plans; no remote publication is performed."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tracemalloc
from pathlib import Path

import pytest

from docxplus import release_publication as publication

VERSION = "9.8.7"
NOW = 2_000_000_000
COMMIT = "a" * 40
TREE = "b" * 40
INPUTS = "c" * 64
LIMIT = 128 * 1024 * 1024
RECEIPT_LIMIT = 4 * 1024 * 1024
CHECKSUM_LIMIT = 4096
PAYLOADS = (
    (f"docxplus-{VERSION}-py3-none-any.whl", f"dist/docxplus-{VERSION}-py3-none-any.whl"),
    (f"docxplus-{VERSION}.tar.gz", f"dist/docxplus-{VERSION}.tar.gz"),
    ("manuscript.pdf", "generated/documents/manuscript.pdf"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def resign(plan: dict) -> dict:
    """Recompute integrity so malformed fields cannot hide behind a stale digest."""
    body = {key: value for key, value in plan.items() if key != "plan_id"}
    plan["plan_id"] = digest(json_bytes(body))
    return plan


def checksums(root: Path) -> None:
    rows = []
    for path in sorted(root.iterdir()):
        if path.name != "SHA256SUMS":
            with path.open("rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            rows.append(f"{checksum}  {path.name}\n")
    (root / "SHA256SUMS").write_text("".join(rows), encoding="utf-8")


@pytest.fixture
def staged(tmp_path):
    """Stage opaque distribution bytes and syntactically bound receipts, not qualification."""
    root = tmp_path / "assets"
    root.mkdir()
    data = {
        f"docxplus-{VERSION}-py3-none-any.whl": b"wheel fixture\x00\xff",
        f"docxplus-{VERSION}.tar.gz": b"sdist fixture\x00\xfe",
        "manuscript.pdf": b"%PDF-1.7\nfixture\n",
    }
    source = {
        "schema": "docxplus.release-source.v1",
        "version": VERSION, "commit": COMMIT, "tree": TREE, "branch": "main",
        "pushed": True, "validated_inputs_sha256": INPUTS,
        "validated_generated_artifacts": {
            "manuscript_pdf_sha256": digest(data["manuscript.pdf"]),
        },
        "tagged": False, "published": False,
        "provenance": {"fixture": "not a producer attestation"},
    }
    validation = {
        "schema": "docxplus.release-validation.asset.v1",
        "version": VERSION, "source_commit": COMMIT,
        "validated_inputs_sha256": INPUTS,
        "host": {"ok": True, "inputs_sha256": INPUTS},
        "results": {"ok": True},
        "lifecycle": {"namespace_reaped": True, "inputs_sha256": INPUTS},
        "distribution_source_proof": {
            "version": VERSION, "inputs_sha256": INPUTS,
            "wheel_sha256": digest(data[f"docxplus-{VERSION}-py3-none-any.whl"]),
            "sdist_sha256": digest(data[f"docxplus-{VERSION}.tar.gz"]),
            "visual_review": {"pdf_sha256": digest(data["manuscript.pdf"])},
        },
        "collected_artifacts": {"files": {
            inventory_name: {"bytes": len(data[name]), "sha256": digest(data[name])}
            for name, inventory_name in PAYLOADS
        }},
    }
    data[f"SOURCE-{VERSION}.json"] = json_bytes(source)
    data[f"VALIDATION-{VERSION}.json"] = json_bytes(validation)
    for name, content in data.items():
        (root / name).write_bytes(content)
    checksums(root)
    return root


@pytest.fixture
def release():
    return {
        "id": 42, "tag_name": f"v{VERSION}", "name": "Release fixture",
        "body": "Reviewed release notes: café", "draft": True, "prerelease": False,
        "updated_at": "incidental timestamp", "download_count": 0,
    }


def make_plan(staged, release, **changes):
    arguments = {
        "version": VERSION, "actor": "release-owner", "main_commit": COMMIT,
        "main_tree": TREE, "release": release, "now": NOW,
    }
    arguments.update(changes)
    return publication.create_plan(staged, **arguments)


@pytest.fixture
def plan(staged, release):
    return make_plan(staged, release)


def remote_rows(plan):
    return [
        {"id": index, "name": name, **record}
        for index, (name, record) in enumerate(plan["assets"].items(), start=100)
    ]


def verify_remote(plan, release, **changes):
    arguments = {
        "actor": "release-owner", "main_commit": COMMIT, "main_tree": TREE,
        "tag_commit": COMMIT, "release": release,
    }
    arguments.update(changes)
    publication.verify_remote_identity(plan, **arguments)


def test_plan_roundtrip_binds_relocated_bytes_and_exact_confirmation(staged, release, tmp_path):
    """A persisted plan binds bytes rather than staging paths or incidental metadata."""
    plan = make_plan(staged, release)
    saved = tmp_path / "plan.json"
    saved.write_bytes(json_bytes(plan))
    restored = json.loads(saved.read_bytes())
    assert publication.validate_plan(restored, now=NOW + 1) == plan
    assert plan["plan_id"] == digest(json_bytes({
        key: value for key, value in restored.items() if key != "plan_id"
    }))
    assert publication.confirmation_phrase(restored) == (
        f"publish docxology/docxplus v{VERSION} {plan['plan_id']}"
    )
    assert plan["release"] == {
        key: release[key] for key in ("id", "tag_name", "name", "body", "prerelease")
    }
    release["updated_at"] = "new incidental timestamp"
    release["download_count"] = 100
    assert make_plan(staged, release) == restored
    expected = {path.name: path.read_bytes() for path in staged.iterdir()}
    relocated = staged.rename(tmp_path / "relocated")
    assert publication.read_assets(restored, relocated) == expected
    assert restored["assets"] == {
        name: {"bytes": len(data), "sha256": digest(data)}
        for name, data in sorted(expected.items())
    }


@pytest.mark.parametrize("ttl", [30, 3600])
def test_explicit_time_window_includes_creation_but_not_expiry(staged, release, ttl):
    """A review is usable only inside its bounded explicit-time window."""
    plan = make_plan(staged, release, ttl_seconds=ttl)
    assert publication.validate_plan(plan, now=NOW)["expires_at"] == NOW + ttl
    assert publication.validate_plan(plan, now=NOW + ttl - 1) == plan
    for outside in (NOW - 1, NOW + ttl, NOW + ttl + 1):
        with pytest.raises(publication.PublicationError):
            publication.validate_plan(plan, now=outside)


@pytest.mark.parametrize("changes", [
    {"ttl_seconds": 29}, {"ttl_seconds": 3601}, {"ttl_seconds": True},
    {"now": True}, {"version": "v9.8.7"}, {"version": "9.8.7rc1"},
    {"actor": "owner/other"}, {"actor": "-owner"},
    {"main_commit": "A" * 40}, {"main_tree": "b" * 39},
])
def test_plan_creation_rejects_ambiguous_identity_or_time(staged, release, changes):
    """Invalid release identities and boolean/out-of-range times cannot be reviewed."""
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release, **changes)


@pytest.mark.parametrize(("field", "value"), [
    ("id", True), ("id", 0), ("draft", False), ("draft", 1),
    ("prerelease", True), ("prerelease", 0), ("tag_name", "v0.0.1"),
])
def test_initial_release_requires_exact_stable_draft(staged, release, field, value):
    """A plan cannot first authorize a published, prerelease or differently tagged release."""
    release[field] = value
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


@pytest.mark.parametrize(("field", "value"), [
    ("repository", "other/docxplus"), ("schema", "unknown"), ("version", "9.8.7rc1"),
    ("tag", "v0.0.1"), ("release_id", True), ("actor", "bad actor"),
    ("main_commit", "0" * 39), ("main_tree", "B" * 40),
    ("created_at", True), ("expires_at", NOW + 3601),
    ("unexpected", "cannot carry arbitrary options"),
])
def test_rehashed_plan_still_requires_closed_valid_schema(plan, field, value):
    """A recomputed digest is integrity, not permission to change the schema."""
    plan[field] = value
    resign(plan)
    with pytest.raises(publication.PublicationError):
        publication.validate_plan(plan, now=NOW)


@pytest.mark.parametrize("change", ["unhashed", "missing", "bad_digest", "release_id", "asset"])
def test_plan_corruption_and_internal_bindings_refuse(plan, change):
    """Persisted plans cannot shed identity or disagree internally after review."""
    if change == "unhashed":
        plan["actor"] = "another-owner"
    elif change == "missing":
        del plan["main_tree"]
        resign(plan)
    elif change == "bad_digest":
        plan["plan_id"] = "g" * 64
    elif change == "release_id":
        plan["release"]["id"] += 1
        resign(plan)
    else:
        del plan["assets"]["manuscript.pdf"]
        resign(plan)
    with pytest.raises(publication.PublicationError):
        publication.validate_plan(plan, now=NOW)


@pytest.mark.parametrize(("receipt", "keys", "value"), [
    ("SOURCE", ("version",), "0.0.1"), ("SOURCE", ("commit",), "d" * 40),
    ("SOURCE", ("tree",), "d" * 40), ("SOURCE", ("branch",), "topic"),
    ("SOURCE", ("pushed",), False), ("SOURCE", ("pushed",), 1),
    ("SOURCE", ("validated_inputs_sha256",), "not-a-digest"),
    ("SOURCE", ("schema",), "unknown"),
    ("SOURCE", ("validated_generated_artifacts", "manuscript_pdf_sha256"), "d" * 64),
    ("VALIDATION", ("version",), "0.0.1"),
    ("VALIDATION", ("source_commit",), "d" * 40),
    ("VALIDATION", ("validated_inputs_sha256",), "d" * 64),
    ("VALIDATION", ("host", "ok"), False),
    ("VALIDATION", ("results", "ok"), 1),
    ("VALIDATION", ("lifecycle", "namespace_reaped"), False),
    ("VALIDATION", ("schema",), "unknown"),
    ("VALIDATION", ("host", "inputs_sha256"), "d" * 64),
    ("VALIDATION", ("lifecycle", "inputs_sha256"), "d" * 64),
    ("VALIDATION", ("distribution_source_proof", "version"), "0.0.1"),
    ("VALIDATION", ("distribution_source_proof", "inputs_sha256"), "d" * 64),
    ("VALIDATION", ("distribution_source_proof", "wheel_sha256"), "d" * 64),
    ("VALIDATION", ("distribution_source_proof", "sdist_sha256"), "d" * 64),
    ("VALIDATION", ("distribution_source_proof", "visual_review", "pdf_sha256"), "d" * 64),
])
def test_checksums_cannot_legitimize_unbound_receipts(staged, release, receipt, keys, value):
    """Even newly checksummed receipt bytes must bind the reviewed source and controls."""
    path = staged / f"{receipt}-{VERSION}.json"
    body = json.loads(path.read_bytes())
    target = body
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    path.write_bytes(json_bytes(body))
    checksums(staged)
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


@pytest.mark.parametrize(("receipt", "keys"), [
    ("SOURCE", ("version",)),
    ("SOURCE", ("validated_generated_artifacts", "manuscript_pdf_sha256")),
    ("VALIDATION", ("version",)),
    ("VALIDATION", ("host", "inputs_sha256")),
    ("VALIDATION", ("lifecycle", "inputs_sha256")),
    ("VALIDATION", ("distribution_source_proof", "version")),
    ("VALIDATION", ("distribution_source_proof", "wheel_sha256")),
    ("VALIDATION", ("distribution_source_proof", "visual_review", "pdf_sha256")),
    *[("VALIDATION", ("collected_artifacts", "files", inventory_name, field))
      for _, inventory_name in PAYLOADS for field in ("bytes", "sha256")],
])
def test_duplicate_receipt_keys_refuse_even_identical_values(staged, release, receipt, keys):
    """Duplicate nested bindings cannot exploit parser-specific receipt interpretation."""
    def encode_duplicate(body, remaining):
        fields = []
        for key, value in body.items():
            encoded = (encode_duplicate(value, remaining[1:])
                       if key == remaining[0] and len(remaining) > 1 else json_bytes(value))
            fields.append(json_bytes(key) + b":" + encoded)
            if key == remaining[0] and len(remaining) == 1:
                fields.append(fields[-1])
        return b"{" + b",".join(fields) + b"}"

    path = staged / f"{receipt}-{VERSION}.json"
    path.write_bytes(encode_duplicate(json.loads(path.read_bytes()), keys))
    checksums(staged)
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


@pytest.mark.parametrize("change", [
    "duplicate", "missing", "unknown", "digest", "uppercase_digest", "non_ascii", "malformed",
])
def test_checksum_manifest_is_exact_not_a_partial_hint(staged, release, change):
    """SHA256SUMS must account for each payload exactly once with matching bytes."""
    path = staged / "SHA256SUMS"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if change == "duplicate":
        lines.append(lines[0])
    elif change == "missing":
        lines.pop()
    elif change == "unknown":
        lines.append("0" * 64 + "  unrelated.bin\n")
    elif change == "digest":
        lines[0] = "0" * 64 + lines[0][64:]
    elif change == "uppercase_digest":
        lines = [line[:64].upper() + line[64:] for line in lines]
    elif change == "non_ascii":
        lines[0] = "é" + lines[0][1:]
    else:
        lines[0] = "not a checksum line\n"
    path.write_text("".join(lines), encoding="utf-8")
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


@pytest.mark.parametrize("change", ["same_size", "resized", "missing", "extra", "rechecksummed"])
def test_reviewed_plan_rejects_any_later_byte_or_inventory_change(staged, plan, change):
    """Rewriting SHA256SUMS cannot authorize changes after a plan was reviewed."""
    target = staged / "manuscript.pdf"
    if change in {"same_size", "rechecksummed"}:
        target.write_bytes(b"X" * target.stat().st_size)
        if change == "rechecksummed":
            checksums(staged)
    elif change == "resized":
        target.write_bytes(target.read_bytes() + b"extra")
    elif change == "missing":
        target.unlink()
    else:
        (staged / "unreviewed.txt").write_bytes(b"extra payload")
    with pytest.raises(publication.PublicationError):
        publication.read_assets(plan, staged)


@pytest.mark.parametrize("operation", ["plan", "read"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "fifo", "empty", "oversize", "aggregate"])
def test_local_file_custody_and_byte_bounds(staged, release, plan, tmp_path, operation, kind):
    """Actual unsafe inodes and sparse byte-limit violations refuse at both entrypoints."""
    target = staged / "manuscript.pdf"
    if kind == "aggregate":
        names = ["manuscript.pdf", f"docxplus-{VERSION}.tar.gz",
                 f"docxplus-{VERSION}-py3-none-any.whl"]
        for name in names:
            with (staged / name).open("r+b") as stream:
                stream.truncate(45 * 1024 * 1024)
    elif kind == "oversize":
        with target.open("r+b") as stream:
            stream.truncate(LIMIT + 1)
    elif kind == "empty":
        target.write_bytes(b"")
    else:
        data = target.read_bytes()
        target.unlink()
        if kind in {"symlink", "hardlink"}:
            outside = tmp_path / "outside.pdf"
            outside.write_bytes(data)
            if kind == "symlink":
                target.symlink_to(outside)
            else:
                os.link(outside, target)
        elif kind == "directory":
            target.mkdir()
        else:
            os.mkfifo(target)
    if kind in {"empty", "oversize", "aggregate"}:
        checksums(staged)
    with pytest.raises(publication.PublicationError):
        if operation == "plan":
            make_plan(staged, release)
        else:
            publication.read_assets(plan, staged)


@pytest.mark.parametrize("operation", ["plan", "read"])
def test_symlinked_directory_component_is_not_a_staging_root(staged, release, plan, tmp_path, operation):
    """A regular payload reached through a symlinked ancestor lacks directory custody."""
    link = tmp_path / "linked-parent"
    link.symlink_to(staged.parent, target_is_directory=True)
    indirect = link / staged.name
    with pytest.raises(publication.PublicationError):
        if operation == "plan":
            make_plan(indirect, release)
        else:
            publication.read_assets(plan, indirect)


@pytest.mark.parametrize(("field", "value"), [
    ("actor", "other-owner"), ("main_commit", "d" * 40),
    ("main_tree", "d" * 40), ("tag_commit", "d" * 40),
])
def test_remote_source_or_actor_drift_refuses(plan, release, field, value):
    """The same draft ID cannot authorize a changed actor, main tree or tag target."""
    with pytest.raises(publication.PublicationError):
        verify_remote(plan, release, **{field: value})


@pytest.mark.parametrize(("field", "value"), [
    ("id", 43), ("id", True), ("tag_name", "v0.0.1"),
    ("name", "Changed release"), ("body", "Changed notes"),
    ("prerelease", True), ("draft", 0), ("draft", "false"),
])
@pytest.mark.parametrize("published", [False, True])
def test_frozen_metadata_cannot_drift_even_after_publication(plan, release, field, value, published):
    """Published reconciliation relaxes only the draft state, never selected metadata."""
    release["draft"] = not published
    release[field] = value
    with pytest.raises(publication.PublicationError):
        verify_remote(plan, release)


def test_partial_upload_then_published_retry_retains_matching_assets(staged, plan, release):
    """A retry uploads exactly missing names and leaves matching remote IDs untouched."""
    rows = remote_rows(plan)
    retained = rows[::2]
    before = copy.deepcopy(retained)
    verify_remote(plan, release)
    missing = publication.missing_assets(plan, list(reversed(retained)))
    assert missing == sorted(set(plan["assets"]) - {row["name"] for row in retained})
    assert retained == before
    complete = retained + [row for row in rows if row["name"] in missing]
    release["draft"] = False
    release["updated_at"] = "published timestamp"
    for _ in range(2):
        verify_remote(plan, release)
        assert publication.missing_assets(plan, complete) == []
        actual = publication.read_assets(plan, staged)
        assert {name: digest(data) for name, data in actual.items()} == {
            name: record["sha256"] for name, record in plan["assets"].items()
        }
    assert retained == before
    assert publication.missing_assets(plan, []) == sorted(plan["assets"])


@pytest.mark.parametrize("change", [
    "duplicate_name", "duplicate_id", "unknown", "size", "digest", "bad_digest",
    "zero_id", "bool_id", "bool_size", "missing_field", "malformed_row",
])
def test_remote_assets_refuse_conflicts_instead_of_overwriting(plan, change):
    """Remote claims must be unique, well typed and byte-identical before retention."""
    rows = remote_rows(plan)
    if change == "duplicate_name":
        rows.append({**rows[0], "id": 999})
    elif change == "duplicate_id":
        rows[1]["id"] = rows[0]["id"]
    elif change == "unknown":
        rows[0]["name"] = "unreviewed.bin"
    elif change == "size":
        rows[0]["bytes"] += 1
    elif change == "digest":
        rows[0]["sha256"] = "0" * 64
    elif change == "bad_digest":
        rows[0]["sha256"] = "G" * 64
    elif change == "zero_id":
        rows[0]["id"] = 0
    elif change == "bool_id":
        rows[0]["id"] = True
    elif change == "bool_size":
        rows[0]["bytes"] = True
    elif change == "missing_field":
        del rows[0]["sha256"]
    else:
        rows[0] = "not an asset row"
    before = copy.deepcopy(rows)
    with pytest.raises(publication.PublicationError):
        publication.missing_assets(plan, rows)
    assert rows == before


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_initial_inventory_cannot_omit_or_add_payloads(staged, release, change):
    """Initial review is closed over the exact staged payload set."""
    if change == "missing":
        (staged / "manuscript.pdf").unlink()
    else:
        (staged / "unreviewed.bin").write_bytes(b"extra")
    checksums(staged)
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


@pytest.mark.parametrize(("field", "value"), [
    ("bytes", 0), ("bytes", True), ("bytes", LIMIT + 1), ("sha256", "A" * 64),
    ("sha256", "0" * 63), ("unexpected", "not part of the asset schema"),
])
def test_rehashed_asset_records_preserve_strict_types(plan, field, value):
    """Boolean sizes and noncanonical hashes cannot become reviewed asset records."""
    plan["assets"]["manuscript.pdf"][field] = value
    resign(plan)
    with pytest.raises(publication.PublicationError):
        publication.validate_plan(plan, now=NOW)


@pytest.mark.parametrize("receipt", ["SOURCE", "VALIDATION"])
@pytest.mark.parametrize("change", ["malformed", "array", "missing_binding"])
def test_checksums_do_not_rescue_unreadable_or_incomplete_receipts(staged, release, receipt, change):
    """Receipt structure and required bindings remain mandatory under valid checksums."""
    path = staged / f"{receipt}-{VERSION}.json"
    if change == "malformed":
        path.write_bytes(b"{not json}")
    elif change == "array":
        path.write_bytes(b"[]")
    else:
        body = json.loads(path.read_bytes())
        del body["validated_inputs_sha256"]
        path.write_bytes(json_bytes(body))
    checksums(staged)
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)



def test_individually_bounded_plan_assets_still_have_an_aggregate_limit(plan):
    """Several individually legal byte sizes cannot bypass the total review budget."""
    names = ["manuscript.pdf", f"docxplus-{VERSION}.tar.gz",
             f"docxplus-{VERSION}-py3-none-any.whl"]
    for name in names:
        plan["assets"][name]["bytes"] = 45 * 1024 * 1024
    resign(plan)
    with pytest.raises(publication.PublicationError):
        publication.validate_plan(plan, now=NOW)


def rebind_asset_metadata(plan, staged):
    """Keep the plan internally consistent when probing earlier byte-intake rules."""
    for path in staged.iterdir():
        with path.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        plan["assets"][path.name] = {"bytes": path.stat().st_size, "sha256": checksum}
    resign(plan)


@pytest.mark.parametrize("name", [name for name, _ in PAYLOADS])
@pytest.mark.parametrize("resized", [False, True])
def test_rechecksummed_payload_substitution_before_review_refuses(
    staged, release, name, resized,
):
    """A fresh checksum cannot substitute payloads for the bytes named by receipts."""
    path = staged / name
    replacement = bytes(byte ^ 0xFF for byte in path.read_bytes())
    path.write_bytes(replacement + (b"substitution" if resized else b""))
    checksums(staged)
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


@pytest.mark.parametrize(("receipt", "keys"), [
    ("SOURCE", ("schema",)),
    ("SOURCE", ("validated_generated_artifacts",)),
    ("SOURCE", ("validated_generated_artifacts", "manuscript_pdf_sha256")),
    ("VALIDATION", ("schema",)),
    ("VALIDATION", ("host", "inputs_sha256")),
    ("VALIDATION", ("lifecycle", "inputs_sha256")),
    ("VALIDATION", ("distribution_source_proof",)),
    *[("VALIDATION", ("distribution_source_proof", field))
      for field in ("version", "inputs_sha256", "wheel_sha256", "sdist_sha256", "visual_review")],
    ("VALIDATION", ("distribution_source_proof", "visual_review", "pdf_sha256")),
    ("VALIDATION", ("collected_artifacts",)),
    ("VALIDATION", ("collected_artifacts", "files")),
])
@pytest.mark.parametrize("change", ["missing", "null", "array"])
def test_required_receipt_links_cannot_disappear(staged, release, receipt, keys, change):
    """Schemas, qualified-byte links and nested inputs are mandatory receipt bindings."""
    path = staged / f"{receipt}-{VERSION}.json"
    body = json.loads(path.read_bytes())
    target = body
    for key in keys[:-1]:
        target = target[key]
    if change == "missing":
        del target[keys[-1]]
    else:
        target[keys[-1]] = None if change == "null" else []
    path.write_bytes(json_bytes(body))
    checksums(staged)
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


@pytest.mark.parametrize(("name", "inventory_name"), PAYLOADS)
@pytest.mark.parametrize("change", [
    "missing_entry", "not_object", "missing_bytes", "missing_digest", "wrong_bytes",
    "zero_bytes", "negative_bytes", "bool_bytes", "float_bytes", "string_bytes", "wrong_digest",
    "uppercase_digest", "short_digest",
])
def test_collected_payload_inventory_must_match_actual_bytes(
    staged, release, name, inventory_name, change,
):
    """Every staged payload needs a canonical positive-size inventory match."""
    path = staged / f"VALIDATION-{VERSION}.json"
    body = json.loads(path.read_bytes())
    files = body["collected_artifacts"]["files"]
    row = files[inventory_name]
    if change == "missing_entry":
        del files[inventory_name]
    elif change == "not_object":
        files[inventory_name] = []
    elif change == "missing_bytes":
        del row["bytes"]
    elif change == "missing_digest":
        del row["sha256"]
    elif change == "wrong_bytes":
        row["bytes"] = (staged / name).stat().st_size + 1
    elif change == "zero_bytes":
        row["bytes"] = 0
    elif change == "negative_bytes":
        row["bytes"] = -1
    elif change == "bool_bytes":
        row["bytes"] = True
    elif change == "float_bytes":
        row["bytes"] = float(row["bytes"])
    elif change == "string_bytes":
        row["bytes"] = str(row["bytes"])
    elif change == "wrong_digest":
        row["sha256"] = "d" * 64
    elif change == "uppercase_digest":
        row["sha256"] = row["sha256"].upper()
    else:
        row["sha256"] = row["sha256"][:-1]
    path.write_bytes(json_bytes(body))
    checksums(staged)
    with pytest.raises(publication.PublicationError):
        make_plan(staged, release)


def test_native_inventory_can_include_nonrelease_entries_and_fields(staged, release):
    """Checking the release subset must not reject additional native collection evidence."""
    path = staged / f"VALIDATION-{VERSION}.json"
    body = json.loads(path.read_bytes())
    files = body["collected_artifacts"]["files"]
    for row in files.values():
        row["archive_mode"] = 384
    report = b"native report fixture"
    files["coverage/report.json"] = {"bytes": len(report), "sha256": digest(report)}
    body["collected_artifacts"]["fixture"] = "not producer qualification"
    path.write_bytes(json_bytes(body))
    checksums(staged)
    plan = make_plan(staged, release)
    assert publication.read_assets(plan, staged)[path.name] == path.read_bytes()


@pytest.mark.parametrize("separator", [b"\n", b"\r\n"])
@pytest.mark.parametrize("terminal", [False, True])
@pytest.mark.parametrize("marker", [b" ", b"*"])
def test_checksum_records_support_interoperable_newlines_and_modes(
    staged, release, separator, terminal, marker,
):
    """LF, CRLF and an unterminated final record work in text and binary modes."""
    path = staged / "SHA256SUMS"
    rows = [row[:65] + marker + row[66:] for row in path.read_bytes().split(b"\n")[:-1]]
    content = separator.join(rows) + (separator if terminal else b"")
    path.write_bytes(content)
    plan = make_plan(staged, release)
    assert publication.read_assets(plan, staged)["SHA256SUMS"] == content


@pytest.mark.parametrize("separator", [b"\v", b"\f", b"\x1c", b"\x1d", b"\x1e", b"\r"])
@pytest.mark.parametrize("position", ["between_records", "terminal"])
@pytest.mark.parametrize("operation", ["plan", "read"])
def test_checksum_nonportable_separators_refuse(staged, release, plan, separator, position, operation):
    """Broader splitlines separators must not authorize a checksum-tool-incompatible file."""
    path = staged / "SHA256SUMS"
    original = path.read_bytes()
    if position == "between_records":
        path.write_bytes(original.replace(b"\n", separator, 1))
    else:
        path.write_bytes(original[:-1] + separator)
    rebind_asset_metadata(plan, staged)
    with pytest.raises(publication.PublicationError):
        if operation == "plan":
            make_plan(staged, release)
        else:
            publication.read_assets(plan, staged)


def pad_receipt(path, size):
    """Append legal JSON whitespace in small chunks, without a size-proportional buffer."""
    remaining = size - path.stat().st_size
    block = b" " * 65536
    with path.open("ab") as stream:
        while remaining:
            written = stream.write(block[:min(remaining, len(block))])
            remaining -= written


@pytest.mark.parametrize("receipt", ["SOURCE", "VALIDATION"])
@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("operation", ["plan", "read"])
def test_receipt_limit_includes_boundary_but_rejects_one_more_byte(
    staged, release, plan, receipt, extra, operation,
):
    """Even valid, checksummed receipt JSON is bounded independently at four MiB."""
    path = staged / f"{receipt}-{VERSION}.json"
    pad_receipt(path, RECEIPT_LIMIT + extra)
    checksums(staged)
    rebind_asset_metadata(plan, staged)

    def read():
        return (make_plan(staged, release) if operation == "plan"
                else publication.read_assets(plan, staged))

    if extra:
        with pytest.raises(publication.PublicationError):
            read()
    elif operation == "plan":
        assert read()["assets"] == plan["assets"]
    else:
        assert digest(read()[path.name]) == plan["assets"][path.name]["sha256"]


@pytest.mark.parametrize(("name", "size"), [
    (f"SOURCE-{VERSION}.json", RECEIPT_LIMIT + 1),
    (f"VALIDATION-{VERSION}.json", RECEIPT_LIMIT + 1),
    ("SHA256SUMS", CHECKSUM_LIMIT + 1),
    ("SHA256SUMS", 8 * 1024 * 1024),
])
@pytest.mark.parametrize("operation", ["plan", "read"])
def test_oversized_sparse_metadata_refuses_before_content_allocation(
    staged, release, plan, name, size, operation,
):
    """Sparse tails and self-consistent hashes cannot force whole-document allocation."""
    path = staged / name
    with path.open("r+b") as stream:
        stream.truncate(size)
    if name != "SHA256SUMS":
        checksums(staged)
    rebind_asset_metadata(plan, staged)
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    baseline, _ = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    try:
        with pytest.raises(publication.PublicationError):
            if operation == "plan":
                make_plan(staged, release)
            else:
                publication.read_assets(plan, staged)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if not was_tracing:
            tracemalloc.stop()
    assert peak - baseline < 2 * 1024 * 1024

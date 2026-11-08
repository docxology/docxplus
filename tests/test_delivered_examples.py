"""Delivered documents, captured measurements, and release gate boundaries."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys

import pytest

from docxplus import crypto, manuscript_vars, payloads, project_paths
from docxplus.container import DocxPlusBuilder, DocxPlusReader
from docxplus.fileext import write_document
from docxplus.odt_container import OdtPlusBuilder
from docxplus.reference_docs import build_reference_dossier
from docxplus.reproduce import OUTPUT_DIGEST_SCHEME
from scripts import release_guest

SCRIPTS = project_paths.project_root() / "scripts"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def isolated_root(tmp_path, monkeypatch):
    """Redirect only the project root; all package/crypto/publication calls are real."""
    source = tmp_path / "src" / "docxplus"
    source.mkdir(parents=True)
    (source / "container.py").write_text("# carried source fixture\n")
    (source / "empty").mkdir()
    monkeypatch.setattr(project_paths, "_ROOT", tmp_path)
    return tmp_path


def test_dossier_export_and_table_describe_the_same_serialized_specimen(isolated_root):
    """DEL4/6: the actual exporter writes both names and the shared slot/channel set."""
    script = load_script("04_dossier")
    assert script.main() == 0
    docs = isolated_root / "output/documents"
    data = (docs / "dossier.docx").read_bytes()
    assert (docs / "dossier.docxplus").read_bytes() == data
    reader = DocxPlusReader.from_bytes(data)
    table, count = manuscript_vars.dossier_table()
    assert count == len(reader.list_modules())
    for slot in reader.list_modules():
        rec = reader.manifest.slot(slot)
        assert f"| `{slot}` | {rec.channel} | {rec.sealing.get('mode', 'plain')} |" in table
    assert set(reader.list_modules()) == {"source", "annex", "review", "notes", "vault"}
    report = json.loads((isolated_root / "output/reports/dossier.json").read_text())
    assert report["ok"] is True
    assert report["module_table"] == manuscript_vars.dossier_table(reader)[0]
    assert report["checks"]["provenance_pinned"] is True
    assert report["checks"]["project_extracted"] is True
    assert "project_reproduced" not in report["checks"]
    assert reader.verify_reproduction("source")["attested"] is False


def test_shared_dossier_retains_credentials_for_real_evaluation(tmp_path):
    """The single constructor supports pinned provenance and each shipped seal."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.txt").write_bytes(b"source bytes\x00\xff")
    specimen = build_reference_dossier(source)
    reader = specimen.reader()
    assert reader.verify_provenance(expected_public_key=specimen.signing_public_key)
    assert not reader.verify_provenance(expected_public_key=crypto.generate_signing_key()[1])
    restored = reader.extract_project("source", tmp_path / "restored", password="reproduce")
    assert payloads.pack_project(restored) == payloads.pack_project(source)
    assert reader.open_nested("annex", password="annex-key").extract("annex") == b"eyes-only annex"
    assert reader.extract("review", private_key=specimen.recipient_private_key) == b"manuscript.pdf bytes"
    assert reader.extract("vault", shares=specimen.threshold_shares[:3]) == b"the combination"
    assert reader.extract("notes", password="a") == b"real coordinates"
    assert reader.extract("notes", password="b") == b"grocery list"


@pytest.mark.skipif(sys.platform != "linux", reason="real qualified Linux reproduction sandbox")
def test_living_export_attests_portable_authored_command(isolated_root):
    """DEL4/5: exercise the real exporter and compare signed argv, never rewrite it."""
    script = load_script("05_living_manuscript")
    assert script.CARRIED_PROJECT == isolated_root
    assert script.main() == 0
    docs = isolated_root / "output/documents"
    data = (docs / "living_manuscript.docx").read_bytes()
    assert (docs / "living_manuscript.docxplus").read_bytes() == data
    reader = DocxPlusReader.from_bytes(data)
    state = reader.verify_reproduction(script.CARRIED_SLOT)
    assert state["self_consistent"] and not state["verified"] and not state["authentic"]
    att = state["unverified_attestation"]
    report = json.loads((isolated_root / "output/reports/living_manuscript.json").read_text())
    assert att["command"] == report["authored_command"]
    assert att["output_digest_scheme"] == OUTPUT_DIGEST_SCHEME
    assert att["source_digest"] == crypto.digest(
        reader.extract(script.CARRIED_SLOT, password="reproduce")
    )
    reproduced = report["reproduction"]
    assert reproduced["output_digest_scheme"] == OUTPUT_DIGEST_SCHEME
    assert reproduced["source_match"] is True
    assert reproduced["expected"] == reproduced["actual"] == att["output_digest"]
    assert report["reproduced_match"] is True


@pytest.mark.skipif(sys.platform != "linux", reason="real qualified Linux reproduction sandbox")
@pytest.mark.parametrize("builder_type", [DocxPlusBuilder, OdtPlusBuilder])
def test_project_example_attests_its_portable_recipe(tmp_path, builder_type):
    script = load_script("06_project_roundtrip")
    source = script.build_example_project(tmp_path / "example")
    authored = json.loads((source / ".docxplus-reproduce.json").read_text())["command"]
    assert authored == ["python3", "compute.py"]
    priv, pub = crypto.generate_signing_key()
    builder = builder_type().add_project("source", source, reproduce=True).sign(priv)
    from docxplus.odt_container import open_document

    reader = open_document(builder.build())
    att = reader.verify_reproduction("source", expected_public_key=pub)
    assert att["verified"] is True
    assert att["attestation"]["command"] == authored
    assert att["attestation"]["output_digest_scheme"] == OUTPUT_DIGEST_SCHEME
    assert att["attestation"]["source_digest"] == crypto.digest(reader.extract("source"))
    reproduced = reader.reproduce("source", tmp_path / "relocated", allow_execution=True)
    assert reproduced["match"] is True
    assert reproduced["source_match"] is True
    assert reproduced["output_digest_scheme"] == OUTPUT_DIGEST_SCHEME


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_template_comparison_rejects_empty_directory_changes(tmp_path, change):
    """DEL9: use real directory snapshots, with unchanged file bytes and modes."""
    script = load_script("07_template_roundtrip")
    source, restored = tmp_path / "source", tmp_path / "restored"
    for root in (source, restored):
        root.mkdir()
        (root / "file.txt").write_bytes(b"same bytes")
        (root / "empty").mkdir()
    before = script.snapshot(source)
    assert script.compare(before, script.snapshot(restored))["identical"] is True
    if change == "missing":
        (restored / "empty").rmdir()
    else:
        (restored / "extra").mkdir()
    comparison = script.compare(before, script.snapshot(restored))
    assert comparison["identical"] is False
    assert comparison["content_mismatches"] == []
    key = "missing_directories" if change == "missing" else "unexpected_directories"
    assert comparison[key] == ["empty" if change == "missing" else "extra"]


def test_document_gate_requires_both_directions_and_identical_bytes(tmp_path):
    """DEL4: surface-only and plus-only exports must not pass artifact qualification."""
    data = DocxPlusBuilder().build()
    write_document(data, tmp_path / "dossier.v2.docx")
    write_document(OdtPlusBuilder().build(), tmp_path / "example.odt")
    assert len(release_guest.document_pair_checks(tmp_path)) == 2
    surface = tmp_path / "dossier.v2.docx"
    surface.unlink()
    with pytest.raises(RuntimeError, match="incomplete dual-name"):
        release_guest.document_pair_checks(tmp_path)
    surface.write_bytes(data)
    counterpart = tmp_path / "dossier.v2.docxplus"
    counterpart.unlink()
    with pytest.raises(RuntimeError, match="incomplete dual-name"):
        release_guest.document_pair_checks(tmp_path)
    counterpart.write_bytes(b"different payload")
    with pytest.raises(RuntimeError, match="dual names differ"):
        release_guest.document_pair_checks(tmp_path)


@pytest.fixture
def captured_report():
    return manuscript_vars.load_roundtrip_report(project_paths.project_root())


def test_measurement_tokens_require_an_existing_successful_report(tmp_path, captured_report):
    """DEL8: absent evidence is unavailable, not a synthetic zero-success experiment."""
    with pytest.raises(ValueError, match="unavailable"):
        manuscript_vars._roundtrip_stats(tmp_path)
    reports = tmp_path / "output/reports"
    reports.mkdir(parents=True)
    path = reports / "project_roundtrip.json"
    path.write_text(json.dumps(captured_report))
    stats = manuscript_vars._roundtrip_stats(tmp_path)
    assert stats["RT_CHECKS"] == stats["RT_PASSED"] == str(len(captured_report["checks"]))
    captured_report["checks"][0]["ok"] = False
    path.write_text(json.dumps(captured_report))
    with pytest.raises(ValueError, match="failed"):
        manuscript_vars._roundtrip_stats(tmp_path)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(ok=False),
    lambda d: d.update(failures=["failed"]),
    lambda d: d.update(checks=[]),
    lambda d: d["checks"][0].update(ok=1),
    lambda d: d["checks"].append(d["checks"][0]),
    lambda d: d["checks"].pop(),
    lambda d: d.update(project=None),
    lambda d: d["project"].update(files=-1),
    lambda d: d.update(profiles={}),
    lambda d: d["profiles"]["docx"].update(bytes=0),
    lambda d: d["profiles"]["docx"]["attestation"].update(verified=False),
    lambda d: d["profiles"]["odt"]["comparison"].update(identical=False),
    lambda d: d["profiles"]["docx"]["comparison"].update(files_compared=0),
    lambda d: d["cross_profile"]["nested"].update(missing_files=["lost"]),
])
def test_measurement_reader_refuses_failed_constituents(captured_report, mutation):
    """A stale affirmative summary cannot override any failed constituent."""
    report = copy.deepcopy(captured_report)
    mutation(report)
    with pytest.raises(ValueError, match="failed"):
        manuscript_vars.require_successful_roundtrip(report)

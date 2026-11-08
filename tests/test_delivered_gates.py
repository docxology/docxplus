"""Release qualification refuses absent, skipped, and failed custody evidence."""

import xml.etree.ElementTree as ET

import pytest

from scripts import release_guest


def junit_fixture(path, *, custody=True, skipped=False, failed=False, office=True, skip_office=False):
    """Write parser fixtures, not evidence that a production process ran."""
    suite = ET.Element("testsuite")
    for name in ("test_steg_bridge", "test_stego_media", "test_reproduce"):
        ET.SubElement(suite, "testcase", classname=f"tests.{name}", name="fixture_case")
    if office:
        for carrier in ("none", "python_lsb", "steganographer"):
            for profile in ("docx", "odt"):
                case = ET.SubElement(suite, "testcase", classname="tests.test_interop",
                                     name=f"test_libreoffice_headless_render[{carrier}-{profile}]")
                if skip_office and carrier == "steganographer" and profile == "odt":
                    ET.SubElement(case, "skipped", message="Office unavailable")
    if custody:
        case = ET.SubElement(suite, "testcase", classname="tests.test_reproduce_custody",
                             name="fixture_detached_child")
        if skipped:
            ET.SubElement(case, "skipped", message="sandbox unavailable")
        if failed:
            ET.SubElement(case, "failure", message="child survived")
    ET.ElementTree(suite).write(path)
    return path


@pytest.mark.parametrize("options", [
    {"custody": False}, {"skipped": True}, {"failed": True},
])
def test_junit_gate_refuses_incomplete_custody_receipts(tmp_path, options):
    path = junit_fixture(tmp_path / "suite.xml", **options)
    with pytest.raises(RuntimeError):
        release_guest.junit_summary(path)


@pytest.mark.parametrize("options", [{"office": False}, {"skip_office": True}])
def test_junit_gate_refuses_missing_or_skipped_office_evidence(tmp_path, options):
    with pytest.raises(RuntimeError):
        release_guest.junit_summary(junit_fixture(tmp_path / "suite.xml", **options))


@pytest.fixture
def office_export_candidate(tmp_path):
    """Untrusted parser fixtures, never receipts that an Office process ran."""
    import hashlib
    import json

    from scripts import validate_release

    guest = tmp_path / "guest"
    files = {}

    def put(path, data):
        destination = guest / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        record = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        files[path] = {"sha256": record["sha256"], "bytes": record["bytes"], "archive_mode": 0o644}
        return record

    visible = "DOCXPLUS INSTALLED WHEEL VISIBLE SENTINEL"
    hidden = "DOCXPLUS_HIDDEN_INSTALLED_WHEEL_SECRET"
    tools = {name: "fixture-version" for name in ("libreoffice", "pdftotext", "pdftoppm", "pdfimages")}
    office = {"schema": "docxplus.release-office.v1", "ok": True, "tools": tools,
              "tool_sha256": dict.fromkeys(tools, "a" * 64), "profiles": {}}
    for profile in ("docx", "odt"):
        records = {}
        original_data = f"fixture {profile} document".encode()
        put(f"installed-wheel/installed.{profile}", original_data)
        for phase in ("original", "saved"):
            for kind, name in (("document", f"installed.{profile}"), ("pdf", "installed.pdf"),
                               ("text", "installed.txt"), ("preview", "first-page.png")):
                data = visible.encode() if kind == "text" else b"non-production parser fixture"
                if kind == "document" and phase == "original":
                    data = original_data
                records[f"{phase}_{kind}"] = put(f"office/{profile}/{phase}/{name}", data)
        outcome = {"visible_text_preserved": True, "hidden_payload_absent": True,
                   "preview_nonblank": True, "preview_dark_pixels": 1000, "ok": True}
        office["profiles"][profile] = {
            "ok": True, "visible_sentinel": visible, "hidden_sentinel": hidden,
            "save_filter": "docx:Office Open XML Text" if profile == "docx" else "odt:writer8",
            "artifacts": records, "original": dict(outcome), "saved": dict(outcome)}
    results = {"installed_wheel": {}, "artifacts": {}}
    for branch, name in (("pytest", "pytest.xml"), ("pipeline_pytest", "pipeline-pytest.xml")):
        root = ET.Element("testsuite")
        for carrier in ("none", "python_lsb", "steganographer"):
            for profile in ("docx", "odt"):
                ET.SubElement(root, "testcase", classname="tests.test_interop",
                              name=f"test_libreoffice_headless_render[{carrier}-{profile}]")
        (guest / name).write_bytes(ET.tostring(root))
        results[branch] = {"office_executed": [dict(case.attrib) for case in root]}
    qualification = {"runtime": {"tools": dict(tools)}}

    def save():
        for branch in ("installed_wheel", "artifacts"):
            results[branch]["office"] = json.loads(json.dumps(office))
        (guest / "office/evidence.json").write_text(json.dumps(office))

    save()
    return {"output": tmp_path, "guest": guest, "office": office, "qualification": qualification,
            "results": results, "artifacts": {"files": files}, "put": put, "save": save,
            "check": validate_release.check_office_export}


@pytest.mark.parametrize("fault", [
    "profile_missing", "runtime", "replica", "artifact_hash", "artifact_size", "source_document",
    "visible_text", "hidden_plaintext", "hidden_base64", "missing_case", "duplicate_case",
    "skipped_case", "doctype_utf16",
])
def test_host_office_gate_refuses_conflicting_or_incomplete_exports(office_export_candidate, fault):
    import base64

    from scripts import validate_release

    candidate = office_export_candidate
    args = tuple(candidate[name] for name in ("output", "qualification", "results", "artifacts"))
    candidate["check"](*args)  # The control must qualify before the adversarial mutation.
    office, results = candidate["office"], candidate["results"]
    info = office["profiles"]["docx"]
    if fault == "profile_missing":
        del office["profiles"]["odt"]
    elif fault == "runtime":
        candidate["qualification"]["runtime"]["tools"]["libreoffice"] = "different runtime"
    elif fault == "artifact_hash":
        candidate["artifacts"]["files"][info["artifacts"]["saved_pdf"]["path"]]["sha256"] = "0" * 64
    elif fault == "artifact_size":
        info["artifacts"]["saved_preview"]["bytes"] += 1
    elif fault == "source_document":
        candidate["artifacts"]["files"]["installed-wheel/installed.docx"]["sha256"] = "0" * 64
    elif fault in {"visible_text", "hidden_plaintext", "hidden_base64"}:
        text = "missing sentinel" if fault == "visible_text" else info["visible_sentinel"]
        if fault == "hidden_plaintext":
            text += info["hidden_sentinel"]
        elif fault == "hidden_base64":
            text += base64.b64encode(info["hidden_sentinel"].encode()).decode()
        path = info["artifacts"]["saved_text"]["path"]
        info["artifacts"]["saved_text"] = candidate["put"](path, text.encode())
    elif fault in {"missing_case", "duplicate_case", "skipped_case", "doctype_utf16"}:
        path = candidate["guest"] / "pytest.xml"
        root = ET.fromstring(path.read_bytes())
        if fault == "missing_case":
            root.remove(root[0])
        elif fault == "duplicate_case":
            root.append(ET.fromstring(ET.tostring(root[0])))
        elif fault == "skipped_case":
            ET.SubElement(root[0], "skipped")
        else:
            root[0].set("time", "0.01")
        results["pytest"]["office_executed"] = [dict(case.attrib) for case in root]
        xml = ET.tostring(root, encoding="unicode")
        if fault == "doctype_utf16":
            xml = ('<?xml version="1.0" encoding="UTF-16"?>'
                   '<!DOCTYPE testsuite [<!ENTITY duration "0.01">]>'
                   + xml.replace('time="0.01"', 'time="&duration;"', 1))
            path.write_bytes(xml.encode("utf-16"))
        else:
            path.write_text(xml)
    candidate["save"]()
    if fault == "replica":
        results["artifacts"]["office"]["ok"] = False
    with pytest.raises(validate_release.Refusal):
        candidate["check"](*args)

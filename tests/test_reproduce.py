"""Reproduction attestation — the Science experiment, as tests.

Hypotheses (docs/reproduction-design.md):
  H1 reproducibility — a clean re-run reproduces the sealed output digest.
  H2 negative control — a tampered source produces a different digest (must fail).
  H3 determinism      — two clean runs of the same source agree.
Plus the load-bearing security invariant: nothing executes without allow_execution.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from docxplus import reproduce
from docxplus.container import ContainerError, DocxPlusBuilder, DocxPlusReader
from docxplus.crypto import generate_signing_key
from docxplus.reproduce import ReproSpec

# Use the running interpreter (a real CPython), not the macOS /usr/bin/python3 stub.
PY = sys.executable


def _make_repro_project(root: Path, sum_offset: int = 0) -> Path:
    """A tiny deterministic template_code_project-style project."""
    (root / "src").mkdir(parents=True)
    (root / "src" / "compute.py").write_text(
        "import json, os\n"
        "os.makedirs('output', exist_ok=True)\n"
        f"vals = [i * i + {sum_offset} for i in range(10)]\n"
        "json.dump({'values': vals, 'sum': sum(vals)}, open('output/result.json', 'w'), sort_keys=True)\n"
    )
    (root / ".docxplus-reproduce.json").write_text(
        json.dumps({"command": [PY, "src/compute.py"], "outputs": ["output/result.json"]})
    )
    return root


# -- H3: determinism -------------------------------------------------------
def test_h3_determinism(tmp_path):
    proj = _make_repro_project(tmp_path / "p")
    spec = reproduce.load_recipe(proj)
    d1 = reproduce.run_and_digest(proj, spec)
    # Fresh output dir, second independent run.
    import shutil

    shutil.rmtree(proj / "output")
    d2 = reproduce.run_and_digest(proj, spec)
    assert d1 == d2 and len(d1) == 64


# -- H1: reproducibility end-to-end through the container ------------------
def test_h1_reproduces_through_docxplus(tmp_path):
    proj = _make_repro_project(tmp_path / "p")
    priv, _ = generate_signing_key()
    data = (
        DocxPlusBuilder(paragraphs=["A living manuscript."])
        .add_project("source", proj, reproduce=True)
        .sign(priv)
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)

    # Cryptographic verification path: executes nothing.
    v = reader.verify_reproduction("source")
    assert v["attested"] and v["signed"] and v["verified"]
    assert len(v["attestation"]["output_digest"]) == 64

    # Opt-in execution path: re-runs and matches.
    result = reader.reproduce("source", tmp_path / "out", allow_execution=True)
    assert result["match"] is True


# -- H2: negative control — a tampered source must fail --------------------
def test_h2_tampered_source_fails(tmp_path):
    proj = _make_repro_project(tmp_path / "p")
    spec = reproduce.load_recipe(proj)
    attestation = reproduce.attest(proj, spec)

    tampered = _make_repro_project(tmp_path / "evil", sum_offset=1)  # different outputs
    result = reproduce.reproduce_and_compare(tampered, attestation)
    assert result["match"] is False


def test_h2_tampered_carried_bytes_caught_before_execution(tmp_path):
    """Flipping the carried project bytes trips the stored-digest guard on extract,
    so a tampered dossier fails before any code could run."""
    proj = _make_repro_project(tmp_path / "p")
    data = DocxPlusBuilder().add_project("source", proj, reproduce=True).build()
    from docxplus.opc import read_package

    pkg = read_package(data)
    part = next(p for p in pkg.parts if p.startswith("intelligence/payload"))
    pkg.parts[part] = pkg.parts[part][:-1] + bytes([pkg.parts[part][-1] ^ 0xFF])
    reader = DocxPlusReader(package=pkg, manifest=__import__("docxplus.manifest", fromlist=["x"]).read_manifest(pkg))
    with pytest.raises(ContainerError, match="stored bytes altered"):
        reader.reproduce("source", tmp_path / "out", allow_execution=True)


# -- security invariant: no execution without explicit opt-in --------------
def test_reproduce_refuses_without_allow_execution(tmp_path):
    proj = _make_repro_project(tmp_path / "p")
    data = DocxPlusBuilder().add_project("source", proj, reproduce=True).build()
    reader = DocxPlusReader.from_bytes(data)
    dest = tmp_path / "out"
    with pytest.raises(ContainerError, match="allow_execution"):
        reader.reproduce("source", dest, allow_execution=False)
    assert not dest.exists()  # nothing was extracted or run


def test_verify_reproduction_executes_nothing(tmp_path):
    proj = _make_repro_project(tmp_path / "p")
    data = DocxPlusBuilder().add_project("source", proj, reproduce=True).build()
    reader = DocxPlusReader.from_bytes(data)
    before = set((tmp_path).iterdir())
    reader.verify_reproduction("source")
    assert set((tmp_path).iterdir()) == before  # no output produced


def test_no_attestation_when_not_requested(tmp_path):
    proj = _make_repro_project(tmp_path / "p")
    data = DocxPlusBuilder().add_project("source", proj).build()  # reproduce not requested
    reader = DocxPlusReader.from_bytes(data)
    assert reader.verify_reproduction("source")["attested"] is False


def test_attest_requires_recipe_or_spec(tmp_path):
    proj = tmp_path / "norecipe"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "x.py").write_text("print('hi')\n")
    with pytest.raises(ContainerError, match="no .docxplus-reproduce"):
        DocxPlusBuilder().add_project("s", proj, reproduce=True)


def test_failing_command_raises_reproerror(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    spec = ReproSpec(command=[PY, "-c", "import sys; sys.exit(3)"], outputs=[])
    with pytest.raises(reproduce.ReproError, match="exit 3"):
        reproduce.attest(proj, spec)


def test_empty_outputs_is_rejected_as_vacuous(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    spec = ReproSpec(command=[PY, "-c", "pass"], outputs=[])
    with pytest.raises(reproduce.ReproError, match="vacuous"):
        reproduce.attest(proj, spec)


def test_missing_declared_output_is_rejected(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    spec = ReproSpec(command=[PY, "-c", "pass"], outputs=["output/never.json"])
    with pytest.raises(reproduce.ReproError, match="produced no file"):
        reproduce.attest(proj, spec)


def test_explicit_reprospec_accepted(tmp_path):
    proj = _make_repro_project(tmp_path / "p")
    spec = ReproSpec(command=[PY, "src/compute.py"], outputs=["output/result.json"])
    data = DocxPlusBuilder().add_project("source", proj, reproduce=spec).build()
    reader = DocxPlusReader.from_bytes(data)
    result = reader.reproduce("source", tmp_path / "o", allow_execution=True)
    assert result["match"] is True
    assert result["toolchain_match"] is True  # same machine


def test_carried_input_cannot_masquerade_as_product(tmp_path):
    """RedTeam: a recipe whose only output is a carried source file that the command
    does not modify must be rejected — it would attest an input, not a product."""
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "carried.py").write_text("CONSTANT = 1\n")
    # Command touches nothing; declares a pre-existing carried file as its output.
    spec = ReproSpec(command=[PY, "-c", "pass"], outputs=["src/carried.py"])
    with pytest.raises(reproduce.ReproError, match="input, not a computed product"):
        reproduce.attest(proj, spec)


def test_timeout_is_clamped_to_ceiling():
    spec = ReproSpec.from_dict({"command": [PY], "outputs": ["x"], "timeout": 10**9})
    assert spec.timeout == reproduce.MAX_REPRO_SECONDS


def test_reproduce_timeout_kills_and_raises(tmp_path):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "c.py").write_text("import time, os\nos.makedirs('output');open('output/r','w').write('x')\ntime.sleep(30)\n")
    spec = ReproSpec(command=[PY, "src/c.py"], outputs=["output/r"], timeout=1)
    with pytest.raises(reproduce.ReproError, match="timed out"):
        reproduce.run_and_digest(proj, spec)


def test_hermetic_extract_and_reproduce(tmp_path):
    proj = Path(_make_repro_project(tmp_path / "proj"))
    from docxplus.payloads import pack_project

    packed = pack_project(proj)
    recipe = reproduce.load_recipe(proj)
    assert recipe is not None
    attestation = reproduce.attest(proj, recipe)

    # Without allow_execution=True, raises ReproError
    with pytest.raises(reproduce.ReproError, match="allow_execution"):
        reproduce.hermetic_extract_and_reproduce(packed, attestation, allow_execution=False)

    # With allow_execution=True, runs hermetically in temporary sandbox and matches
    res = reproduce.hermetic_extract_and_reproduce(packed, attestation, allow_execution=True)
    assert res["match"] is True



# -- v0.6.2: sandbox profile construction ------------------------------------


def test_reproduce_helpers_coverage(tmp_path):
    """Cover ReproSpec dictionary serialization and sandbox wrapper on Linux/fallback."""
    spec = reproduce.ReproSpec(command=["python", "main.py"], outputs=["out.txt"], timeout=60)
    d = spec.to_dict()
    assert d["command"] == ["python", "main.py"]
    assert d["timeout"] == 60

    # Wildcard checks
    assert reproduce._is_wildcard("*.txt") is True
    assert reproduce._is_wildcard("file.txt") is False

    # Sandbox wrap fallback / Linux
    wrapped = reproduce._sandbox_wrap(["echo", "1"], tmp_path)
    assert isinstance(wrapped, list)
    assert len(wrapped) >= 2

@pytest.mark.skipif(sys.platform != "darwin", reason="seatbelt profile is macOS-only")
def test_sandbox_profile_refuses_an_unquotable_project_path(tmp_path):
    """A path containing a quote could append rules to the seatbelt profile.

    `x") (allow network*) (subpath "/` closes the SBPL string literal and turns the
    network denial back on its head, so the wrapper must refuse to build at all.
    """
    hostile = tmp_path / 'x") (allow network*) (subpath "/'
    hostile.mkdir()
    with pytest.raises(reproduce.ReproError, match="cannot be safely quoted"):
        reproduce._sandbox_wrap(["/bin/echo", "hi"], str(hostile))


@pytest.mark.skipif(sys.platform != "darwin", reason="seatbelt profile is macOS-only")
def test_sandbox_profile_denies_network_for_an_ordinary_path(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    argv = reproduce._sandbox_wrap(["/bin/echo", "hi"], str(proj))
    assert argv[0] == "sandbox-exec"
    profile = argv[2]
    assert "(deny network*)" in profile
    assert "(allow network*)" not in profile
    assert str(proj.resolve()) in profile

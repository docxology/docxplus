"""Reproduction attestation — the Science experiment, as tests.

Hypotheses (docs/reproduction-design.md):
  H1 reproducibility — a clean re-run reproduces the sealed output digest.
  H2 negative control — a tampered source produces a different digest (must fail).
  H3 determinism      — two clean runs of the same source agree.
Plus the load-bearing security invariant: nothing executes without allow_execution.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

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
    priv, pub = generate_signing_key()
    data = (
        DocxPlusBuilder(paragraphs=["A living manuscript."])
        .add_project("source", proj, reproduce=True)
        .sign(priv)
        .build()
    )
    reader = DocxPlusReader.from_bytes(data)

    # Cryptographic verification path: executes nothing.
    v = reader.verify_reproduction("source", expected_public_key=pub)
    assert v["attested"] and v["signed"] and v["verified"]
    assert len(v["attestation"]["output_digest"]) == 64
    assert v["attestation"]["output_digest_scheme"] == reproduce.OUTPUT_DIGEST_SCHEME

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
    spec = ReproSpec(command=[PY, "-c", "import sys; sys.exit(3)"], outputs=["result"])
    with pytest.raises(reproduce.ReproError, match="exit 3"):
        reproduce.attest(proj, spec)


def test_empty_outputs_is_rejected_as_vacuous(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    spec = ReproSpec(command=[PY, "-c", "pass"], outputs=[])
    with pytest.raises(reproduce.ReproError):
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
    with pytest.raises(reproduce.ReproError):
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


def test_execution_refuses_when_no_confinement_tool_is_available(tmp_path, monkeypatch):
    """Missing sandbox tools must fail before carried code can write outside its project."""
    project = tmp_path / "project"
    project.mkdir()
    marker = tmp_path / "outside-project"
    monkeypatch.setenv("PATH", "")
    command = [
        PY, "-c",
        (
            f"from pathlib import Path; Path({str(marker)!r}).write_text('escaped'); "
            "Path('result').write_text('computed')"
        ),
    ]
    with pytest.raises(reproduce.ReproError, match="refusing to run"):
        reproduce.run_and_digest(project, ReproSpec(command, ["result"]))
    assert not marker.exists()
    assert not (project / "result").exists()

@pytest.mark.parametrize("command", [
    ["--share-net", "--bind", "/", "/"],
    ["-p", "(version 1)(allow default)"],
])
def test_carried_command_cannot_supply_sandbox_options(tmp_path, command):
    """A recipe's first argument is a program; as an option it would rewrite confinement."""
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(reproduce.ReproError, match="must name a program"):
        reproduce.run_and_digest(project, ReproSpec(command, ["result"]))
    assert not (project / "result").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="seatbelt profile is macOS-only")
def test_sandbox_profile_refuses_an_unquotable_project_path(tmp_path):
    """A path containing a quote could append rules to the seatbelt profile.

    `x") (allow network*) (subpath "/` closes the SBPL string literal and turns the
    network denial back on its head, so the wrapper must refuse to build at all.
    """
    hostile = tmp_path / 'x") (allow network*) (subpath "/'
    hostile.mkdir()
    with pytest.raises(reproduce.ReproError, match="cannot be safely quoted"):
        reproduce._sandbox_wrap(["/bin/echo", "hi"], hostile, tmp_path / "temp")




def test_output_digest_cannot_shift_bytes_across_file_boundaries(tmp_path):
    """A one-file and two-file tree shared the same unframed digest preimage."""
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a").write_bytes(b"Xb\0Y")
    (second / "a").write_bytes(b"X")
    (second / "b").write_bytes(b"Y")
    assert reproduce._digest_outputs(first, ["*"], {}) != reproduce._digest_outputs(second, ["*"], {})


def test_one_new_output_does_not_launder_an_unchanged_carried_result(tmp_path):
    """Every declared product must be computed, not merely one marker beside an input."""
    import hashlib

    carried = tmp_path / "carried-result"
    carried.write_bytes(b"hand-authored result")
    before = {str(carried): (carried.stat().st_size, hashlib.blake2b(carried.read_bytes(), digest_size=32).hexdigest())}
    (tmp_path / "marker").write_bytes(b"new")
    with pytest.raises(reproduce.ReproError):
        reproduce._digest_outputs(tmp_path, ["*"], before)
    assert carried.read_bytes() == b"hand-authored result"


def test_generated_output_symlink_is_not_a_computed_host_input(tmp_path):
    """Collection runs in the parent and must never follow a child-created host link."""
    root = tmp_path / "project"
    root.mkdir()
    host = tmp_path / "host-input"
    host.write_bytes(b"not computed by the recipe")
    (root / "result").symlink_to(host)
    with pytest.raises(reproduce.ReproError):
        reproduce._digest_outputs(root, ["result"], {})
    assert host.read_bytes() == b"not computed by the recipe"


def test_output_collection_has_a_file_count_and_deadline_bound(tmp_path):
    """Zero-length outputs still have bounded metadata/hash work in the verifier."""
    import time

    for i in range(reproduce.MAX_OUTPUT_FILES + 1):
        (tmp_path / f"{i:05d}").touch()
    with pytest.raises(reproduce.ReproError):
        reproduce._digest_outputs(tmp_path, ["*"], {})
    with pytest.raises(reproduce.ReproError):
        reproduce._digest_outputs(tmp_path, ["*"], {}, deadline=time.monotonic() - 1)


def test_portable_python_recipe_uses_the_recipient_interpreter(tmp_path):
    """A sealed recipe must not depend on the author's absolute venv prefix."""
    project = tmp_path / "project"
    project.mkdir()
    spec = ReproSpec(["{python}", "-c", "from pathlib import Path; Path('output').mkdir(); Path('output/value').write_bytes(b'computed')"], ["output/value"])
    attestation = reproduce.attest(project, spec)
    import shutil

    shutil.rmtree(project / "output")
    result = reproduce.reproduce_and_compare(project, attestation)
    assert result["source_match"] and result["match"]
    assert (project / "output/value").read_bytes() == b"computed"


@pytest.mark.skipif(sys.platform != "linux", reason="private reproduction PID namespace is Linux-only")
@pytest.mark.parametrize("new_session", [False, True])
def test_successful_reproduction_does_not_leave_a_writing_descendant(tmp_path, new_session):
    """Both ordinary and setsid descendants are dead before output collection returns.

    The leader records its private PID namespace. After ``run_and_digest`` returns
    that namespace must contain no live member (a killed descendant may linger as a
    zombie until reaped), and the 30-second child's delayed write never lands. The
    child's *inner* PID is meaningless on the outer host, so liveness is observed
    through the namespace the sandbox actually owns.
    """
    import time

    child = (
        "from pathlib import Path; import time; "
        "Path('ready').write_text('ready'); time.sleep(30); Path('late').write_text('escaped')"
    )
    command = (
        "import os,subprocess,sys,time; from pathlib import Path\n"
        "Path('custody.json').write_text(os.readlink('/proc/self/ns/pid'))\n"
        f"subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session={new_session!r})\n"
        "deadline=time.monotonic()+3\n"
        "while not Path('ready').exists() and time.monotonic()<deadline: time.sleep(0.01)\n"
        "assert Path('ready').read_text()=='ready'\n"
        "Path('result').write_text('computed')\n"
    )
    reproduce.run_and_digest(tmp_path, ReproSpec([PY, "-c", command], ["result"], timeout=10))
    assert (tmp_path / "result").read_text() == "computed"
    identity = (tmp_path / "custody.json").read_text()
    assert identity != Path("/proc/self/ns/pid").readlink()
    live = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if Path(entry / "ns/pid").readlink() != identity:
                continue
            status = (entry / "status").read_text()
            state = next(line.split()[1] for line in status.splitlines()
                         if line.startswith("State:"))
        except (FileNotFoundError, ProcessLookupError, PermissionError, StopIteration):
            continue
        if state not in {"Z", "X"}:
            live.append((int(entry.name), state))
    assert not live, f"live descendants remain in the private namespace: {live}"
    time.sleep(0.2)
    assert not (tmp_path / "late").exists()


@pytest.mark.parametrize("scheme", [None, "docxplus-output-tree-v2-blake2b-256", "unknown"])
def test_unknown_output_digest_scheme_refuses_before_execution(tmp_path, scheme):
    """Old signed digests cannot silently acquire new semantics or execute a recipe."""
    attestation = {
        "command": [PY, "-c", "from pathlib import Path; Path('executed').touch()"],
        "outputs": ["executed"],
        "output_digest": "00" * 32,
    }
    if scheme is not None:
        attestation["output_digest_scheme"] = scheme
    with pytest.raises(reproduce.ReproError, match="output_digest_scheme"):
        reproduce.reproduce_and_compare(tmp_path, attestation)
    assert not (tmp_path / "executed").exists()


def test_output_digest_v3_has_explicit_path_size_hash_transcript(tmp_path):
    """Freeze the declared digest framing, not incidental traversal implementation."""
    import hashlib

    (tmp_path / "z").write_bytes(b"\0tail")
    (tmp_path / "a").write_bytes(b"first")
    h = hashlib.blake2b(digest_size=32)
    h.update(b"docxplus/reproduction-outputs/v3\0")
    h.update((2).to_bytes(8, "big"))
    for name, content in (("a", b"first"), ("z", b"\0tail")):
        path = name.encode("utf-8")
        h.update(len(path).to_bytes(8, "big"))
        h.update(path)
        h.update(len(content).to_bytes(8, "big"))
        h.update(hashlib.blake2b(content, digest_size=32).digest())
    assert reproduce._digest_outputs(tmp_path, ["z", "*", "a"], {}) == h.hexdigest()


def test_signed_consumer_digest_cannot_shift_output_boundaries(tmp_path):
    """CriticNEW2: serialized consumer evidence distinguishes formerly colliding trees."""
    from docxplus.payloads import unpack_project

    project = tmp_path / "project"
    project.mkdir()
    (project / "mode").write_text("one")
    (project / "compute.py").write_text(
        "from pathlib import Path\n"
        "Path('output').mkdir()\n"
        "one = Path('mode').read_text() == 'one'\n"
        "Path('output/a').write_bytes(b'Xoutput/b\\0Y' if one else b'X')\n"
        "if not one: Path('output/b').write_bytes(b'Y')\n"
    )
    spec = ReproSpec(["{python}", "compute.py"], ["output/*"])
    private, public = generate_signing_key()
    data = DocxPlusBuilder().add_project("source", project, reproduce=spec).sign(private).build()
    reader = DocxPlusReader.from_bytes(data)
    verified = reader.verify_reproduction("source", expected_public_key=public)
    assert verified["verified"]
    attestation = verified["attestation"]
    assert attestation["output_digest_scheme"] == reproduce.OUTPUT_DIGEST_SCHEME
    clean = reader.reproduce("source", tmp_path / "clean", allow_execution=True)
    assert clean["match"] and clean["actual"] == attestation["output_digest"]
    changed = unpack_project(reader.extract("source"), tmp_path / "changed")
    (changed / "mode").write_text("two")
    result = reproduce.reproduce_and_compare(changed, attestation)
    assert result["actual"] != attestation["output_digest"]
    assert not result["match"]


def test_signed_reproduction_binds_source_even_when_outputs_match(tmp_path):
    """The user's source commitment must survive the v3 output-digest cutover."""
    from docxplus.payloads import unpack_project

    project = _make_repro_project(tmp_path / "project")
    spec = ReproSpec(["{python}", "src/compute.py"], ["output/result.json"])
    private, public = generate_signing_key()
    data = DocxPlusBuilder().add_project("source", project, reproduce=spec).sign(private).build()
    reader = DocxPlusReader.from_bytes(data)
    verified = reader.verify_reproduction("source", expected_public_key=public)
    assert verified["verified"]
    attestation = verified["attestation"]
    assert attestation["command"][0] == "{python}"
    assert attestation["output_digest_scheme"] == reproduce.OUTPUT_DIGEST_SCHEME

    changed = unpack_project(reader.extract("source"), tmp_path / "changed")
    source = changed / "src" / "compute.py"
    source.write_text(source.read_text() + "\n# Different source, identical computation.\n")
    result = reproduce.reproduce_and_compare(changed, attestation)
    assert result["actual"] == result["expected"]
    assert result["output_digest_scheme"] == reproduce.OUTPUT_DIGEST_SCHEME
    assert result["toolchain_match"]
    assert not result["source_match"]
    assert not result["match"]

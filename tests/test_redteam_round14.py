"""Regressions for the round-14 security review: extraction, execution, timing.

Three findings on the paths where untrusted material stops being data and starts
being behaviour — a tarball becoming files on disk, a carried command becoming a
process, and a password attempt becoming an observable duration.

Each was a control that held in the configuration it was developed in and not in
one the project supports. The extraction hardening depended on the interpreter
version, the execution confinement bounded the child but not the parent, and the
deniability of a decoy held against everything except a clock.
"""

from __future__ import annotations

import gzip
import io
import statistics
import sys
import tarfile
import time

import pytest

from docxplus import payloads
from docxplus import reproduce
from docxplus.container import DocxPlusBuilder, DocxPlusReader


# -- Finding 1: extraction hardening must not depend on the interpreter -------


def _tar_with(info: tarfile.TarInfo, data: bytes | None = None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return gzip.compress(raw.getvalue(), mtime=0)


def test_a_setuid_member_never_lands_with_its_setuid_bit(tmp_path):
    """The finding, in the form it would actually be exploited.

    ``requires-python`` is ``>=3.10``, and ``extractall(filter="data")`` raises
    ``TypeError`` before 3.12, where the code fell through to an unfiltered
    ``extractall``. A payload carrying ``run.sh`` at 04755 extracted with the setuid
    bit intact — a privilege-escalation primitive handed over by a document. The
    manual pre-check loop refused links and traversal, and said nothing about mode.
    """
    info = tarfile.TarInfo("run.sh")
    info.size, info.mode, info.type = 4, 0o4755, tarfile.REGTYPE
    out = payloads.unpack_project(_tar_with(info, b"echo"), tmp_path / "dest")
    mode = (out / "run.sh").stat().st_mode & 0o7777
    assert not mode & 0o4000, f"setuid survived extraction: {oct(mode)}"
    assert not mode & 0o2000, f"setgid survived extraction: {oct(mode)}"
    assert mode == 0o755, oct(mode)


def test_the_executable_bit_is_still_carried(tmp_path):
    """Clamping must not cost the one permission the format promises to keep."""
    info = tarfile.TarInfo("run.sh")
    info.size, info.mode, info.type = 4, 0o755, tarfile.REGTYPE
    out = payloads.unpack_project(_tar_with(info, b"echo"), tmp_path / "dest")
    assert (out / "run.sh").stat().st_mode & 0o111

    plain = tarfile.TarInfo("notes.txt")
    plain.size, plain.mode, plain.type = 4, 0o644, tarfile.REGTYPE
    out2 = payloads.unpack_project(_tar_with(plain, b"text"), tmp_path / "dest2")
    assert not (out2 / "notes.txt").stat().st_mode & 0o111


def test_extraction_does_not_call_extractall(tmp_path):
    """Asserted structurally, because the version-dependent branch was the bug.

    A test on this interpreter alone cannot see the 3.10 path, and the 3.10 path is
    where the vulnerability lived. Requiring that members be written out explicitly
    is the property that makes the guarantee interpreter-independent.
    """
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(payloads.unpack_project)))
    function = tree.body[0]
    # Drop the docstring: it *describes* the removed call, and matching prose rather
    # than code is how a guard ends up failing on its own explanation.
    body = function.body[1:] if ast.get_docstring(function) else function.body
    calls = {
        node.func.attr
        for statement in body
        for node in ast.walk(statement)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "extractall" not in calls, (
        "unpack_project delegates to extractall again; its hardening is then whatever "
        "the running interpreter's default filter happens to be"
    )


# -- Finding 2: confinement must bound the verifier, not only the child -------


def test_child_output_does_not_accumulate_in_the_verifier(tmp_path):
    """`communicate()` buffered the child's stdout in the parent's address space.

    Every other confinement held — network denied, writes confined, RLIMIT_AS and
    RLIMIT_FSIZE set on the child — and none of them reaches a pipe the parent is
    reading. A carried command that merely printed could exhaust the machine doing
    the verifying, and the run was reported as a success.
    """
    project = tmp_path / "p"
    project.mkdir()
    (project / "gen.py").write_text(
        "import sys\n"
        "open('out.txt','w').write('result')\n"
        "buf = 'A' * (1 << 20)\n"
        "for _ in range(64): sys.stdout.write(buf)\n"
    )
    spec = reproduce.ReproSpec(
        command=[sys.executable, "gen.py"], outputs=["out.txt"], timeout=60
    )
    import resource

    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    try:
        reproduce.run_and_digest(project, spec)
    except reproduce.ReproError:
        pass  # the child hitting its own file-size limit is an acceptable outcome
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    unit = 1024 * 1024 if sys.platform == "darwin" else 1024
    grew = (after - before) / unit
    assert grew < 32, f"verifier RSS grew {grew:.0f} MiB on 64 MiB of child stdout"


def test_a_failing_run_still_reports_why(tmp_path):
    """Bounding the capture must not cost the diagnostic."""
    project = tmp_path / "p"
    project.mkdir()
    (project / "bad.py").write_text(
        "import sys\nsys.stderr.write('the reason it failed\\n')\nsys.exit(3)\n"
    )
    spec = reproduce.ReproSpec(
        command=[sys.executable, "bad.py"], outputs=["out.txt"], timeout=30
    )
    with pytest.raises(reproduce.ReproError, match="the reason it failed"):
        reproduce.run_and_digest(project, spec)


def test_captured_stderr_is_bounded(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "loud.py").write_text(
        "import sys\nsys.stderr.write('X' * (1 << 20))\nsys.exit(1)\n"
    )
    spec = reproduce.ReproSpec(
        command=[sys.executable, "loud.py"], outputs=["out.txt"], timeout=30
    )
    with pytest.raises(reproduce.ReproError) as caught:
        reproduce.run_and_digest(project, spec)
    assert len(str(caught.value)) < reproduce.MAX_CAPTURED_STDERR + 512


# -- Finding 3: deniability has to survive a clock ----------------------------


def _median_open_seconds(reader: DocxPlusReader, slot: str, password: str, runs: int = 5) -> float:
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        reader.extract(slot, password=password)
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def test_the_real_and_decoy_passwords_take_the_same_time():
    """The decoy's whole purpose fails if a stopwatch separates the two answers.

    Frames were tried in order and the first success returned, so the real payload
    in frame 1 cost one key derivation and the cover story in frame 2 cost two:
    measured at 154 ms against 307 ms, a clean factor of two on a derivation that is
    deliberately expensive. An adversary who has compelled a password and can time
    the extraction learns whether they were given the whole story, which is the one
    question the lineage exists to refuse.

    The tolerance is loose because this asserts the absence of a *structural* factor
    of two, not a constant-time guarantee. Python cannot offer the latter, and
    claiming it would be worse than this bound.
    """
    builder = DocxPlusBuilder(paragraphs=["cover"], title="t")
    builder.add_decoy(
        "s", real=b"THE REAL SECRET", real_password="real-pw",
        decoy=b"innocuous cover story", decoy_password="decoy-pw",
    )
    reader = DocxPlusReader.from_bytes(builder.build())

    real = _median_open_seconds(reader, "s", "real-pw")
    decoy = _median_open_seconds(reader, "s", "decoy-pw")
    ratio = max(real, decoy) / max(1e-9, min(real, decoy))
    assert ratio < 1.35, (
        f"real={real*1000:.0f}ms decoy={decoy*1000:.0f}ms ratio={ratio:.2f} — the "
        f"frame that opened is observable, so the cover story is not one"
    )


def test_both_payloads_are_still_recoverable_under_their_own_passwords():
    """Trying every frame must not change which payload each password yields."""
    builder = DocxPlusBuilder(paragraphs=["cover"], title="t")
    builder.add_decoy(
        "s", real=b"THE REAL SECRET", real_password="real-pw",
        decoy=b"innocuous cover story", decoy_password="decoy-pw",
    )
    reader = DocxPlusReader.from_bytes(builder.build())
    assert reader.extract("s", password="real-pw") == b"THE REAL SECRET"
    assert reader.extract("s", password="decoy-pw") == b"innocuous cover story"
    with pytest.raises(Exception):
        reader.extract("s", password="neither")


def test_an_ordinary_sealed_module_costs_the_same_as_a_decoy():
    """Otherwise timing separates 'has a hidden payload' from 'does not'.

    The chaff frame equalises the static shape; attempting every frame equalises the
    dynamic one. Both halves are needed and only together do they mean anything.
    """
    ordinary = DocxPlusBuilder(paragraphs=["cover"], title="t")
    ordinary.add_module("s", "package_part", b"ordinary payload", payload_type="bytes",
                        password="only-pw")
    plain_reader = DocxPlusReader.from_bytes(ordinary.build())

    with_decoy = DocxPlusBuilder(paragraphs=["cover"], title="t")
    with_decoy.add_decoy("s", real=b"THE REAL SECRET", real_password="real-pw",
                         decoy=b"cover", decoy_password="decoy-pw")
    decoy_reader = DocxPlusReader.from_bytes(with_decoy.build())

    plain = _median_open_seconds(plain_reader, "s", "only-pw")
    hidden = _median_open_seconds(decoy_reader, "s", "real-pw")
    ratio = max(plain, hidden) / max(1e-9, min(plain, hidden))
    assert ratio < 1.35, f"plain={plain*1000:.0f}ms decoy={hidden*1000:.0f}ms ratio={ratio:.2f}"

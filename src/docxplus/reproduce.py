"""Reproduction attestation — execute-once-upstream, verify-cryptographically-downstream.

This module is the only place in docxplus that executes carried code, and it does so
ONLY when a caller explicitly opts in (``container.reproduce(allow_execution=True)``).
Nothing on the read/validate/verify path ever calls it. Following the Council
synthesis (``docs/reproduction-design.md``):

* The **author** (who has the toolchain) runs a project's declared reproduce command
  once and seals a signed **attestation** binding ``source_digest → output_digest``
  plus a toolchain fingerprint.
* A downstream reader **verifies cryptographically, executing nothing**.
* A zero-trust reader may **opt in** to re-run here, in a best-effort hermetic
  sandbox: scrubbed environment, resource + file-size limits, a clamped wall-clock
  timeout, own process group, network denied and writes confined to the project +
  temp dirs where the platform supports it (macOS seatbelt / Linux bwrap).

The sandbox is best-effort, not a microVM; its exact guarantees per platform (and
where confinement does NOT hold) are documented in ``docs/security-model.md``. The
load-bearing guarantee is the opt-in: a document never runs itself.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import tempfile
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Recipe filename a carried project may ship to declare its own reproduction.
RECIPE_FILE = ".docxplus-reproduce.json"

# Reader-side ceilings on author-controlled values (a hostile attestation must not
# be able to hang the reader or pull an enormous output into memory).
MAX_REPRO_SECONDS = 900
#: Bytes of a failed run's stderr quoted back in the error. The rest is
#: discarded unread, so a chatty failure cannot become a memory exhaustion.
MAX_CAPTURED_STDERR = 8192

MAX_OUTPUT_BYTES = 256 * 1024 * 1024
_CHUNK = 1 << 16


@dataclass
class ReproSpec:
    """A project's reproduction recipe: a command and the outputs it must produce."""

    command: list[str]
    outputs: list[str] = field(default_factory=list)  # globs relative to project root
    timeout: int = 300

    def to_dict(self) -> dict:
        return {"command": list(self.command), "outputs": list(self.outputs), "timeout": self.timeout}

    @classmethod
    def from_dict(cls, d: dict) -> ReproSpec:
        # Clamp the author-supplied timeout to a sane reader-side ceiling.
        timeout = max(1, min(int(d.get("timeout", 300)), MAX_REPRO_SECONDS))
        return cls(command=list(d["command"]), outputs=list(d.get("outputs", [])), timeout=timeout)


def toolchain_fingerprint() -> dict:
    """Identify the environment a reproduction ran in (so a match is meaningful)."""
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
    }


def _scrubbed_env() -> dict:
    """A minimal environment: no host credentials, just enough PATH to find python,
    with dangerous linker/loader preloads, python path overrides, and scratch dirs explicitly stripped.
    """
    path = os.pathsep.join(["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"])
    return {
        "PATH": path,
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONHASHSEED": "0",
        "HOME": "/nonexistent",
        # Explicit anti-injection guards against host environment inheritance
        "LD_PRELOAD": "",
        "LD_LIBRARY_PATH": "",
        "DYLD_INSERT_LIBRARIES": "",
        "DYLD_LIBRARY_PATH": "",
        "DYLD_FALLBACK_LIBRARY_PATH": "",
        "PYTHONPATH": "",
        "PYTHONHOME": "",
        "TMPDIR": "/tmp",
        "TEMP": "/tmp",
        "TMP": "/tmp",
    }


def _sandbox_wrap(argv: list[str], project_dir: Path) -> list[str]:
    """Confine ``argv``: deny network AND writes outside the project + temp dirs.

    macOS: a seatbelt profile that allows reads but denies all writes except under
    the project directory and the system temp root. Linux: bubblewrap with a
    read-only root and a writable bind of the project dir when available, else a
    bare network namespace (writes NOT confined — documented). Elsewhere: best-effort
    passthrough (the caller must supply their own jail; see docs/security-model.md).
    """
    import tempfile

    proj = str(Path(project_dir).resolve())
    tmp = os.path.realpath(tempfile.gettempdir())
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        # The profile is a quoted SBPL string, so a path containing a quote or
        # backslash would close the literal and append attacker-chosen rules — a
        # directory named `x") (allow network*) (subpath "/` silently restores the
        # network this profile exists to deny. Refuse rather than escape: no
        # legitimate project or temp path needs these characters, and a hard
        # refusal cannot be defeated by a quoting subtlety.
        for label, path in (("project directory", proj), ("temp directory", tmp)):
            if any(ch in path for ch in '"\\\n\r\x00'):
                raise ReproError(
                    f"refusing to build a sandbox profile: {label} path contains a "
                    f"character that cannot be safely quoted in SBPL: {path!r}"
                )
        profile = (
            "(version 1)(allow default)(deny network*)(deny file-write*)"
            f'(allow file-write* (subpath "{proj}") (subpath "{tmp}") (subpath "/private/tmp")'
            ' (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr")'
            ' (literal "/dev/dtracehelper") (literal "/dev/tty"))'
        )
        return ["sandbox-exec", "-p", profile, *argv]
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        return [
            "bwrap", "--unshare-net", "--die-with-parent", "--ro-bind", "/", "/",
            "--dev", "/dev", "--proc", "/proc", "--bind", proj, proj, "--bind", tmp, tmp,
            "--chdir", proj, *argv,
        ]
    if sys.platform.startswith("linux") and shutil.which("unshare"):
        return ["unshare", "-n", *argv]  # network-only; writes not confined (documented)
    return argv


def _apply_limits() -> None:  # pragma: no cover - runs in the child process
    """preexec_fn: cap CPU, address space, and process count against runaway code."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        try:
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        except (ValueError, OSError):
            pass  # RLIMIT_AS is not reliably honoured on macOS
        # Note: Do not set RLIMIT_NPROC when launching unshare / bwrap on Linux;
        # setting RLIMIT_NPROC prevents unshare() / clone(CLONE_NEWUSER/CLONE_NEWPID)
        # from creating namespaces, causing bwrap to fail with EAGAIN (Resource temporarily unavailable).
        # We enforce RLIMIT_CPU, RLIMIT_AS, and RLIMIT_FSIZE.
        try:
            # Cap any single output file the child can write (parent then digests it).
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
        except (ValueError, OSError, AttributeError):
            pass
    except Exception:  # noqa: BLE001, S110 - limits are best-effort hardening
        pass


def _is_wildcard(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def _hash_file(path: Path) -> str:
    h = hashlib.blake2b(digest_size=32)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _snapshot(project_dir: Path, outputs: list[str]) -> dict[str, str]:
    """Content-hash every existing file matching the output patterns (pre-run)."""
    snap: dict[str, str] = {}
    for pattern in outputs:
        for p in project_dir.glob(pattern):
            if p.is_file():
                snap[str(p)] = _hash_file(p)
    return snap


def _digest_outputs(project_dir: Path, outputs: list[str], before: dict[str, str]) -> str:
    """Digest the declared outputs, rejecting vacuous/carried-input attestations.

    Guards (RedTeam v0.4): an empty output set is vacuous; a *literal* declared path
    matching nothing is a silent-subset error; a digested file that is a pre-existing
    carried input **unchanged** by the run is not a computed product; and each file
    is streamed with a per-file size ceiling so a giant output cannot exhaust memory.
    """
    if not outputs:
        raise ReproError("reproduction declares no outputs; the digest would be vacuous")
    files: list[Path] = []
    for pattern in outputs:
        matched = sorted(p for p in project_dir.glob(pattern) if p.is_file())
        if not matched and not _is_wildcard(pattern):
            raise ReproError(f"declared output {pattern!r} produced no file")
        files.extend(matched)
    files = sorted(set(files))
    if not files:
        raise ReproError("reproduction produced none of its declared output files")

    if not any(str(p) not in before or _hash_file(p) != before[str(p)] for p in files):
        raise ReproError(
            "every declared output is a pre-existing carried file unchanged by the run "
            "— the attestation would bind an input, not a computed product"
        )

    h = hashlib.blake2b(digest_size=32)
    for path in files:
        if path.stat().st_size > MAX_OUTPUT_BYTES:
            raise ReproError(f"output {path.name} exceeds the {MAX_OUTPUT_BYTES}-byte cap")
        h.update(path.relative_to(project_dir).as_posix().encode("utf-8"))
        h.update(b"\0")
        with path.open("rb") as fh:
            for chunk in iter(lambda fh=fh: fh.read(_CHUNK), b""):
                h.update(chunk)
    return h.hexdigest()


def run_and_digest(project_dir: Path, spec: ReproSpec) -> str:
    """Run ``spec.command`` in ``project_dir`` (sandboxed) and digest its outputs.

    Snapshots outputs before running (so a carried input cannot masquerade as a
    product), runs the child in its own process group (so a timeout reaps orphans),
    denies the network and confines writes where the platform supports it, and closes
    stdin.
    """
    project_dir = Path(project_dir)
    before = _snapshot(project_dir, spec.outputs)
    argv = _sandbox_wrap(list(spec.command), project_dir)

    # Streams go to files, not pipes. `communicate()` buffers whatever the child
    # writes into the *parent's* address space, and none of the child's limits reach
    # there: RLIMIT_AS bounds the child, RLIMIT_FSIZE bounds files it opens, and a
    # pipe is neither. A carried command that simply wrote to stdout could therefore
    # exhaust the verifier's memory while every other confinement held — measured at
    # roughly 1 GiB of parent RSS for 400 MiB of child output, with the run reported
    # as a success. Redirecting to real files puts the child's own RLIMIT_FSIZE back
    # in the path, and the parent reads only a bounded prefix for its message.
    with tempfile.TemporaryDirectory(prefix="docxplus-repro-") as stream_dir:
        stdout_path = Path(stream_dir) / "stdout"
        stderr_path = Path(stream_dir) / "stderr"
        with open(stdout_path, "wb") as out_stream, open(stderr_path, "wb") as err_stream:
            proc = subprocess.Popen(
                argv,
                cwd=str(project_dir),
                env=_scrubbed_env(),
                stdin=subprocess.DEVNULL,
                stdout=out_stream,
                stderr=err_stream,
                preexec_fn=_apply_limits if os.name == "posix" else None,  # noqa: PLW1509 - single-threaded, POSIX rlimits
                start_new_session=True,
            )
            try:
                proc.wait(timeout=spec.timeout)
            except subprocess.TimeoutExpired:
                _kill_group(proc)
                raise ReproError(
                    f"reproduce command timed out after {spec.timeout}s"
                ) from None
            finally:
                _kill_group(proc)  # reap any surviving double-forked orphans
        if proc.returncode != 0:
            with open(stderr_path, "rb") as handle:
                tail = handle.read(MAX_CAPTURED_STDERR)
            raise ReproError(
                f"reproduce command failed (exit {proc.returncode}): "
                f"{tail.decode('utf-8', 'replace')}"
            )
    return _digest_outputs(project_dir, spec.outputs, before)


def _kill_group(proc: subprocess.Popen) -> None:
    if os.name != "posix":  # pragma: no cover - non-POSIX has no process groups
        return
    try:
        os.killpg(os.getpgid(proc.pid), 9)
    except (ProcessLookupError, PermissionError, OSError):
        pass


class ReproError(RuntimeError):
    """A reproduction run failed to execute (distinct from a digest mismatch)."""


def attest(project_dir: Path, spec: ReproSpec) -> dict:
    """Author-side: run the recipe once and build a signed-in attestation dict."""
    return {
        "command": list(spec.command),
        "outputs": list(spec.outputs),
        "timeout": spec.timeout,
        "output_digest": run_and_digest(Path(project_dir), spec),
        "toolchain": toolchain_fingerprint(),
    }


def reproduce_and_compare(project_dir: Path, attestation: dict) -> dict:
    """Reader-side (opt-in): re-run the attested recipe and compare digests."""
    spec = ReproSpec.from_dict(attestation)
    actual = run_and_digest(Path(project_dir), spec)
    expected_tc = attestation.get("toolchain", {})
    actual_tc = toolchain_fingerprint()
    return {
        "expected": attestation["output_digest"],
        "actual": actual,
        "match": actual == attestation["output_digest"],
        # A digest match on a *different* toolchain is weaker evidence; surface it.
        "toolchain_match": expected_tc == actual_tc,
        "toolchain_expected": expected_tc,
        "toolchain_actual": actual_tc,
    }


def load_recipe(project_dir: Path) -> ReproSpec | None:
    """Load a project's ``.docxplus-reproduce.json`` recipe, if it ships one."""
    recipe = Path(project_dir) / RECIPE_FILE
    if not recipe.is_file():
        return None
    import json

    return ReproSpec.from_dict(json.loads(recipe.read_text()))

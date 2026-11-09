"""Reproduction attestation — execute-once-upstream, verify-cryptographically-downstream.

This module is the only place in docxplus that executes carried code, and it does so
ONLY when a caller explicitly opts in (``container.reproduce(allow_execution=True)``).
Nothing on the read/validate/verify path ever calls it. Following the Council
synthesis (``docs/reproduction-design.md``):

* The **author** (who has the toolchain) runs a project's declared reproduce command
  once and seals a signed **attestation** binding ``source_digest → output_digest``
  plus a toolchain fingerprint.
* A downstream reader **verifies cryptographically, executing nothing**.
* A zero-trust reader may **opt in** to re-run here, in a best-effort sandbox:
  scrubbed environment, resource + file-size limits, a clamped wall-clock
  timeout, own process group, network denied and writes confined to the project +
  private temp dir. Linux bubblewrap runs the command as private PID 1 and owns
  the namespace, including detached descendants.

The sandbox is best-effort, not a microVM; its exact guarantees per platform (and
where confinement does NOT hold) are documented in ``docs/security-model.md``. The
load-bearing guarantee is the opt-in: a document never runs itself.
"""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
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
MAX_TOTAL_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_FILES = 4096
MAX_OUTPUT_PATTERNS = 128
OUTPUT_DIGEST_SCHEME = "docxplus-output-tree-v3-blake2b-256"
OUTPUT_DIGEST_DOMAIN = b"docxplus/reproduction-outputs/v3\0"
_CHUNK = 1 << 16
#: bubblewrap's status object is one short JSON line; never read an unbounded file.
_STATUS_LIMIT = 4096


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


def _sandbox_wrap(argv: list[str], project_dir: Path, temp_dir: Path,
                  *, status_fd: int | None = None) -> list[str]:
    """Confine ``argv``: deny network AND writes outside the project + temp dirs.

    macOS: Seatbelt denies fork, writes outside admitted paths, and network use,
    but does not provide Linux's private PID/proc view. Linux: bubblewrap with
    private user, PID and network namespaces, isolated procfs, and read-only root.
    Readable host files are not secret-isolated. Missing confinement refuses
    execution; no network-only/passthrough fallback.

    On Linux, ``status_fd`` receives bubblewrap's JSON status so the caller can
    pin and later kill the sandbox init; ``--`` ends bubblewrap's own options.
    """

    if not argv or argv[0].startswith("-"):
        # argv[0] is a program, never an option. Without this, a carried recipe
        # starting with `--share-net` or `--bind /work /work` would be parsed by
        # bubblewrap itself and replace the caller's confinement.
        raise ReproError("reproduction command must name a program, not an option")
    proj = str(Path(project_dir).resolve())
    tmp = str(Path(temp_dir).resolve())
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
            "(version 1)(allow default)(deny network*)(deny file-write*)(deny process-fork)"
            f'(allow file-write* (subpath "{proj}") (subpath "{tmp}")'
            ' (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr")'
            ' (literal "/dev/dtracehelper") (literal "/dev/tty"))'
        )
        return ["sandbox-exec", "-p", profile, *argv]
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        wrapped = [
            "bwrap", "--unshare-user", "--unshare-pid", "--as-pid-1", "--unshare-net", "--new-session",
            "--die-with-parent", "--ro-bind", "/", "/",
            "--dev", "/dev", "--proc", "/proc", "--bind", proj, proj, "--bind", tmp, tmp,
            "--chdir", proj,
        ]
        if status_fd is not None:
            wrapped += ["--json-status-fd", str(status_fd)]
        return [*wrapped, "--", *argv]
    raise ReproError(
        "execution requires macOS sandbox-exec or Linux bubblewrap; "
        "refusing to run without network and write confinement"
    )


def _apply_limits() -> None:  # pragma: no cover - runs in the child process
    """Apply per-process CPU, address-space and file-size limits."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        try:
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        except (ValueError, OSError):
            pass  # RLIMIT_AS is not reliably honoured on macOS
        try:
            # Cap any single output file the child can write (parent then digests it).
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
        except (ValueError, OSError, AttributeError):
            pass
    except Exception:  # noqa: BLE001, S110 - limits are best-effort hardening
        pass
    # Never lower RLIMIT_NPROC for the launcher: the kernel counts every process
    # of the *real UID* on the host, so a busy desktop makes bubblewrap's
    # clone(CLONE_NEWUSER/CLONE_NEWPID) fail with EAGAIN before any sandbox
    # exists. It was never a private sandbox quota; measured at 222 UID tasks,
    # --nproc=128 refused the namespace outright.


def _is_wildcard(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise ReproError("reproduction collection exceeded its wall-clock budget")
    return left


def _matches_tokens(names: tuple[str, ...], patterns: tuple[str, ...]) -> bool:
    """Match pre-tokenised POSIX segments; ** recursive, * confined to one segment.

    Callers tokenise each pattern once per collection and each relative path once,
    so a tree of N entries and P patterns costs N×P DP evaluations instead of
    2×N×P string splits plus a fresh cache construction per pair.
    """

    @functools.cache
    def match(i: int, j: int) -> bool:
        if j == len(patterns):
            return i == len(names)
        if patterns[j] == "**":
            return match(i, j + 1) or (i < len(names) and match(i + 1, j))
        return (i < len(names) and fnmatch.fnmatchcase(names[i], patterns[j])
                and match(i + 1, j + 1))

    return match(0, 0)


def _output_hashes(project_dir: Path, outputs: list[str], deadline: float,
                   *, require_matches: bool) -> dict[str, tuple[int, str]]:
    """Return bounded regular outputs as absolute path -> (byte size, BLAKE2b-256)."""
    from .payloads import MAX_PROJECT_MEMBERS

    if not outputs or len(outputs) > MAX_OUTPUT_PATTERNS:
        raise ReproError("reproduction declares no outputs or too many output patterns")
    for pattern in outputs:
        if (not isinstance(pattern, str) or not pattern or len(pattern) > 4096
                or len(pattern.split("/")) > 64 or "\\" in pattern
                or Path(pattern).is_absolute()
                or any(part in {"", ".", ".."} for part in pattern.split("/"))):
            raise ReproError(f"unsafe reproduction output pattern: {pattern!r}")
    tokenised = {pattern: tuple(pattern.split("/")) for pattern in outputs}
    root = Path(project_dir).resolve()
    stack, files, matched = [root], {}, set()
    entries = total = 0
    while stack:
        directory = stack.pop()
        _remaining(deadline)
        with os.scandir(directory) as children:
            for entry in children:
                _remaining(deadline)
                entries += 1
                if entries > MAX_PROJECT_MEMBERS:
                    raise ReproError("reproduction tree exceeds the collection entry cap")
                path = Path(entry.path)
                rel = path.relative_to(root).as_posix()
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                    continue
                name_tokens = tuple(rel.split("/"))
                hits = [p for p in outputs if _matches_tokens(name_tokens, tokenised[p])]
                if not hits:
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ReproError(f"output is not a regular file: {rel}")
                if len(files) >= MAX_OUTPUT_FILES:
                    raise ReproError("reproduction exceeds the output file-count cap")
                # Open every component relative to an anchored directory descriptor.
                # Neither a generated final symlink nor a swapped ancestor is followed.
                descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    for part in path.relative_to(root).parts[:-1]:
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=descriptor)
                        os.close(descriptor)
                        descriptor = child
                    handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=descriptor)
                except OSError as exc:
                    raise ReproError(f"unsafe output path: {rel}") from exc
                finally:
                    os.close(descriptor)
                with os.fdopen(handle, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_OUTPUT_BYTES:
                        raise ReproError(f"output {rel} exceeds the regular-file byte cap")
                    h, count = hashlib.blake2b(digest_size=32), 0
                    while block := stream.read(_CHUNK):
                        _remaining(deadline)
                        count += len(block)
                        total += len(block)
                        if count > MAX_OUTPUT_BYTES or total > MAX_TOTAL_OUTPUT_BYTES:
                            raise ReproError("reproduction exceeds the output byte budget")
                        h.update(block)
                    after = os.fstat(stream.fileno())
                    if ((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                            != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            or count != after.st_size):
                        raise ReproError(f"output changed while being collected: {rel}")
                files[str(path)] = (count, h.hexdigest())
                matched.update(hits)
    if require_matches:
        for pattern in outputs:
            if pattern not in matched and not _is_wildcard(pattern):
                raise ReproError(f"declared output {pattern!r} produced no file")
        if not files:
            raise ReproError("reproduction produced none of its declared output files")
    return files


def _snapshot(project_dir: Path, outputs: list[str], deadline: float) -> dict[str, tuple[int, str]]:
    """Snapshot bounded regular outputs before executing, never following links."""
    return _output_hashes(project_dir, outputs, deadline, require_matches=False)


def _digest_outputs(project_dir: Path, outputs: list[str], before: dict[str, tuple[int, str]],
                    deadline: float | None = None) -> str:
    """Hash the v3 sorted path/size/per-file-digest transcript; reject unchanged inputs."""
    deadline = deadline if deadline is not None else time.monotonic() + MAX_REPRO_SECONDS
    files = _output_hashes(project_dir, outputs, deadline, require_matches=True)
    resolved_root = Path(project_dir).resolve()
    h = hashlib.blake2b(digest_size=32)
    h.update(OUTPUT_DIGEST_DOMAIN)
    h.update(len(files).to_bytes(8, "big"))
    for name, (size, digest) in sorted(files.items()):
        if before.get(name) == (size, digest):
            raise ReproError(f"declared output {name!r} is a carried file unchanged by the run")
        relative = Path(name).relative_to(resolved_root).as_posix().encode("utf-8")
        h.update(len(relative).to_bytes(8, "big"))
        h.update(relative)
        h.update(size.to_bytes(8, "big"))
        h.update(bytes.fromhex(digest))
    return h.hexdigest()


def run_and_digest(project_dir: Path, spec: ReproSpec) -> str:
    """Run ``spec.command`` in ``project_dir`` (sandboxed) and digest its outputs.

    Snapshots outputs before running (so a carried input cannot masquerade as a
    product), closes stdin, and retains the launch process-group identity before
    waiting. Linux bubblewrap runs the command as private PID 1 and reports it,
    so cleanup kills namespace init itself and the kernel reaps every detached
    descendant before collection (a killed member may linger as a zombie until its
    adopter reaps it, which cannot execute or write). macOS Seatbelt denies process
    creation, so a recipe that needs subprocesses must run on the Linux backend.
    """
    project_dir = Path(project_dir).resolve()
    deadline = time.monotonic() + max(1, min(spec.timeout, MAX_REPRO_SECONDS))
    before = _snapshot(project_dir, spec.outputs, deadline)
    command = list(spec.command)
    if not command:
        raise ReproError("reproduction declares no command")
    if command[0] == "{python}":
        command[0] = sys.executable

    # Streams go to files, not pipes. `communicate()` buffers whatever the child
    # writes into the *parent's* address space, and none of the child's limits reach
    # there: RLIMIT_AS bounds the child, RLIMIT_FSIZE bounds files it opens, and a
    # pipe is neither. A carried command that simply wrote to stdout could therefore
    # exhaust the verifier's memory while every other confinement held — measured at
    # roughly 1 GiB of parent RSS for 400 MiB of child output, with the run reported
    # as a success. Redirecting to real files puts the child's own RLIMIT_FSIZE back
    # in the path, and the parent reads only a bounded prefix for its message.
    with tempfile.TemporaryDirectory(prefix="docxplus-repro-") as stream_dir:
        scratch = Path(stream_dir) / "tmp"
        scratch.mkdir()
        environment = _scrubbed_env()
        environment.update({key: str(scratch) for key in ("TMPDIR", "TMP", "TEMP")})
        stdout_path = Path(stream_dir) / "stdout"
        stderr_path = Path(stream_dir) / "stderr"
        status_path = Path(stream_dir) / "sandbox-status"
        linux = sys.platform.startswith("linux")
        with open(stdout_path, "wb") as out_stream, open(stderr_path, "wb") as err_stream, \
                open(status_path, "w+b") as status_stream:
            argv = _sandbox_wrap(command, project_dir, scratch,
                                 status_fd=status_stream.fileno() if linux else None)
            if linux:
                _require_pidfd()
            _remaining(deadline)
            proc = subprocess.Popen(
                argv,
                cwd=str(project_dir),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=out_stream,
                stderr=err_stream,
                preexec_fn=_apply_limits if os.name == "posix" else None,  # noqa: PLW1509 - single-threaded, POSIX rlimits
                pass_fds=(status_stream.fileno(),) if linux else (),
                start_new_session=True,
            )
            # start_new_session establishes PGID == PID before exec; retain it now,
            # never rediscover it after wait() has reaped a short-lived leader.
            launch_pgid = proc.pid
            init = None
            try:
                if linux:
                    reported = _sandbox_init_pid(status_path, proc, deadline)
                    if reported is not None:
                        init = _pin_sandbox_init(reported, launch_pgid)
                try:
                    proc.wait(timeout=_remaining(deadline))
                except subprocess.TimeoutExpired:
                    raise ReproError(
                        f"reproduce command timed out after {spec.timeout}s"
                    ) from None
            finally:
                try:
                    _terminate_sandbox_init(init)
                finally:
                    try:
                        # While the monitor is still unreaped it owns its own
                        # PGID, so a numeric group kill cannot reach a recycled
                        # group. A reaped monitor's group holds nothing to kill:
                        # the namespace init already died.
                        if proc.poll() is None:
                            _kill_group(launch_pgid)
                    finally:
                        proc.wait()  # always join the owned leader, including cleanup errors
        if proc.returncode != 0:
            with open(stderr_path, "rb") as handle:
                tail = handle.read(MAX_CAPTURED_STDERR)
            raise ReproError(
                f"reproduce command failed (exit {proc.returncode}): "
                f"{tail.decode('utf-8', 'replace')}"
            )
    return _digest_outputs(project_dir, spec.outputs, before, deadline)


def _sandbox_init_pid(status_path: Path, monitor: subprocess.Popen,
                      deadline: float) -> int | None:
    """Return bubblewrap's reported init PID in the caller's PID namespace.

    bubblewrap writes one JSON object with ``child-pid`` after starting the
    command, before it waits. A monitor that exits without writing it never
    started a sandbox, so there is nothing to own.
    """
    while True:
        try:
            with status_path.open("rb") as handle:
                raw = handle.read(_STATUS_LIMIT + 1)
        except OSError:
            raw = b""
        if len(raw) > _STATUS_LIMIT and b"\n" not in raw:
            raise ReproError("bubblewrap status exceeded its bound")
        # Parse complete lines only, and ignore objects without `child-pid`:
        # bubblewrap documents that future members/objects may appear.
        for line in raw.split(b"\n")[:-1] if b"\n" in raw else ():
            try:
                value = json.loads(line)
            except ValueError as exc:
                raise ReproError("bubblewrap status is not JSON") from exc
            pid = value.get("child-pid") if isinstance(value, dict) else None
            if type(pid) is int and pid > 0:
                return pid
        if monitor.poll() is not None:
            return None
        _remaining(deadline)
        time.sleep(0.005)


def _require_pidfd() -> None:
    """Prove kernel pidfd support before launching anything that needs custody.

    Pinning must happen after the sandbox reports its init, so support is probed
    on our own process first: an unsupported kernel refuses before carried code
    can run at all.
    """
    try:
        descriptor = os.pidfd_open(os.getpid(), 0)
    except (AttributeError, OSError) as exc:
        raise ReproError("Linux pidfd support is required to own the sandbox init") from exc
    os.close(descriptor)


def _pin_sandbox_init(pid: int, monitor_pid: int) -> int | None:
    """Pin the reported init instance, or None once it has already exited.

    A pidfd pins the process instance rather than a reusable PID, so a recycled
    number can never be signalled later. A reported PID whose parent is not this
    monitor is unattributable and refuses; absent pidfd support refuses too,
    because the namespace leader could not be killed.
    """
    try:
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return None
    except (AttributeError, OSError) as exc:
        raise ReproError("Linux pidfd support is required to own the sandbox init") from exc
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        parent = int(next(line.split()[1] for line in status.splitlines()
                          if line.startswith("PPid:")))
    except (OSError, StopIteration, ValueError):
        os.close(descriptor)
        return None
    if parent != monitor_pid:
        os.close(descriptor)
        # The reported PID is not this monitor's child: refuse rather than run a
        # sandbox whose namespace leader cannot be attributed.
        raise ReproError("sandbox init is not owned by its monitor")
    return descriptor


def _terminate_sandbox_init(descriptor: int | None) -> None:
    """Kill the private namespace leader; the kernel then kills every member."""
    if descriptor is None:
        return
    try:
        signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
    except ProcessLookupError:
        pass  # It exited on its own; the pinned instance is already gone.
    except OSError as exc:
        raise ReproError("could not terminate the sandbox init") from exc
    finally:
        os.close(descriptor)


def _kill_group(launch_pgid: int) -> None:
    """Kill the retained launch group, even after its leader has been reaped."""
    if os.name != "posix":  # pragma: no cover - unsupported platform refuses execution
        return
    try:
        os.killpg(launch_pgid, 9)
    except ProcessLookupError:
        return  # The entire group already exited.
    except OSError as exc:
        raise ReproError("could not clean up the reproduction process group") from exc


class ReproError(RuntimeError):
    """A reproduction run failed to execute (distinct from a digest mismatch)."""


def require_output_digest_scheme(attestation: dict) -> str:
    """Refuse missing/legacy schemes without executing or reinterpreting signed bytes."""
    if attestation.get("output_digest_scheme") != OUTPUT_DIGEST_SCHEME:
        raise ReproError("unsupported or missing reproduction output_digest_scheme")
    return OUTPUT_DIGEST_SCHEME


def attest(project_dir: Path, spec: ReproSpec) -> dict:
    """Author-side: run the recipe once and build a signed-in attestation dict."""
    from . import crypto, payloads

    source_digest = crypto.digest(payloads.pack_project(Path(project_dir)))
    return {
        "command": list(spec.command),
        "outputs": list(spec.outputs),
        "timeout": spec.timeout,
        "output_digest_scheme": OUTPUT_DIGEST_SCHEME,
        "output_digest": run_and_digest(Path(project_dir), spec),
        "toolchain": toolchain_fingerprint(),
        "source_digest": source_digest,
    }


def reproduce_and_compare(project_dir: Path, attestation: dict) -> dict:
    """Reader-side (opt-in): re-run the attested recipe and compare digests."""
    from . import crypto, payloads

    require_output_digest_scheme(attestation)
    source_match = attestation.get("source_digest") == crypto.digest(
        payloads.pack_project(Path(project_dir))
    )
    spec = ReproSpec.from_dict(attestation)
    actual = run_and_digest(Path(project_dir), spec)
    expected_tc = attestation.get("toolchain", {})
    actual_tc = toolchain_fingerprint()
    return {
        "output_digest_scheme": OUTPUT_DIGEST_SCHEME,
        "expected": attestation["output_digest"],
        "actual": actual,
        "match": source_match and actual == attestation["output_digest"],
        "source_match": source_match,
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


def hermetic_extract_and_reproduce(
    packed_project: bytes,
    attestation: dict,
    *,
    allow_execution: bool = False,
    temp_dir_prefix: str = "docxplus-hermetic-",
) -> dict:
    """Safely unpack a project payload into an isolated temporary workspace and reproduce."""
    if not allow_execution:
        raise ReproError(
            "hermetic_extract_and_reproduce requires allow_execution=True (executes carried code)"
        )
    from .payloads import unpack_project

    with tempfile.TemporaryDirectory(prefix=temp_dir_prefix) as td:
        proj_dir = Path(td) / "workspace"
        unpack_project(packed_project, proj_dir)
        return reproduce_and_compare(proj_dir, attestation)


__all__ = [
    "MAX_CAPTURED_STDERR",
    "MAX_OUTPUT_BYTES",
    "MAX_REPRO_SECONDS",
    "OUTPUT_DIGEST_SCHEME",
    "RECIPE_FILE",
    "ReproError",
    "ReproSpec",
    "attest",
    "hermetic_extract_and_reproduce",
    "load_recipe",
    "reproduce_and_compare",
    "require_output_digest_scheme",
    "run_and_digest",
    "toolchain_fingerprint",
]



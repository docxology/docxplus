#!/usr/bin/env python3
"""Qualify the disposable image, orchestrate release gates, and export evidence.

Only the image builder uses --record-runtime. Compute has no acquisition path.
Stdout is exclusively the bounded JSONL archive protocol consumed by the host;
command output stays in /outputs/logs. No host mounts or persistent credentials.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

SOURCE = Path("/source/docxplus")
OUTPUTS = Path("/outputs")
MANIFEST = Path("/inputs/manifest.json")
PYTHON = "/opt/venv/bin/python"
CLI = "/opt/steganographer/bin/steganographer"
ROOTS = {
    "docxplus": SOURCE,
    "steganographer": Path("/inputs/steganographer"),
    "template": Path("/inputs/template"),
}
LOG_LIMIT = 64 * 1024 * 1024
ARCHIVE_LIMIT = 256 * 1024 * 1024
EXTRACTED_LIMIT = 1024 * 1024 * 1024
FILE_LIMIT = 20000
GUEST_ERRORS = (RuntimeError, OSError, ValueError, TypeError, KeyError, IndexError,
                ImportError, subprocess.SubprocessError, ET.ParseError, tarfile.TarError)


def dump(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def relative_path(name: str) -> Path:
    parsed = PurePosixPath(name)
    require(bool(name) and not parsed.is_absolute(), f"invalid input path: {name!r}")
    require(all(p not in {"", ".", ".."} for p in name.split("/")),
            f"noncanonical input path: {name!r}")
    require("\\" not in name and "\x00" not in name, f"invalid input path: {name!r}")
    return Path(*parsed.parts)


def source_file(key: str, name: str) -> Path:
    rel = relative_path(name)
    # Docker hides the source output directory with a private tmpfs. The exact
    # original bytes remain separately available for binding and package builds.
    if key == "docxplus" and rel.parts[0] == "output":
        return Path("/inputs/docxplus-output").joinpath(*rel.parts[1:])
    return ROOTS[key] / rel


def verify_sources(manifest: dict) -> dict:
    require(manifest["schema"] == "docxplus.release-inputs.v1", "wrong input schema")
    require(set(manifest["sources"]) == set(ROOTS), "wrong source set")
    bindings = {}
    for key, root in ROOTS.items():
        source = manifest["sources"][key]
        files = source["files"]
        canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        require(hashlib.sha256(canonical).hexdigest() == source["sha256"],
                f"invalid inventory digest: {key}")
        for name, wanted in files.items():
            path = source_file(key, name)
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode), f"not a regular input: {key}/{name}")
            require(info.st_size == wanted["bytes"], f"size drift: {key}/{name}")
            require(stat.S_IMODE(info.st_mode) == wanted["mode"], f"mode drift: {key}/{name}")
            require(digest(path) == wanted["sha256"], f"content drift: {key}/{name}")
        for name in source["dirs"]:
            path = source_file(key, name)
            require(stat.S_ISDIR(path.lstat().st_mode), f"missing input directory: {key}/{name}")
        actual = set()
        for path in root.rglob("*"):
            rel = path.relative_to(root)
            if key == "docxplus" and rel.parts[0] in {".git", ".venv", "output"}:
                continue
            require(not path.is_symlink(), f"unexpected input symlink: {path}")
            if path.is_file():
                actual.add(rel.as_posix())
        expected = {name for name in files if not (
            key == "docxplus" and PurePosixPath(name).parts[0] == "output"
        )}
        require(actual == expected, f"nonexhaustive source inventory: {key}")
        bindings[key] = {k: v for k, v in source.items() if k != "root"}
        bindings[key]["container_root"] = str(root)
    return bindings


def tool_version(argv: list[str], *, env: dict | None = None, cwd: Path | None = None) -> str:
    result = subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=30, env=env, cwd=cwd)
    require(len(result.stdout) <= 1024 * 1024, f"oversized tool version: {argv[0]}")
    return result.stdout.decode(errors="replace").strip()


def office_settings(private: Path, base_env: dict | None = None) -> tuple[list[str], dict]:
    """Each Office process owns all mutable profile, home, cache and temp state."""
    private.mkdir(parents=True, mode=0o700, exist_ok=True)
    env = dict(os.environ if base_env is None else base_env)
    for key, name in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                      ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"),
                      ("XDG_RUNTIME_DIR", "runtime"), ("TMPDIR", "tmp")):
        directory = private / name
        directory.mkdir(mode=0o700)
        env[key] = str(directory)
    env["TMP"] = env["TEMP"] = env["TMPDIR"]
    command = ["/usr/bin/libreoffice", f"-env:UserInstallation={(private / 'profile').as_uri()}",
               "--headless", "--nologo", "--nodefault", "--nofirststartwizard", "--norestore"]
    return command, env


def office_versions() -> dict:
    with tempfile.TemporaryDirectory(prefix="release-office-", dir="/tmp") as td:
        private = Path(td)
        command, env = office_settings(private)
        versions = {"libreoffice": tool_version([*command, "--version"], env=env, cwd=private)}
        versions.update({name: tool_version([f"/usr/bin/{name}", "-v"], env=env, cwd=private)
                         for name in ("pdftotext", "pdftoppm", "pdfimages")})
    require(all(versions.values()), "actual Office/poppler tool versions are absent")
    return versions


def runtime_metadata() -> dict:
    require(sys.version_info[:3] == (3, 15, 2), "required Python 3.15.2 is absent")
    import matplotlib
    from PIL import Image

    project = tomllib.loads((SOURCE / "pyproject.toml").read_text())["project"]
    cargo = tomllib.loads((ROOTS["steganographer"] / "Cargo.toml").read_text())
    tools = {
        "python": sys.version,
        "uv": tool_version(["/usr/local/bin/uv", "--version"]),
        "ruff": tool_version([PYTHON, "-m", "ruff", "--version"]),
        "steganographer": tool_version([CLI, "--version"]),
        "pandoc": tool_version(["/usr/bin/pandoc", "--version"]),
        "pandoc-crossref": tool_version(["/opt/crossref/bin/pandoc-crossref", "--version"]),
        "xelatex": tool_version(["/usr/bin/xelatex", "--version"]),
        "bwrap": tool_version(["/usr/bin/bwrap", "--version"]),
        "timeout": tool_version(["/usr/bin/timeout", "--version"]),
        "prlimit": tool_version(["/usr/bin/prlimit", "--version"]),
        "pillow": Image.__version__,
        "matplotlib": matplotlib.__version__,
    }
    tools.update(office_versions())
    require(tools["pandoc"].splitlines()[0] == "pandoc 2.17.1.1", "Pandoc pin drift")
    require("0.3.12.2" in tools["pandoc-crossref"], "crossref pin drift")
    require(cargo["workspace"]["package"]["version"] in tools["steganographer"],
            "CLI/source version mismatch")
    require(importlib.metadata.version("docxplus") == project["version"],
            "installed/source version mismatch")
    required_tex = ("amsmath.sty", "amssymb.sty", "amsthm.sty", "booktabs.sty",
                    "graphicx.sty", "xcolor.sty", "hyperref.sty", "caption.sty",
                    "subcaption.sty", "microtype.sty", "geometry.sty", "fontspec.sty",
                    "unicode-math.sty", "longtable.sty", "fancyvrb.sty", "upquote.sty")
    tex = {name: tool_version(["/usr/bin/kpsewhich", name]) for name in required_tex}
    require(all(tex.values()), "required TeX package is absent")
    return {
        "schema": "docxplus.release-runtime.v1", "tools": tools,
        "platform": platform.platform(), "machine": platform.machine(),
        "docxplus_version": project["version"],
        "steganographer_version": cargo["workspace"]["package"]["version"],
        "steganographer_sha256": digest(Path(CLI)),
        "steganographer_build": {
            "command": "cargo build --locked --release -p steganographer-cli --no-default-features",
            "toolchain": Path("/opt/steganographer/build-toolchain.txt").read_text(),
        },
        "crossref_toolchain": Path("/opt/crossref/build-toolchain.txt").read_text(),
        "tex_packages": tex,
        "python_packages": dict(sorted((d.metadata["Name"], d.version)
                                       for d in importlib.metadata.distributions())),
        "debian_packages": tool_version(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]),
        "snapshot_index": "private git init/add only; no history or original commit synthesized",
        "acquisition_sources": [
            "https://packages.debian.org/bookworm/libreoffice-writer",
            "https://packages.debian.org/bookworm/poppler-utils",
            "https://packages.debian.org/bookworm/pandoc",
            "https://downloads.haskell.org/~cabal/cabal-install-3.18.2.0/SHA256SUMS",
            "https://hackage.haskell.org/package/pandoc-crossref-0.3.12.2",
            "https://github.com/lierdakil/pandoc-crossref/blob/v0.3.12.2/pandoc-crossref.cabal",
            "https://raw.githubusercontent.com/docker-library/python/master/versions.json",
            "https://github.com/astral-sh/uv/releases/tag/0.13.7",
        ],
    }


def write_refused(path: Path, *, allow_missing: bool = False) -> dict:
    try:
        # Never create, truncate or write, even if a kernel boundary is broken.
        fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    except OSError as exc:
        require(exc.errno in {errno.EROFS, errno.EACCES, errno.EPERM}
                or (allow_missing and exc.errno == errno.ENOENT),
                f"write refusal was not protection: {path}: {exc}")
        return {"path": str(path), "errno": exc.errno, "error": str(exc)}
    else:
        os.close(fd)
        raise RuntimeError(f"write-open unexpectedly allowed: {path}")


def network_probes() -> list[dict]:
    observations = []
    for family, address in ((socket.AF_INET, "1.1.1.1"),
                            (socket.AF_INET6, "2606:4700:4700::1111")):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            item = {"family": family.name, "transport": kind.name, "address": address}
            try:
                sock = socket.socket(family, kind)
            except OSError as exc:
                require(family == socket.AF_INET6 and exc.errno in {
                    errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT
                }, f"unexpected network probe failure: {exc}")
                item.update(unsupported=True, errno=exc.errno)
                observations.append(item)
                continue
            with sock:
                sock.settimeout(0.75)
                try:
                    sock.connect((address, 443))
                    if kind == socket.SOCK_DGRAM:
                        sock.send(b"docxplus-release-network-denial-probe")
                except OSError as exc:
                    require(exc.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH,
                                          errno.EACCES, errno.EPERM, errno.ENETDOWN},
                            f"network denial not established: {item}: {exc}")
                    item.update(denied=True, errno=exc.errno, error=str(exc))
                else:
                    raise RuntimeError(f"off-host network operation succeeded: {item}")
            observations.append(item)
    return observations


class Runner:
    def __init__(self) -> None:
        self.stages: list[dict] = []
        self.started = time.monotonic()

    def run(self, name: str, argv: list[str], *, cwd: Path = SOURCE,
            env: dict | None = None, seconds: int = 900) -> str:
        argv = ["/usr/bin/prlimit", f"--fsize={LOG_LIMIT}:{LOG_LIMIT}", "--", *argv]
        log = OUTPUTS / "logs" / f"{len(self.stages):02d}-{name}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        record = {"name": name, "argv": argv, "cwd": str(cwd),
                  "log": str(log.relative_to(OUTPUTS)), "ok": False}
        self.stages.append(record)
        start = time.monotonic()


        with log.open("xb") as stream:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            record["pid"] = process.pid
            try:
                process.wait(timeout=min(seconds, max(1, 1700 - (start - self.started))))
            except BaseException:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise
            finally:
                record["returncode"] = process.returncode
                record["elapsed_seconds"] = round(time.monotonic() - start, 3)
        require(log.stat().st_size < LOG_LIMIT, f"stage log limit exceeded: {name}")
        require(process.returncode == 0, f"stage {name} exited {process.returncode}; see {log}")
        record["ok"] = True
        # Small machine-readable stages use the return value; big logs stay on disk.
        return log.read_text() if log.stat().st_size <= 2 * 1024 * 1024 else ""


def qualify_reproduction(project: Path, runner: Runner) -> dict:
    """Exercise the production Linux sandbox and successful-leader custody."""
    from docxplus.reproduce import OUTPUT_DIGEST_SCHEME, ReproSpec, _sandbox_wrap, run_and_digest

    project.mkdir()
    scratch = project.parent / f"{project.name}-tmp"
    scratch.mkdir(mode=0o700)
    canary = OUTPUTS / "outer-write-canary"
    signal_canary = OUTPUTS / "outer-signal-canary"
    canary.write_text("allowed outer write\n")
    ancestor_fd = os.open(canary, os.O_WRONLY)
    helper_code = (
        "import json,os,signal,time\n"
        f"fd=os.open({str(canary)!r},os.O_WRONLY)\n"
        f"signal.signal(signal.SIGUSR1,lambda *_:open({str(signal_canary)!r},'w').write('signaled'))\n"
        "print(json.dumps({'pid':os.getpid(),'fd':fd}),flush=True)\n"
        "while True: time.sleep(1)\n"
    )
    helper = subprocess.Popen([PYTHON, "-c", helper_code], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    try:
        require(helper.stdout is not None, "outer proc helper has no capture pipe")
        identity = json.loads(helper.stdout.readline(4096))
        pid, fd = identity["pid"], identity["fd"]
        probe = (
            "import errno,json,os,pathlib,signal\n"
            "denied=[]\n"
            f"paths={[str(canary), f'/proc/{pid}/root{canary}', f'/proc/{pid}/fd/{fd}', f'/proc/{os.getpid()}/root{canary}', f'/proc/{os.getpid()}/fd/{ancestor_fd}']!r}\n"
            "for name in paths:\n"
            " try: pathlib.Path(name).write_text('forbidden wrapped write')\n"
            " except OSError as e:\n"
            "  assert e.errno in (errno.EROFS,errno.EACCES,errno.EPERM,errno.ENOENT,errno.ESRCH)\n"
            "  denied.append(name)\n"
            " else: raise AssertionError('outer proc write succeeded: '+name)\n"
            f"assert not pathlib.Path('/proc/{pid}').exists(), 'outer helper visible in private proc'\n"
            f"try: os.kill({pid},signal.SIGUSR1)\n"
            "except OSError as e: assert e.errno in (errno.ESRCH,errno.EPERM)\n"
            "else: raise AssertionError('outer helper signal succeeded')\n"
            "pathlib.Path('project-canary').write_text('project writable')\n"
            f"pathlib.Path({str(scratch / 'bwrap-tmp-canary')!r}).write_text('tmp writable')\n"
            "print(json.dumps({'network_namespace':os.readlink('/proc/self/ns/net'),"
            "'pid_namespace':os.readlink('/proc/self/ns/pid'),'denied_writes':denied,"
            "'outer_signal_denied':True,'project_write':True,'tmp_write':True}))\n"
        )
        wrapped = _sandbox_wrap([PYTHON, "-c", probe], project, scratch)
        require(Path(wrapped[0]).name == "bwrap", "production bwrap sandbox is unavailable")
        result = json.loads(runner.run("bwrap-qualification", wrapped, cwd=project, seconds=30))
        for name, field in (("net", "network_namespace"), ("pid", "pid_namespace")):
            require(result[field] != os.readlink(f"/proc/self/ns/{name}"),
                    f"bwrap did not create a distinct {name} namespace")
        require(canary.read_text() == "allowed outer write\n", "bwrap changed outer canary")
        require(not signal_canary.exists() and helper.poll() is None,
                "bwrap signaled the controlled outer process")
        require((project / "project-canary").read_text() == "project writable",
                "bwrap project positive control failed")
        require((scratch / "bwrap-tmp-canary").read_text() == "tmp writable",
                "bwrap private temporary positive control failed")
    finally:
        os.close(ancestor_fd)
        helper.terminate()
        helper.wait(timeout=5)
        if helper.stdout is not None:
            helper.stdout.close()

    # A detached child must die when its successful leader exits, before digesting.
    child_code = (
        "import pathlib,time\n"
        "pathlib.Path('child-ready').write_text('ready')\n"
        "time.sleep(1)\n"
        "pathlib.Path('post-return-write').write_text('custody failed')\n"
        "time.sleep(30)\n"
    )
    custody_code = (
        "import os,pathlib,subprocess,sys,time\n"
        "pathlib.Path('pid-namespace').write_text(os.readlink('/proc/self/ns/pid'))\n"
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}],start_new_session=True)\n"
        "deadline=time.monotonic()+5\n"
        "while not pathlib.Path('child-ready').exists():\n"
        " assert time.monotonic()<deadline, 'detached child did not start'\n"
        " time.sleep(.01)\n"
        "pathlib.Path('result.txt').write_text('successful leader')\n"
    )
    spec = ReproSpec(command=[PYTHON, "-c", custody_code], outputs=["result.txt"], timeout=15)
    output_digest = run_and_digest(project, spec)
    namespace = (project / "pid-namespace").read_text()
    survivors = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if os.readlink(proc / "ns/pid") == namespace:
                survivors.append(int(proc.name))
        except FileNotFoundError:
            continue
    require(not survivors, f"production reproduction retained private-PID members: {survivors}")
    time.sleep(1.1)
    require(not (project / "post-return-write").exists(), "detached child wrote after leader exit")
    return {"argv": wrapped, **result, "successful_leader_detached_child": {
        "output_digest_scheme": OUTPUT_DIGEST_SCHEME,
        "output_digest": output_digest, "pid_namespace": namespace,
        "remaining_namespace_members": survivors, "post_return_write": False,
    }}



def qualify(manifest: dict, runner: Runner, report: dict) -> None:
    report["sources"] = verify_sources(manifest)
    report["runtime"] = runtime_metadata()
    report["recorded_runtime"] = json.loads(Path("/opt/release-runtime.json").read_text())
    require(report["runtime"] == report["recorded_runtime"], "runtime identity changed since build")
    require(os.getuid() == os.geteuid() == 1000 and os.getgid() == 1000,
            "compute is not unprivileged UID/GID 1000")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    report["process_status"] = {key: status[key].strip() for key in (
        "Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "NSpid"
    )}
    require(all(int(status[key].strip(), 16) == 0 for key in (
        "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"
    )), "capabilities were not fully dropped")
    require(status["NoNewPrivs"].strip() == "1", "no-new-privileges is absent")
    report["network"] = network_probes()
    report["mountinfo"] = Path("/proc/self/mountinfo").read_text()
    report["read_only_filesystems"] = {
        str(path): bool(os.statvfs(path).f_flag & os.ST_RDONLY)
        for path in (Path("/"), SOURCE, Path("/inputs/template"), Path("/opt/venv"),
                     Path("/opt/steganographer"), Path("/sys"))
    }
    require(all(report["read_only_filesystems"].values()),
            "source/runtime/root/sys filesystem is not kernel read-only")
    report["namespaces"] = {name: os.readlink(f"/proc/self/ns/{name}")
                            for name in ("pid", "net", "mnt", "user")}
    report["write_refusals"] = [write_refused(path) for path in (
        SOURCE / "pyproject.toml", Path("/inputs/template") / next(iter(
            manifest["sources"]["template"]["files"])),
        Path(PYTHON).resolve(), Path(CLI), Path("/opt/release_guest.py"),
        Path("/opt/venv/pyvenv.cfg"),
    )]
    report["kernel_write_refusals"] = []
    for path in (Path("/proc/sys/kernel/hostname"), Path("/proc/sysrq-trigger"),
                 Path("/sys/kernel/uevent_helper")):
        report["kernel_write_refusals"].append(write_refused(path, allow_missing=True))
    forbidden = {"/var/run/docker.sock", "/run/docker.sock", "/run/secrets",
                 "/root/.ssh", "/root/.aws", "/root/.config/gcloud", "/root/.docker/config.json"}
    forbidden.update(source["root"] for source in manifest["sources"].values())
    report["host_paths"] = []
    for name in sorted(forbidden):
        try:
            Path(name).stat()
        except (FileNotFoundError, PermissionError) as exc:
            report["host_paths"].append({"path": name, "inaccessible": True,
                                         "errno": exc.errno})
        else:
            raise RuntimeError(f"host/credential path is accessible: {name}")
    secret_vars = {key for key in os.environ if key.startswith(("AWS_", "AZURE_", "GOOGLE_"))
                   or key in {"GH_TOKEN", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "DOCKER_HOST"}}
    require(not secret_vars, f"credential/daemon environment leaked: {sorted(secret_vars)}")
    report["bwrap"] = qualify_reproduction(Path("/work/bwrap-project"), runner)
    report["ok"] = True


def seed_outputs() -> None:
    destination = SOURCE / "output"
    require(not any(destination.iterdir()), "generated-output tmpfs is not initially empty")
    shutil.copytree("/inputs/docxplus-output", destination, dirs_exist_ok=True)
    # Preserve tracked link targets for the unchanged suite. Artifact qualification
    # below proves regeneration by post-pipeline timestamps instead of deleting
    # the committed plates that documentation tests legitimately inspect.


def junit_summary(path: Path) -> dict:
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    failed = [case.attrib for case in cases if case.find("failure") is not None
              or case.find("error") is not None]
    skipped = [{**case.attrib, "reason": case.find("skipped").get("message", "")}
               for case in cases if case.find("skipped") is not None]
    real_cli = [case for case in cases if case.get("classname", "").endswith(
        ("test_steg_bridge", "test_stego_media"))]
    require(cases and not failed, "full suite result is empty or failed")
    require(real_cli and all(case.find("skipped") is None for case in real_cli),
            "real steganographer integration tests were skipped")
    reproduction = [case for case in cases if "reproduc" in case.get("classname", "")
                    and case.find("skipped") is None]
    require(reproduction, "no real reproduction tests ran")
    custody = [case for case in cases
               if case.get("classname", "").endswith("test_reproduce_custody")]
    require(custody and all(case.find("skipped") is None for case in custody),
            "production reproduction custody cases were absent or skipped")
    office = [case for case in cases if case.get("classname", "").endswith("test_interop")]
    expected_office = {f"test_libreoffice_headless_render[{carrier}-{profile}]"
                       for carrier in ("none", "python_lsb", "steganographer")
                       for profile in ("docx", "odt")}
    require(expected_office <= {case.get("name") for case in office}
            and all(case.find("skipped") is None for case in office),
            "required real DOCX/ODT text and carrier Office interoperability cases did not run")
    return {"tests": len(cases), "failures": failed, "skipped": skipped,
            "reproduction_executed": [case.attrib for case in reproduction],
            "custody_executed": [case.attrib for case in custody],
            "office_executed": [case.attrib for case in office],
            "real_cli_executed": [case.attrib for case in real_cli]}


def copy_package_source(manifest: dict) -> Path:
    destination = Path("/work/package-source")
    destination.mkdir()
    for name in manifest["sources"]["docxplus"]["dirs"]:
        (destination / relative_path(name)).mkdir(parents=True, exist_ok=True)
    for name in manifest["sources"]["docxplus"]["files"]:
        target = destination / relative_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file("docxplus", name), target)
    return destination


def office_roundtrip(runner: Runner, document: Path, root: Path, env: dict,
                     visible: str, hidden: str) -> dict:
    """Render real wheel output, save it with Writer, then render the edited package."""
    from PIL import Image

    profile = document.suffix[1:]
    destination = OUTPUTS / "office" / profile
    original = destination / "original"
    saved = destination / "saved"
    original.mkdir(parents=True)
    saved.mkdir()
    original_document = original / document.name
    shutil.copy2(document, original_document)
    save_filter = "docx:Office Open XML Text" if profile == "docx" else "odt:writer8"
    artifacts = {}
    outcomes = {}
    for phase in ("original", "saved"):
        source = original_document if phase == "original" else saved / document.name
        directory = original if phase == "original" else saved
        if phase == "saved":
            private = root / "office-invocations" / profile / "save"
            command, private_env = office_settings(private, env)
            runner.run(f"office-{profile}-save", [*command, "--convert-to", save_filter,
                       "--outdir", str(saved), str(original_document)],
                       cwd=private, env=private_env, seconds=60)
            require(source.is_file(), f"Office did not save {profile}")
        private = root / "office-invocations" / profile / phase
        command, private_env = office_settings(private, env)
        runner.run(f"office-{profile}-{phase}-pdf", [*command, "--convert-to",
                   "pdf:writer_pdf_Export", "--outdir", str(directory), str(source)],
                   cwd=private, env=private_env, seconds=60)
        pdf = directory / "installed.pdf"
        require(pdf.is_file(), f"Office did not render {profile}/{phase}")
        with pdf.open("rb") as stream:
            require(stream.read(5) == b"%PDF-", f"invalid Office PDF: {pdf}")
        text = directory / "installed.txt"
        runner.run(f"office-{profile}-{phase}-text", ["/usr/bin/pdftotext", "-layout",
                   str(pdf), str(text)], cwd=private, env=private_env, seconds=30)
        extracted = text.read_text()
        require(visible in extracted, f"visible sentinel missing in {profile}/{phase}")
        require(hidden not in extracted, f"hidden payload rendered in {profile}/{phase}")
        preview = directory / "first-page"
        runner.run(f"office-{profile}-{phase}-preview", ["/usr/bin/pdftoppm", "-f", "1",
                   "-singlefile", "-scale-to", "1200", "-png", str(pdf), str(preview)],
                   cwd=private, env=private_env, seconds=30)
        png = preview.with_suffix(".png")
        with Image.open(png) as image:
            require(image.format == "PNG" and min(image.size) > 100,
                    f"invalid Office preview: {png}")
            dark = sum(1 for r, g, b in image.convert("RGB").getdata()
                       if max(r, g, b) < 200)
        require(dark > 100, f"Office preview is blank: {png}")
        for kind, path in (("document", source), ("pdf", pdf), ("text", text), ("preview", png)):
            artifacts[f"{phase}_{kind}"] = {"path": path.relative_to(OUTPUTS).as_posix(),
                                            "sha256": digest(path), "bytes": path.stat().st_size}
        outcomes[phase] = {"visible_text_preserved": True, "hidden_payload_absent": True,
                           "preview_nonblank": True, "preview_dark_pixels": dark, "ok": True}
    return {"visible_sentinel": visible, "hidden_sentinel": hidden, "save_filter": save_filter,
            "artifacts": artifacts, **outcomes, "ok": True}


def installed_smoke(runner: Runner, wheel: Path) -> dict:
    root = Path("/work/installed-smoke")
    root.mkdir()
    venv = root / "venv"
    runner.run("wheel-venv", ["uv", "venv", "--offline", "--python", PYTHON, str(venv)], cwd=root)
    python = str(venv / "bin/python")
    runner.run("wheel-install", ["uv", "pip", "install", "--offline", "--no-deps",
                                 "--python", python, str(wheel)], cwd=root)
    # Reuse only the immutable, locked dependency environment. The wheel's own
    # package precedes this .pth; the origin assertion below rejects a fallback.
    site = venv / "lib/python3.15/site-packages"
    (site / "release-dependencies.pth").write_text("/opt/venv/lib/python3.15/site-packages\n")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTEST_ADDOPTS", None)
    origin = runner.run("wheel-import-origin", [python, "-I", "-c",
        ("import docxplus,importlib.metadata,json,pathlib; "
         f"assert pathlib.Path(docxplus.__file__).is_relative_to({str(site)!r}); "
         "print(json.dumps({'module':docxplus.__file__,"
         "'version':importlib.metadata.version('docxplus')}))")], cwd=root, env=env)
    payload = root / "payload.bin"
    hidden = "DOCXPLUS_HIDDEN_INSTALLED_WHEEL_SECRET"
    visible = "DOCXPLUS INSTALLED WHEEL VISIBLE SENTINEL"
    payload.write_bytes(hidden.encode() + b"\x00\xff\n")
    # /work remains noexec. Interpret the actual installed console script with
    # its own venv Python, rather than granting executability to writable scratch.
    command = [python, str(venv / "bin/docxplus")]
    runner.run("wheel-entrypoint", [*command, "--help"], cwd=root, env=env)
    artifacts = OUTPUTS / "installed-wheel"
    artifacts.mkdir()
    office = {"schema": "docxplus.release-office.v1", "tools": office_versions(),
              "tool_sha256": {name: digest(Path(f"/usr/bin/{name}").resolve())
                              for name in ("libreoffice", "pdftotext", "pdftoppm", "pdfimages")},
              "profiles": {}, "ok": False,
              "payload_preservation": "Not asserted after Office save: editing may strip payloads "
                                      "or invalidate signatures; only visible rendering is qualified."}
    dump(OUTPUTS / "office/evidence.json", office)
    profile_modules = {}
    for profile in ("docx", "odt"):
        document = artifacts / f"installed.{profile}"
        channels = [("probe", "custom_xml"), ("package", "package_part"),
                    ("properties", "metadata"), ("compatibility", "mce")]
        slots = [slot for slot, _ in channels] if profile == "docx" else ["probe"]
        modules = [f"{slot}:{channel}:{payload}" for slot, channel in channels] if profile == "docx" else [f"probe:{payload}"]
        module_args = [argument for module in modules for argument in ("--module", module)]
        profile_modules[profile] = slots
        build = "build" if profile == "docx" else "odt-build"
        extract = "extract" if profile == "docx" else "odt-extract"
        validate = "validate" if profile == "docx" else "odt-validate"
        runner.run(f"wheel-{profile}-build", [*command, build, str(document), *module_args,
                                            "--password", "release-smoke", "--text", visible],
                   cwd=root, env=env)
        runner.run(f"wheel-{profile}-validate", [*command, validate, str(document)], cwd=root, env=env)
        for slot in slots:
            recovered = root / f"recovered-{profile}-{slot}.bin"
            runner.run(f"wheel-{profile}-extract-{slot}", [*command, extract, str(document), slot,
                       "--out", str(recovered), "--password", "release-smoke"], cwd=root, env=env)
            require(recovered.read_bytes() == payload.read_bytes(),
                    f"installed {profile}/{slot} roundtrip failed")
        office["profiles"][profile] = office_roundtrip(runner, document, root, env, visible, hidden)
        dump(OUTPUTS / "office/evidence.json", office)
    office["ok"] = True
    dump(OUTPUTS / "office/evidence.json", office)
    return {"origin": json.loads(origin), "payload_sha256": digest(payload),
            "profiles": ["docx", "odt"], "modules": profile_modules, "office": office, "ok": True}


def artifact_checks(pipeline_started_ns: int) -> dict:
    generated = SOURCE / "output"
    pdf = generated / "documents/manuscript.pdf"
    require(pdf.is_file(), "the render did not generate manuscript.pdf")
    require(pdf.stat().st_mtime_ns >= pipeline_started_ns, "manuscript.pdf is a stale seeded file")
    with pdf.open("rb") as stream:
        require(stream.read(5) == b"%PDF-", "render output is not a PDF")
    figures = list((generated / "figures").glob("*.png"))
    require(figures, "no actual figure plates were generated")
    require(all(path.stat().st_mtime_ns >= pipeline_started_ns for path in figures),
            "a figure plate was reused rather than regenerated")
    report = json.loads((generated / "reports/template_roundtrip.json").read_text())
    require(report["source"] == str(ROOTS["template"]), "template report used the wrong project")
    require((generated / "reports/template_roundtrip.json").stat().st_mtime_ns >= pipeline_started_ns,
            "template comparison report was not regenerated")
    require(report["ok"] is True and not report["failures"], "template comparison failed")
    require(all(check["ok"] for check in report["checks"]), "template report has failed checks")
    require(set(report["formats"]) == {"docx", "odt"}, "template report omits a profile")
    require(all(value["comparison"]["identical"] and value["comparison"]["files_compared"] > 0
                for value in report["formats"].values()), "template file comparison is not identical")
    require({"dispatch.docx", "dispatch.docxplus", "dispatch.odt", "dispatch.odtplus"} <=
            {check["name"] for check in report["checks"]}, "template omits four-format dispatch")
    from docxplus.manuscript_vars import load_roundtrip_report
    from docxplus.reproduce import require_output_digest_scheme

    synthetic_path = generated / "reports/project_roundtrip.json"
    require(synthetic_path.stat().st_mtime_ns >= pipeline_started_ns,
            "project comparison report was not regenerated")
    synthetic = load_roundtrip_report(SOURCE)
    dossier_path = generated / "reports/dossier.json"
    require(dossier_path.stat().st_mtime_ns >= pipeline_started_ns, "dossier report was not regenerated")
    dossier = json.loads(dossier_path.read_text())
    require(dossier["ok"] is True and all(v is True for k, v in dossier["checks"].items()
                                        if k != "merkle_root"), "dossier evaluation failed")
    for name in ("dossier", "living_manuscript"):
        require((generated / f"documents/{name}.docx").is_file(),
                f"showcase document is missing: {name}")
    living_path = generated / "reports/living_manuscript.json"
    require(living_path.stat().st_mtime_ns >= pipeline_started_ns,
            "living manuscript report was not regenerated")
    living = json.loads(living_path.read_text())
    require(living["opc_valid"] is True and living["reproduced_match"] is True,
            "living manuscript failed validation or reproduction")
    verified = living["verify_reproduction"]
    require(all(verified[k] is True for k in ("attested", "signed", "verified")),
            "living manuscript attestation failed")
    reproduced = living["reproduction"]
    require(reproduced["source_match"] is True and reproduced["match"] is True,
            "living manuscript did not reproduce its carried source")
    require_output_digest_scheme(reproduced)
    require(reproduced["expected"] == verified["attestation"]["output_digest"]
            and reproduced["actual"] == reproduced["expected"],
            "living manuscript output digest comparison failed")
    attestations = [verified["attestation"]]
    attestations.extend(v["attestation"]["attestation"] for v in synthetic["profiles"].values())
    for attestation in attestations:
        require_output_digest_scheme(attestation)
        require(attestation["command"][0] == "python3",
                "newly authored example recipe is not portable")
    require(verified["attestation"]["command"] == living["authored_command"],
            "living manuscript did not attest its authored command")
    require(all(v["attestation"]["attestation"]["command"] == synthetic["authored_command"]
                for v in synthetic["profiles"].values()),
            "project examples did not attest the authored command")
    require(all(v["comparison"].get("missing_directories") == []
                and v["comparison"].get("unexpected_directories") == []
                and v["comparison"].get("directories_compared") == report["project"]["directories"]
                for v in report["formats"].values()), "template directory comparison failed")
    pairs = []
    for root in (generated / "documents", OUTPUTS / "installed-wheel"):
        pairs.extend(document_pair_checks(root))
    office = json.loads((OUTPUTS / "office/evidence.json").read_text())
    require(office["schema"] == "docxplus.release-office.v1" and office["ok"] is True
            and set(office["profiles"]) == {"docx", "odt"}, "Office evidence is incomplete")
    require(set(office["tools"]) == {"libreoffice", "pdftotext", "pdftoppm", "pdfimages"}
            and all(office["tools"].values()), "Office tool evidence is incomplete")
    expected_artifacts = {f"{phase}_{kind}" for phase in ("original", "saved")
                          for kind in ("document", "pdf", "text", "preview")}
    for profile, proof in office["profiles"].items():
        require(proof["ok"] is True and set(proof["artifacts"]) == expected_artifacts,
                f"Office artifacts are incomplete: {profile}")
        for phase in ("original", "saved"):
            require(all(proof[phase][key] is True for key in (
                "ok", "visible_text_preserved", "hidden_payload_absent", "preview_nonblank"
            )), f"Office rendering outcomes failed: {profile}/{phase}")
        for artifact in proof["artifacts"].values():
            path = OUTPUTS / relative_path(artifact["path"])
            require(path.is_file() and path.stat().st_size == artifact["bytes"]
                    and digest(path) == artifact["sha256"], f"Office artifact drift: {path}")
    return {"pdf_sha256": digest(pdf), "figures": [p.name for p in figures],
            "template_report": report, "project_report": synthetic,
            "living_report": living, "dossier_report": dossier, "dual_names": pairs, "office": office, "ok": True}


def document_pair_checks(root: Path) -> list[dict]:
    """Require complete byte-identical pairs in both export directions."""
    pairs = []
    for base, plus in ((".docx", ".docxplus"), (".odt", ".odtplus")):
        surfaces = {p.with_suffix("") for p in root.glob(f"*{base}")}
        counterparts = {p.with_suffix("") for p in root.glob(f"*{plus}")}
        require(surfaces or counterparts, f"missing dual-name {base} artifacts in {root}")
        require(surfaces == counterparts, f"incomplete dual-name {base}/{plus} exports in {root}")
        for stem in sorted(surfaces):
            path, counterpart = Path(str(stem) + base), Path(str(stem) + plus)
            require(path.is_file() and counterpart.is_file(), f"missing document pair: {stem}")
            sha256 = digest(path)
            require(sha256 == digest(counterpart), f"dual names differ: {path}")
            pairs.append({"surface": str(path), "plus": str(counterpart), "sha256": sha256})
    return pairs


def become_subreaper() -> None:
    """Adopt sandbox orphans so their exited processes can actually be reaped."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def children_remaining() -> list[dict]:
    # A process can reparent to PID1, so inspect the complete private PID namespace,
    # not merely the guest's direct descendants. Exclude only the guest and ancestors.
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break
    ancestors = {os.getpid()}
    pid = os.getpid()
    while pid > 1:
        fields = Path(f"/proc/{pid}/status").read_text().splitlines()
        pid = int(next(line.split()[1] for line in fields if line.startswith("PPid:")))
        if pid <= 0:
            break
        ancestors.add(pid)
    remaining = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal() or int(directory.name) in ancestors:
            continue
        try:
            remaining.append({"pid": int(directory.name),
                              "status": (directory / "status").read_text()})
        except FileNotFoundError:
            continue
    return remaining


def output_inventory() -> list[Path]:
    paths = sorted(OUTPUTS.rglob("*"))
    require(len(paths) < FILE_LIMIT, "output file count exceeds limit")
    total = 0
    files = {}
    for path in paths:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                f"nonregular output is refused: {path}")
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            require(total <= EXTRACTED_LIMIT, "output bytes exceed limit")
            files[path.relative_to(OUTPUTS).as_posix()] = {
                "sha256": digest(path), "bytes": info.st_size, "mode": stat.S_IMODE(info.st_mode),
            }
    dump(OUTPUTS / "artifacts.json", {"schema": "docxplus.release-artifacts.v1", "files": files,
                                     "total_bytes": total})
    require(total + (OUTPUTS / "artifacts.json").stat().st_size <= EXTRACTED_LIMIT,
            "output inventory exceeds extracted-byte limit")
    return sorted(OUTPUTS.rglob("*"))


def export_outputs(ok: bool) -> None:
    paths = output_inventory()
    archive = Path("/work/release-outputs.tar.gz")
    with tarfile.open(archive, "w:gz", dereference=False) as stream:
        for path in paths:
            stream.add(path, arcname=path.relative_to(OUTPUTS).as_posix(), recursive=False)
    size = archive.stat().st_size
    require(size <= ARCHIVE_LIMIT, "compressed output archive exceeds limit")
    print(json.dumps({"schema": "docxplus.release-stream.v1", "event": "archive-start",
                      "encoding": "base64+tar.gz"}), flush=True)
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(48 * 1024), b""):
            print(json.dumps({"event": "archive-chunk", "data": base64.b64encode(block).decode()}),
                  flush=True)
    print(json.dumps({"event": "archive-end", "sha256": digest(archive), "bytes": size,
                      "guest_ok": ok}), flush=True)


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    if sys.argv[1:] == ["--record-runtime"]:
        bindings = verify_sources(manifest)
        dump(Path("/opt/release-runtime.json"), runtime_metadata())
        dump(Path("/opt/release-source-bindings.json"), bindings)
        return 0
    require(not sys.argv[1:], "unexpected guest arguments")
    become_subreaper()
    os.umask(0o077)
    OUTPUTS.mkdir(exist_ok=True)
    for path in (Path("/work/home"), Path("/cache/config"), Path("/cache/matplotlib"),
                 OUTPUTS / "coverage"):
        path.mkdir(parents=True, exist_ok=True)
    os.environ["PYTEST_ADDOPTS"] = "-o cache_dir=/cache/pytest --basetemp=/work/pytest"
    os.environ["DOCXPLUS_REQUIRE_OFFICE"] = "1"
    runner = Runner()
    qualification = {"schema": "docxplus.release-qualification.v1", "ok": False}
    result = {"schema": "docxplus.release-results.v1", "ok": False, "stages": runner.stages}
    try:
        qualify(manifest, runner, qualification)
        dump(OUTPUTS / "qualification.json", qualification)
        seed_outputs()
        runner.run("ruff", [PYTHON, "-m", "ruff", "check", "src", "scripts", "tests"])
        runner.run("pytest", [PYTHON, "-m", "pytest", "--cov=src", "--cov-branch",
                              "--cov-report=term-missing",
                              "--cov-report=json:/outputs/coverage/pytest.json",
                              "--junitxml=/outputs/pytest.xml", "-q"])
        result["pytest"] = junit_summary(OUTPUTS / "pytest.xml")
        coverage = json.loads((OUTPUTS / "coverage/pytest.json").read_text())
        result["coverage_percent"] = coverage["totals"]["percent_covered"]
        require(coverage["totals"]["num_branches"] > 0, "branch coverage was not measured")
        require(result["coverage_percent"] >= 90, "whole-suite coverage is below 90%")
        os.environ["PYTEST_ADDOPTS"] += " --junitxml=/outputs/pipeline-pytest.xml"
        result["pipeline_started_ns"] = time.time_ns()
        runner.run("pipeline-all", ["bash", "run.sh", "all"], seconds=1200)
        result["pipeline_pytest"] = junit_summary(OUTPUTS / "pipeline-pytest.xml")
        package_source = copy_package_source(manifest)
        runner.run("uv-build", ["uv", "build", "--offline", "--no-build-isolation", "--python",
                                PYTHON, "--out-dir", "/outputs/dist", str(package_source)],
                   cwd=package_source)
        wheels = list((OUTPUTS / "dist").glob("*.whl"))
        sdists = list((OUTPUTS / "dist").glob("*.tar.gz"))
        require(len(wheels) == len(sdists) == 1, "build did not emit exactly one wheel and sdist")
        result["installed_wheel"] = installed_smoke(runner, wheels[0])
        result["artifacts"] = artifact_checks(result["pipeline_started_ns"])
        result["sources_after"] = verify_sources(manifest)
        require(result["sources_after"] == qualification["sources"], "input sources changed")
        result["remaining_processes"] = children_remaining()
        require(not result["remaining_processes"], "compute left child processes alive")
        result["ok"] = True
    except GUEST_ERRORS as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["traceback"] = traceback.format_exc()
        print(result["error"], file=sys.stderr, flush=True)
        if not qualification["ok"]:
            qualification["error"] = result["error"]
    finally:
        # Even failures export the actual partial evidence. A timeout is instead
        # evidenced by the host's captured stream, exit status and lifecycle log.
        try:
            result["sources_final"] = verify_sources(manifest)
            result["remaining_processes_final"] = children_remaining()
            if result["remaining_processes_final"]:
                result["ok"] = False
                result["process_cleanup_error"] = "private PID namespace still contains children"
        except GUEST_ERRORS as exc:
            result["ok"] = False
            result["final_binding_error"] = str(exc)
        dump(OUTPUTS / "qualification.json", qualification)
        dump(OUTPUTS / "results.json", result)
        if (SOURCE / "output").is_dir():
            shutil.copytree(SOURCE / "output", OUTPUTS / "generated", symlinks=True)
        export_outputs(result["ok"])
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

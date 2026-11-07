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


def tool_version(argv: list[str]) -> str:
    result = subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=30)
    require(len(result.stdout) <= 1024 * 1024, f"oversized tool version: {argv[0]}")
    return result.stdout.decode(errors="replace").strip()


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
            "https://packages.debian.org/bookworm/pandoc",
            "https://downloads.haskell.org/~cabal/cabal-install-3.18.2.0/SHA256SUMS",
            "https://hackage.haskell.org/package/pandoc-crossref-0.3.12.2",
            "https://github.com/lierdakil/pandoc-crossref/blob/v0.3.12.2/pandoc-crossref.cabal",
            "https://raw.githubusercontent.com/docker-library/python/master/versions.json",
            "https://github.com/astral-sh/uv/releases/tag/0.13.7",
        ],
    }


def write_refused(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_WRONLY)  # no truncate, even if a boundary is broken
    except OSError as exc:
        require(exc.errno in {errno.EROFS, errno.EACCES, errno.EPERM},
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
                     Path("/opt/steganographer"))
    }
    require(all(report["read_only_filesystems"].values()),
            "source/runtime/root filesystem is not kernel read-only")
    report["namespaces"] = {name: os.readlink(f"/proc/self/ns/{name}")
                            for name in ("pid", "net", "mnt", "user")}
    report["write_refusals"] = [write_refused(path) for path in (
        SOURCE / "pyproject.toml", Path("/inputs/template") / next(iter(
            manifest["sources"]["template"]["files"])),
        Path(PYTHON).resolve(), Path(CLI), Path("/opt/release_guest.py"),
        Path("/opt/venv/pyvenv.cfg"),
    )]
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
    project = Path("/work/bwrap-project")
    project.mkdir()
    canary = OUTPUTS / "outer-write-canary"
    canary.write_text("allowed outer write\n")
    from docxplus.reproduce import _sandbox_wrap

    probe = (
        "import errno,json,os,pathlib; "
        "p=pathlib.Path('/outputs/outer-write-canary'); "
        "denied=False; "
        "\ntry:\n p.write_text('forbidden wrapped write')\n"
        "except OSError as e:\n denied=e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)\n"
        "assert denied, 'bwrap allowed an outer writable canary'; "
        "pathlib.Path('project-canary').write_text('project writable'); "
        "pathlib.Path('/tmp/bwrap-tmp-canary').write_text('tmp writable'); "
        "print(json.dumps({'network_namespace':os.readlink('/proc/self/ns/net'),"
        "'outer_write_denied':denied,'project_write':True,'tmp_write':True}))"
    )
    wrapped = _sandbox_wrap([PYTHON, "-c", probe], project)
    require(Path(wrapped[0]).name == "bwrap", "production bwrap sandbox is unavailable")
    result = json.loads(runner.run("bwrap-qualification", wrapped, cwd=project, seconds=30))
    require(result["network_namespace"] != report["namespaces"]["net"],
            "bwrap did not create a distinct network namespace")
    require(canary.read_text() == "allowed outer write\n", "bwrap changed outer canary")
    require((project / "project-canary").read_text() == "project writable",
            "bwrap project positive control failed")
    require(Path("/tmp/bwrap-tmp-canary").read_text() == "tmp writable",
            "bwrap temporary positive control failed")
    report["bwrap"] = {"argv": wrapped, **result}
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
    return {"tests": len(cases), "failures": failed, "skipped": skipped,
            "reproduction_executed": [case.attrib for case in reproduction],
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
    payload.write_bytes(b"installed wheel roundtrip\x00\xff\n")
    # /work remains noexec. Interpret the actual installed console script with
    # its own venv Python, rather than granting executability to writable scratch.
    command = [python, str(venv / "bin/docxplus")]
    runner.run("wheel-entrypoint", [*command, "--help"], cwd=root, env=env)
    artifacts = OUTPUTS / "installed-wheel"
    artifacts.mkdir()
    for profile in ("docx", "odt"):
        document = artifacts / f"installed.{profile}"
        module = f"probe:custom_xml:{payload}" if profile == "docx" else f"probe:{payload}"
        build = "build" if profile == "docx" else "odt-build"
        extract = "extract" if profile == "docx" else "odt-extract"
        validate = "validate" if profile == "docx" else "odt-validate"
        runner.run(f"wheel-{profile}-build", [*command, build, str(document), "--module", module,
                                            "--password", "release-smoke"], cwd=root, env=env)
        runner.run(f"wheel-{profile}-validate", [*command, validate, str(document)], cwd=root, env=env)
        recovered = root / f"recovered-{profile}.bin"
        runner.run(f"wheel-{profile}-extract", [*command, extract, str(document), "probe", "--out",
                                              str(recovered), "--password", "release-smoke"],
                   cwd=root, env=env)
        require(recovered.read_bytes() == payload.read_bytes(), f"installed {profile} roundtrip failed")
    return {"origin": json.loads(origin), "payload_sha256": digest(payload),
            "profiles": ["docx", "odt"], "ok": True}


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
    pairs = []
    for root in (generated / "documents", OUTPUTS / "installed-wheel"):
        for base, plus in ((".docx", ".docxplus"), (".odt", ".odtplus")):
            counterparts = list(root.glob(f"*{plus}"))
            require(counterparts, f"missing dual-name {plus} artifacts in {root}")
            for counterpart in counterparts:
                path = counterpart.with_suffix(base)
                require(path.is_file(), f"dual-name surface is missing: {path}")
                require(digest(path) == digest(counterpart), f"dual names differ: {path}")
                pairs.append({"surface": str(path), "plus": str(counterpart), "sha256": digest(path)})
    return {"pdf_sha256": digest(pdf), "figures": [p.name for p in figures],
            "template_report": report, "dual_names": pairs, "ok": True}


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
    runner = Runner()
    qualification = {"schema": "docxplus.release-qualification.v1", "ok": False}
    result = {"schema": "docxplus.release-results.v1", "ok": False, "stages": runner.stages}
    try:
        qualify(manifest, runner, qualification)
        dump(OUTPUTS / "qualification.json", qualification)
        seed_outputs()
        runner.run("ruff", [PYTHON, "-m", "ruff", "check", "src", "scripts", "tests"])
        runner.run("pytest", [PYTHON, "-m", "pytest", "--cov=src", "--cov-report=term-missing",
                              "--cov-report=json:/outputs/coverage/pytest.json",
                              "--junitxml=/outputs/pytest.xml", "-q"])
        result["pytest"] = junit_summary(OUTPUTS / "pytest.xml")
        coverage = json.loads((OUTPUTS / "coverage/pytest.json").read_text())
        result["coverage_percent"] = coverage["totals"]["percent_covered"]
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

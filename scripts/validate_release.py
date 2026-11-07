#!/usr/bin/env python3
"""Source-bound acquisition and offline disposable-Linux release supervision.

Provision never claims validation. Validate never acquires dependencies. All Docker
commands select a private client configuration and the explicitly requested context.
The guest streams its tmpfs outputs before PID 1 exits; stopped tmpfs is not evidence.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

INPUT_SCHEMA = "docxplus.release-inputs.v1"
PROVISION_SCHEMA = "docxplus.release-provision.v1"
SOURCE_NAMES = {"docxplus", "steganographer", "template"}
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
TTL = 1800
MAX_FILES = 20000
MAX_BYTES = 1024**3
MAX_ARCHIVE = 256 * 1024**2
MAX_LOG = 64 * 1024**2
ENTRYPOINT = ["timeout"]
COMMAND = [
    "--signal=TERM", "--kill-after=5s", "1800s",
    "/opt/venv/bin/python", "/opt/release_guest.py",
]
TMPFS = {
    "/tmp": "rw,nosuid,nodev,size=1073741824,mode=1777",
    "/work": "rw,nosuid,nodev,size=4294967296,uid=1000,gid=1000,mode=0700",
    "/cache": "rw,nosuid,nodev,size=2147483648,uid=1000,gid=1000,mode=0700",
    "/outputs": "rw,nosuid,nodev,size=1073741824,uid=1000,gid=1000,mode=0700",
    "/source/docxplus/output":
        "rw,nosuid,nodev,size=2147483648,uid=1000,gid=1000,mode=0700",
}
LABEL = "org.docxplus.release.inputs-sha256"
OWNER_LABEL = "org.docxplus.release.supervisor"


class Refusal(Exception):
    """A missing control, failed command or inconsistent piece of evidence."""


CONTROL_ERRORS = (Refusal, OSError, ValueError, TypeError, KeyError, IndexError,
                  subprocess.SubprocessError, tarfile.TarError, KeyboardInterrupt)


def require(condition, message):
    if not condition:
        raise Refusal(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def clean_path(path):
    path = Path(os.path.abspath(path))
    for component in [path, *path.parents]:
        require(not component.is_symlink(), f"Symlink path component: {component}")
    return path


def read_regular(path, maximum=16 * 1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), f"Not a regular file: {path}")
        require(info.st_size <= maximum, f"Oversized input: {path}")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(data) == info.st_size and len(data) <= maximum
                and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                f"Changing input: {path}")
        return data


def relative_name(name):
    require(isinstance(name, str) and name and "\\" not in name,
            f"Invalid relative path: {name!r}")
    parts = name.split("/")
    require(all(part not in {"", ".", ".."} for part in parts)
            and not PurePosixPath(name).is_absolute(), f"Unsafe path: {name!r}")
    require(not any(ord(char) < 32 for char in name), "Control character in path")
    return parts


def secret_or_history(name):
    parts = [part.lower() for part in PurePosixPath(name).parts]
    forbidden = {".git", ".hg", ".svn", ".ssh", ".aws", ".azure", ".gnupg",
                 ".docker", ".netrc", ".npmrc", ".pypirc", "credentials",
                 "id_rsa", "id_ed25519", "authorized_keys", "kubeconfig"}
    return any(part in forbidden or part == ".env" or part.startswith(".env.")
               and part not in {".env.example", ".env.sample", ".env.template"}
               or part.endswith((".pem", ".key", ".p12", ".pfx")) for part in parts)


def private_directory(path):
    require(path.is_dir(), f"Missing directory: {path}")
    require(path.stat().st_uid == os.getuid(), f"Directory not owned by caller: {path}")
    require(any(parent.stat().st_uid == os.getuid()
                and stat.S_IMODE(parent.stat().st_mode) & 0o077 == 0
                for parent in [path, *path.parents]), f"No private ancestor: {path}")


def inventory(root):
    files, dirs = {}, []
    total = 0

    def inaccessible(error):
        raise Refusal(f"Cannot inventory directory: {error.filename}") from error

    for directory, names, filenames in os.walk(root, followlinks=False, onerror=inaccessible):
        names.sort()
        filenames.sort()
        for name in names + filenames:
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            relative_name(rel)
            require(not secret_or_history(rel), f"History/credential-like path refused: {rel}")
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), f"Snapshot symlink: {rel}")
            if stat.S_ISDIR(info.st_mode):
                dirs.append(rel)
                require(len(dirs) <= MAX_FILES, "Source directory count exceeds limit")
                continue
            require(stat.S_ISREG(info.st_mode), f"Snapshot special file: {rel}")
            require(info.st_nlink == 1, f"Snapshot is not an independent file: {rel}")
            require(not info.st_mode & 0o6000, f"Set-ID source file: {rel}")
            total += info.st_size
            require(len(files) < MAX_FILES and total <= 4 * MAX_BYTES,
                    "Source inventory exceeds limits")
            hasher = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                copied = 0
                for block in iter(lambda: stream.read(1024**2), b""):
                    copied += len(block)
                    require(copied <= info.st_size, f"Growing source file: {rel}")
                    hasher.update(block)
                after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                     before.st_ctime_ns) ==
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                        after.st_ctime_ns), f"File changed during inventory: {rel}")
            files[rel] = {"sha256": hasher.hexdigest(), "bytes": info.st_size,
                          "mode": stat.S_IMODE(info.st_mode)}
    return files, sorted(dirs)


def verify_inputs(manifest):
    require(isinstance(manifest, dict) and manifest.get("schema") == INPUT_SCHEMA,
            "Unsupported input schema")
    sources = manifest.get("sources")
    require(isinstance(sources, dict) and set(sources) == SOURCE_NAMES,
            "Exactly docxplus, steganographer and template sources are required")
    roots = []
    canonical_source = Path(__file__).resolve().parent.parent
    for name, source in sources.items():
        require(isinstance(source, dict), f"Invalid source: {name}")
        require(set(source) <= {"root", "sha256", "files", "dirs", "base_commit",
                                "dirty", "identity"}, f"Unknown source fields: {name}")
        root_value = source.get("root")
        require(isinstance(root_value, str) and Path(root_value).is_absolute(),
                f"Source root must be absolute: {name}")
        root = clean_path(root_value)
        private_directory(root)
        require(root != canonical_source and not root.is_relative_to(canonical_source)
                and not canonical_source.is_relative_to(root), "Canonical source is not a snapshot")
        require(not any(root == other or root.is_relative_to(other)
                        or other.is_relative_to(root) for other in roots), "Overlapping snapshots")
        roots.append(root)
        require(isinstance(source.get("dirty"), bool)
                and isinstance(source.get("identity"), str) and source["identity"],
                f"Missing source identity/dirty state: {name}")
        require("base_commit" not in source or isinstance(source["base_commit"], str),
                f"Invalid base commit: {name}")
        files = source.get("files")
        dirs = source.get("dirs")
        require(isinstance(files, dict) and isinstance(dirs, list)
                and all(isinstance(item, str) for item in dirs), "Invalid file inventory")
        require(len(dirs) == len(set(dirs)), "Duplicate directory inventory")
        for rel, metadata in files.items():
            relative_name(rel)
            require(isinstance(metadata, dict) and set(metadata) == {"sha256", "bytes", "mode"},
                    f"Invalid file metadata: {rel}")
            require(isinstance(metadata["sha256"], str) and HASH_RE.fullmatch(metadata["sha256"])
                    and type(metadata["bytes"]) is int and metadata["bytes"] >= 0
                    and type(metadata["mode"]) is int and 0 <= metadata["mode"] <= 0o7777,
                    f"Invalid file binding: {rel}")
        for rel in dirs:
            relative_name(rel)
        require(source.get("sha256") == digest(canonical(files)),
                f"Inventory digest mismatch: {name}")
        actual_files, actual_dirs = inventory(root)
        require(actual_files == files and actual_dirs == sorted(dirs),
                f"Snapshot drift: {name}")
    return sources


def new_output(value, sources):
    output = clean_path(value)
    parent = output.parent
    private_directory(parent)
    require(not output.exists(), f"Output already exists: {output}")
    script_root = Path(__file__).resolve().parent.parent
    require(not output.is_relative_to(script_root), "Output must be outside the script's source")
    for ancestor in [parent, *parent.parents]:
        require(not any((ancestor / marker).exists() for marker in (".git", ".hg", ".svn")),
                "Output must not be inside a canonical working copy")
        if (ancestor.stat().st_uid == os.getuid()
                and stat.S_IMODE(ancestor.stat().st_mode) & 0o077 == 0):
            break
    for source in sources.values():
        root = Path(source["root"])
        require(not output.is_relative_to(root) and not root.is_relative_to(output),
                "Output overlaps a source")
    output.mkdir(mode=0o700)
    return output


def safe_environment():
    # Docker context lookup requires HOME, but no token, proxy, SSH agent, DOCKER_HOST,
    # DOCKER_AUTH_CONFIG or project environment is inherited by a child process.
    return {"PATH": os.defpath + ":/opt/homebrew/bin:/usr/local/bin",
            "HOME": str(Path.home()), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


class Runner:
    def __init__(self, output):
        self.output = output
        self.records = []
        self.env = safe_environment()
        self.docker_binary = shutil.which("docker", path=self.env["PATH"])
        require(self.docker_binary, "Docker CLI is unavailable")
        self.prefix = [self.docker_binary]
        self.buildx_metadata = None

    def run(self, args, *, timeout=60, maximum=MAX_LOG, consumer=None, check=True,
            capture=True):
        index = len(self.records)
        stdout_path = self.output / f"command-{index:03d}.stdout"
        stderr_path = self.output / f"command-{index:03d}.stderr"
        command = self.prefix + args
        record = {"argv": command, "timeout_seconds": timeout,
                  "stdout": stdout_path.name, "stderr": stderr_path.name}
        record["stdout_mode"] = "consumer" if consumer is not None else "file"
        self.records.append(record)
        save(self.output / "commands.json", self.records)
        started = time.monotonic()
        output = bytearray()
        sizes = {"stdout": 0, "stderr": 0}
        process = None
        selector = None
        problem = None
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=self.env, start_new_session=True)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                while selector.get_map():
                    require(time.monotonic() - started < timeout, "Host command deadline exceeded")
                    for key, _ in selector.select(timeout=0.2):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        channel = key.data
                        sizes[channel] += len(block)
                        bound = min(maximum, MAX_LOG) if channel == "stderr" else maximum
                        require(sizes[channel] <= bound, f"{channel} exceeded output bound")
                        if channel == "stdout" and consumer is not None:
                            consumer.feed(block)
                        else:
                            (stdout if channel == "stdout" else stderr).write(block)
                            if channel == "stdout" and capture:
                                require(len(output) + len(block) <= 16 * 1024**2,
                                        "Command response exceeded memory bound")
                                output.extend(block)
                process.wait(timeout=max(1, timeout - (time.monotonic() - started)))
                if consumer is not None:
                    consumer.finish()
        except BaseException as exc:
            problem = str(exc)
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
            raise
        finally:
            if selector is not None:
                selector.close()
            if process is not None:
                process.stdout.close()
                process.stderr.close()
            record.update(returncode=None if process is None else process.returncode,
                          elapsed_seconds=time.monotonic() - started, bytes=sizes, error=problem,
                          host_process_reaped=process is not None and process.returncode is not None)
            save(self.output / "commands.json", self.records)
        require(not check or process.returncode == 0,
                f"Docker command failed ({process.returncode}); see command-{index:03d}.stderr")
        return bytes(output), process.returncode

    def json(self, args):
        data, _ = self.run(args, maximum=8 * 1024**2)
        return load_json(data)

    def configure(self, context):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context),
                "Invalid Docker context name")
        self.prefix = [self.docker_binary, "--context", context]
        details = self.json(["context", "inspect", context])
        require(isinstance(details, list) and len(details) == 1, "Ambiguous Docker context")
        endpoint = details[0].get("Endpoints", {}).get("docker", {})
        host = endpoint.get("Host", "")
        require(host.startswith("unix:///") and not endpoint.get("SkipTLSVerify")
                and not details[0].get("TLSMaterial"), "Only local Unix Docker contexts are supported")
        save(self.output / "docker-context.json", details[0])
        config = self.output / "docker-client"
        config.mkdir(mode=0o700)
        # Keep credentials/configuration isolated while exposing an installed
        # standalone Buildx plugin through this client's private plugin directory.
        buildx = shutil.which("docker-buildx", path=self.env["PATH"])
        if buildx:
            executable = Path(buildx).resolve(strict=True)
            require(executable.is_file() and os.access(executable, os.X_OK),
                    "Buildx executable is unavailable")
            plugins = config / "cli-plugins"
            plugins.mkdir(mode=0o700)
            (plugins / "docker-buildx").symlink_to(executable)
            with executable.open("rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            self.buildx_metadata = {"path": str(executable), "sha256": checksum}
        self.prefix = [self.docker_binary, "--config", str(config), "--context", context]
        self.run(["context", "create", context, "--docker", f"host={host}"])
        save(self.output / "docker-version.json", self.json(["version", "--format", "{{json .}}"]))
        # Format before receipt capture: Docker info can otherwise disclose daemon
        # proxy credentials and unrelated workloads in its raw command log.
        keys = ("ID", "OSType", "Architecture", "KernelVersion", "ServerVersion",
                "Name", "DockerRootDir", "SecurityOptions", "CgroupVersion", "CgroupDriver",
                "MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota", "PidsLimit")
        # Docker's Go fields retain the CPU initialism; JSON keys use Cpu.
        go_fields = {"CpuCfsPeriod": "CPUCfsPeriod", "CpuCfsQuota": "CPUCfsQuota"}
        template = "{" + ",".join(
            f'"{key}":{{{{json .{go_fields.get(key, key)}}}}}' for key in keys
        ) + "}"
        identity = self.json(["info", "--format", template])
        require(identity.get("OSType") == "linux", "Docker daemon must run Linux containers")
        require(identity.get("ID"), "Docker daemon has no identity")
        require(all(identity.get(key) is True for key in
                    ("MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota", "PidsLimit")),
                "Docker daemon cannot enforce required memory/swap/CPU/PID bounds")
        save(self.output / "docker-daemon.json", identity)
        return {"context": details[0], "daemon": identity}


def image_binding(image):
    return {key: image.get(key) for key in
            ("Id", "RepoDigests", "Architecture", "Os", "RootFS", "Config")}


def inspect_image(runner, image_id):
    require(isinstance(image_id, str) and IMAGE_RE.fullmatch(image_id), "Image ID is not immutable")
    images = runner.json(["image", "inspect", image_id])
    require(len(images) == 1 and images[0].get("Id") == image_id, "Image identity mismatch")
    image = images[0]
    require(image.get("Os") == "linux", "Image is not Linux")
    config = image.get("Config", {})
    require(not config.get("Volumes") and not config.get("ExposedPorts")
            and not config.get("Healthcheck") and not config.get("OnBuild"),
            "Image requests implicit volumes, ports, healthchecks or build hooks")
    for value in config.get("Env", []):
        key = value.split("=", 1)[0].upper()
        require(not any(word in key for word in ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL",
                                                "PROXY", "AUTH", "SSH", "AWS_", "AZURE_")),
                f"Credential/network configuration in image environment: {key}")
    return image


@contextmanager
def bounded_tar(archive, limit, count_limit):
    """Preflight bounded gzip bytes and physical headers before tar metadata parsing."""
    metadata_limit = 16 * 1024**2
    uncompressed_limit = limit + metadata_limit + 2048 * count_limit + 10240
    with tempfile.TemporaryFile(dir=archive.parent) as raw:
        copied = 0
        with archive.open("rb") as encoded:
            require(encoded.read(2) == b"\x1f\x8b", "Artifact archive must use gzip")
            encoded.seek(0)
            with gzip.GzipFile(fileobj=encoded) as decoded:
                while block := decoded.read(min(1024**2, uncompressed_limit - copied + 1)):
                    copied += len(block)
                    require(copied <= uncompressed_limit, "Uncompressed archive exceeds bound")
                    raw.write(block)
        raw.seek(0)
        headers = metadata_bytes = 0
        metadata_types = {tarfile.XHDTYPE, tarfile.XGLTYPE,
                          tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
        regular_types = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
        while raw.tell() < copied:
            header = raw.read(512)
            require(len(header) == 512, "Truncated physical tar header")
            if header == bytes(512):
                break
            member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
            headers += 1
            require(headers <= 2 * count_limit + 4, "Physical tar header count exceeds bound")
            require(member.type in regular_types | metadata_types,
                    "Archive physical header contains links/special files")
            require(member.size >= 0, "Negative physical tar payload")
            next_header = raw.tell() + (member.size + 511) // 512 * 512
            require(next_header <= copied, "Truncated physical tar payload")
            if member.type in metadata_types:
                metadata_bytes += member.size
                require(member.size <= 64 * 1024 and metadata_bytes <= metadata_limit,
                        "Tar metadata exceeds allocation bound")
                metadata = raw.read(member.size)
                require(not re.search(rb"(?:^|\n)\d+ GNU\.sparse[.=]", metadata),
                        "Sparse artifact metadata is unsupported")
            raw.seek(next_header)
        raw.seek(0)
        yield raw


def extract_archive(archive, destination, *, limit=MAX_BYTES, count_limit=MAX_FILES):
    destination.mkdir(mode=0o700)
    total, count, names, hashes = 0, 0, set(), {}
    with bounded_tar(archive, limit, count_limit) as raw, tarfile.open(fileobj=raw, mode="r:") as tar:
        for member in tar:
            name = member.name
            while name.startswith("./"):
                name = name[2:]
            if name in {"", "."}:
                require(member.isdir(), "Invalid archive root")
                continue
            relative_name(name.rstrip("/") if member.isdir() else name)
            name = name.rstrip("/")
            require(name not in names, f"Duplicate archive member: {name}")
            names.add(name)
            count += 1
            require(count <= count_limit and (member.isfile() or member.isdir()),
                    "Archive contains links/special files or exceeds count limit")
            require(not member.mode & 0o6000, "Set-ID artifact refused")
            path = destination / name
            require(path.is_relative_to(destination), "Archive escaped destination")
            if member.isdir():
                require(not path.exists() or path.is_dir(), "Artifact path collision")
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            total += member.size
            require(0 <= member.size <= limit and total <= limit, "Extracted output exceeds bound")
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = tar.extractfile(member)
            require(source is not None, "Unreadable archive member")
            hasher, copied = hashlib.sha256(), 0
            with source, path.open("xb") as target:
                while block := source.read(1024**2):
                    copied += len(block)
                    require(copied <= member.size, "Oversized archive member")
                    target.write(block)
                    hasher.update(block)
            require(copied == member.size, "Truncated archive member")
            path.chmod(0o600)
            hashes[name] = {"sha256": hasher.hexdigest(), "bytes": copied,
                            "archive_mode": member.mode}
    return {"files": hashes, "file_count": len(hashes), "entry_count": count, "bytes": total}


class GuestStream:
    def __init__(self, output):
        self.output = output
        self.buffer = bytearray()
        self.stream = (output / "guest-outputs.tar.gz").open("xb")
        self.hasher = hashlib.sha256()
        self.size = 0
        self.started = False
        self.ended = False
        self.events = []
        self.guest_ok = False

    def feed(self, block):
        self.buffer.extend(block)
        while b"\n" in self.buffer:
            line, _, remainder = self.buffer.partition(b"\n")
            self.buffer = bytearray(remainder)
            require(len(line) <= 128 * 1024, "Oversized guest protocol line")
            event = load_json(line)
            kind = event.get("event")
            require(not self.ended, "Guest emitted data after archive end")
            if kind == "archive-start":
                require(not self.started and event.get("schema") == "docxplus.release-stream.v1"
                        and event.get("encoding") == "base64+tar.gz", "Invalid archive start")
                self.started = True
                self.events.append(event)
            elif kind == "archive-chunk":
                require(self.started, "Archive chunk before start")
                data = event.get("data")
                require(isinstance(data, str) and len(data) <= 90 * 1024,
                        "Invalid archive chunk")
                decoded = base64.b64decode(data, validate=True)
                self.size += len(decoded)
                require(self.size <= MAX_ARCHIVE, "Guest archive exceeds bound")
                self.hasher.update(decoded)
                self.stream.write(decoded)
            elif kind == "archive-end":
                require(self.started and event.get("sha256") == self.hasher.hexdigest()
                        and event.get("bytes") == self.size and type(event.get("guest_ok")) is bool,
                        "Guest archive digest/length mismatch")
                self.ended = True
                self.guest_ok = event["guest_ok"]
                self.events.append(event)
            else:
                raise Refusal("Unexpected guest stdout protocol event")
        require(len(self.buffer) <= 128 * 1024, "Unterminated guest protocol line")

    def finish(self):
        require(not self.buffer and self.started and self.ended, "Incomplete guest archive stream")

    def close(self):
        self.stream.close()
        save(self.output / "guest-stream.json", {"events": self.events,
             "bytes": self.size, "sha256": self.hasher.hexdigest(), "complete": self.ended})


def copy_context(output, manifest, raw):
    context = output / "build-context"
    context.mkdir(mode=0o700)
    for name, source in manifest["sources"].items():
        target = context / name
        target.mkdir(mode=0o700)
        for rel in sorted(source["dirs"], key=lambda item: (item.count("/"), item)):
            (target / rel).mkdir(mode=0o755)
        for rel, metadata in source["files"].items():
            destination = target / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            with (Path(source["root"]) / rel).open("rb") as src, destination.open("xb") as dst:
                shutil.copyfileobj(src, dst, length=1024**2)
            destination.chmod(metadata["mode"])
        files, dirs = inventory(target)
        require(files == source["files"] and dirs == sorted(source["dirs"]),
                f"Build context copy drift: {name}")
    dockerfile = context / "docxplus" / "Dockerfile.release-validation"
    require(dockerfile.is_file(), "Snapshot lacks Dockerfile.release-validation")
    shutil.copyfile(dockerfile, context / "Dockerfile")
    (context / "inputs.json").write_bytes(raw)
    return context


def created_container(runner, cidfile, name, token):
    """Recover daemon custody even when the create client was interrupted."""
    if cidfile.exists():
        cid = read_regular(cidfile).decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", cid), "Invalid container ID")
        return cid
    data, code = runner.run(["inspect", "--type", "container", name],
                            check=False, maximum=8 * 1024**2)
    if code != 0:
        require(not data.strip() or load_json(data) == [], "Ambiguous container create failure")
        return None
    objects = load_json(data)
    require(len(objects) == 1
            and objects[0].get("Config", {}).get("Labels", {}).get(OWNER_LABEL) == token,
            "Cannot recover ownership of created container")
    cid = objects[0].get("Id")
    require(isinstance(cid, str) and re.fullmatch(r"[0-9a-f]{64}", cid),
            "Recovered container ID is invalid")
    cidfile.write_text(cid + "\n")
    return cid


def runtime_receipt(runner, image_id, output, token):
    name = "docxplus-release-metadata-" + token
    cidfile = output / "metadata-container.cid"
    cid, complete = None, False
    try:
        try:
            runner.run(["create", "--pull", "never", "--name", name,
                        "--cidfile", str(cidfile), "--label", f"{OWNER_LABEL}={token}",
                        "--network", "none", "--read-only", "--user", "1000:1000",
                        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                        "--entrypoint", "/bin/true", image_id])
        finally:
            cid = created_container(runner, cidfile, name, token)
            save(output / "metadata-container.json",
                 {"id": cid, "name": name, "never_started": True})
        require(cid, "Metadata container creation was not confirmed")
        archive = output / "runtime-receipt.tar.gz"

        class Capture:
            def __init__(self, stream):
                self.stream = stream

            def feed(self, block):
                self.stream.write(block)

            def finish(self):
                self.stream.close()

        # Docker cp emits raw tar; retain the extractor's strict gzip boundary.
        with gzip.open(archive, "xb") as compressed:
            capture = Capture(compressed)
            runner.run(["cp", f"{cid}:/opt/release-runtime.json", "-"],
                       maximum=4 * 1024**2, consumer=capture)
        extract_archive(archive, output / "runtime", limit=1024**2, count_limit=4)
        receipt = load_json(read_regular(output / "runtime" / "release-runtime.json"))
        require(isinstance(receipt, dict)
                and receipt.get("schema") == "docxplus.release-runtime.v1"
                and isinstance(receipt.get("tools"), dict) and receipt["tools"]
                and HASH_RE.fullmatch(str(receipt.get("steganographer_sha256", ""))),
                "Incomplete/unsupported runtime receipt")
        complete = True
        return receipt
    finally:
        if cid is not None:
            state = runner.json(["inspect", cid])[0]
            save(output / "metadata-container-final.json", state)
            require(not state["State"].get("Running") and state["State"].get("Pid") == 0,
                    "Metadata container unexpectedly active")
            if complete:
                runner.run(["rm", cid])


def resolve_bases(runner, context):
    """Pin the context-only Dockerfile to the exact acquired registry digests."""
    bases, stages, resolved = [], set(), []
    for line in (context / "Dockerfile").read_text().splitlines(keepends=True):
        match = re.match(r"(\s*FROM\s+(?:--platform=\S+\s+)?)(\S+)", line, re.IGNORECASE)
        if match:
            reference = match.group(2)
            stage = re.search(r"\s+AS\s+(\S+)\s*$", line, re.IGNORECASE)
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", reference),
                    "Base image requires an explicit public image reference")
            if reference.lower() not in stages:
                require(reference != "scratch", "Runtime base must have recorded provenance")
                runner.run(["pull", reference], timeout=1200, capture=False)
                image = runner.json(["image", "inspect", reference])[0]
                require(IMAGE_RE.fullmatch(image["Id"]), "Unresolved base image ID")
                repo_digests = image.get("RepoDigests") or []
                require(repo_digests and all("@sha256:" in item for item in repo_digests),
                        "Acquired base image has no registry digest")
                pinned = min(repo_digests)
                bases.append({"reference": reference, "resolved": pinned,
                              "image": image_binding(image)})
                line = line[:match.start(2)] + pinned + line[match.end(2):]
            if stage:
                stages.add(stage.group(1).lower())
        resolved.append(line)
    require(bases, "No base image provenance")
    (context / "Dockerfile").write_text("".join(resolved))
    return bases


def provision(runner, output, manifest, raw, context, custody, token):
    input_hash = digest(raw)
    buildx_version, _ = runner.run(["buildx", "version"])
    bases = resolve_bases(runner, context)
    iidfile = output / "image-id.txt"
    runner.run(["buildx", "build", "--load", "--pull", "--network", "default", "--progress", "plain",
                "--iidfile", str(iidfile), "--label", f"{LABEL}={input_hash}",
                "--label", f"{OWNER_LABEL}={token}", "--tag", f"docxplus-release:{token}",
                str(context)], timeout=3600, maximum=MAX_LOG, capture=False)
    image_id = read_regular(iidfile).decode().strip()
    image = inspect_image(runner, image_id)
    require(image["Config"].get("Labels", {}).get(LABEL) == input_hash,
            "Built image lacks source binding")
    save(output / "image-inspect.json", image)
    runner.run(["image", "history", "--no-trunc", image_id], capture=False)
    runtime = runtime_receipt(runner, image_id, output, token)
    verify_inputs(manifest)
    record = {"schema": PROVISION_SCHEMA, "image_id": image_id,
              "docker_context": custody["context"]["Name"], "inputs_sha256": input_hash,
              "sources": manifest["sources"], "image": image_binding(image), "runtime": runtime,
              "build": {"base_images": bases, "source_dockerfile_sha256":
                        digest(read_regular(context / "docxplus" / "Dockerfile.release-validation")),
                        "resolved_dockerfile_sha256": digest(read_regular(context / "Dockerfile")),
                        "custody": custody,
                        "buildx": {"version": buildx_version.decode().strip(),
                                   "executable": runner.buildx_metadata},
                        "network": "acquisition-only", "token": token},
              "validation_performed": False}
    return record


def check_controls(inspected, image_id, image, token, input_hash):
    config, host = inspected["Config"], inspected["HostConfig"]
    require(inspected.get("Image") == image_id and config.get("Image") == image_id,
            "Container image drift")
    require(config.get("User") == "1000:1000" and config.get("Entrypoint") == ENTRYPOINT
            and config.get("Cmd") == COMMAND, "Container user/TTL entrypoint drift")
    require(config.get("Env") == image["Config"].get("Env") and not config.get("Healthcheck"),
            "Container environment/healthcheck drift")
    require(config.get("Labels", {}).get(OWNER_LABEL) == token
            and config.get("Labels", {}).get(LABEL) == input_hash, "Container ownership drift")
    require(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True,
            "Container network/root is not isolated")
    require(host.get("Privileged") is False and not host.get("CapAdd")
            and {value.upper() for value in host.get("CapDrop", [])} == {"ALL"},
            "Container capability drift")
    require(set(host.get("SecurityOpt", [])) ==
            {"no-new-privileges=true", "seccomp=unconfined"},
            "Container security policy drift")
    # Docker API accepts an empty PID mode for a new private namespace, not
    # the string 'private' (valid values are empty, host or container:<id>).
    require(host.get("PidMode") == "" and host.get("IpcMode") == "private"
            and host.get("CgroupnsMode") == "private" and host.get("UTSMode") == "",
            "Container namespace drift")
    require(host.get("Memory") == 8 * 1024**3 and host.get("MemorySwap") == 8 * 1024**3
            and host.get("NanoCpus") == 4 * 10**9 and host.get("PidsLimit") == 512,
            "Container resource bound drift")
    require(host.get("Tmpfs") == TMPFS, "Container writable tmpfs drift")
    require(not host.get("Binds") and not host.get("Mounts")
            and not host.get("VolumesFrom") and not config.get("Volumes"), "Host/volume mount refused")
    require(all(mount.get("Type") == "tmpfs" and mount.get("Destination") in TMPFS
                for mount in inspected.get("Mounts", [])), "Unexpected effective mount")
    require(not host.get("Devices") and not host.get("DeviceRequests")
            and not host.get("DeviceCgroupRules") and not host.get("ExtraHosts")
            and not host.get("Links") and not host.get("PortBindings")
            and not host.get("PublishAllPorts") and not host.get("Sysctls"),
            "Unexpected device/network/kernel configuration")
    require(host.get("RestartPolicy", {}).get("Name") == "no"
            and host.get("AutoRemove") is False and host.get("Init") is not True
            and host.get("LogConfig", {}).get("Type") == "none", "Container lifecycle drift")
    require(host.get("MaskedPaths") and host.get("ReadonlyPaths"),
            "Default Docker proc/kernel path protections are missing")


def cleanup_container(runner, cid, output, evidence):
    errors = []
    for args in (["stop", "--time", "5", cid], ["kill", cid], ["wait", cid]):
        try:
            if args[0] == "wait":
                current = runner.json(["inspect", cid])[0]["State"]
                if current.get("Status") == "created" and current.get("Pid") == 0:
                    evidence["wait_not_needed"] = "Container never started; no PID namespace existed"
                    continue
            data, code = runner.run(args, timeout=20, maximum=1024**2, check=False)
            evidence.setdefault("cleanup_commands", []).append(
                {"argv": args, "returncode": code, "stdout": data.decode(errors="replace")})
        except CONTROL_ERRORS as exc:
            errors.append(str(exc))
    try:
        inspected = runner.json(["inspect", cid])[0]
        save(output / "container-final.json", inspected)
        state = inspected["State"]
        require(not state.get("Running") and not state.get("Restarting")
                and not state.get("Paused") and state.get("Pid") == 0
                and state.get("Status") in {"exited", "created", "dead"},
                "Container/namespace remains active")
        evidence["final_state"] = state
        evidence["namespace_reaped"] = True
        require(state.get("Status") != "dead", "Docker reports dead container cleanup")
    except CONTROL_ERRORS as exc:
        errors.append(str(exc))
    evidence["cleanup_errors"] = errors
    if errors:
        # Evidence writes can fail before Runner launches a control command.
        # Still stop/reap physically; missing custody evidence remains a failure.
        emergency = evidence.setdefault("emergency_cleanup", [])
        for args in (["kill", cid], ["wait", cid]):
            try:
                process = subprocess.run(runner.prefix + args, env=runner.env,
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=20, check=False)
                emergency.append({"argv": args, "returncode": process.returncode})
            except CONTROL_ERRORS as exc:
                emergency.append({"argv": args, "error": str(exc)})
    require(not errors, "Cannot prove container stop/reap: " + "; ".join(errors))


def validate(runner, output, manifest, raw, record, custody, token):
    input_hash = digest(raw)
    require(record.get("schema") == PROVISION_SCHEMA, "Unsupported provision schema")
    require(record.get("inputs_sha256") == input_hash
            and record.get("sources") == manifest["sources"], "Provision source/manifest drift")
    require(record.get("docker_context") == custody["context"]["Name"], "Docker context drift")
    prior = record.get("build", {}).get("custody", {})
    require(prior.get("context", {}).get("Endpoints") == custody["context"].get("Endpoints")
            and prior.get("daemon", {}).get("ID") == custody["daemon"]["ID"],
            "Docker daemon custody drift")
    image_id = record.get("image_id")
    image = inspect_image(runner, image_id)
    require(image_binding(image) == record.get("image"), "Provision image/runtime configuration drift")
    require(image["Config"].get("Labels", {}).get(LABEL) == input_hash,
            "Image source binding mismatch")
    save(output / "image-inspect.json", image)
    require(runtime_receipt(runner, image_id, output, token) == record.get("runtime"),
            "Provision runtime receipt drift")
    name = "docxplus-release-validation-" + token
    cidfile = output / "container.cid"
    args = ["create", "--pull", "never", "--name", name, "--cidfile", str(cidfile),
            "--label", f"{OWNER_LABEL}={token}", "--label", f"{LABEL}={input_hash}",
            "--user", "1000:1000", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--security-opt", "seccomp=unconfined",
            "--pid", "", "--ipc", "private", "--cgroupns", "private",
            "--memory", "8g", "--memory-swap", "8g", "--cpus", "4", "--pids-limit", "512",
            "--restart", "no", "--log-driver", "none", "--entrypoint", "timeout"]
    for path, options in TMPFS.items():
        args += ["--tmpfs", f"{path}:{options}"]
    args += [image_id, *COMMAND]
    evidence = {"schema": "docxplus.release-lifecycle.v1", "container_name": name,
                "docker_context": custody["context"]["Name"], "image_id": image_id,
                "inputs_sha256": input_hash, "internal_ttl_seconds": TTL,
                "host_timeout_seconds": TTL + 45, "namespace_reaped": False,
                "seccomp": "unconfined",
                "seccomp_risk": "Non-default per-container policy permits real unprivileged "
                                "bubblewrap user/mount/network namespace syscalls; kernel "
                                "capability, read-only mount, network and PID isolation remain. "
                                "Actual guest negative qualification is mandatory.",
                "pid_namespace": "private (Docker PidMode empty; never host/container sharing)"}
    save(output / "lifecycle.json", evidence)
    cid = None
    stream = None
    failure = None
    attach_code = None
    try:
        try:
            runner.run(args)
        finally:
            cid = created_container(runner, cidfile, name, token)
            evidence["container_id"] = cid
            save(output / "lifecycle.json", evidence)
        require(cid, "Docker did not record a container ID")
        inspected = runner.json(["inspect", cid])[0]
        save(output / "container-before.json", inspected)
        check_controls(inspected, image_id, image, token, input_hash)
        require(inspected["State"]["Status"] == "created"
                and not inspected["State"]["Running"], "Container started before inspection")
        evidence["controls_verified_before_start"] = True
        save(output / "lifecycle.json", evidence)
        stream = GuestStream(output)
        _, attach_code = runner.run(["start", "--attach", cid], timeout=TTL + 45,
                                    maximum=384 * 1024**2, consumer=stream, check=False)
        evidence["attach_returncode"] = attach_code
    except CONTROL_ERRORS as exc:
        failure = exc
        evidence["failure"] = str(exc)
    finally:
        try:
            if stream is not None:
                stream.close()
        except CONTROL_ERRORS as exc:
            failure = failure or exc
            evidence["stream_close_failure"] = str(exc)
        finally:
            if cid is not None:
                try:
                    cleanup_container(runner, cid, output, evidence)
                except CONTROL_ERRORS as exc:
                    failure = failure or exc
                    evidence["cleanup_failure"] = str(exc)
            else:
                evidence["failure"] = evidence.get("failure", "Container creation was not confirmed")
        try:
            verify_inputs(manifest)
            evidence["sources_verified_after"] = True
            if cid is not None:
                final_image = inspect_image(runner, image_id)
                require(image_binding(final_image) == record["image"], "Image drift after validation")
                evidence["image_verified_after"] = True
        except CONTROL_ERRORS as exc:
            failure = failure or exc
            evidence["drift_failure"] = str(exc)
        save(output / "lifecycle.json", evidence)
    # Never extract unverified partial archives, and never treat absent output as success.
    if stream is not None and stream.ended:
        artifacts = extract_archive(output / "guest-outputs.tar.gz", output / "guest")
        save(output / "collected-artifacts.json", artifacts)
    if failure is not None:
        raise failure
    require(evidence.get("namespace_reaped"), "No namespace stop/reap evidence")
    final_container = runner.json(["inspect", cid])[0]
    check_controls(final_container, image_id, image, token, input_hash)
    state = evidence["final_state"]
    require(not state.get("OOMKilled") and not state.get("Error")
            and state.get("ExitCode") == 0 and attach_code == 0,
            "Guest container failed; inspect lifecycle and guest evidence")
    require(stream is not None and stream.guest_ok, "Guest reported validation failure")
    qualification = load_json(read_regular(output / "guest" / "qualification.json"))
    results = load_json(read_regular(output / "guest" / "results.json"))
    require(qualification.get("schema") == "docxplus.release-qualification.v1"
            and results.get("schema") == "docxplus.release-results.v1"
            and qualification.get("ok") is True and results.get("ok") is True,
            "Guest qualification/results did not succeed")
    return {"schema": "docxplus.release-validation.v1", "ok": True,
            "image_id": image_id, "inputs_sha256": input_hash, "sources": manifest["sources"],
            "lifecycle": "lifecycle.json", "qualification": "guest/qualification.json",
            "results": "guest/results.json", "artifacts": "collected-artifacts.json"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("provision", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--inputs", required=True, type=Path)
        command.add_argument("--output", required=True, type=Path)
        command.add_argument("--docker-context", required=True)
        if name == "validate":
            command.add_argument("--provision-record", required=True, type=Path)
    args = parser.parse_args()
    output = None
    def interrupted(signum, _frame):
        raise Refusal(f"Supervisor received signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raw = read_regular(clean_path(args.inputs))
        manifest = load_json(raw)
        sources = verify_inputs(manifest)
        output = new_output(args.output, sources)
        (output / "inputs.json").write_bytes(raw)
        save(output / "source-inventory.json", sources)
        runner = Runner(output)
        custody = runner.configure(args.docker_context)
        token = uuid.uuid4().hex
        if args.command == "provision":
            context = copy_context(output, manifest, raw)
            result = provision(runner, output, manifest, raw, context, custody, token)
            require(read_regular(clean_path(args.inputs)) == raw, "Input manifest changed")
            verify_inputs(manifest)
            save(output / "provision.json", result)
            print(output / "provision.json")
        else:
            provision_raw = read_regular(clean_path(args.provision_record))
            (output / "provision-input.json").write_bytes(provision_raw)
            record = load_json(provision_raw)
            result = validate(runner, output, manifest, raw, record, custody, token)
            require(read_regular(clean_path(args.inputs)) == raw, "Input manifest changed")
            require(read_regular(clean_path(args.provision_record)) == provision_raw,
                    "Provision record changed")
            verify_inputs(manifest)
            save(output / "validation.json", result)
            print(output / "validation.json")
        return 0
    except CONTROL_ERRORS as exc:
        if output is not None:
            save(output / "failure.json", {"ok": False, "command": args.command,
                 "error": str(exc), "type": type(exc).__name__})
        print(f"Release {args.command} failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

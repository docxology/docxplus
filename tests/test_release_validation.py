"""Release admission and archive parsing reject unsafe serialized input."""

import hashlib
import importlib.util
import io
import json
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from scripts import validate_release as release

PAYLOAD = b"release artifact\x00\xff\n"


def _archive(path, mode, *, metadata=None):
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("artifact.bin")
        member.mode = 0o755
        member.size = len(PAYLOAD)
        if metadata is not None:
            member.pax_headers = metadata
        archive.addfile(member, io.BytesIO(PAYLOAD))
    return path


def test_release_archive_preserves_bytes_and_seals_extracted_permissions(tmp_path):
    """Actual gzip/PAX data is hashed and extracted without executable permissions."""
    archive = _archive(tmp_path / "artifacts.tar.gz", "w:gz")
    destination = tmp_path / "extracted"
    receipt = release.extract_archive(archive, destination, limit=1024, count_limit=4)
    artifact = destination / "artifact.bin"
    assert artifact.read_bytes() == PAYLOAD
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert receipt["files"]["artifact.bin"]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()


def test_release_archive_rejects_oversized_pax_before_parsing(tmp_path):
    """Tiny compressed input must not allocate an unbounded ignored PAX comment."""
    archive = _archive(
        tmp_path / "metadata.tar.gz", "w:gz", metadata={"comment": "x" * (2 * 1024**2)}
    )
    destination = tmp_path / "extracted"
    with pytest.raises(release.Refusal):
        release.extract_archive(archive, destination, limit=1024, count_limit=4)
    assert not (destination / "artifact.bin").exists()


def test_release_archive_rejects_bzip2_disguised_as_gzip(tmp_path):
    """The declared tar.gz export protocol must not select an alternate decoder."""
    archive = _archive(tmp_path / "artifacts.tar.gz", "w:bz2")
    destination = tmp_path / "extracted"
    with pytest.raises(release.Refusal):
        release.extract_archive(archive, destination, limit=1024, count_limit=4)
    assert not (destination / "artifact.bin").exists()


@pytest.fixture
def control_candidate(tmp_path):
    """Serialized policy input, not a stand-in Docker runner or execution result."""
    image_id = "sha256:" + "a" * 64
    candidate = {
        "image_id": image_id,
        "image": {"Config": {"Env": ["PATH=/opt/venv/bin:/usr/bin:/bin"]}},
        "token": "admission-owner",
        "input_hash": "b" * 64,
        "custody": {
            "daemon": {
                "ID": "rootless-daemon-admission",
                "OSType": "linux",
                "SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless"],
            },
        },
        "inspected": {
            "Image": image_id,
            "Config": {
                "Image": image_id,
                "User": "1000:1000",
                "Entrypoint": ["timeout"],
                "Cmd": [
                    "--signal=TERM", "--kill-after=5s", "1800s",
                    "/opt/venv/bin/python", "/opt/release_guest.py",
                ],
                "Env": ["PATH=/opt/venv/bin:/usr/bin:/bin"],
                "Labels": {
                    "org.docxplus.release.supervisor": "admission-owner",
                    "org.docxplus.release.inputs-sha256": "b" * 64,
                },
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges=true", "seccomp=unconfined"],
                "PidMode": "",
                "IpcMode": "private",
                "CgroupnsMode": "private",
                "UTSMode": "",
                "Memory": 8589934592,
                "MemorySwap": 8589934592,
                "NanoCpus": 4000000000,
                "PidsLimit": 512,
                "Tmpfs": {
                    "/tmp": "rw,nosuid,nodev,size=1073741824,mode=1777",
                    "/work": "rw,nosuid,nodev,size=4294967296,uid=1000,gid=1000,mode=0700",
                    "/cache": "rw,nosuid,nodev,size=2147483648,uid=1000,gid=1000,mode=0700",
                    "/outputs": "rw,nosuid,nodev,size=1073741824,uid=1000,gid=1000,mode=0700",
                    "/source/docxplus/output":
                        "rw,nosuid,nodev,size=2147483648,uid=1000,gid=1000,mode=0700",
                },
                "RestartPolicy": {"Name": "no"},
                "AutoRemove": False,
                "LogConfig": {"Type": "none"},
                "MaskedPaths": ["/proc/kcore", "/sys/firmware"],
                "ReadonlyPaths": ["/proc/sys", "/proc/sysrq-trigger"],
            },
            "Mounts": [],
        },
    }
    path = tmp_path / "admission.json"
    path.write_text(json.dumps(candidate))
    return release.load_json(path.read_bytes())


def _check_candidate(candidate, profile=None):
    return release.check_controls(
        candidate["inspected"], candidate["image_id"], candidate["image"],
        candidate["token"], candidate["input_hash"], procfs_profile=profile,
    )


def _unmasked_candidate(candidate):
    custody = candidate["custody"]
    profile = release.procfs_profile(custody, custody["daemon"]["ID"])
    host = candidate["inspected"]["HostConfig"]
    host["MaskedPaths"] = []
    host["ReadonlyPaths"] = []
    return profile


@pytest.mark.parametrize("requested_id", ["other-daemon", "", True])
def test_proc_kernel_exception_rejects_unbound_daemon(control_candidate, requested_id):
    """An explicit exception cannot authorize another daemon."""
    with pytest.raises(release.Refusal):
        release.procfs_profile(control_candidate["custody"], requested_id)


@pytest.mark.parametrize(("field", "value"), [
    ("OSType", "windows"),
    ("SecurityOptions", []),
    ("SecurityOptions", None),
    ("SecurityOptions", ["name=rootless-other"]),
    ("SecurityOptions", "name=rootless-other"),
    ("SecurityOptions", ["name=seccomp,profile=builtin"]),
])
def test_proc_kernel_exception_rejects_ineligible_daemon(control_candidate, field, value):
    """Knowing a daemon's ID does not authorize a non-Linux or rootful daemon."""
    custody = control_candidate["custody"]
    custody["daemon"][field] = value
    with pytest.raises(release.Refusal):
        release.procfs_profile(custody, custody["daemon"]["ID"])


@pytest.mark.parametrize("systempaths_option", [False, True])
def test_unapproved_proc_kernel_unmasking_is_refused(control_candidate, systempaths_option):
    """Neither empty API path lists nor a Docker option silently opts into the exception."""
    host = control_candidate["inspected"]["HostConfig"]
    host["MaskedPaths"] = []
    host["ReadonlyPaths"] = []
    if systempaths_option:
        host["SecurityOpt"].append("systempaths=unconfined")
    with pytest.raises(release.Refusal):
        _check_candidate(control_candidate)


@pytest.mark.parametrize("field", ["MaskedPaths", "ReadonlyPaths"])
@pytest.mark.parametrize("representation", ["missing", "still-masked", "invalid-empty"])
def test_admitted_unmasking_requires_actual_both_path_fields(
    control_candidate, field, representation,
):
    """A requested option alone cannot establish that both outer path protections changed."""
    profile = _unmasked_candidate(control_candidate)
    _check_candidate(control_candidate, profile)
    host = control_candidate["inspected"]["HostConfig"]
    if representation == "missing":
        del host[field]
    else:
        host[field] = ["/proc/sys"] if representation == "still-masked" else ""
    with pytest.raises(release.Refusal):
        _check_candidate(control_candidate, profile)


@pytest.mark.parametrize("options", [
    ["seccomp=unconfined"],
    ["no-new-privileges=true"],
    ["no-new-privileges=true", "seccomp=unconfined", "apparmor=unconfined"],
    ["no-new-privileges=true", "seccomp=unconfined", "systempaths=unconfined"],
])
def test_admitted_unmasking_does_not_authorize_other_security_policy_changes(
    control_candidate, options,
):
    """The scoped exception neither substitutes other security controls nor grants extras."""
    profile = _unmasked_candidate(control_candidate)
    _check_candidate(control_candidate, profile)
    control_candidate["inspected"]["HostConfig"]["SecurityOpt"] = options
    with pytest.raises(release.Refusal):
        _check_candidate(control_candidate, profile)


@pytest.mark.parametrize(("section", "field", "value"), [
    ("Config", "Image", "sha256:" + "c" * 64),
    ("Config", "User", "0:0"),
    ("Config", "Entrypoint", ["/bin/sh"]),
    ("Config", "Cmd", ["sleep", "infinity"]),
    ("Config", "Env", ["PATH=/opt/venv/bin:/usr/bin:/bin", "TOKEN=host-secret"]),
    ("Config", "Healthcheck", {"Test": ["CMD", "/bin/true"]}),
    ("Config", "Labels", {}),
    ("Config", "Volumes", {"/source/docxplus": {}}),
    ("HostConfig", "NetworkMode", "host"),
    ("HostConfig", "ReadonlyRootfs", False),
    ("HostConfig", "Privileged", True),
    ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
    ("HostConfig", "CapDrop", []),
    ("HostConfig", "PidMode", "host"),
    ("HostConfig", "IpcMode", "host"),
    ("HostConfig", "CgroupnsMode", "host"),
    ("HostConfig", "UTSMode", "host"),
    ("HostConfig", "Memory", 0),
    ("HostConfig", "MemorySwap", -1),
    ("HostConfig", "NanoCpus", 0),
    ("HostConfig", "PidsLimit", -1),
    ("HostConfig", "Tmpfs", {"/source/docxplus": "rw"}),
    ("HostConfig", "Binds", ["/host:/source/docxplus:rw"]),
    ("HostConfig", "Mounts", [{"Type": "bind", "Source": "/host", "Target": "/host"}]),
    ("HostConfig", "VolumesFrom", ["another-container"]),
    ("HostConfig", "Devices", [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm"}]),
    ("HostConfig", "DeviceRequests", [{"Capabilities": [["gpu"]]}]),
    ("HostConfig", "DeviceCgroupRules", ["a *:* rwm"]),
    ("HostConfig", "ExtraHosts", ["host:127.0.0.1"]),
    ("HostConfig", "Links", ["other:other"]),
    ("HostConfig", "PortBindings", {"8000/tcp": [{"HostPort": "8000"}]}),
    ("HostConfig", "PublishAllPorts", True),
    ("HostConfig", "Sysctls", {"kernel.hostname": "changed"}),
    ("HostConfig", "RestartPolicy", {"Name": "always"}),
    ("HostConfig", "AutoRemove", True),
    ("HostConfig", "Init", True),
    ("HostConfig", "LogConfig", {"Type": "json-file"}),
])
def test_admitted_proc_kernel_exception_preserves_other_guards(
    control_candidate, section, field, value,
):
    """Unmasking cannot admit privilege, host access, writable runtime or custody/resource drift."""
    profile = _unmasked_candidate(control_candidate)
    _check_candidate(control_candidate, profile)
    control_candidate["inspected"][section][field] = value
    with pytest.raises(release.Refusal):
        _check_candidate(control_candidate, profile)


def test_admitted_proc_kernel_exception_rejects_effective_host_mount(control_candidate):
    """An effective bind mount remains refused even if HostConfig hides its declaration."""
    profile = _unmasked_candidate(control_candidate)
    _check_candidate(control_candidate, profile)
    control_candidate["inspected"]["Mounts"] = [
        {"Type": "bind", "Source": "/host", "Destination": "/work"},
    ]
    with pytest.raises(release.Refusal):
        _check_candidate(control_candidate, profile)


def _refresh_release_source(subject, source):
    files, directories = subject.inventory(Path(source["root"]))
    source.update(files=files, dirs=directories, sha256=subject.digest(subject.canonical(files)))


@pytest.fixture
def versioned_release_sources(tmp_path):
    """Independent real supervisor/source copies; no Docker or execution stand-in."""
    original = Path(release.__file__).resolve().parents[1]
    deployment = tmp_path / "supervisor"
    for relative in ("scripts/validate_release.py", "src/docxplus/archive_limits.py"):
        target = deployment / relative
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        target.write_bytes((original / relative).read_bytes())
    script = deployment / "scripts/validate_release.py"
    spec = importlib.util.spec_from_file_location("private_release_supervisor", script)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    metadata = {
        "pyproject.toml": '[project]\nname = "docxplus"\nversion = "4.5.6"\n',
        "uv.lock": '[[package]]\nname = "docxplus"\nversion = "4.5.6"\n',
        "src/docxplus/__init__.py": '__version__ = "4.5.6"\n',
        "CITATION.cff": 'cff-version: 1.2.0\nversion: "4.5.6"\n',
        "codemeta.json": '{"version": "4.5.6"}\n',
        ".zenodo.json": '{"version": "4.5.6"}\n',
        ".agents/skills/docxplus/SKILL.md": "---\nname: docxplus\nversion: 4.5.6\n---\nPointer.\n",
    }
    sources = {}
    for name in sorted(subject.SOURCE_NAMES):
        root = tmp_path / "sources" / name
        root.mkdir(parents=True, mode=0o700)
        contents = metadata if name == "docxplus" else {"README.md": "Independent test input.\n"}
        for relative, text in contents.items():
            target = root / relative
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            target.write_text(text)
        source = {"root": str(root), "identity": name, "dirty": False}
        _refresh_release_source(subject, source)
        sources[name] = source
    return subject, {"schema": subject.INPUT_SCHEMA, "sources": sources}


@pytest.mark.parametrize("relative", [
    "uv.lock", "src/docxplus/__init__.py", "CITATION.cff", "codemeta.json", ".zenodo.json",
    ".agents/skills/docxplus/SKILL.md",
])
def test_release_metadata_conflict_refuses_even_with_valid_inventory(versioned_release_sources, relative):
    """A perfectly hash-bound snapshot must not release conflicting software identities."""
    subject, manifest = versioned_release_sources
    subject.verify_inputs(manifest)
    source = manifest["sources"]["docxplus"]
    target = Path(source["root"]) / relative
    target.write_text(target.read_text().replace("4.5.6", "4.5.5"))
    _refresh_release_source(subject, source)
    with pytest.raises(subject.Refusal):
        subject.verify_inputs(manifest)


def test_release_metadata_duplicate_citation_version_refuses(versioned_release_sources):
    """The preflight must not choose one of two conflicting citation identities."""
    subject, manifest = versioned_release_sources
    subject.verify_inputs(manifest)
    source = manifest["sources"]["docxplus"]
    target = Path(source["root"]) / "CITATION.cff"
    target.write_text(target.read_text() + 'version: "4.5.5"\n')
    _refresh_release_source(subject, source)
    with pytest.raises(subject.Refusal):
        subject.verify_inputs(manifest)


def test_release_metadata_inspection_executes_no_package_code(versioned_release_sources, tmp_path):
    """Version inspection must parse source, not execute a snapshot on the host."""
    subject, manifest = versioned_release_sources
    source = manifest["sources"]["docxplus"]
    canary = tmp_path / "package-code-executed"
    target = Path(source["root"]) / "src/docxplus/__init__.py"
    target.write_text(target.read_text() + f"open({str(canary)!r}, 'w').write('executed')\n")
    _refresh_release_source(subject, source)
    subject.verify_inputs(manifest)
    assert not canary.exists()


def test_release_metadata_cli_refuses_before_creating_provision_output(
    versioned_release_sources, tmp_path,
):
    """Conflicting identities refuse at the real CLI before any provisioning side effect."""
    subject, manifest = versioned_release_sources
    subject.verify_inputs(manifest)
    source = manifest["sources"]["docxplus"]
    target = Path(source["root"]) / "codemeta.json"
    target.write_text('{"version": "4.5.5"}\n')
    _refresh_release_source(subject, source)
    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps(manifest))
    output = tmp_path / "refused-provision"
    result = subprocess.run(
        [sys.executable, subject.__file__, "provision", "--inputs", str(inputs),
         "--output", str(output), "--docker-context", "release-metadata-do-not-contact"],
        check=False, stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
    )
    assert result.returncode != 0
    assert not output.exists()


def test_release_metadata_crlf_preserves_conflict_detection(versioned_release_sources):
    """CRLF is not malformed metadata; a conflicting version must still refuse."""
    subject, manifest = versioned_release_sources
    source = manifest["sources"]["docxplus"]
    for relative in source["files"]:
        target = Path(source["root"]) / relative
        target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))
    _refresh_release_source(subject, source)
    subject.verify_inputs(manifest)
    target = Path(source["root"]) / "codemeta.json"
    target.write_bytes(target.read_bytes().replace(b"4.5.6", b"4.5.5"))
    _refresh_release_source(subject, source)
    with pytest.raises(subject.Refusal):
        subject.verify_inputs(manifest)

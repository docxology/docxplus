"""Typed payload registry.

A payload is not an opaque blob — it has a *type* that knows how to pack an object
into bytes and unpack it back. This is the modularity backbone: new payload kinds
plug in without touching channels, crypto, or the container.

Built-in types:

* ``bytes``    — identity.
* ``text``     — UTF-8 string.
* ``json``     — any JSON-serialisable object (canonical, sorted keys).
* ``project``  — an entire directory tree packed to a *deterministic* tar.gz
                 (the flagship: a document can carry the reproducible project that
                 produced it). Excludes junk (.venv, output, __pycache__, .git).
* ``docxplus`` — a nested docxplus container (identity bytes, typed so readers know to
                 recurse). Enables matryoshka documents.

The payload *type id* is recorded in the manifest so extraction reconstructs the
right object.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import stat
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .archive_limits import ArchiveLimitError, bounded_tar, validate_plain_tar

# Directories never packed into a `project` payload, split by where the name is
# actually junk.
#
# Matching a bare name at *any* depth silently deletes real source: a tree with
# `src/output/model.py` or `docs/venv/notes.md` lost those files entirely, because
# "output" and "venv" are ordinary words that mean "build artefact" only at the root
# of a project. Tool caches, by contrast, are junk wherever they appear.
_ROOT_ONLY_EXCLUDE = {".venv", "venv", "output", "htmlcov", "node_modules", "dist", "build"}
_ANY_DEPTH_EXCLUDE = {"__pycache__", ".git", ".pytest_cache", ".ruff_cache", ".mypy_cache"}

#: Kept for callers and reports that want the full set as one name.
_PROJECT_EXCLUDE = _ROOT_ONLY_EXCLUDE | _ANY_DEPTH_EXCLUDE
_FIXED_MTIME = 315532800  # 1980-01-01, for reproducible archives.


class PayloadType:
    """One registered payload type."""

    def __init__(
        self,
        type_id: str,
        mimetype: str,
        pack: Callable[[Any], bytes],
        unpack: Callable[[bytes], Any],
    ) -> None:
        self.id = type_id
        self.mimetype = mimetype
        self.pack = pack
        self.unpack = unpack


# -- codecs ----------------------------------------------------------------
def _pack_bytes(obj: Any) -> bytes:
    if not isinstance(obj, (bytes, bytearray)):
        raise TypeError("bytes payload requires bytes")
    return bytes(obj)


def _pack_text(obj: Any) -> bytes:
    return str(obj).encode("utf-8")


def _pack_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Refuse to inflate a project payload past this many bytes
#: (decompression-bomb cap). Shared by ``pack_project`` (authoring-time refusal)
#: and ``unpack_project`` (untrusted-input guard), so the two sides of the
#: contract cannot disagree about the budget.
MAX_PROJECT_UNCOMPRESSED = 512 * 1024 * 1024  # 512 MiB
MAX_PROJECT_COMPRESSED = 256 * 1024 * 1024
MAX_PROJECT_MEMBERS = 20_000
MAX_PROJECT_METADATA = 16 * 1024 * 1024
MAX_PROJECT_PAX = 64 * 1024
MAX_PROJECT_DEPTH = 128
_COPY_CHUNK = 64 * 1024


class ProjectPackError(ValueError):
    """The tree cannot be packed faithfully or safely as it stands."""


def pack_project(
    root: Path,
    *,
    follow_symlinks: bool = False,
    max_uncompressed: int = MAX_PROJECT_UNCOMPRESSED,
    max_members: int = MAX_PROJECT_MEMBERS,
    max_metadata: int = MAX_PROJECT_METADATA,
    max_compressed: int = MAX_PROJECT_COMPRESSED,
) -> bytes:
    """Pack a directory tree into a deterministic tar.gz (sorted, fixed mtime).

    What is preserved, exactly — the manuscript claims a document can carry the
    software that produced it, so the boundary has to be stated rather than assumed:

    * file contents, byte for byte;
    * the **executable bit**, clamped to 0o755 or 0o644 and nothing else, because a
      carried ``run.sh`` that comes back non-executable is not the software that
      produced anything;
    * **empty directories**, which some build systems require and which a
      files-only walk silently drops;
    * relative directory structure.

    What is deliberately normalised: mtimes (to a fixed epoch), uid/gid/uname/gname
    (to zero and empty), and every mode bit other than execute. Determinism is worth
    more here than ownership metadata, and arbitrary modes are an unpack hazard.

    **Symlinks are refused by default.** ``Path.is_file()`` follows links, so the
    previous behaviour was to silently embed the *target's* content under the link's
    name: a tree containing ``creds -> ~/.ssh/id_rsa`` shipped that key inside the
    document, with nothing in the manifest or the package suggesting it had. The
    unpack side has always rejected link members; the pack side was the open door.
    Passing ``follow_symlinks=True`` restores dereferencing, but the caller has then
    said so explicitly and the choice is visible in review.

    **The decompression cap applies on the way in too.** ``unpack_project`` refuses
    to inflate more than ``max_uncompressed`` bytes, and it must: the archive is
    untrusted input there. But a cap that only fires on extraction leaves the
    failure far from its cause — a tree over the limit sealed cleanly into a
    signed, validated, perfectly shipped document whose payload could never be
    extracted. The same accounting therefore runs here against the inflated size
    actually measured (the sum of member sizes after exclusions and symlink policy),
    so an oversized tree is refused at authoring time with names, not at read time
    on someone else's machine. Raising the cap for one call is a deliberate act:
    pass ``max_uncompressed=...`` explicitly and let review see it.

    Capture pins each opened source inode and bounds its reads, but it is not a
    global filesystem snapshot: concurrent edits between different files may
    appear together. Use a quiescent source tree when cross-file consistency matters.
    """
    try:
        _check_project_limits(max_uncompressed, max_members, max_metadata, max_compressed)
    except ValueError as exc:
        raise ProjectPackError(str(exc)) from exc
    root = Path(root)
    flags = _directory_flags()
    root_fd = os.open(root, flags & ~os.O_NOFOLLOW) if follow_symlinks else _open_directory(root)
    total = 0
    visited = 0
    ancestors: set[tuple[int, int]] = set()

    def capture(directory: int, relative: Path, tar: tarfile.TarFile) -> None:
        nonlocal total, visited
        if len(relative.parts) > MAX_PROJECT_DEPTH:
            raise ProjectPackError("project path depth exceeds limit")
        identity = os.fstat(directory)
        key = (identity.st_dev, identity.st_ino)
        if key in ancestors:
            raise ProjectPackError(f"directory cycle in project: {relative}")
        ancestors.add(key)
        try:
            names = []
            physically_empty = True
            with os.scandir(directory) as scan:
                for entry in scan:
                    physically_empty = False
                    rel = relative / entry.name
                    if _excluded(rel):
                        continue
                    visited += 1
                    if visited > max_members:
                        raise ProjectPackError("project member count exceeds limit")
                    names.append(entry.name)
            if relative.parts and physically_empty:
                info = _project_info(relative)
                info.type = tarfile.DIRTYPE
                info.mode = _DIR_MODE
                tar.addfile(info)
            for name in sorted(names):
                rel = relative / name
                before = os.stat(name, dir_fd=directory, follow_symlinks=follow_symlinks)
                if stat.S_ISLNK(before.st_mode):
                    raise ProjectPackError(
                        f"refusing to pack symlinks: {rel}. "
                        "Pass follow_symlinks=True to dereference them deliberately."
                    )
                if not (stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode)):
                    continue
                open_flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                if not follow_symlinks:
                    open_flags |= getattr(os, "O_NOFOLLOW", 0)
                if stat.S_ISDIR(before.st_mode):
                    open_flags |= os.O_DIRECTORY
                try:
                    descriptor = os.open(name, open_flags, dir_fd=directory)
                except OSError as exc:
                    raise ProjectPackError(f"project source changed while opening {rel}") from exc
                try:
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode)) != (
                        before.st_dev,
                        before.st_ino,
                        stat.S_IFMT(before.st_mode),
                    ):
                        raise ProjectPackError(f"project source changed while opening {rel}")
                    if stat.S_ISDIR(opened.st_mode):
                        capture(descriptor, rel, tar)
                        continue
                    if opened.st_size > max_uncompressed - total:
                        raise ProjectPackError(
                            f"project tree is over the {max_uncompressed}-byte decompression cap "
                            f"(offending member: {rel})"
                        )
                    with tempfile.SpooledTemporaryFile(max_size=_COPY_CHUNK) as source:
                        size = 0
                        while True:
                            chunk = os.read(
                                descriptor, min(_COPY_CHUNK, max_uncompressed - total - size + 1)
                            )
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > max_uncompressed - total:
                                raise ProjectPackError(
                                    "project source exceeds decompression cap while reading"
                                )
                            source.write(chunk)
                        after = os.fstat(descriptor)
                        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                            opened.st_size,
                            opened.st_mtime_ns,
                            opened.st_ctime_ns,
                        ) or size != opened.st_size:
                            raise ProjectPackError(f"project source changed while reading {rel}")
                        total += size
                        info = _project_info(rel)
                        info.size = size
                        info.mode = (
                            _FILE_MODE_EXEC if opened.st_mode & stat.S_IXUSR else _FILE_MODE_PLAIN
                        )
                        source.seek(0)
                        tar.addfile(info, source)
                finally:
                    os.close(descriptor)
        finally:
            ancestors.remove(key)

    try:
        with tempfile.TemporaryFile() as raw:
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
                capture(root_fd, Path(), tar)
            try:
                validate_plain_tar(
                    raw,
                    max_data_bytes=max_uncompressed,
                    max_members=max_members,
                    max_metadata_bytes=max_metadata,
                )
            except ArchiveLimitError as exc:
                raise ProjectPackError(str(exc)) from exc
            out = io.BytesIO()
            with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=9, mtime=0) as gz:
                while chunk := raw.read(_COPY_CHUNK):
                    gz.write(chunk)
                    if out.tell() > max_compressed:
                        raise ProjectPackError("compressed project exceeds limit")
            if out.tell() > max_compressed:
                raise ProjectPackError("compressed project exceeds limit")
            return out.getvalue()
    finally:
        os.close(root_fd)


#: Modes a carried file may end up with. `pack_project` already clamps to these on
#: the way in; unpacking clamps again because the archive is untrusted on the way out.
_FILE_MODE_EXEC = 0o755
_FILE_MODE_PLAIN = 0o644
_DIR_MODE = 0o755


def unpack_project(
    blob: bytes,
    dest: Path,
    *,
    max_uncompressed: int = MAX_PROJECT_UNCOMPRESSED,
    max_members: int = MAX_PROJECT_MEMBERS,
    max_metadata: int = MAX_PROJECT_METADATA,
    max_compressed: int = MAX_PROJECT_COMPRESSED,
) -> Path:
    """Validate a bounded project and publish a fresh private tree.

    Existing nonempty destinations and destination symlinks refuse. No existing
    file is merged, truncated, chmodded or followed. The root remains 0700; carried
    executable bits and empty directories are preserved inside it.
    """
    _check_project_limits(max_uncompressed, max_members, max_metadata, max_compressed)
    requested_dest = Path(dest)
    if len(blob) > max_compressed:
        raise ValueError("compressed project exceeds limit")
    with (
        io.BytesIO(blob) as encoded,
        bounded_tar(
            encoded,
            max_data_bytes=max_uncompressed,
            max_members=max_members,
            max_metadata_bytes=max_metadata,
            max_encoded_bytes=max_compressed,
        ) as raw,
        tarfile.open(fileobj=raw, mode="r:") as tar,
    ):
        members = []
        kinds: dict[tuple[str, ...], bool] = {}
        nodes: set[tuple[str, ...]] = set()
        total = 0
        for member in tar:
            if len(members) >= max_members:
                raise ValueError("project member count exceeds limit")
            if not (member.isfile() or member.isdir()) or member.sparse is not None:
                raise ValueError(
                    f"only plain files and directories may be carried; "
                    f"{member.name!r} is a {_member_kind(member)}"
                )
            if member.isdir() and member.size:
                raise ValueError("project directory carries unexpected content")
            name = member.name.rstrip("/") if member.isdir() else member.name
            if member.isdir() and name in ("", "."):
                continue  # Root metadata never controls the private staging root.
            parts = _project_parts(name)
            if parts in kinds:
                raise ValueError(f"duplicate path in project payload: {member.name}")
            for count in range(1, len(parts)):
                if kinds.get(parts[:count]) is False:
                    raise ValueError(f"file/directory conflict in project payload: {member.name}")
                nodes.add(parts[:count])
            if member.isfile() and parts in nodes:
                raise ValueError(f"file/directory conflict in project payload: {member.name}")
            nodes.add(parts)
            if len(nodes) > max_members:
                raise ValueError("project filesystem node count exceeds limit")
            kinds[parts] = member.isdir()
            total += member.size
            if member.size < 0 or total > max_uncompressed:
                raise ValueError("project payload exceeds decompression cap (possible bomb)")
            members.append((member, parts))

        dest = requested_dest.absolute()
        parent = _open_directory(dest.parent, create=True)
        staging: str | None = None
        tree = -1
        try:
            _empty_destination(parent, dest.name)
            # The staging root has an unpredictable name and is private from
            # creation. Every member operation is relative to owned descriptors.
            for _ in range(100):
                name = f".{dest.name}.{os.urandom(12).hex()}"
                try:
                    os.mkdir(name, 0o700, dir_fd=parent)
                except FileExistsError:
                    continue
                staging = name
                break
            if staging is None:
                raise FileExistsError("cannot create private project staging tree")
            tree = os.open(
                staging, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent
            )
            for member, parts in members:
                directory = os.dup(tree)
                try:
                    for part in parts[:-1] if member.isfile() else parts:
                        try:
                            os.mkdir(part, _DIR_MODE, dir_fd=directory)
                        except FileExistsError:
                            pass
                        child = os.open(
                            part,
                            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=directory,
                        )
                        os.close(directory)
                        directory = child
                        os.fchmod(directory, _DIR_MODE)
                    if member.isdir():
                        continue
                    descriptor = os.open(
                        parts[-1],
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=directory,
                    )
                    with os.fdopen(descriptor, "wb") as target:
                        source = tar.extractfile(member)
                        if source is None:
                            raise ValueError(f"unreadable member: {member.name}")
                        with source:
                            remaining = member.size
                            while remaining:
                                chunk = source.read(min(_COPY_CHUNK, remaining))
                                if not chunk:
                                    raise ValueError(f"truncated member: {member.name}")
                                target.write(chunk)
                                remaining -= len(chunk)
                        os.fchmod(
                            target.fileno(),
                            _FILE_MODE_EXEC if member.mode & 0o100 else _FILE_MODE_PLAIN,
                        )
                finally:
                    os.close(directory)
            _empty_destination(parent, dest.name)
            # POSIX rename refuses a nonempty directory even if it races this
            # last check. A symlink can only be replaced, never traversed.
            os.rename(staging, dest.name, src_dir_fd=parent, dst_dir_fd=parent)
            staging = None
        finally:
            if tree >= 0:
                os.close(tree)
            try:
                if staging is not None:
                    _remove_tree(parent, staging)
            finally:
                os.close(parent)
    return requested_dest


def _remove_tree(parent: int, name: str) -> None:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent
    )
    try:
        with os.scandir(descriptor) as scan:
            for entry in scan:
                if entry.is_dir(follow_symlinks=False):
                    _remove_tree(descriptor, entry.name)
                else:
                    os.unlink(entry.name, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent)


def _check_project_limits(*limits: int) -> None:
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in limits):
        raise ValueError("project limits must be nonnegative integers")


def _directory_flags() -> int:
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
    ):
        raise NotImplementedError(
            "safe project I/O requires descriptor-relative no-follow directory support"
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_directory(path: Path, *, create: bool = False) -> int:
    """Open/create ancestors relative to retained descriptors, never symlinks."""
    flags = _directory_flags()
    descriptor = os.open(path.anchor or ".", flags)
    try:
        for part in path.parts[1:] if path.is_absolute() else path.parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _empty_destination(parent: int, name: str) -> None:
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode):
        raise FileExistsError("project destination must be absent or an empty directory")
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent
    )
    try:
        with os.scandir(descriptor) as entries:
            if next(entries, None) is not None:
                raise FileExistsError("refusing nonempty project destination")
    finally:
        os.close(descriptor)


def _project_info(relative: Path) -> tarfile.TarInfo:
    try:
        _project_parts(relative.as_posix())
    except ValueError as exc:
        raise ProjectPackError(str(exc)) from exc
    info = tarfile.TarInfo(relative.as_posix())
    info.mtime = _FIXED_MTIME
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def _project_parts(name: str) -> tuple[str, ...]:
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or (len(name) >= 2 and name[0].isascii() and name[0].isalpha() and name[1] == ":")
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ValueError(f"unsafe path in project payload: {name!r}")
    parts = tuple(name.split("/"))
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"unsafe path in project payload: {name!r}")
    if len(parts) > MAX_PROJECT_DEPTH:
        raise ValueError("project path depth exceeds limit")
    return parts


def _member_kind(member: tarfile.TarInfo) -> str:
    for predicate, label in (
        (member.issym, "symlink"),
        (member.islnk, "hard link"),
        (member.ischr, "character device"),
        (member.isblk, "block device"),
        (member.isfifo, "FIFO"),
    ):
        if predicate():
            return label
    return "special file"


def _excluded(rel: Path) -> bool:
    """True when ``rel`` sits inside a directory this format refuses to carry.

    Root-only names are matched against the first component alone, so a legitimate
    ``src/output/`` or ``docs/venv/`` is carried rather than deleted. Cache names are
    matched at any depth, because a ``__pycache__`` is never source no matter where
    it sits.
    """
    parts = rel.parts
    if not parts:
        return False
    return parts[0] in _ROOT_ONLY_EXCLUDE or any(p in _ANY_DEPTH_EXCLUDE for p in parts)


_REGISTRY: dict[str, PayloadType] = {
    "bytes": PayloadType("bytes", "application/octet-stream", _pack_bytes, bytes),
    "text": PayloadType(
        "text", "text/plain; charset=utf-8", _pack_text, lambda b: b.decode("utf-8")
    ),
    "json": PayloadType("json", "application/json", _pack_json, lambda b: json.loads(b)),
    # project/docxplus pack to bytes here; unpack (to a directory / nested reader)
    # is driven by the container, which owns the destination.
    "project": PayloadType("project", "application/x-docxplus-project+tar.gz", lambda o: o, bytes),
    "docxplus": PayloadType("docxplus", "application/vnd.docxplus.document", _pack_bytes, bytes),
}


def get_type(type_id: str) -> PayloadType:
    try:
        return _REGISTRY[type_id]
    except KeyError as exc:
        raise ValueError(f"unknown payload type: {type_id}") from exc


def register_type(payload_type: PayloadType) -> None:
    """Register a custom payload type (modularity hook)."""
    _REGISTRY[payload_type.id] = payload_type


def available_types() -> list[str]:
    return sorted(_REGISTRY)


__all__ = [
    "MAX_PROJECT_COMPRESSED",
    "MAX_PROJECT_DEPTH",
    "MAX_PROJECT_MEMBERS",
    "MAX_PROJECT_METADATA",
    "MAX_PROJECT_PAX",
    "MAX_PROJECT_UNCOMPRESSED",
    "PayloadType",
    "ProjectPackError",
    "available_types",
    "get_type",
    "pack_project",
    "register_type",
    "unpack_project",
]

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
import os
import json
import shutil
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

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


#: Refuse to inflate a project payload past this many bytes (decompression-bomb cap).
MAX_PROJECT_UNCOMPRESSED = 512 * 1024 * 1024  # 512 MiB


class ProjectPackError(ValueError):
    """The tree cannot be packed faithfully or safely as it stands."""


def pack_project(
    root: Path,
    *,
    follow_symlinks: bool = False,
    max_uncompressed: int = MAX_PROJECT_UNCOMPRESSED,
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
    """
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    entries = sorted(p for p in root.rglob("*") if not _excluded(p.relative_to(root)))

    if not follow_symlinks:
        links = [str(p.relative_to(root)) for p in entries if p.is_symlink()]
        if links:
            raise ProjectPackError(
                "refusing to pack symlinks (their targets would be embedded as "
                f"ordinary files, exfiltrating whatever they point at): {', '.join(links)}. "
                "Pass follow_symlinks=True to dereference them deliberately."
            )

    # Build the tar uncompressed, then gzip it with an explicit mtime.
    #
    # `tarfile.open(mode="w:gz")` gives no way to pin the gzip header's timestamp:
    # the previous `tar.gzip_mtime = 0` assigned an attribute TarFile does not have,
    # so it was a silent no-op and the header carried wall-clock time. Two packs of
    # the same tree one second apart therefore produced different bytes — and so
    # different module digests — while the docstring promised determinism. The
    # `# type: ignore[attr-defined]` sat on the exact line where the intent failed.
    raw = io.BytesIO()
    total_uncompressed = 0
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in entries:
            arcname = str(path.relative_to(root))
            info = tarfile.TarInfo(arcname)
            info.mtime = _FIXED_MTIME
            info.uid = info.gid = 0
            info.uname = info.gname = ""

            if path.is_dir():
                # Only directories that would otherwise vanish need an entry; tar
                # recreates the rest implicitly from the file paths.
                if any(path.iterdir()):
                    continue
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                tar.addfile(info)
                continue
            if not path.is_file():
                continue  # sockets, fifos, devices: not source code

            data = path.read_bytes()
            total_uncompressed += len(data)
            if total_uncompressed > max_uncompressed:
                raise ProjectPackError(
                    f"project total uncompressed size exceeds limit of {max_uncompressed} bytes"
                )
            info.size = len(data)
            info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
            tar.addfile(info, io.BytesIO(data))

    out = io.BytesIO()
    # mtime=0 and no embedded filename: the wrapper must add nothing time- or
    # host-dependent to the payload the manifest digests.
    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


#: Modes a carried file may end up with. `pack_project` already clamps to these on
#: the way in; unpacking clamps again because the archive is untrusted on the way out.
_FILE_MODE_EXEC = 0o755
_FILE_MODE_PLAIN = 0o644
_DIR_MODE = 0o755


def unpack_project(blob: bytes, dest: Path, *, max_uncompressed: int = MAX_PROJECT_UNCOMPRESSED) -> Path:
    """Extract a ``project`` payload into ``dest`` (created if needed).

    Untrusted-input hardening (standards-report §14.3): a decompression-bomb cap on
    total inflated size, a path-traversal guard, refusal of every member that is not
    a plain file or directory, and permission bits clamped rather than honoured.

    **Nothing here depends on the interpreter version.** It used to: extraction was
    ``tar.extractall(dest, filter="data")`` with a ``TypeError`` fallback to a bare
    ``tar.extractall(dest)`` for Python below 3.12, where the filter argument does not
    exist. Since ``requires-python`` is ``>=3.10``, that fallback was reachable in
    supported configurations, and it is unfiltered: a payload carrying ``run.sh`` at
    mode ``04755`` extracted *with the setuid bit intact*, and a FIFO or device node
    was created as given. The manual pre-check loop refused neither — it tested only
    for links and traversal — so on 3.10 and 3.11 the sole thing standing between a
    hostile document and a setuid binary was a feature of the interpreter.

    Members are therefore written out here rather than handed to ``extractall``, which
    also retires an untested branch that existed solely to be a fallback.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        members = tar.getmembers()
        total = 0
        for member in members:
            total += max(0, member.size)
            if total > max_uncompressed:
                raise ValueError("project payload exceeds decompression cap (possible bomb)")
            # One positive check rather than a list of member types to reject: a new
            # tar member type would otherwise be admitted by default.
            if not (member.isfile() or member.isdir()):
                raise ValueError(
                    f"only plain files and directories may be carried; {member.name!r} "
                    f"is a {_member_kind(member)}"
                )
            target = (dest / member.name).resolve()
            if target != dest_root and not target.is_relative_to(dest_root):
                raise ValueError(f"unsafe path in project payload: {member.name}")

        for member in members:
            target = dest / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(_DIR_MODE)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:  # pragma: no cover - isfile() already guaranteed this
                raise ValueError(f"unreadable member in project payload: {member.name}")
            with source, open(target, "wb") as handle:
                shutil.copyfileobj(source, handle)
            # The executable bit is the one permission the format promises to carry;
            # every other bit, setuid and setgid above all, is discarded.
            target.chmod(_FILE_MODE_EXEC if member.mode & 0o100 else _FILE_MODE_PLAIN)
    return dest


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
    "text": PayloadType("text", "text/plain; charset=utf-8", _pack_text, lambda b: b.decode("utf-8")),
    "json": PayloadType("json", "application/json", _pack_json, lambda b: json.loads(b)),
    # project/docxplus pack to bytes here; unpack (to a directory / nested reader)
    # is driven by the container, which owns the destination.
    "project": PayloadType("project", "application/x-docxplus-project+tar.gz", lambda o: o, bytes),
    "docxplus": PayloadType(
        "docxplus", "application/vnd.docxplus.document", _pack_bytes, bytes
    ),
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

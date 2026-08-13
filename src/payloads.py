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
* ``docxplus`` — a nested DOCX+ container (identity bytes, typed so readers know to
                 recurse). Enables matryoshka documents.

The payload *type id* is recorded in the manifest so extraction reconstructs the
right object.
"""

from __future__ import annotations

import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Directories/globs never packed into a `project` payload.
_PROJECT_EXCLUDE = {
    ".venv", "venv", "output", "__pycache__", ".git", ".pytest_cache",
    ".ruff_cache", ".mypy_cache", "htmlcov", "node_modules",
}
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


def pack_project(root: Path) -> bytes:
    """Pack a directory tree into a deterministic tar.gz (sorted, fixed mtime)."""
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    files = sorted(
        p for p in root.rglob("*")
        if p.is_file() and not _excluded(p.relative_to(root))
    )
    raw = io.BytesIO()
    # mtime=0 on the gzip wrapper for reproducibility.
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT, compresslevel=9) as tar:
        tar.gzip_mtime = 0  # type: ignore[attr-defined]
        for path in files:
            arcname = str(path.relative_to(root))
            info = tarfile.TarInfo(arcname)
            data = path.read_bytes()
            info.size = len(data)
            info.mtime = _FIXED_MTIME
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def unpack_project(blob: bytes, dest: Path) -> Path:
    """Extract a ``project`` payload into ``dest`` (created if needed)."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            # Zip-Slip / path-traversal guard (standards-report §14.3).
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError(f"unsafe path in project payload: {member.name}")
        tar.extractall(dest)
    return dest


def _excluded(rel: Path) -> bool:
    return any(part in _PROJECT_EXCLUDE for part in rel.parts)


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

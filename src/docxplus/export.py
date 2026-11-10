"""Inert, bounded payload export with private atomic no-replace publication."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path

from .crypto import digest as _share_digest
from .inspection import inspect_document
from .payloads import _directory_flags, _open_directory, _remove_tree

MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_EXPORT_MODULES = 1024


def _rename_noreplace(
    source_parent: int, source: str, destination_parent: int, destination: str,
) -> None:
    """Move between pinned directories atomically, never replacing any entry."""
    native, flag = _publication_primitive()
    if native(source_parent, os.fsencode(source), destination_parent,
              os.fsencode(destination), flag) != 0:
        code = ctypes.get_errno()
        if code in (errno.ENOSYS, errno.ENOTSUP, errno.EINVAL):
            raise NotImplementedError("atomic no-replace publication is unavailable")
        raise OSError(code, os.strerror(code))


def _publication_primitive():
    """Require the actual platform no-replace syscall, not a check/rename pair."""
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        name, flag = "renameat2", 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        name, flag = "renameatx_np", 0x00000004  # RENAME_EXCL
    else:
        raise NotImplementedError("atomic no-replace publication requires Linux or Darwin")
    try:
        native = getattr(library, name)
    except AttributeError:
        raise NotImplementedError("atomic no-replace publication is unavailable") from None
    native.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    native.restype = ctypes.c_int
    return native, flag


def _index_bytes(index: dict) -> bytes:
    return (json.dumps(index, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _write_private(directory: int, name: str, data: bytes) -> None:
    """Write recovered plaintext with the same private-mode rule as secure_io.

    The pinned stage descriptor additionally prevents path-ancestor substitution.
    """
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            target.write(data)
    finally:
        os.close(descriptor)


def export_modules(
    data: bytes,
    destination: str | Path,
    *,
    slots: Sequence[str] | None = None,
    password: str | None = None,
    private_key: bytes | None = None,
    shares: list[bytes] | None = None,
    expected_public_key: bytes | None = None,
    require_cosigners: Sequence[bytes] = (),
    max_bytes: int = MAX_EXPORT_BYTES,
    max_modules: int = MAX_EXPORT_MODULES,
) -> dict:
    """Export exact packed plaintext to inert ordinal ``.bin`` files and an index.

    Intelligence declarations and the requested trust policy must pass inspection.
    Decryption alone never authenticates; the index preserves inspection's trust
    result. No typed codecs, project unpackers, nested readers, or recipes run.
    ``max_bytes`` bounds payload plus serialized index output, not whole-process
    memory: inspection and extraction may allocate more than this output bound.
    The destination must be absent, including no dangling symlink or empty folder.
    Publication uses a genuine native atomic no-replace operation, or refuses.
    The parent must be caller-owned and not group/other-writable; its ACL and
    same-UID actors remain trusted. Plaintext cleanup uses a private holder FD.
    Created parents may remain; filesystem cleanup failures can retain a private
    stage. Atomic publication does not imply crash durability.
    """
    if any(
        isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0
        for limit in (max_bytes, max_modules)
    ):
        raise ValueError("export limits must be positive integers")
    inspected = inspect_document(
        data, expected_public_key=expected_public_key, require_cosigners=require_cosigners
    )
    if (
        not inspected.ok
        or not inspected.manifest_present
        or inspected.reader is None
        or inspected.report["intelligence"]["declaration_valid"] is not True
    ):
        raise ValueError("export requires valid intelligence and the requested trust policy")
    records = {record.slot: record for record in inspected.reader.manifest.records}
    if slots is None:
        selected = sorted(records)
    else:
        if isinstance(slots, (str, bytes)):
            raise ValueError("slots must be a sequence of unique slot strings")
        requested = list(slots)
        if not requested or any(not isinstance(slot, str) for slot in requested):
            raise ValueError("selection must contain slot strings")
        if len(set(requested)) != len(requested):
            raise ValueError("duplicate export slots")
        if any(slot not in records for slot in requested):
            raise ValueError("requested export slot is absent")
        selected = sorted(requested)
    if len(selected) > max_modules:
        raise ValueError("export module count exceeds limit")

    # A CLI bundle may contain independent share sets for several modules. Match
    # complete committed share bytes, without discarding unknown supplied shares.
    share_owners: dict[str, list[str]] = {}
    for slot, record in records.items():
        if record.sealing['mode'] == 'threshold':
            for commitment in record.sealing['share_digests']:
                share_owners.setdefault(commitment, []).append(slot)
    shares_by_slot: dict[str, list[bytes]] = {}
    for share in shares or ():
        if not isinstance(share, bytes):
            raise TypeError('threshold shares must be complete share bytes')
        owners = share_owners.get(_share_digest(share))
        if not owners:
            raise ValueError('threshold share is not committed by this document')
        for slot in owners:
            shares_by_slot.setdefault(slot, []).append(share)

    index = {
        "schema": "docxplus.payload-export-index.v1",
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "profile": inspected.profile,
        "signature": inspected.report["signature"],
        "modules": [],
    }
    # Declared sizes bind STORED bytes. Only plain records declare plaintext size;
    # encrypted/padded records have no declared plaintext lower bound. Never use
    # their envelope sizes to reject a small legitimate decrypted export.
    declared_bytes = 0
    for ordinal, slot in enumerate(selected, 1):
        record = records[slot]
        size = record.size if record.sealing["mode"] == "plain" else 0
        declared_bytes += size
        index["modules"].append({
            "slot": slot,
            "file": f"module-{ordinal:06d}.bin",
            "payload_type": record.payload_type,
            "content_type": record.content_type,
            "bytes": size,
            "sha256": "0" * 64,
        })
    index_size = len(_index_bytes(index))
    if declared_bytes + index_size > max_bytes:
        raise ValueError("export payload and index bytes exceed limit")

    dest = Path(destination)
    if not dest.name or dest.name in (".", ".."):
        raise ValueError("export destination must name an absent directory")
    _directory_flags()
    _publication_primitive()
    parent = _open_directory(dest.parent, create=True)
    stage = None
    holder = -1
    tree_created = False
    published = False
    tree = -1
    try:
        parent_info = os.fstat(parent)
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise PermissionError(
                'export parent must be owned by this user and not group/other-writable'
            )
        try:
            os.stat(dest.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("export destination must be absent")
        while stage is None:
            candidate = ".docxplus-export-" + secrets.token_hex(16)
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent)
            except FileExistsError:
                continue
            stage = candidate
        holder = os.open(stage, _directory_flags(), dir_fd=parent)
        os.fchmod(holder, 0o700)
        os.mkdir('payloads', 0o700, dir_fd=holder)
        tree_created = True
        tree = os.open('payloads', _directory_flags(), dir_fd=holder)
        os.fchmod(tree, 0o700)
        actual_bytes = 0
        for entry in index["modules"]:
            try:
                plaintext = inspected.reader.extract(
                    entry["slot"], password=password, private_key=private_key,
                    shares=shares_by_slot.get(entry['slot']), as_object=False,
                )
            except Exception:  # noqa: BLE001 — sanitize decoder/crypto credential failures
                # Decoder/crypto messages must not disclose caller credentials.
                raise ValueError("cannot recover selected export payload") from None
            if not isinstance(plaintext, bytes):
                raise TypeError("export extraction did not return packed bytes")
            actual_bytes += len(plaintext)
            # Only decimal size width changes: hashes remain 64 ASCII hex bytes.
            index_size += len(str(len(plaintext))) - len(str(entry['bytes']))
            entry["bytes"] = len(plaintext)
            entry["sha256"] = hashlib.sha256(plaintext).hexdigest()
            if actual_bytes + index_size > max_bytes:
                raise ValueError("export payload and index bytes exceed limit")
            _write_private(tree, entry["file"], plaintext)
        encoded_index = _index_bytes(index)
        if len(index["modules"]) > max_modules or actual_bytes + len(encoded_index) > max_bytes:
            raise ValueError("export payload and index bytes exceed limit")
        _write_private(tree, "index.json", encoded_index)
        result = {
            "schema": "docxplus.payload-export.v1", "destination": str(dest), "index": index
        }
        _rename_noreplace(holder, 'payloads', parent, dest.name)
        published = True
        return result
    finally:
        if tree >= 0:
            os.close(tree)
        try:
            if holder >= 0 and tree_created and not published:
                _remove_tree(holder, 'payloads')
        finally:
            if holder >= 0:
                os.close(holder)
            try:
                if stage is not None:
                    # The caller-owned, non-writable parent protects this name;
                    # never recursively reopen the holder through that name.
                    os.rmdir(stage, dir_fd=parent)
            finally:
                os.close(parent)


__all__ = ["MAX_EXPORT_BYTES", "MAX_EXPORT_MODULES", "export_modules"]

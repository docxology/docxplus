"""Bound ZIP directory allocation and gzip/TAR metadata before rich parsing.

Shared by carried-project intake and release-evidence import. Only regular files,
directories and one local pathname/standard-metadata header per member are admitted.
Global PAX state and size/sparse overrides are refused: they can amplify retained
objects or make the preflight and consuming parser disagree about physical offsets.
"""
from __future__ import annotations

import io
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from typing import BinaryIO

_METADATA_BYTES = 16 * 1024 * 1024
MAX_ZIP_DIRECTORY_BYTES = 8 * 1024 * 1024
_PAX_BYTES = 64 * 1024
_PAX_KEYS = frozenset({b"path", b"hdrcharset", b"mtime", b"atime", b"ctime",
                       b"uid", b"gid", b"uname", b"gname"})


class ArchiveLimitError(ValueError):
    """A compressed archive violates the supported bounded plain-tree protocol."""


def guard_zip_directory(data: bytes, *, max_data_bytes: int, max_members: int,
                        max_directory_bytes: int = MAX_ZIP_DIRECTORY_BYTES) -> int:
    """Bound physical ZIP metadata before constructing potentially many ZipInfo objects.

    Use the stdlib's own EOCD/ZIP64 parser, not a second interpretation of its
    directory. Its private field interface is intentionally coupled to zipfile;
    reader regressions exercise it on the supported Python runtimes. Consumers
    must also compare the actual entry count with the returned declaration.
    Byte budgets do not represent a whole-process memory quota.
    """
    # Reserve bounded deflate expansion as well as local/central metadata.
    if len(data) > max_data_bytes + (max_data_bytes + 999) // 1000 + 2 * max_directory_bytes + 65557:
        raise ArchiveLimitError("encoded ZIP exceeds byte cap")
    try:
        with io.BytesIO(data) as encoded:
            directory = zipfile._EndRecData(encoded)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveLimitError("invalid ZIP directory") from exc
    if directory is None:
        raise ArchiveLimitError("missing ZIP end-of-directory record")
    entries = directory[zipfile._ECD_ENTRIES_TOTAL]
    if entries > max_members:
        raise ArchiveLimitError("package has too many entries")
    if directory[zipfile._ECD_SIZE] > max_directory_bytes:
        raise ArchiveLimitError("ZIP central-directory metadata exceeds byte cap")
    if (directory[zipfile._ECD_DISK_NUMBER] != 0 or directory[zipfile._ECD_DISK_START] != 0
            or directory[zipfile._ECD_ENTRIES_THIS_DISK] != entries):
        raise ArchiveLimitError("multi-disk or inconsistent ZIP directory is unsupported")
    return entries


def _pax_metadata(value: bytes) -> None:
    cursor = 0
    keys = set()
    while cursor < len(value):
        separator = value.find(b" ", cursor, min(cursor + 12, len(value)))
        if separator < 0 or not value[cursor:separator].isdigit():
            raise ArchiveLimitError("malformed PAX record length")
        length = int(value[cursor:separator])
        end = cursor + length
        if end > len(value) or end <= separator + 2 or value[end - 1:end] != b"\n":
            raise ArchiveLimitError("malformed PAX record boundary")
        key, equals, _ = value[separator + 1:end - 1].partition(b"=")
        if not equals or key not in _PAX_KEYS or key in keys:
            raise ArchiveLimitError("unsupported or duplicate PAX metadata field")
        keys.add(key)
        cursor = end


def _tar_limit(max_data_bytes: int, max_members: int, max_metadata_bytes: int) -> int:
    if any(type(value) is not int or value < 0
           for value in (max_data_bytes, max_members, max_metadata_bytes)):
        raise ArchiveLimitError("invalid archive resource budget")
    # Headers and extension bodies count as metadata; reserve at most 511 bytes
    # of padding for each file and its one optional local extension, plus trailer.
    return max_data_bytes + max_metadata_bytes + 1024 * max_members + 10240


def validate_plain_tar(source: BinaryIO, *, max_data_bytes: int, max_members: int,
                       max_metadata_bytes: int = _METADATA_BYTES) -> None:
    """Preflight a seekable plain TAR, rewinding it on successful admission.

    Count physical headers and local metadata before rich parsing, and bound the
    aggregate regular-file content. Only one local PAX/long-name header may precede
    each file or directory. Require aligned blocks, an end marker and zero-only
    trailing padding. Effective names and destination policy remain caller-owned.
    Byte budgets are not a whole-process memory quota.
    """
    limit = _tar_limit(max_data_bytes, max_members, max_metadata_bytes)
    source.seek(0, io.SEEK_END)
    size = source.tell()
    if size > limit:
        raise ArchiveLimitError("uncompressed archive exceeds decompression cap")
    if size % 512:
        raise ArchiveLimitError("truncated physical TAR block")
    source.seek(0)
    headers = metadata = members = content = 0
    pending = False
    metadata_types = {tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME}
    plain_types = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
    while source.tell() < size:
        header = source.read(512)
        if header == bytes(512):
            if pending:
                raise ArchiveLimitError("orphaned archive metadata header")
            if source.read(512) != bytes(512):
                raise ArchiveLimitError("missing complete TAR end marker")
            while block := source.read(1024 * 1024):
                if block.strip(b"\0"):
                    raise ArchiveLimitError("nonzero data after TAR end marker")
            source.seek(0)
            return
        headers += 1
        metadata += 512
        if headers > 2 * max_members + 4:
            raise ArchiveLimitError("physical TAR header-count cap exceeded")
        if metadata > max_metadata_bytes:
            raise ArchiveLimitError("TAR metadata exceeds allocation cap")
        try:
            member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
        except tarfile.HeaderError as exc:
            raise ArchiveLimitError("invalid physical TAR header") from exc
        if member.type not in plain_types | metadata_types:
            raise ArchiveLimitError("only plain files and directories may be carried; global metadata is refused")
        if member.type == tarfile.DIRTYPE and member.size != 0:
            raise ArchiveLimitError("directory TAR payload must be empty")
        end = source.tell() + (member.size + 511) // 512 * 512
        if member.size < 0 or end > size:
            raise ArchiveLimitError("truncated physical TAR payload")
        if member.type in metadata_types:
            if pending:
                raise ArchiveLimitError("stacked archive metadata headers are unsupported")
            pending = True
            metadata += member.size
            if member.size > _PAX_BYTES or metadata > max_metadata_bytes:
                raise ArchiveLimitError("TAR metadata exceeds allocation cap")
            value = source.read(member.size)
            if member.type == tarfile.XHDTYPE:
                _pax_metadata(value)
        else:
            pending = False
            members += 1
            if members > max_members:
                raise ArchiveLimitError("archive member-count cap exceeded")
            content += member.size
            if content > max_data_bytes:
                raise ArchiveLimitError("archive content exceeds decompression cap")
        source.seek(end)
    raise ArchiveLimitError("missing TAR end marker")


@contextmanager
def bounded_tar(source: BinaryIO, *, max_data_bytes: int, max_members: int,
                temporary_directory: str | None = None,
                max_metadata_bytes: int = _METADATA_BYTES,
                max_encoded_bytes: int | None = None) -> Iterator[BinaryIO]:
    """Yield a seekable plain TAR after strict single-gzip physical admission.

    ``max_encoded_bytes`` defaults to the derived inflated-byte ceiling for
    existing callers. The caller owns ``source`` and must separately validate
    effective names and destination publication. No extraction occurs here.
    """
    limit = _tar_limit(max_data_bytes, max_members, max_metadata_bytes)
    if max_encoded_bytes is None:
        max_encoded_bytes = limit
    if type(max_encoded_bytes) is not int or max_encoded_bytes < 0:
        raise ArchiveLimitError("invalid encoded archive resource budget")
    source.seek(0)
    if source.read(2) != b"\x1f\x8b":
        raise ArchiveLimitError("archive must use gzip")
    source.seek(0)
    with tempfile.TemporaryFile(dir=temporary_directory) as raw:
        copied = encoded = 0
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            while not decoder.eof:
                block = source.read(min(64 * 1024, max_encoded_bytes - encoded + 1))
                if not block:
                    raise ArchiveLimitError("truncated gzip stream")
                encoded += len(block)
                if encoded > max_encoded_bytes:
                    raise ArchiveLimitError("encoded archive exceeds resource cap")
                while block:
                    decoded = decoder.decompress(block, min(1024 * 1024, limit - copied + 1))
                    copied += len(decoded)
                    if copied > limit:
                        raise ArchiveLimitError("uncompressed archive exceeds decompression cap")
                    raw.write(decoded)
                    block = decoder.unconsumed_tail
                    if decoder.eof:
                        if decoder.unused_data or source.read(1):
                            raise ArchiveLimitError("concatenated gzip members or trailing bytes are unsupported")
                        break
        except zlib.error as exc:
            raise ArchiveLimitError("invalid gzip archive") from exc
        validate_plain_tar(raw, max_data_bytes=max_data_bytes, max_members=max_members,
                           max_metadata_bytes=max_metadata_bytes)
        yield raw


__all__ = ["ArchiveLimitError", "bounded_tar", "guard_zip_directory", "validate_plain_tar"]

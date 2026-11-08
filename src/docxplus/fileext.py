"""File extensions and media types for the docxplus format.

A docxplus document is *byte-identical* to the ordinary Office document it also is —
that is the whole dual-contract premise, and it is why the surface extension has to
keep working. So every export writes the file twice under two names:

* ``report.docx``     — the surface contract. Double-click it; Word opens it.
* ``report.docxplus`` — the same bytes, asserting the intelligence contract.

and correspondingly ``report.odt`` / ``report.odtplus``. Nothing distinguishes the
two files but the name. That is deliberate: an extension is a *claim* about content,
and a claim a reader can check by opening either one is a better claim than a magic
byte nobody looks at. The `.docxplus` name says "this carries a signed intelligence
layer"; `docxplus validate` is what turns the assertion into a verdict.

Writing both also removes a trap. A `.docxplus` file mailed to someone whose system
has no handler for it looks broken, while the identical `.docx` beside it does not.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

#: Surface extension → the docxplus extension asserting the intelligence layer.
PLUS_EXTENSION = {
    ".docx": ".docxplus",
    ".odt": ".odtplus",
}
#: And back, for readers handed either name.
SURFACE_EXTENSION = {plus: base for base, plus in PLUS_EXTENSION.items()}

#: Media types. The surface types are the registered OOXML/ODF ones and must not be
#: changed; the plus types are this project's own, in a vendor tree.
MEDIA_TYPES = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docxplus": "application/vnd.docxplus.document+docx",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".odtplus": "application/vnd.docxplus.document+odt",
}

DOCX_EXTENSIONS = (".docx", ".docxplus")
ODT_EXTENSIONS = (".odt", ".odtplus")
ALL_EXTENSIONS = DOCX_EXTENSIONS + ODT_EXTENSIONS


def is_docxplus_name(path: str | Path) -> bool:
    """True when the name asserts the intelligence contract (``.docxplus``/``.odtplus``).

    A name is only ever a claim. Use :func:`validate.validate_bytes` or
    :func:`validate.validate_odt_bytes` to find out whether it is true.
    """
    return Path(path).suffix.lower() in SURFACE_EXTENSION


def surface_path(path: str | Path) -> Path:
    """The surface-extension sibling of ``path`` (identity if it is already one)."""
    p = Path(path)
    return p.with_suffix(SURFACE_EXTENSION.get(p.suffix.lower(), p.suffix))


def plus_path(path: str | Path) -> Path:
    """The docxplus-extension sibling of ``path`` (identity if it is already one)."""
    p = Path(path)
    return p.with_suffix(PLUS_EXTENSION.get(p.suffix.lower(), p.suffix))


def document_paths(path: str | Path) -> list[Path]:
    """Select surface/plus siblings, or one explicitly unknown-suffix target."""
    target = Path(path)
    if target.suffix.lower() not in PLUS_EXTENSION and target.suffix.lower() not in SURFACE_EXTENSION:
        return [target]
    return [surface_path(target), plus_path(target)]


def preflight_document(path: str | Path) -> list[Path]:
    """Check every selected target without writing document contents.

    Existing regular files may be replaced. Symlinks, special files, directories
    and non-directory ancestors refuse before either sibling is overwritten.
    This check is not a reservation against concurrent filesystem mutation.
    """
    _publication_flags()
    targets = document_paths(path)
    for target in targets:
        if not target.name:
            raise ValueError("document target must have a filename")
        for parent in reversed(target.absolute().parents):
            try:
                mode = parent.lstat().st_mode
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(mode):
                raise NotADirectoryError(f"document parent is not a plain directory: {parent}")
        _preflight_target(target)
    return targets


def _preflight_target(path: Path, *, directory: int | None = None) -> None:
    try:
        mode = os.stat(path.name if directory is not None else path, dir_fd=directory, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise FileExistsError(f"document target is not a plain regular file: {path}")


def write_document(data: bytes, path: str | Path) -> list[Path]:
    """Stage complete private siblings before replacing any selected target.

    Each replacement is atomic and never truncates an existing inode. The pair
    is not a cross-file crash-atomic transaction: a crash during publication can
    leave one old sibling and one new sibling.
    """
    targets = preflight_document(path)
    payload = memoryview(data)
    parent = targets[0].parent
    descriptor = _open_parent(parent)
    staged = []
    try:
        for target in targets:
            _preflight_target(target, directory=descriptor)
            name = f".{target.name}.{os.urandom(12).hex()}"
            handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=descriptor)
            staged.append((name, target))
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        for _, target in staged:
            _preflight_target(target, directory=descriptor)
        for name, target in staged:
            os.replace(name, target.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    finally:
        for name, _ in staged:
            try:
                os.unlink(name, dir_fd=descriptor)
            except FileNotFoundError:
                pass
        os.close(descriptor)
    return targets


def _publication_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise NotImplementedError("safe document publication requires descriptor-relative no-follow directory support")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_parent(path: Path) -> int:
    """Anchor publication to opened, non-symlink directory components."""
    absolute = path.absolute()
    flags = _publication_flags()
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
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


__all__ = [
    "ALL_EXTENSIONS",
    "DOCX_EXTENSIONS",
    "MEDIA_TYPES",
    "ODT_EXTENSIONS",
    "PLUS_EXTENSION",
    "SURFACE_EXTENSION",
    "document_paths",
    "is_docxplus_name",
    "plus_path",
    "preflight_document",
    "surface_path",
    "write_document",
]



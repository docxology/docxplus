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


def write_document(data: bytes, path: str | Path) -> list[Path]:
    """Write ``data`` under both its surface and its docxplus name.

    Returns the paths written, surface first. Given a path whose suffix is neither
    known extension, writes that one path alone rather than guessing — an explicit
    caller choice is not something to override.
    """
    target = Path(path)
    suffix = target.suffix.lower()
    if suffix not in PLUS_EXTENSION and suffix not in SURFACE_EXTENSION:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return [target]

    surface, plus = surface_path(target), plus_path(target)
    written = []
    for candidate in (surface, plus):
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(data)
        written.append(candidate)
    return written

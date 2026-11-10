"""docxplus — DOCX and ODT containers with modular, signed and payload-encrypted
intelligence layers through standards-defined package extension points.

Public surface:

    from .container import DocxPlusBuilder, DocxPlusReader
    from .validate import validate_bytes, assert_valid
    from .manifest import Manifest
    from . import channels, crypto
"""

from __future__ import annotations

from . import channels, crypto
from .audit import audit_document, audit_files
from .comparison import compare_documents
from .container import DocxPlusBuilder, DocxPlusReader
from .export import export_modules
from .fileext import is_docxplus_name, plus_path, surface_path, write_document
from .inspection import Inspection, inspect_document
from .manifest import Manifest
from .odt_container import OdtPlusBuilder, OdtPlusReader, open_document, read_document_package
from .reproduce import (
    ReproSpec,
    attest,
    hermetic_extract_and_reproduce,
    load_recipe,
    reproduce_and_compare,
)
from .shamir import combine_weighted, split_weighted
from .validate import assert_valid, validate_bytes, validate_odt_bytes

__version__ = "2.3.0"

__all__ = [
    "DocxPlusBuilder",
    "DocxPlusReader",
    "Inspection",
    "Manifest",
    "OdtPlusBuilder",
    "OdtPlusReader",
    "ReproSpec",
    "__version__",
    "assert_valid",
    "attest",
    "audit_document",
    "audit_files",
    "channels",
    "combine_weighted",
    "compare_documents",
    "crypto",
    "export_modules",
    "hermetic_extract_and_reproduce",
    "inspect_document",
    "is_docxplus_name",
    "load_recipe",
    "open_document",
    "plus_path",
    "read_document_package",
    "reproduce_and_compare",
    "split_weighted",
    "surface_path",
    "validate_bytes",
    "validate_odt_bytes",
    "write_document",
]

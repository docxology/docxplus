"""docxplus — a byte-valid OOXML .docx that also carries a modular, signed,
encrypted intelligence layer through spec-sanctioned side-channels.

Public surface:

    from .container import DocxPlusBuilder, DocxPlusReader
    from .validate import validate_bytes, assert_valid
    from .manifest import Manifest
    from . import channels, crypto
"""

from __future__ import annotations

from . import channels, crypto
from .container import DocxPlusBuilder, DocxPlusReader
from .fileext import is_docxplus_name, plus_path, surface_path, write_document
from .manifest import Manifest
from .odt_container import OdtPlusBuilder, OdtPlusReader, open_document
from .reproduce import ReproSpec, attest, hermetic_extract_and_reproduce, load_recipe, reproduce_and_compare
from .shamir import combine_weighted, split_weighted
from .validate import assert_valid, validate_bytes, validate_odt_bytes

__version__ = "1.0.1"

__all__ = [
    "DocxPlusBuilder",
    "DocxPlusReader",
    "Manifest",
    "OdtPlusBuilder",
    "OdtPlusReader",
    "ReproSpec",
    "__version__",
    "assert_valid",
    "attest",
    "channels",
    "combine_weighted",
    "crypto",
    "hermetic_extract_and_reproduce",
    "is_docxplus_name",
    "load_recipe",
    "open_document",
    "plus_path",
    "reproduce_and_compare",
    "split_weighted",
    "surface_path",
    "validate_bytes",
    "validate_odt_bytes",
    "write_document",
]

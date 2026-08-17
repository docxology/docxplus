"""docxplus — a byte-valid OOXML .docx that also carries a modular, signed,
encrypted intelligence layer through spec-sanctioned side-channels.

Public surface:

    from container import DocxPlusBuilder, DocxPlusReader
    from validate import validate_bytes, assert_valid
    from manifest import Manifest
    import crypto, channels
"""

from __future__ import annotations

__version__ = "0.6.0"

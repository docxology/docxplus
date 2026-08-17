"""Interop tests including optional headless LibreOffice openability verification."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from container import DocxPlusBuilder


@pytest.mark.skipif(shutil.which("soffice") is None and shutil.which("libreoffice") is None,
                    reason="LibreOffice (soffice/libreoffice) not installed on host")
def test_libreoffice_headless_convert_docx():
    bin_name = shutil.which("soffice") or shutil.which("libreoffice")
    with tempfile.TemporaryDirectory() as td:
        docx_path = Path(td) / "test_doc.docx"
        b = DocxPlusBuilder(paragraphs=["Hello from docxplus interop test."])
        b.add_module("m1", "custom_xml", b"payload1")
        b.add_module("m2", "mce", b"mce payload")
        docx_path.write_bytes(b.build())

        res = subprocess.run(
            [bin_name, "--headless", "--convert-to", "pdf", str(docx_path), "--outdir", td],
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert res.returncode == 0
        pdf_path = Path(td) / "test_doc.pdf"
        assert pdf_path.is_file()
        assert pdf_path.stat().st_size > 0

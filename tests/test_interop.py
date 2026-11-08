"""Optional host Office rendering; disposable release qualification requires every case."""

import base64
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from docxplus import steg_bridge
from docxplus.container import DocxPlusBuilder
from docxplus.odt_container import OdtPlusBuilder

VISIBLE = "DOCXPLUS OFFICE VISIBLE SENTINEL"
HIDDEN = b"DOCXPLUS_HIDDEN_PAYLOAD_MUST_NOT_RENDER"


def _optional_capability(present, reason):
    if not present:
        if os.environ.get("DOCXPLUS_REQUIRE_OFFICE") == "1":
            pytest.fail(reason)
        pytest.skip(reason)


def _run(argv, tmp_path):
    # Even consecutive conversions never share a running Office instance/profile.
    with tempfile.TemporaryDirectory(prefix="office-invocation-", dir=tmp_path) as td:
        private = Path(td)
        env = dict(os.environ)
        for key, name in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                          ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"),
                          ("XDG_RUNTIME_DIR", "runtime"), ("TMPDIR", "tmp")):
            directory = private / name
            directory.mkdir(mode=0o700)
            env[key] = str(directory)
        env["TMP"] = env["TEMP"] = env["TMPDIR"]
        if Path(argv[0]).name in {"soffice", "libreoffice"}:
            argv = [argv[0], f"-env:UserInstallation={(private / 'profile').as_uri()}",
                    "--headless", "--nologo", "--nodefault", "--nofirststartwizard",
                    "--norestore", *argv[1:]]
        result = subprocess.run(argv, cwd=private, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, check=False, timeout=60)
        assert result.returncode == 0, (result.stdout, result.stderr)
        return result.stdout.decode(errors="replace")


@pytest.mark.parametrize("profile", ["docx", "odt"])
@pytest.mark.parametrize("carrier", ["none", "python_lsb", "steganographer"])
def test_libreoffice_headless_render(tmp_path, profile, carrier):
    """Both profiles render visible text, never payload; carrier pixels reach the page."""
    office = shutil.which("soffice") or shutil.which("libreoffice")
    tools = {name: shutil.which(name) for name in ("pdftotext", "pdftoppm", "pdfimages")}
    _optional_capability(office and all(tools.values()),
                         "real LibreOffice and poppler-utils are required for Office interop")
    if carrier != "none":
        try:
            from PIL import Image
        except ImportError:
            _optional_capability(False, "Pillow is required for rendered carrier assertions")
        if carrier == "steganographer":
            _optional_capability(steg_bridge.available(),
                                 "real steganographer is required for its Office carrier case")
        image = tmp_path / "carrier.png"
        Image.new("RGB", (256, 256), (192, 64, 32)).save(image)
        kwargs = {"backend": carrier, "carrier_png": image, "carrier_size": (256, 256)}
    else:
        kwargs = {}
    if profile == "docx":
        builder = DocxPlusBuilder(paragraphs=[VISIBLE])
        builder.add_module("hidden", "custom_xml", HIDDEN)
        builder.add_module("mce", "mce", HIDDEN)
        if carrier != "none":
            builder.add_module("figure", "stego_media", HIDDEN, **kwargs)
    else:
        builder = OdtPlusBuilder(paragraphs=[VISIBLE])
        builder.add_module("hidden", HIDDEN)
        if carrier != "none":
            builder.add_module("figure", HIDDEN, channel_id="stego_media", **kwargs)
    document = tmp_path / f"interop.{profile}"
    document.write_bytes(builder.build())
    rendered = tmp_path / "rendered"
    rendered.mkdir()
    _run([office, "--convert-to", "pdf", "--outdir", str(rendered), str(document)], tmp_path)
    pdf = rendered / "interop.pdf"
    assert pdf.read_bytes().startswith(b"%PDF-")
    text = _run([tools["pdftotext"], "-layout", str(pdf), "-"], tmp_path)
    assert VISIBLE in text
    compact_text = "".join(text.split())
    assert HIDDEN.decode() not in compact_text
    assert base64.b64encode(HIDDEN).decode() not in compact_text
    if carrier != "none":
        listing = _run([tools["pdfimages"], "-list", str(pdf)], tmp_path)
        assert any(len(row.split()) >= 5 and row.split()[2] == "image"
                   for row in listing.splitlines())
        preview = rendered / "first-page"
        _run([tools["pdftoppm"], "-f", "1", "-singlefile", "-scale-to", "1200",
              "-png", str(pdf), str(preview)], tmp_path)
        with Image.open(preview.with_suffix(".png")) as page:
            colored = sum(1 for r, g, b in page.convert("RGB").getdata()
                          if r > 150 and 30 < g < 110 and b < 90 and r > 1.5 * g)
        assert colored > 2000, "the visible carrier did not reach the rendered first page"

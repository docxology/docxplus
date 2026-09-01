"""Media-steganography channel.

The payload is hidden in the LSBs of a PNG that is *also* a visible image part of
the document (``word/media/`` under OOXML, ``Pictures/`` under ODF). To a reader the
file is a document with a picture; the picture's pixels carry the intelligence packet.
This is the channel that lets a docxplus "look completely ordinary" while carrying
content.

Two real backends:

* ``python_lsb`` (default) — the pure-Python LSB codec in :mod:`lsb`, needing only
  Pillow. Zero external setup; deterministic and reversible.
* ``steganographer`` — the docxology/steganographer Rust CLI (see
  :mod:`steg_bridge`), which additionally BLAKE3-hashes, Ed25519-signs and can
  Reed-Solomon-protect the packet. Requires the built binary.

Both are genuine steganographic embeddings; the backend is recorded in the
manifest so extraction uses the matching decoder.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from .. import lsb, steg_bridge
from ..crypto import digest as _digest
from ..opc import OpcPackage, Relationship
from .base import ChannelRecord

CT_PNG = "image/png"
REL_IMAGE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
)
BACKENDS = ("python_lsb", "steganographer")


def _insert_drawing(pkg: OpcPackage, rid: str, size: tuple[int, int]) -> None:
    """Add a `<w:drawing>` paragraph rendering the carrier at its natural size.

    A relationship alone does not put an image on the page. The channel's premise is
    that the carrier is a figure the document *visibly displays* — that is what makes
    it plausible cover rather than an obviously spare part — so the body gets a
    drawing that references it.

    EMU is the WordprocessingML unit: 914400 per inch, and a PNG with no declared DPI
    is conventionally read at 96, giving 9525 EMU per pixel.
    """
    from .mce import _body_insertion_point

    width_emu, height_emu = size[0] * 9525, size[1] * 9525
    drawing = (
        '<w:p><w:r><w:drawing>'
        '<wp:inline distT="0" distB="0" distL="0" distR="0" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
        f'<wp:extent cx="{width_emu}" cy="{height_emu}"/>'
        '<wp:docPr id="1" name="Figure"/>'
        '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:nvPicPr><pic:cNvPr id="1" name="Figure"/><pic:cNvPicPr/></pic:nvPicPr>'
        '<pic:blipFill>'
        '<a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        f'r:embed="{rid}"/>'
        '<a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        '<pic:spPr><a:xfrm><a:off x="0" y="0"/>'
        f'<a:ext cx="{width_emu}" cy="{height_emu}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
        '</pic:pic></a:graphicData></a:graphic></wp:inline>'
        '</w:drawing></w:r></w:p>'
    )
    doc_xml = pkg.parts["word/document.xml"].decode("utf-8")
    pos = _body_insertion_point(doc_xml)
    pkg.parts["word/document.xml"] = (doc_xml[:pos] + drawing + doc_xml[pos:]).encode("utf-8")


class StegMediaChannel:
    """Embed via LSB stego into a PNG carrier part.

    ``backend`` selects the codec. ``carrier_png`` may be supplied; otherwise a
    deterministic carrier is generated (needs Pillow). ``signing_key`` is an
    optional path to a raw Ed25519 key file used by the steganographer backend.
    """

    id = "stego_media"

    def __init__(
        self,
        backend: str = "python_lsb",
        *,
        carrier_png: Path | None = None,
        signing_key: Path | None = None,
        carrier_size: tuple[int, int] = (256, 256),
        redundancy: int = 1,
    ) -> None:
        if backend not in BACKENDS:
            raise ValueError(f"unknown stego backend: {backend}")
        if redundancy < 1:
            raise ValueError("redundancy must be >= 1")
        self.backend = backend
        self.carrier_png = carrier_png
        self.signing_key = signing_key
        self.carrier_size = carrier_size
        self.redundancy = redundancy

    def embed(self, pkg: OpcPackage, payload: bytes, *, slot: str) -> ChannelRecord:
        # The polyglot carrier: replicate the payload across ``redundancy`` images so
        # the document survives losing all but one (crop, re-export, a stripped figure).
        parts = [self._embed_one(pkg, payload) for _ in range(self.redundancy)]
        return ChannelRecord(
            channel=self.id,
            slot=slot,
            size=len(payload),
            digest=_digest(payload),
            content_type=CT_PNG,
            location={"parts": parts, "backend": self.backend},
        )

    def _embed_one(self, pkg: OpcPackage, payload: bytes) -> str:
        index = _next_media_index(pkg)
        part_name = f"word/media/image{index}.png"
        with tempfile.TemporaryDirectory() as td:
            carrier = self.carrier_png or lsb.make_carrier(
                Path(td) / "carrier.png", self.carrier_size
            )
            out_png = Path(td) / "stego.png"
            if self.backend == "python_lsb":
                lsb.embed(Path(carrier), payload, out_png)
            else:
                if not steg_bridge.available():
                    raise steg_bridge.StegError("steganographer CLI not available")
                steg_bridge.embed_payload(
                    Path(carrier), payload, out_png, signing_key=self.signing_key
                )
            stego_bytes = out_png.read_bytes()
        pkg.set_default_type("png", CT_PNG)
        pkg.add_part(part_name, stego_bytes)
        rid = pkg.next_rel_id("word/document.xml")
        pkg.add_relationship(
            Relationship(rid, REL_IMAGE, f"media/image{index}.png"),
            source_part="word/document.xml",
        )
        # A relationship alone does not put the image on the page. The channel's
        # premise is that the carrier is a figure the document *visibly displays* —
        # that is what makes it plausible cover rather than an obviously spare part —
        # so the body gets a drawing that references it.
        _insert_drawing(pkg, rid, self.carrier_size)
        return part_name

    def extract(self, pkg: OpcPackage, record: ChannelRecord) -> bytes:
        backend = record.location.get("backend", "python_lsb")
        # Back-compat: a single "part", or the redundant "parts" list. Try each
        # surviving carrier and return the first whose decoded bytes match the
        # module digest — so a corrupted-but-still-decodable replica is skipped in
        # favour of an intact one, not returned silently.
        parts = record.location.get("parts") or [record.location["part"]]
        last: Exception | None = None
        for part in parts:
            if part not in pkg.parts:
                continue
            try:
                payload = self._extract_one(pkg.parts[part], backend)
            except Exception as exc:  # noqa: BLE001 - this carrier was damaged; try next
                last = exc
                continue
            if _digest(payload) == record.digest:
                return payload
            last = ValueError(f"carrier {part} decoded to bytes not matching the module digest")
        raise RuntimeError(f"no surviving media carrier decoded correctly ({last})")

    def _extract_one(self, blob: bytes, backend: str) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            stego_png = Path(td) / "stego.png"
            stego_png.write_bytes(blob)
            if backend == "python_lsb":
                return lsb.extract(stego_png)
            if not steg_bridge.available():
                raise steg_bridge.StegError("steganographer CLI not available")
            return steg_bridge.extract_payload(stego_png, Path(td) / "out.bin")

    def capacity(self, pkg: OpcPackage | None = None) -> int | None:
        w, h = self.carrier_size
        return lsb.capacity_bytes(w, h)


class OdtStegMediaChannel(StegMediaChannel):
    """The same channel over an ODF package: LSB stego into ``Pictures/<name>.png``.

    Subclassing is the point: extraction is driven by ``record.location`` and reads
    ``pkg.parts`` by name, neither of which cares which packaging standard named the
    part, so the decode path — backend dispatch, redundancy, digest-verified replica
    selection — is literally the parent's code. Only *placement* differs: ODF declares
    images as package file-entries and renders them through a ``<draw:frame>`` in
    ``content.xml`` rather than a relationship plus a ``<w:drawing>``.

    The carrier is inserted into the visible body so the channel's premise holds on
    this profile too: an image nothing renders is a conspicuously spare part, not
    cover. Media carriers live under the ODF-conventional ``Pictures/`` tree.
    """

    def _embed_one(self, pkg, payload: bytes) -> str:
        index = _next_odt_media_index(pkg)
        part_name = f"Pictures/figure{index}.png"
        with tempfile.TemporaryDirectory() as td:
            carrier = self.carrier_png or lsb.make_carrier(
                Path(td) / "carrier.png", self.carrier_size
            )
            out_png = Path(td) / "stego.png"
            if self.backend == "python_lsb":
                lsb.embed(Path(carrier), payload, out_png)
            else:
                if not steg_bridge.available():
                    raise steg_bridge.StegError("steganographer CLI not available")
                steg_bridge.embed_payload(
                    Path(carrier), payload, out_png, signing_key=self.signing_key
                )
            stego_bytes = out_png.read_bytes()
        pkg.add_part(part_name, stego_bytes, CT_PNG)
        _insert_odt_frame(pkg, part_name, self.carrier_size)
        return part_name

    def capacity(self, pkg=None) -> int | None:
        w, h = self.carrier_size
        return lsb.capacity_bytes(w, h)


def _next_odt_media_index(pkg) -> int:
    """Deterministically number ``Pictures/figureN.png`` carriers."""
    n = 1
    while f"Pictures/figure{n}.png" in pkg.parts:
        n += 1
    return n


def _insert_odt_frame(pkg, part_name: str, size: tuple[int, int]) -> None:
    """Insert a `<draw:frame>` that displays the carrier into ``content.xml``.

    A package entry alone is not an image on the page; the frame is what makes the
    carrier a figure the document visibly renders. Dimensions follow the same 96-dpi
    convention the OOXML drawing uses (2.54 cm per inch).
    """
    width_cm = size[0] / 96.0 * 2.54
    height_cm = size[1] / 96.0 * 2.54
    frame = (
        '<text:p><draw:frame draw:name="Figure" '
        'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
        'xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'svg:width="{width_cm:.3f}cm" svg:height="{height_cm:.3f}cm" '
        'text:anchor-type="as-char">'
        f'<draw:image xlink:href="{part_name}" xlink:type="simple" '
        'xlink:show="embed" xlink:actuate="onLoad"/>'
        "</draw:frame></text:p>"
    )
    doc_xml = pkg.parts["content.xml"].decode("utf-8")
    pos = _odt_body_insertion_point(doc_xml)
    pkg.parts["content.xml"] = (doc_xml[:pos] + frame + doc_xml[pos:]).encode("utf-8")


def _odt_body_insertion_point(doc_xml: str) -> int:
    """Offset before ``</office:text>`` so the frame stays inside the visible body.

    ODF content models differ from WordprocessingML's, and the OPC helper in
    :mod:`mce` looks for ``</w:body>`` — reusing it here would refuse every ODF
    document. ``</office:text>`` closes the visible text body; appending before it
    keeps the frame inside ``office:body``, which is what a conforming consumer
    renders.
    """
    end = doc_xml.rfind("</office:text>")
    if end == -1:
        raise ValueError("invalid content.xml: missing </office:text>")
    return end


def _next_media_index(pkg: OpcPackage) -> int:
    n = 1
    while f"word/media/image{n}.png" in pkg.parts:
        n += 1
    return n


__all__ = [
    "BACKENDS",
    "CT_PNG",
    "REL_IMAGE",
    "OdtStegMediaChannel",
    "StegMediaChannel",
]



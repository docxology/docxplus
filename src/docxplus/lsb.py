"""Pure-Python LSB steganography over PNG carriers (Pillow only).

A dependency-light, fully-functional backend for the media channel: it hides a
length-prefixed payload in the least-significant bit of each RGB colour channel,
exactly the LSB technique the standards report and the docxology/steganographer
project describe. Deterministic and reversible; no external toolchain.

The optional steganographer Rust CLI uses a different BLAKE3-checked packet
format, with signing only when a key is supplied. This backend needs only Pillow
and does not authenticate payloads or provide error correction.
"""

from __future__ import annotations

from contextlib import contextmanager
from itertools import islice
from pathlib import Path

_MAGIC = b"DXL1"
_HEADER = len(_MAGIC) + 4  # magic + uint32 length
# Bound decompressed RGB/sample storage before Pillow converts or loads pixels.
MAX_CARRIER_PIXELS = 16_000_000


def _check_dimensions(width: int, height: int) -> None:
    if width <= 0 or height <= 0 or width * height > MAX_CARRIER_PIXELS:
        raise ValueError(f"carrier pixel count exceeds limit {MAX_CARRIER_PIXELS}")


@contextmanager
def _open_rgb(path: Path):
    """Load RGB pixels only after enforcing the carrier's decoded-size budget."""
    from PIL import Image

    with Image.open(path) as source:
        _check_dimensions(*source.size)
        with source.convert("RGB") as image:
            yield image


def capacity_bytes(width: int, height: int) -> int:
    """Payload bytes a ``width``×``height`` RGB carrier can hold (minus header)."""
    return max(0, (width * height * 3) // 8 - _HEADER)


def make_carrier(path: Path, size: tuple[int, int]) -> Path:
    """Write a deterministic gradient PNG carrier (no RNG)."""
    from PIL import Image

    w, h = size
    _check_dimensions(w, h)
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 255) // max(1, w - 1), (y * 255) // max(1, h - 1), 128)
    img.save(path, format="PNG")
    return path


def embed(carrier_png: Path, payload: bytes, out_png: Path) -> Path:
    """Embed ``payload`` into ``carrier_png`` LSBs → ``out_png`` (lossless PNG)."""
    with _open_rgb(carrier_png) as img:
        width, height = img.size
        if (_HEADER + len(payload)) * 8 > width * height * 3:
            raise ValueError(
                f"payload too large: {len(payload)} bytes exceeds carrier capacity "
                f"{capacity_bytes(width, height)}"
            )
        framed = _MAGIC + len(payload).to_bytes(4, "big") + payload
        px = img.load()
        bit_count = len(framed) * 8
        i = 0
        for pixel in range((bit_count + 2) // 3):
            x, y = pixel % width, pixel // width
            channels = list(px[x, y])
            for channel in range(min(3, bit_count - i)):
                bit = (framed[i // 8] >> (7 - i % 8)) & 1
                channels[channel] = (channels[channel] & ~1) | bit
                i += 1
            px[x, y] = tuple(channels)
        img.save(out_png, format="PNG")
    return out_png


def extract(stego_png: Path) -> bytes:
    """Reverse :func:`embed`; return the original payload bytes."""
    with _open_rgb(stego_png) as img:
        width, height = img.size
        if width * height * 3 < _HEADER * 8:
            raise ValueError("carrier too small for full DXL1 header")
        px = img.load()
        samples = (
            channel for y in range(height) for x in range(width) for channel in px[x, y]
        )
        header = _read_bytes(samples, _HEADER)
        if header[:len(_MAGIC)] != _MAGIC:
            raise ValueError("no DXL1 payload found in carrier")
        length = int.from_bytes(header[len(_MAGIC):], "big")
        if length > capacity_bytes(width, height):
            raise ValueError("declared DXL1 payload exceeds carrier capacity")
        return _read_bytes(samples, length)


def _read_bytes(samples, count: int) -> bytes:
    """Consume an exact byte count without a per-bit list or a carrier copy."""
    out = bytearray(count)
    for i in range(count):
        byte = 0
        bits = 0
        for sample in islice(samples, 8):
            byte = (byte << 1) | (sample & 1)
            bits += 1
        if bits != 8:
            raise ValueError("truncated DXL1 payload in carrier")
        out[i] = byte
    return bytes(out)


__all__ = [
    "MAX_CARRIER_PIXELS",
    "capacity_bytes",
    "embed",
    "extract",
    "make_carrier",
]



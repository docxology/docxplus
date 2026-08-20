"""Pure-Python LSB steganography over PNG carriers (Pillow only).

A dependency-light, fully-functional backend for the media channel: it hides a
length-prefixed payload in the least-significant bit of each RGB colour channel,
exactly the LSB technique the standards report and the docxology/steganographer
project describe. Deterministic and reversible; no external toolchain.

The steganographer Rust CLI remains the *premium* backend (adds BLAKE3 + Ed25519
signing and Reed-Solomon ECC); this module is the zero-setup default so a docxplus
with a media-carried payload can be produced and read with Pillow alone.
"""

from __future__ import annotations

from pathlib import Path

_MAGIC = b"DXL1"
_HEADER = len(_MAGIC) + 4  # magic + uint32 length


def capacity_bytes(width: int, height: int) -> int:
    """Payload bytes a ``width``×``height`` RGB carrier can hold (minus header)."""
    return max(0, (width * height * 3) // 8 - _HEADER)


def make_carrier(path: Path, size: tuple[int, int]) -> Path:
    """Write a deterministic gradient PNG carrier (no RNG)."""
    from PIL import Image

    w, h = size
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 255) // max(1, w - 1), (y * 255) // max(1, h - 1), 128)
    img.save(path, format="PNG")
    return path


def embed(carrier_png: Path, payload: bytes, out_png: Path) -> Path:
    """Embed ``payload`` into ``carrier_png`` LSBs → ``out_png`` (lossless PNG)."""
    from PIL import Image

    img = Image.open(carrier_png).convert("RGB")
    width, height = img.size
    framed = _MAGIC + len(payload).to_bytes(4, "big") + payload
    if len(framed) > capacity_bytes(width, height) + _HEADER:
        raise ValueError(
            f"payload too large: {len(payload)} bytes exceeds carrier capacity "
            f"{capacity_bytes(width, height)}"
        )
    bits = _to_bits(framed)
    px = img.load()
    i = 0
    for y in range(height):
        for x in range(width):
            r, g, b = px[x, y]
            channels = [r, g, b]
            for c in range(3):
                if i < len(bits):
                    channels[c] = (channels[c] & ~1) | bits[i]
                    i += 1
            px[x, y] = tuple(channels)
        if i >= len(bits):
            break
    img.save(out_png, format="PNG")
    return out_png


def extract(stego_png: Path) -> bytes:
    """Reverse :func:`embed`; return the original payload bytes."""
    from PIL import Image

    img = Image.open(stego_png).convert("RGB")
    width, height = img.size
    px = img.load()

    header_bits = _read_bits(px, width, height, _HEADER * 8)
    framed_header = _from_bits(header_bits)
    if framed_header[: len(_MAGIC)] != _MAGIC:
        raise ValueError("no DXL1 payload found in carrier")
    length = int.from_bytes(framed_header[len(_MAGIC) : _HEADER], "big")

    total_bits = (_HEADER + length) * 8
    all_bits = _read_bits(px, width, height, total_bits)
    return _from_bits(all_bits)[_HEADER : _HEADER + length]


def _to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _from_bits(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def _read_bits(px, width: int, height: int, count: int) -> list[int]:
    bits: list[int] = []
    for y in range(height):
        for x in range(width):
            for c in px[x, y]:
                bits.append(c & 1)
                if len(bits) >= count:
                    return bits
    return bits


__all__ = [
    "capacity_bytes",
    "embed",
    "extract",
    "make_carrier",
]



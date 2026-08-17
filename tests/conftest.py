"""Shared fixtures. ``pythonpath`` in pyproject already exposes ``.`` and ``src``."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_payload() -> bytes:
    return b'{"kind": "brief", "priority": 3, "body": "structured intelligence"}'


@pytest.fixture
def large_payload() -> bytes:
    return b"A" * 20_000


def pixels(image) -> list[tuple[int, ...]]:
    """Flat per-pixel sequence, across the Pillow versions this project supports.

    ``Image.getdata`` is deprecated and removed in Pillow 14; ``get_flattened_data``
    replaces it but does not exist before Pillow 12. ``pyproject.toml`` allows the
    whole range, so the tests have to as well — pinning the floor upward to avoid one
    compatibility shim would be the tail wagging the dog.
    """
    getter = getattr(image, "get_flattened_data", None) or image.getdata
    return list(getter())

"""Shared fixtures. ``pythonpath`` in pyproject already exposes ``.`` and ``src``."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_payload() -> bytes:
    return b'{"kind": "brief", "priority": 3, "body": "structured intelligence"}'


@pytest.fixture
def large_payload() -> bytes:
    return b"A" * 20_000

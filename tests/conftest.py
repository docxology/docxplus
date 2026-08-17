"""Shared fixtures. ``pythonpath`` in pyproject already exposes ``.`` and ``src``."""

from __future__ import annotations

from pathlib import Path

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

def pytest_configure(config):
    """Let coverage follow the CLI into the subprocesses that actually run it.

    The command line is tested by launching it for real, which is the only way to
    prove the entry point, the argument parsing, and the exit codes work. Coverage
    measures the parent process only, so without this the most end-to-end-tested
    module in the repository reported 0% and dragged the total under the gate.

    Set here rather than in `run.sh` so a bare `pytest` measures the same thing the
    pipeline does. A gate that depends on the caller remembering an environment
    variable is a gate that passes for the wrong reason.
    """
    import os

    if config.pluginmanager.hasplugin("pytest_cov"):
        os.environ.setdefault("COVERAGE_PROCESS_START", str(Path(__file__).parent.parent / "pyproject.toml"))

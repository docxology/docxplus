"""Single source of manuscript/documentation variables — derived, never hard-coded.

Every drift-prone number the manuscript cites (channel count, KDF parameters,
capacities, caps, module/test counts, the dossier module table) is *computed here*
from the live code constants and the actual repository, so a change in the code
changes the document. The manuscript sources carry ``{{TOKENS}}``; the renderer
(`scripts/render_manuscript.py`) substitutes these values.

Rule: this module reads facts from the code (``crypto.SCRYPT_N_LOG2``,
``channels.available_channels()``, ``lsb.capacity_bytes`` …) and the filesystem —
it must not restate a literal that already lives in a module constant.
"""

from __future__ import annotations

import re
from pathlib import Path

import channels
import container
import crypto
import lsb
import opc
import payloads
import reproduce
from channels.metadata import MAX_PAYLOAD as METADATA_MAX
from project_paths import project_root

TOKEN_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def render_text(text: str, values: dict[str, str]) -> tuple[str, set[str]]:
    """Substitute ``{{TOKEN}}`` from ``values``; return ``(rendered, unresolved)``."""
    unresolved: set[str] = set()

    def sub(match: re.Match) -> str:
        name = match.group(1)
        if name not in values:
            unresolved.add(name)
            return match.group(0)
        return values[name]

    return TOKEN_RE.sub(sub, text), unresolved


def _pyproject_version(root: Path) -> str:
    text = (root / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else "0.0.0"


def _coverage_gate(root: Path) -> int:
    text = (root / "pyproject.toml").read_text()
    m = re.search(r"fail_under\s*=\s*(\d+)", text)
    return int(m.group(1)) if m else 0


def _count_test_functions(root: Path) -> int:
    total = 0
    for path in (root / "tests").glob("test_*.py"):
        total += len(re.findall(r"^def test_", path.read_text(), re.MULTILINE))
    return total


def _count_src_modules(root: Path) -> int:
    return sum(
        1
        for p in (root / "src").rglob("*.py")
        if p.name != "__init__.py"
    )


def _cli_commands(root: Path) -> list[str]:
    text = (root / "docxplus_cli.py").read_text()
    return sorted(set(re.findall(r'add_parser\("([a-z-]+)"', text)))


def dossier_table() -> tuple[str, int]:
    """Build the showcase dossier in memory and render its module table + count.

    The table is *generated from a real document*, so the manuscript's evaluation
    table can never disagree with what the code produces.
    """
    from reference_docs import build_reference_dossier

    reader = build_reference_dossier()
    rows = ["| Slot | Channel | Sealing |", "| --- | --- | --- |"]
    for slot in sorted(reader.list_modules()):
        rec = reader.manifest.slot(slot)
        rows.append(f"| `{slot}` | {rec.channel} | {rec.sealing.get('mode', 'plain')} |")
    return "\n".join(rows), len(reader.list_modules())


def variables(include_dossier: bool = True) -> dict[str, str]:
    """Compute every manuscript token value from the live system."""
    root = project_root()
    chans = channels.available_channels()
    ptypes = payloads.available_types()
    v: dict[str, object] = {
        "VERSION": _pyproject_version(root),
        "CHANNELS": ", ".join(chans),
        "CHANNEL_COUNT": len(chans),
        "PAYLOAD_TYPES": ", ".join(ptypes),
        "PAYLOAD_TYPE_COUNT": len(ptypes),
        "SEALING_LINEAGES": ", ".join(container.SEALING_LINEAGES),
        "SEALING_COUNT": len(container.SEALING_LINEAGES),
        "KEY_BITS": crypto.KEY_BYTES * 8,
        "SCRYPT_N": 1 << crypto.SCRYPT_N_LOG2,
        "SCRYPT_N_LOG2": crypto.SCRYPT_N_LOG2,
        "SCRYPT_R": crypto.SCRYPT_R,
        "SCRYPT_P": crypto.SCRYPT_P,
        "SCRYPT_N_MAX_LOG2": crypto.MAX_SCRYPT_N_LOG2,
        "PBKDF2_ITERATIONS": crypto.PBKDF2_ITERATIONS,
        "PBKDF2_ITERATIONS_MAX": crypto.MAX_PBKDF2_ITERATIONS,
        "METADATA_MAX_BYTES": METADATA_MAX,
        "MEDIA_CAP_256": lsb.capacity_bytes(256, 256),
        "MEDIA_CAP_512": lsb.capacity_bytes(512, 512),
        "MAX_ENTRIES": opc.MAX_ENTRIES,
        "MAX_ENTRY_MIB": opc.MAX_ENTRY_BYTES // (1024 * 1024),
        "MAX_TOTAL_MIB": opc.MAX_TOTAL_BYTES // (1024 * 1024),
        "MAX_INFLATE_RATIO": opc.MAX_INFLATE_RATIO,
        "REPRO_TIMEOUT_MAX": reproduce.MAX_REPRO_SECONDS,
        "REPRO_OUTPUT_MAX_MIB": reproduce.MAX_OUTPUT_BYTES // (1024 * 1024),
        "MAX_NEST_DEPTH": container.DocxPlusReader.MAX_NEST_DEPTH,
        "SRC_MODULE_COUNT": _count_src_modules(root),
        "TEST_COUNT": _count_test_functions(root),
        "COVERAGE_GATE": _coverage_gate(root),
        "CLI_COMMANDS": ", ".join(_cli_commands(root)),
        "CLI_COMMAND_COUNT": len(_cli_commands(root)),
    }
    if include_dossier:
        table, count = dossier_table()
        v["DOSSIER_TABLE"] = table
        v["DOSSIER_MODULE_COUNT"] = count
    return {k: str(val) for k, val in v.items()}

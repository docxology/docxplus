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

from . import channels
from . import container
from . import crypto
from . import lsb
from . import opc
from . import payloads
from . import reproduce
from . import shamir
from .channels.metadata import MAX_PAYLOAD as METADATA_MAX
from .project_paths import project_root

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


def _doc_date(root: Path) -> str:
    """Manuscript date: the last commit's date, else SOURCE_DATE_EPOCH, else today.

    Deriving from the commit keeps a re-render of the same tree byte-stable; a
    wall-clock date would make every rebuild differ from the last for no reason.
    """
    import datetime
    import os
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%cs"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return datetime.datetime.utcfromtimestamp(int(epoch)).strftime("%Y-%m-%d")
    return datetime.date.today().isoformat()


def _cli_commands(root: Path) -> list[str]:
    # `\s*` matters: a subparser registered across several lines would otherwise be
    # skipped, silently under-reporting the command count in the manuscript — the
    # exact drift this module exists to prevent.
    text = (root / "src" / "docxplus" / "cli.py").read_text()
    return sorted(set(re.findall(r'add_parser\(\s*"([a-z-]+)"', text)))


def _roundtrip_stats(root: Path) -> dict[str, str]:
    """Read the measured round-trip report, so results are cited rather than typed.

    Returns zeroes when the harness has not been run, which makes an unrun harness
    visible in the rendered manuscript instead of silently plausible.
    """
    import json

    path = root / "output" / "reports" / "project_roundtrip.json"
    if not path.is_file():
        return {"RT_CHECKS": "0", "RT_PASSED": "0", "RT_FILES": "0", "RT_DIRS": "0",
                "RT_DOCX_BYTES": "0", "RT_ODT_BYTES": "0", "RT_COMPARED": "0"}
    d = json.loads(path.read_text())
    checks = d.get("checks", [])
    return {
        "RT_CHECKS": str(len(checks)),
        "RT_PASSED": str(sum(1 for c in checks if c.get("ok"))),
        "RT_FILES": str(d.get("project", {}).get("files", 0)),
        "RT_DIRS": str(d.get("project", {}).get("directories", 0)),
        "RT_DOCX_BYTES": f"{d.get('profiles', {}).get('docx', {}).get('bytes', 0):,}",
        "RT_ODT_BYTES": f"{d.get('profiles', {}).get('odt', {}).get('bytes', 0):,}",
        "RT_COMPARED": str(
            d.get("profiles", {}).get("docx", {}).get("comparison", {}).get("files_compared", 0)
        ),
    }


def _redteam_stats(root: Path) -> tuple[int, int]:
    """Count red-team audit cycles and confirmed findings from the audit record.

    Derived, never asserted: the manuscript must not be able to claim a different
    number of audits than ``docs/redteam-audit.md`` actually documents.
    """
    text = (root / "docs" / "redteam-audit.md").read_text()
    # One cycle per release heading. The H1 is a document title, not a cycle: counting
    # it too inflated the total the moment the first cycle got its own H2.
    cycles = len(re.findall(r"^## v\d", text, re.MULTILINE))
    # One finding per numbered row of a findings table (`| 3 | medium | ...`).
    findings = len(re.findall(r"^\|\s*\d+\s*\|", text, re.MULTILINE))
    return cycles, findings


def dossier_table() -> tuple[str, int]:
    """Build the showcase dossier in memory and render its module table + count.

    The table is *generated from a real document*, so the manuscript's evaluation
    table can never disagree with what the code produces.
    """
    from .reference_docs import build_reference_dossier

    reader = build_reference_dossier()
    rows = ["| Slot | Channel | Sealing |", "| --- | --- | --- |"]
    for slot in sorted(reader.list_modules()):
        rec = reader.manifest.slot(slot)
        rows.append(f"| `{slot}` | {rec.channel} | {rec.sealing.get('mode', 'plain')} |")
    return "\n".join(rows), len(reader.list_modules())


def _doi() -> str:
    """The minted Zenodo DOI from CITATION.cff, or "" before one exists.

    CITATION.cff is the single place a DOI is written; every other surface derives
    from it, so a release cannot end up citing two different identifiers. Empty is
    a legitimate state and must render as *nothing* rather than as a placeholder —
    a document that prints "DOI: TBD" has made a false claim about its own identity.
    """
    cff = project_root() / "CITATION.cff"
    if not cff.is_file():
        return ""
    match = re.search(r'^doi:\s*"?(10\.\d{4,}/[^\s"]+)"?', cff.read_text(), re.M)
    return match.group(1) if match else ""


def variables(include_dossier: bool = True) -> dict[str, str]:
    """Compute every manuscript token value from the live system."""
    root = project_root()
    chans = channels.available_channels()
    ptypes = payloads.available_types()
    v: dict[str, object] = {
        "VERSION": _pyproject_version(root),
        "DOC_DATE": _doc_date(root),
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
        "ARGON2_MEMORY_MIB": crypto.ARGON2_MEMORY_COST_KIB // 1024,
        "ARGON2_TIME_COST": crypto.ARGON2_TIME_COST,
        "ARGON2_PARALLELISM": crypto.ARGON2_PARALLELISM,
        "ARGON2_MEMORY_MAX_MIB": crypto.MAX_ARGON2_MEMORY_COST_KIB // 1024,
        "DOI": _doi(),
        # Rendered as a whole line so the cover shows nothing at all before a DOI
        # exists, rather than an empty label or a placeholder.
        "DOI_LINE": (
            r"{\normalsize DOI: \href{https://doi.org/" + _doi() + "}{" + _doi() + r"}\par}"
            if _doi() else ""
        ),
        "METADATA_MAX_BYTES": METADATA_MAX,
        "MEDIA_CAP_256": lsb.capacity_bytes(256, 256),
        "MEDIA_CAP_512": lsb.capacity_bytes(512, 512),
        # The square carrier at which the media channel first out-carries the fixed
        # metadata ceiling. Derived, because both sides of the comparison are.
        "STEGO_CROSSOVER_PX": next(
            e for e in range(1, 8192) if lsb.capacity_bytes(e, e) >= METADATA_MAX
        ),
        "ZIP_EPOCH": "-".join(f"{n:02d}" for n in opc._FIXED_ZIP_TIME[:3]),
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
        "REDTEAM_AUDIT_COUNT": _redteam_stats(root)[0],
        "REDTEAM_FINDING_COUNT": _redteam_stats(root)[1],
        "MAX_SCRYPT_MEMORY_MIB": crypto.MAX_SCRYPT_MEMORY_BYTES // (1024 * 1024),
        "SHAMIR_MAX_SHARES": shamir.MAX_X,
        **_roundtrip_stats(root),
    }
    if include_dossier:
        table, count = dossier_table()
        v["DOSSIER_TABLE"] = table
        v["DOSSIER_MODULE_COUNT"] = count
        # Coverage is derived, so prose can never claim more than the table shows.
        # "exercises every operational mode" was written when it exercised every
        # sealing lineage but only two of the channels.
        from .reference_docs import build_reference_dossier

        reader = build_reference_dossier()
        recs = [reader.manifest.slot(s) for s in reader.list_modules()]
        chans = sorted({r.channel for r in recs})
        seals = sorted({r.sealing.get("mode", "plain") for r in recs})
        v["DOSSIER_CHANNELS"] = ", ".join(f"`{c}`" for c in chans)
        v["DOSSIER_CHANNEL_COUNT"] = len(chans)
        v["DOSSIER_SEALING"] = ", ".join(f"`{s}`" for s in seals)
        v["DOSSIER_SEALING_COUNT"] = len(seals)
    return {k: str(val) for k, val in v.items()}


__all__ = [
    "dossier_table",
    "render_text",
    "variables",
]


"""Manuscript variables: derived-not-hard-coded, resolve, and no-drift guards."""

from __future__ import annotations

import re

import channels
import container
import crypto
import lsb
import manuscript_vars
import opc
import payloads
from channels.metadata import MAX_PAYLOAD
from project_paths import project_root

_SECTIONS = sorted(
    p for p in (project_root() / "manuscript").glob("*.md")
    if p.name not in {"AGENTS.md", "README.md"}
)
_TOKEN = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def test_values_derive_from_live_constants():
    v = manuscript_vars.variables(include_dossier=False)
    assert v["KEY_BITS"] == str(crypto.KEY_BYTES * 8)
    assert v["SCRYPT_N"] == str(1 << crypto.SCRYPT_N_LOG2)
    assert v["PBKDF2_ITERATIONS"] == str(crypto.PBKDF2_ITERATIONS)
    assert v["CHANNEL_COUNT"] == str(len(channels.available_channels()))
    assert v["PAYLOAD_TYPE_COUNT"] == str(len(payloads.available_types()))
    assert v["SEALING_COUNT"] == str(len(container.SEALING_LINEAGES))
    assert v["METADATA_MAX_BYTES"] == str(MAX_PAYLOAD)
    assert v["MEDIA_CAP_256"] == str(lsb.capacity_bytes(256, 256))
    assert v["MAX_ENTRIES"] == str(opc.MAX_ENTRIES)
    assert v["MAX_NEST_DEPTH"] == str(container.DocxPlusReader.MAX_NEST_DEPTH)


def test_version_matches_pyproject():
    v = manuscript_vars.variables(include_dossier=False)
    pyproject = (project_root() / "pyproject.toml").read_text()
    assert f'version = "{v["VERSION"]}"' in pyproject


def test_dossier_table_generated_from_a_real_document():
    table, count = manuscript_vars.dossier_table()
    assert count >= 5
    assert table.startswith("| Slot | Channel | Sealing |")
    # Every sealing lineage the dossier uses is a real, registered one.
    for line in table.splitlines()[2:]:
        mode = line.rsplit("|", 2)[1].strip()
        assert mode in (*container.SEALING_LINEAGES, "plain")


def test_every_manuscript_token_resolves():
    known = set(manuscript_vars.variables())
    for path in _SECTIONS:
        for token in _TOKEN.findall(path.read_text()):
            assert token in known, f"{path.name} uses undefined token {token!r}"


def test_manuscript_sources_hardcode_no_drift_prone_values():
    """The point of the token system: a drift-prone value must appear only as a
    token in the sources, never as a literal a future code change would strand."""
    v = manuscript_vars.variables()
    guarded = [
        "TEST_COUNT", "MEDIA_CAP_256", "MEDIA_CAP_512",
        "PBKDF2_ITERATIONS", "METADATA_MAX_BYTES",
    ]
    blob = "\n".join(p.read_text() for p in _SECTIONS)
    for name in guarded:
        literal = v[name]
        assert literal not in blob, (
            f"manuscript hard-codes {name}={literal}; use {{{{{name}}}}} instead"
        )


def test_generator_and_renderer_produce_clean_output():
    # A section rendered with the live values must contain no leftover token braces.
    values = manuscript_vars.variables()
    for path in _SECTIONS:
        rendered, missing = manuscript_vars.render_text(path.read_text(), values)
        assert not missing
        assert "{{" not in rendered

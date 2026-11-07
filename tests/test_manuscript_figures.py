"""Check exported manuscript artifacts at their consumer-visible boundaries."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET

import pytest

pytest.importorskip("matplotlib")

from docxplus import manuscript_figures, manuscript_vars

SVG = "{http://www.w3.org/2000/svg}"


@pytest.fixture(autouse=True)
def _isolate_figures():
    """Keep renderer settings and figures local, including when an assertion fails."""
    import matplotlib as mpl
    from matplotlib import pyplot as plt

    existing = set(plt.get_fignums())
    with mpl.rc_context({"svg.fonttype": "none", "svg.hashsalt": "figure-claims"}):
        try:
            yield
        finally:
            for number in set(plt.get_fignums()) - existing:
                plt.close(number)


def _svg(tmp_path, builder, v, *args):
    out = tmp_path / f"{builder.__name__}.svg"
    builder(out, v, *args)
    return ET.parse(out).getroot()


def _texts(svg):
    return list(svg.iter(f"{SVG}text"))


def _text(svg, value):
    matches = [t for t in _texts(svg) if t.text == value]
    assert len(matches) == 1, value
    return matches[0]


def _xy(text):
    return float(text.attrib["x"]), float(text.attrib["y"])


def _vertices(path):
    # Matplotlib's unrotated diagram paths use absolute M/L/Q coordinates.
    numbers = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?(?:e[+-]?\d+)?",
                                          path.attrib["d"])]
    return list(zip(numbers[::2], numbers[1::2]))


@pytest.fixture(scope="module")
def v() -> dict:
    return manuscript_vars.variables(include_dossier=False)


def _digest(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cover_export_keeps_its_dark_ground_and_readable_foreground(tmp_path, v):
    """An axes-only background vanished when axis('off') exported pale type on white."""
    import numpy as np
    from PIL import Image

    out = tmp_path / "cover.png"
    manuscript_figures.build_cover_art(out, v)
    with Image.open(out) as image:
        # Sample the full-resolution export without allocating several large
        # floating-point copies of a print-resolution plate.
        rgba = np.asarray(image.convert("RGBA"))[::4, ::4]

    # The document viewer's page colour must not become the cover's background.
    assert np.all(rgba[:, :, 3] == 255)
    rgb = rgba[:, :, :3].astype(np.float32) / 255
    linear = np.where(rgb <= 0.04045, rgb / 12.92, ((rgb + 0.055) / 1.055) ** 2.4)
    luminance = linear @ np.array([0.2126, 0.7152, 0.0722])
    height, width = luminance.shape
    margin_h, margin_w = height // 100, width // 100
    corners = (
        luminance[:margin_h, :margin_w],
        luminance[:margin_h, -margin_w:],
        luminance[-margin_h:, :margin_w],
        luminance[-margin_h:, -margin_w:],
    )
    for corner in corners:
        assert np.quantile(corner, 0.99) < 0.05

    # A broad title band, not a glyph/pixel snapshot: antialiasing and font
    # substitutions may move edges, but the light foreground must remain legible.
    title_band = luminance[:height // 3]
    ground = float(np.median(title_band))
    assert ground < 0.05
    assert (float(np.quantile(title_band, 0.999)) + 0.05) / (ground + 0.05) >= 4.5


def test_trust_ladder_renders_deterministically(tmp_path, v):
    out = tmp_path / "trust_ladder.png"
    manuscript_figures.build_trust_ladder(out, v)
    first = _digest(out)
    manuscript_figures.build_trust_ladder(out, v)
    assert first == _digest(out)


def test_byte_labels_use_binary_prefixes():
    assert manuscript_figures._fmt(512) == "512 B"
    assert manuscript_figures._fmt(2048) == "2.0 KiB"
    assert manuscript_figures._fmt(3 * 1024 * 1024) == "3.0 MiB"


def test_architecture_places_each_capacity_on_its_transport_row(tmp_path, v):
    from docxplus import channels
    from docxplus.channels.metadata import MAX_PAYLOAD

    svg = _svg(tmp_path, manuscript_figures.build_architecture_diagram, v)
    rows = {
        "metadata": "docProps/custom.xml",
        "mce": "word/document.xml",
        "stego_media": "media/imageN.png",
        "custom_xml": "customXml/itemN.xml",
        "package_part": "intelligence/payloadN.dxp",
    }
    assert set(rows) == set(channels.available_channels())
    part_positions = {part: _xy(_text(svg, part)) for part in rows.values()}
    for channel, part in rows.items():
        channel_x, channel_y = _xy(_text(svg, channel))
        assert channel_x > part_positions[part][0]
        # Row association matters; font-dependent glyph baselines do not.
        assert min(part_positions, key=lambda name: abs(part_positions[name][1] - channel_y)) == part
    capacity = next(t for t in _texts(svg) if re.fullmatch(r"≤ [\d,]+ B", t.text or ""))
    assert int(re.search(r"[\d,]+", capacity.text)[0].replace(",", "")) == MAX_PAYLOAD
    assert min(rows, key=lambda name: abs(_xy(_text(svg, name))[1] - _xy(capacity)[1])) == "metadata"
    assert _xy(capacity)[0] > _xy(_text(svg, "metadata"))[0]


def test_crypto_artifact_reports_shipped_lineages_and_work_factors(tmp_path, v):
    from docxplus import container, crypto, shamir

    svg = _svg(tmp_path, manuscript_figures.build_crypto_diagram, v)
    labels = [t.text or "" for t in _texts(svg)]
    assert {label for label in labels if label in container.SEALING_LINEAGES} == set(
        container.SEALING_LINEAGES
    )
    text = "\n".join(labels)
    assert int(re.search(r"AES-(\d+)-GCM", text)[1]) == crypto.KEY_BYTES * 8
    assert int(re.search(r"n ≤ (\d+)", text)[1]) == shamir.MAX_X
    assert int(re.search(r"Argon2id (\d+) MiB", text)[1]) * 1024 == crypto.ARGON2_MEMORY_COST_KIB
    assert int(re.search(r"Scrypt 2\^(\d+)", text)[1]) == crypto.SCRYPT_N_LOG2
    assert int(re.search(r"PBKDF2 ([\d,]+)", text)[1].replace(",", "")) == crypto.PBKDF2_ITERATIONS
    assert int(re.search(r"capped at (\d+) MiB", text)[1]) * 1024**2 == crypto.MAX_SCRYPT_MEMORY_BYTES
    # Password work factors must not visually become dependencies of recipient or
    # threshold sealing: the KDF is below the password lane, not in another lane.
    password_y = _xy(_text(svg, "password"))[1]
    assert password_y > _xy(_text(svg, "threshold"))[1]
    assert _xy(_text(svg, "key derivation"))[1] > password_y


def test_fidelity_artifact_distinguishes_missing_measurements_and_failed_checks(tmp_path, v):
    absent = _svg(tmp_path, manuscript_figures.build_fidelity_figure, v, None)
    absent_text = "\n".join(t.text or "" for t in _texts(absent))
    assert re.search(r"\b(\d+)/(\d+) invariants", absent_text).groups() == ("0", "0")
    assert re.search(r"(\S+) files", absent_text)[1] == "?"

    # Match the harness schema, but include an explicit failure and an unevaluated
    # check. Neither may be counted as success, even if a stale top-level summary is.
    report = {
        "ok": True,
        "project": {"files": 17, "directories": 9},
        "checks": [{"ok": True}, {"ok": False}, {}],
        "fidelity_boundary": {
            "preserved": ["file contents", "executable bit", "empty directories",
                          "directory structure", "non-ASCII and spaced filenames",
                          "zero-byte files"],
            "normalised_by_design": ["mtimes", "uid/gid", "non-execute mode bits"],
            "refused": ["symlinks (their targets would be embedded)"],
            "excluded_by_policy": [".venv", "__pycache__"],
        },
    }
    measured = _svg(tmp_path, manuscript_figures.build_fidelity_figure, v, report)
    text = "\n".join(t.text or "" for t in _texts(measured))
    assert re.search(r"\b(\d+)/(\d+) invariants", text).groups() == ("1", "3")
    # Refusal branches above the preserved route; normalisation and exclusion
    # branch below it. Do not pin font-specific multiline text transforms.
    preserved_x, preserved_y = _xy(_text(measured, "PRESERVED"))
    assert _xy(_text(measured, "pack"))[0] < preserved_x < _xy(_text(measured, "unpack"))[0]
    assert _xy(_text(measured, "REFUSED"))[1] < preserved_y
    for category in ("NORMALISED", "EXCLUDED"):
        assert _xy(_text(measured, category))[1] > preserved_y


def test_parity_artifact_includes_both_real_odf_transports(tmp_path, v):
    from docxplus import channels
    from docxplus.odt_container import OdtPlusBuilder, OdtPlusReader

    builder = OdtPlusBuilder()
    payloads = {"entry": b"package payload", "image": b"concealed payload"}
    builder.add_module("entry", payloads["entry"])
    builder.add_module("image", payloads["image"], channel_id="stego_media",
                       backend="python_lsb", carrier_size=(32, 32))
    reader = OdtPlusReader.from_bytes(builder.build())
    assert {slot: reader.extract(slot) for slot in payloads} == payloads
    carried = {reader.manifest.slot(slot).channel for slot in payloads}

    svg = _svg(tmp_path, manuscript_figures.build_parity_figure, v)
    core_x = _xy(_text(svg, "ONE SHARED IMPLEMENTATION"))[0]
    native_labels = [
        t for t in _texts(svg)
        if t.text in set(channels.available_channels()) | carried
    ]
    assert {t.text for t in native_labels if _xy(t)[0] > core_x} == carried
    assert {t.text for t in native_labels if _xy(t)[0] < core_x} == (
        set(channels.available_channels()) - {"package_part", "stego_media"}
    )


def test_redteam_attack_arrows_stop_at_their_layer_boundary(tmp_path, v):
    svg = _svg(tmp_path, manuscript_figures.build_redteam_matrix, v)
    walls = []
    for group in svg.iter(f"{SVG}g"):
        if not group.attrib.get("id", "").startswith("line2d_"):
            continue
        for path in group.findall(f"{SVG}path"):
            points = _vertices(path)
            if len(points) == 2 and points[0][0] == points[1][0]:
                walls.append(points)
    # Each independently coloured trust layer has a wall. Every attack shaft and
    # arrowhead stays on the attacker's side of the wall for its own layer.
    assert len(walls) == 4
    attacked_layers = set()
    for group in svg.iter(f"{SVG}g"):
        if not group.attrib.get("id", "").startswith("patch_"):
            continue
        paths = [p for p in group.findall(f"{SVG}path")
                 if f"stroke: {manuscript_figures.RISK.lower()}" in p.attrib.get("style", "")]
        if not paths:
            continue
        points = [point for path in paths for point in _vertices(path)]
        mid_y = (min(y for _, y in points) + max(y for _, y in points)) / 2
        layer = next(i for i, wall in enumerate(walls)
                     if min(y for _, y in wall) < mid_y < max(y for _, y in wall))
        attacked_layers.add(layer)
        assert max(x for x, _ in points) <= walls[layer][0][0]
        assert min(x for x, _ in points) < walls[layer][0][0]
    assert attacked_layers == set(range(len(walls)))


def test_reproduction_artifact_keeps_execution_gate_off_default_branch(tmp_path, v):
    from docxplus import reproduce

    svg = _svg(tmp_path, manuscript_figures.build_reproduction_diagram, v)
    text = "\n".join(t.text or "" for t in _texts(svg))
    assert int(re.search(r"timeout beyond (\d+) s", text)[1]) == reproduce.MAX_REPRO_SECONDS
    default = next(t for t in _texts(svg) if (t.text or "").startswith("DEFAULT"))
    opt_in = next(t for t in _texts(svg) if (t.text or "").startswith("OPT-IN"))
    default_x, default_y = _xy(default)
    opt_in_x, opt_in_y = _xy(opt_in)
    gate_x, gate_y = _xy(_text(svg, "--allow-execution"))
    assert default_y == pytest.approx(opt_in_y)
    assert default_x < gate_x < opt_in_x
    assert gate_y > opt_in_y

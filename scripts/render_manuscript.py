#!/usr/bin/env python3
"""Render the token-driven manuscript → output/manuscript/.

Substitutes ``{{TOKEN}}`` in each manuscript source with values generated from the
live system (`manuscript_vars.variables`). Fails loudly on any unresolved token, so a
manuscript that references a variable the generator does not produce cannot ship.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from manuscript_vars import render_text, variables
from project_paths import ensure_output_dirs, project_root


def main() -> int:
    values = variables()
    src_dir = project_root() / "manuscript"
    out_dir = ensure_output_dirs()["output"] / "manuscript"
    out_dir.mkdir(parents=True, exist_ok=True)

    unresolved: set[str] = set()
    rendered: list[Path] = []
    for path in sorted(src_dir.glob("*.md")):
        if path.name in {"AGENTS.md", "README.md"}:  # not manuscript sections
            continue
        text, missing = render_text(path.read_text(), values)
        unresolved |= missing
        dest = out_dir / path.name
        dest.write_text(text)
        rendered.append(dest)

    for dest in rendered:
        print(str(dest))
    if unresolved:
        sys.stderr.write(f"unresolved manuscript tokens: {sorted(unresolved)}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

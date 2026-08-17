#!/usr/bin/env python3
"""Write a minted Zenodo DOI into every surface that must cite it.

Run once, after Zenodo has minted the DOI for a GitHub release:

    uv run python scripts/set_doi.py 10.5281/zenodo.NNNNNNN

`CITATION.cff` is the single source: `manuscript_vars._doi()` reads it, so the
manuscript picks the DOI up as a token and it reaches the PDF on the next render
without anyone editing the paper. The other files here are formats that cannot
read CITATION.cff for themselves, so they are written rather than derived.

The DOI is validated against the Zenodo API before anything is written. A
citation identifier that does not resolve is worse than an absent one: absent is
visibly incomplete, wrong is quietly permanent.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Installed, `docxplus` is a real package and this is a no-op. Run out of a checkout
# the package lives under src/ and nothing has put it on the path yet. Importing
# first keeps an installed copy authoritative instead of being shadowed.
try:  # pragma: no cover - one branch or the other, trivially
    import docxplus as _docxplus  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from docxplus.project_paths import project_root

DOI_RE = re.compile(r"^10\.\d{4,}/zenodo\.\d+$")


def resolves(doi: str, *, timeout: int = 20) -> tuple[bool, str]:
    """Confirm the DOI is real and ours, published or reserved.

    A published DOI is a public record and needs no credentials. A *reserved* one
    exists only as a draft deposition, so it 404s on the records API and can be
    checked only with the token that reserved it. Both are verified, because the
    reserved case is the one that matters here: the PDF has to print the DOI
    before the record carrying that PDF can be published, so the identifier is
    always written while still reserved.

    What is never allowed is writing a DOI on trust. An identifier that does not
    resolve is worse than an absent one — absent is visibly incomplete, wrong is
    quietly permanent.
    """
    record = doi.rsplit(".", 1)[-1]
    url = f"https://zenodo.org/api/records/{record}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.load(response)
        title = data.get("metadata", {}).get("title", "")
        if "docxplus" not in title.lower():
            return False, f"published record {record} is titled {title!r}, not this project"
        return True, f"published record: {title}"
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return False, f"Zenodo returned HTTP {exc.code} for {url}"
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return False, f"could not reach Zenodo: {exc}"

    token = os.environ.get("ZENODO_PROD_TOKEN", "").strip()
    if not token:
        return False, (
            f"DOI {doi} is not a published record, and ZENODO_PROD_TOKEN is unset so a "
            "reserved draft cannot be checked either"
        )
    request = urllib.request.Request(
        f"https://zenodo.org/api/deposit/depositions/{record}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            draft = json.load(response)
    except urllib.error.HTTPError as exc:
        return False, f"no published record and no draft deposition {record} (HTTP {exc.code})"
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return False, f"could not reach Zenodo: {exc}"

    reserved = draft.get("metadata", {}).get("prereserve_doi", {}).get("doi")
    title = draft.get("metadata", {}).get("title", "")
    if reserved != doi:
        return False, f"draft {record} reserves {reserved!r}, not {doi!r}"
    if "docxplus" not in title.lower():
        return False, f"draft {record} is titled {title!r}, not this project"
    return True, f"reserved on draft deposition {record}: {title}"


def concept_doi(version_doi: str, *, timeout: int = 20) -> str:
    """The record's concept DOI, which always resolves to the latest version."""
    record = version_doi.rsplit(".", 1)[-1]
    try:
        with urllib.request.urlopen(
            f"https://zenodo.org/api/records/{record}", timeout=timeout
        ) as response:
            return json.load(response).get("conceptdoi", "") or ""
    except Exception:
        pass
    # A reserved DOI has no public record yet, and the badge is written *before*
    # publication so the released README is correct on the day it ships. The draft
    # knows its own concept DOI, so ask it.
    token = os.environ.get("ZENODO_PROD_TOKEN", "").strip()
    if not token:
        return ""
    request = urllib.request.Request(
        f"https://zenodo.org/api/deposit/depositions/{record}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response).get("conceptdoi", "") or ""
    except Exception:
        return ""


def apply(doi: str) -> list[str]:
    root = project_root()
    touched: list[str] = []

    cff = root / "CITATION.cff"
    text = cff.read_text()
    if re.search(r"^doi:", text, re.M):
        text = re.sub(r"^doi:.*$", f'doi: "{doi}"', text, count=1, flags=re.M)
    else:
        text = re.sub(
            r'^(repository-code:.*)$', rf'\1\ndoi: "{doi}"', text, count=1, flags=re.M
        )
    cff.write_text(text)
    touched.append("CITATION.cff")

    for name, key in (("codemeta.json", "identifier"), (".zenodo.json", "doi")):
        path = root / name
        if not path.is_file():
            continue
        data = json.loads(path.read_text())
        data[key] = doi if name == ".zenodo.json" else f"https://doi.org/{doi}"
        path.write_text(json.dumps(data, indent=2) + "\n")
        touched.append(name)

    # The README badge cites the *concept* DOI, which Zenodo resolves to whatever
    # the latest version is. A badge pinned to a version DOI goes stale the moment
    # the next release lands, and a reader following it lands on an old artefact
    # while believing they are looking at the current one.
    concept = concept_doi(doi) or doi
    readme = root / "README.md"
    text = original = readme.read_text()
    badge = f"[![DOI](https://zenodo.org/badge/DOI/{concept}.svg)](https://doi.org/{concept})"
    existing = re.compile(r"\[!\[DOI\]\(https://zenodo\.org/badge/DOI/10\.\d{4,}/zenodo\.\d+\.svg\)\]\([^)]+\)")
    if existing.search(text):
        # Replace rather than append. Appending left two badges citing different
        # records, which is worse than citing none.
        text = existing.sub(badge, text)
    else:
        lines = text.splitlines()
        insert_at = next((i + 1 for i, line in enumerate(lines) if line.startswith("# ")), 0)
        lines.insert(insert_at, "\n" + badge)
        text = "\n".join(lines) + "\n"
    # Any other bare mention of a superseded version DOI is rewritten too.
    text = re.sub(r"10\.\d{4,}/zenodo\.\d+", lambda m: m.group(0) if m.group(0) in {doi, concept} else doi, text)
    if text != original:
        readme.write_text(text)
        touched.append("README.md")

    return touched


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write(f"usage: {sys.argv[0]} 10.5281/zenodo.NNNNNNN\n")
        return 2
    doi = sys.argv[1].strip().removeprefix("https://doi.org/")
    if not DOI_RE.match(doi):
        sys.stderr.write(f"not a Zenodo DOI: {doi!r}\n")
        return 2

    ok, detail = resolves(doi)
    if not ok:
        sys.stderr.write(f"refusing to write an unverified DOI — {detail}\n")
        return 1

    touched = apply(doi)
    print(f"verified against Zenodo: {detail}")
    for name in touched:
        print(f"  wrote {name}")
    print("\nNow re-render so the DOI reaches the PDF:  ./run.sh render")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

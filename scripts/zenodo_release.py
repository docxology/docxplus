#!/usr/bin/env python3
"""Create, populate, and publish the Zenodo record for a docxplus release.

Three subcommands, run in this order, because the DOI has to exist *before* the
PDF that prints it is built:

    reserve   create a draft and reserve its DOI (prints the DOI, publishes nothing)
    upload    attach files to the draft
    publish   make the record public and mint the reserved DOI for real

Zenodo's ``prereserve_doi`` is what breaks the circularity. Without it the DOI
only exists after publication, so either the archived PDF cannot cite its own
record or a second version has to be uploaded immediately to fix it. Reserving
first means one record, one DOI, and a PDF that carries it.

Metadata comes from ``.zenodo.json`` so the record and the repository cannot
disagree, with the GitHub repository attached as a related identifier in both
directions: Zenodo points at the release, the release points at the DOI.

The token is read from the environment and never written anywhere.
"""

from __future__ import annotations

import json
import os
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

API = "https://zenodo.org/api"
REPO_URL = "https://github.com/docxology/docxplus"
TOKEN_ENV = "ZENODO_PROD_TOKEN"


def _token() -> str:
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        sys.stderr.write(f"{TOKEN_ENV} is not set\n")
        raise SystemExit(2)
    return token


def _call(method: str, path: str, *, payload: dict | None = None, raw: bytes | None = None,
          content_type: str = "application/json") -> dict:
    url = path if path.startswith("http") else f"{API}{path}"
    body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Authorization", f"Bearer {_token()}")
    if body is not None:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            text = response.read()
            return json.loads(text) if text else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:600]
        sys.stderr.write(f"Zenodo {method} {url} -> HTTP {exc.code}\n{detail}\n")
        raise SystemExit(1) from None


def _metadata(version: str) -> dict:
    source = json.loads((project_root() / ".zenodo.json").read_text())
    return {
        "title": source["title"],
        "description": source["description"],
        "upload_type": source.get("upload_type", "software"),
        "license": source.get("license", "MIT").lower(),
        "keywords": source.get("keywords", []),
        "creators": source["creators"],
        "version": version,
        # The cross-reference Zenodo shows on the record page. Its counterpart —
        # the DOI badge and CITATION.cff entry — is written by scripts/set_doi.py.
        "related_identifiers": [
            {"identifier": f"{REPO_URL}/tree/v{version}",
             "relation": "isSupplementTo", "scheme": "url"},
        ],
        "prereserve_doi": True,
    }


def reserve(version: str) -> None:
    draft = _call("POST", "/deposit/depositions", payload={"metadata": _metadata(version)})
    doi = draft["metadata"]["prereserve_doi"]["doi"]
    print(json.dumps({"deposition_id": draft["id"], "doi": doi,
                      "bucket": draft["links"]["bucket"]}, indent=2))


def upload(deposition_id: str, paths: list[str]) -> None:
    draft = _call("GET", f"/deposit/depositions/{deposition_id}")
    bucket = draft["links"]["bucket"]
    for path in paths:
        file_path = Path(path)
        data = file_path.read_bytes()
        _call("PUT", f"{bucket}/{file_path.name}", raw=data,
              content_type="application/octet-stream")
        print(f"  uploaded {file_path.name} ({len(data):,} bytes)")


def publish(deposition_id: str) -> None:
    record = _call("POST", f"/deposit/depositions/{deposition_id}/actions/publish")
    print(json.dumps({"doi": record["doi"], "record": record["links"]["record_html"],
                      "state": record["state"]}, indent=2))


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__ or "")
        return 2
    command = sys.argv[1]
    if command == "reserve":
        reserve(sys.argv[2])
    elif command == "upload":
        upload(sys.argv[2], sys.argv[3:])
    elif command == "publish":
        publish(sys.argv[2])
    else:
        sys.stderr.write(f"unknown command: {command}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
import urllib.parse
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


def _provider_url(path: str, *, api: str = API) -> str:
    """Admit HTTPS URLs only at the configured provider authority."""
    try:
        base = urllib.parse.urlsplit(api)
        target = urllib.parse.urlsplit(path)
        if not target.scheme and not target.netloc and path.startswith("/"):
            path = f"{api.rstrip('/')}{path}"
            target = urllib.parse.urlsplit(path)
        trusted = (
            base.scheme == target.scheme == "https"
            and base.hostname is not None
            and target.hostname == base.hostname
            and (target.port if target.port is not None else 443)
            == (base.port if base.port is not None else 443)
            and base.username is None
            and base.password is None
            and target.username is None
            and target.password is None
            and not target.fragment
        )
    except ValueError:
        trusted = False
    if not trusted:
        raise urllib.error.URLError(
            "refusing Zenodo URL: HTTPS at the configured provider authority is required"
        )
    return path


class _ProviderRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, api: str) -> None:
        self.api = api

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib can copy Authorization into redirected requests. Check before
        # constructing that request, including HTTPS-to-HTTP downgrades.
        _provider_url(newurl, api=self.api)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _provider_open(
    request: str | urllib.request.Request, *, api: str = API, timeout: int = 180,
):
    """Open a provider request without forwarding credentials to another origin."""
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    _provider_url(url, api=api)
    opener = urllib.request.build_opener(_ProviderRedirectHandler(api))
    return opener.open(request, timeout=timeout)


def _token() -> str:
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        sys.stderr.write(f"{TOKEN_ENV} is not set\n")
        raise SystemExit(2)
    return token


def _call(method: str, path: str, *, payload: dict | None = None, raw: bytes | None = None,
          content_type: str = "application/json", api: str = API) -> dict:
    url = _provider_url(path, api=api)
    body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Authorization", f"Bearer {_token()}")
    if body is not None:
        request.add_header("Content-Type", content_type)
    try:
        with _provider_open(request, api=api) as response:
            text = response.read()
            return json.loads(text) if text else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:600]
        sys.stderr.write(f"Zenodo {method} {url} -> HTTP {exc.code}\n{detail}\n")
        raise SystemExit(1) from None
    except urllib.error.URLError as exc:
        sys.stderr.write(f"Zenodo request refused or failed: {exc.reason}\n")
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


def upload(deposition_id: str, paths: list[str], *, api: str = API) -> None:
    draft = _call("GET", f"/deposit/depositions/{deposition_id}", api=api)
    bucket = _provider_url(draft["links"]["bucket"], api=api)
    for path in paths:
        file_path = Path(path)
        data = file_path.read_bytes()
        name = urllib.parse.quote(file_path.name, safe="")
        _call("PUT", f"{bucket.rstrip('/')}/{name}", raw=data,
              content_type="application/octet-stream", api=api)
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
    try:
        if command == "reserve":
            reserve(sys.argv[2])
        elif command == "upload":
            upload(sys.argv[2], sys.argv[3:])
        elif command == "publish":
            publish(sys.argv[2])
        else:
            sys.stderr.write(f"unknown command: {command}\n")
            return 2
    except urllib.error.URLError as exc:
        sys.stderr.write(f"Zenodo request refused or failed: {exc.reason}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

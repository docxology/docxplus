"""Exact DOI identity and DEL-12 credential custody over real local TLS sockets."""

from __future__ import annotations

import datetime as dt
import importlib
import ipaddress
import json
import ssl
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from docxplus.project_paths import project_root

TOKEN = "local-nonsecret-provider-sentinel"
DOI = "10.5281/zenodo.12345"


@pytest.fixture
def scripts(monkeypatch):
    monkeypatch.syspath_prepend(str(project_root() / "scripts"))
    monkeypatch.setenv("ZENODO_PROD_TOKEN", TOKEN)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    return SimpleNamespace(
        provider=importlib.import_module("zenodo_release"),
        doi=importlib.import_module("set_doi"),
    )


@pytest.fixture
def local_provider(tmp_path, monkeypatch):
    """Serve real HTTPS with an ephemeral local certificate, never production."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "local-test-cert.pem"
    key_path = tmp_path / "local-test-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))
    servers = []

    def start(*, tls=True):
        requests = []
        routes = {}

        class Handler(BaseHTTPRequestHandler):
            def handle_request(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                requests.append((self.command, self.path, self.headers.get("Authorization"), body))
                status, headers, data = routes.get(self.path, (404, {}, {}))
                encoded = json.dumps(data).encode()
                self.send_response(status)
                for header, value in headers.items():
                    self.send_header(header, value)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = handle_request
            do_POST = handle_request
            do_PUT = handle_request

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        origin = f"{'https' if tls else 'http'}://127.0.0.1:{server.server_port}"
        return SimpleNamespace(origin=origin, api=f"{origin}/api", routes=routes, requests=requests)

    yield start
    for server, thread in servers:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.parametrize("url", [
    "http://zenodo.org/api/files/bucket",
    "https://zenodo.org.evil.invalid/api/files/bucket",
    "https://zenodo.org@evil.invalid/api/files/bucket",
    "https://untrusted@zenodo.org/api/files/bucket",
    "https://zenodo.org:444/api/files/bucket",
    "https://zenodo.org:0/api/files/bucket",
    "https://zenodo.org/api/files/bucket#fragment",
    "//evil.invalid/api/files/bucket",
    "https://[invalid",
])
def test_provider_url_rejects_untrusted_authorities(scripts, url):
    """DEL-12: links cannot select another authority or downgrade transport."""
    with pytest.raises(urllib.error.URLError, match="HTTPS.*provider authority"):
        scripts.provider._provider_url(url)


def test_upload_valid_bucket_and_filename(scripts, local_provider, tmp_path):
    """A same-authority HTTPS bucket receives exact bytes and the sentinel token."""
    server = local_provider()
    server.routes["/api/deposit/depositions/12345"] = (
        200, {}, {"links": {"bucket": f"{server.origin}/api/files/bucket"}},
    )
    server.routes["/api/files/bucket/fixture%20%23%3F.bin"] = (200, {}, {"ok": True})
    artifact = tmp_path / "fixture #?.bin"
    artifact.write_bytes(b"release\x00fixture")
    scripts.provider.upload("12345", [str(artifact)], api=server.api)
    assert server.requests == [
        ("GET", "/api/deposit/depositions/12345", f"Bearer {TOKEN}", b""),
        ("PUT", "/api/files/bucket/fixture%20%23%3F.bin", f"Bearer {TOKEN}", b"release\x00fixture"),
    ]


@pytest.mark.parametrize("tls", [True, False])
def test_upload_rejects_foreign_or_plaintext_bucket(scripts, local_provider, tls, tmp_path):
    """DEL-12: a hostile bucket fails before even opening the upload file."""
    server = local_provider()
    foreign = local_provider(tls=tls)
    server.routes["/api/deposit/depositions/12345"] = (
        200, {}, {"links": {"bucket": f"{foreign.origin}/bucket"}},
    )
    with pytest.raises(urllib.error.URLError, match="HTTPS.*provider authority"):
        scripts.provider.upload("12345", [str(tmp_path / "does-not-exist")], api=server.api)
    assert len(server.requests) == 1
    assert foreign.requests == []


@pytest.mark.parametrize("method,code", [("GET", 302), ("POST", 303), ("PUT", 307)])
@pytest.mark.parametrize("tls", [True, False])
def test_provider_redirect_never_reaches_foreign_origin(
    scripts, local_provider, capsys, method, code, tls,
):
    """DEL-12: reject redirects before another origin can see Authorization."""
    server = local_provider()
    foreign = local_provider(tls=tls)
    server.routes["/api/redirect"] = (code, {"Location": f"{foreign.origin}/capture"}, {})
    with pytest.raises(SystemExit) as exc:
        scripts.provider._call(method, "/redirect", api=server.api)
    assert exc.value.code == 1
    assert "HTTPS at the configured provider authority" in capsys.readouterr().err
    assert server.requests[0][2] == f"Bearer {TOKEN}"
    assert foreign.requests == []


def test_same_origin_redirect_remains_usable(scripts, local_provider):
    """Safe provider redirects retain normal authenticated GET behavior."""
    server = local_provider()
    server.routes["/api/redirect"] = (302, {"Location": "/api/result"}, {})
    server.routes["/api/result"] = (200, {}, {"ok": True})
    assert scripts.provider._call("GET", "/redirect", api=server.api) == {"ok": True}
    assert [request[2] for request in server.requests] == [f"Bearer {TOKEN}"] * 2


@pytest.mark.parametrize("returned", ["10.9999/zenodo.12345", "10.5281/zenodo.12346", None])
def test_public_numeric_record_requires_exact_doi(scripts, local_provider, returned):
    """Matching numeric suffix and title cannot authorize a different full DOI."""
    server = local_provider()
    server.routes["/api/records/12345"] = (
        200, {}, {"doi": returned, "metadata": {"title": "docxplus"}, "conceptdoi": DOI},
    )
    ok, detail = scripts.doi.resolves(DOI, api=server.api)
    assert not ok
    assert "identifies DOI" in detail
    assert scripts.doi.concept_doi(DOI, api=server.api) == ""
    assert all(request[2] is None for request in server.requests)


@pytest.mark.parametrize("returned", [DOI, " HTTPS://DOI.ORG/10.5281/ZENODO.12345 "])
def test_public_exact_doi_normalization_control(scripts, local_provider, returned):
    """Canonical normalization matches full identifiers without claiming ownership."""
    server = local_provider()
    server.routes["/api/records/12345"] = (
        200, {}, {"doi": returned, "metadata": {"title": "An operator-selected release"},
                  "conceptdoi": "10.5281/zenodo.12000"},
    )
    ok, detail = scripts.doi.resolves(f"https://doi.org/{DOI}", api=server.api)
    assert ok, detail
    assert scripts.doi.concept_doi(DOI, api=server.api) == "10.5281/zenodo.12000"
    assert all(request[2] is None for request in server.requests)


@pytest.mark.parametrize("returned,expected", [
    ("10.9999/zenodo.12345", False),
    ("10.5281/zenodo.12346", False),
    (DOI, True),
    ("https://doi.org/10.5281/ZENODO.12345", True),
])
def test_reserved_draft_uses_same_exact_doi_rule(scripts, local_provider, returned, expected):
    """A 404 may fall back to an authenticated draft, never suffix-only identity."""
    server = local_provider()
    server.routes["/api/deposit/depositions/12345"] = (
        200, {}, {"metadata": {"title": "An operator-selected draft",
                              "prereserve_doi": {"doi": returned}},
                  "conceptdoi": "10.5281/zenodo.12000"},
    )
    ok, detail = scripts.doi.resolves(DOI, api=server.api)
    assert ok is expected
    if not expected:
        assert "reserves" in detail
    concept = scripts.doi.concept_doi(DOI, api=server.api)
    assert concept == ("10.5281/zenodo.12000" if expected else "")
    assert server.requests[0][2] is None
    assert server.requests[1][2] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("operation", ["resolves", "concept_doi"])
def test_authenticated_doi_lookup_rejects_foreign_redirect(
    scripts, local_provider, operation,
):
    """Both DOI draft consumers use the credential-safe provider transport."""
    server = local_provider()
    foreign = local_provider()
    server.routes["/api/deposit/depositions/12345"] = (
        302, {"Location": f"{foreign.origin}/capture"}, {},
    )
    result = getattr(scripts.doi, operation)(DOI, api=server.api)
    if operation == "resolves":
        ok, detail = result
        assert not ok
        assert "HTTPS at the configured provider authority" in detail
    else:
        assert result == ""
    assert server.requests[1][2] == f"Bearer {TOKEN}"
    assert foreign.requests == []

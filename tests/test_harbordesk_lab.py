"""The vulnerable target is deliberately weak; its containment must not be."""

import io
import json
import sqlite3
from email.parser import Parser
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from labs.harbordesk import app, verify


class Connection:
    def __init__(self, raw):
        self.input = io.BytesIO(raw)
        self.output = bytearray()

    def makefile(self, *_args, **_kwargs):
        return self.input

    def sendall(self, raw):
        self.output.extend(raw)


def request(path, *, method="GET", body=b"", host="127.0.0.1:8787", headers=None, server=None):
    fields = {"Host": host, "Content-Length": str(len(body)), **(headers or {})}
    raw = (
        f"{method} {path} HTTP/1.1\r\n"
        + "".join(f"{key}: {value}\r\n" for key, value in fields.items())
        + "\r\n"
    ).encode() + body
    connection = Connection(raw)
    if server is None:
        server = SimpleNamespace(
            server_address=("127.0.0.1", 8787),
            workspace=app.Workspace(),
            secure_workspace=app.Workspace(),
        )
    app.Handler(connection, ("127.0.0.1", 1), server)
    header, content = bytes(connection.output).split(b"\r\n\r\n", 1)
    status, rest = header.decode().split("\r\n", 1)
    return int(status.split()[1]), Parser().parsestr(rest), content


def test_all_eight_ground_truth_cases_reproduce_offline(monkeypatch):
    class Response(io.BytesIO):
        pass

    class Opener:
        def open(self, req, timeout):
            parsed = urlsplit(req.full_url)
            status, headers, body = request(
                parsed.path + ("?" + parsed.query if parsed.query else ""),
                method=req.get_method(),
                body=req.data or b"",
                headers=dict(req.header_items()),
            )
            response = Response(body)
            response.status, response.headers = status, headers
            return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: Opener())
    report = verify.verify("http://127.0.0.1:8787/")
    assert report["passed"] == report["total"] == 8
    assert report["checks"][4]["evidence"]["browser_script_execution_tested"] is False


@pytest.mark.parametrize("host", ["attacker.invalid:8787", "localhost:8787", "127.0.0.1:8765"])
def test_host_rebinding_is_refused(host):
    assert request("/debug/config", host=host)[0] == 403


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.0.1", "::", "localhost"])
def test_non_loopback_binding_refused_before_socket_creation(host):
    with pytest.raises(ValueError, match="ONLY"):
        app.LabServer((host, 8787))


def test_cross_origin_posts_refused():
    assert (
        request(
            "/api/login",
            method="POST",
            body=b"username=demo",
            headers={"Origin": "https://untrusted.invalid"},
        )[0]
        == 403
    )


def test_database_read_only_and_recreated():
    db = app.database()
    try:
        with pytest.raises(sqlite3.OperationalError):
            db.execute("DELETE FROM users")
    finally:
        db.close()
    assert len(app.query("SELECT * FROM users")) == 2


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8787",
        "http://localhost:8787",
        "http://example.invalid",
        "http://127.0.0.1:8787/admin",
        "http://demo@127.0.0.1:8787",
        "http://127.0.0.1:8787/?x=1",
    ],
)
def test_verifier_cannot_target_arbitrary_sites(url):
    with pytest.raises(ValueError, match="only"):
        verify.verify(url)


def test_does_not_serve_host_files_or_claim_cves():
    for path in ("/.env", "/.git/config", "/../../config/scope.yaml", "/assets/../../.env"):
        assert request(path)[0] == 404
    assert json.loads(request("/__lab__/ground-truth")[2])["real_cves"] == []


def test_front_page_and_assets_are_available():
    for path, marker in [
        ("/", b"HarborDesk"),
        ("/assets/site.css", b".lab-banner"),
        ("/assets/site.js", b"customer-form"),
    ]:
        status, _, body = request(path)
        assert status == 200 and marker in body


def test_head_has_no_body():
    status, _, body = request("/", method="HEAD")
    assert status == 200 and body == b""


def test_hostless_discovery_only_allows_http10_root():
    for path, expected in [("/", 200), ("/debug/config", 403)]:
        connection = Connection(f"GET {path} HTTP/1.0\r\n\r\n".encode())
        app.Handler(
            connection, ("127.0.0.1", 1), SimpleNamespace(server_address=("127.0.0.1", 8787))
        )
        assert int(bytes(connection.output).split()[1]) == expected


def test_verifier_never_follows_redirects():
    with pytest.raises(ValueError, match="never follows"):
        verify.NoRedirects().redirect_request(
            None, None, 302, "Found", {}, "http://example.invalid/"
        )

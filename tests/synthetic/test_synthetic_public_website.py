"""Synthetic public-website boundary/transport/UI tests; no live network or AI."""

import json
import socket
import ssl
from unittest.mock import MagicMock

import pytest

from tests.test_ui import DATABASE, ROOT, request
from vulnassess import public_website as web
from vulnassess.errors import ConfigError
from vulnassess.ui.server import UiApplication

PUBLIC = "93.184.215.14"
PUBLIC6 = "2606:4700:4700::1111"


def wire(*headers, body=b""):
    return ("HTTP/1.1 200 OK\r\n" + "\r\n".join(headers) + "\r\n\r\n").encode() + body


def transport(monkeypatch, raw=None, addresses=None):
    rows = addresses or [PUBLIC]
    dns = MagicMock(return_value=[(0, 0, 0, "", (ip, 443)) for ip in rows])
    monkeypatch.setattr(web.socket, "getaddrinfo", dns)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.recv.side_effect = [raw if raw is not None else wire("X-Frame-Options: DENY")]
    factory = MagicMock(return_value=connection)
    monkeypatch.setattr(web.socket, "socket", factory)
    secured = MagicMock()
    secured.__enter__.return_value = secured
    secured.recv.side_effect = [raw if raw is not None else wire("X-Frame-Options: DENY")]
    secured.getpeercert.return_value = {
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "subject": "PRIVATE",
    }
    secured.version.return_value = "TLSv1.3"
    context = MagicMock()
    context.wrap_socket.return_value = secured
    monkeypatch.setattr(web.ssl, "create_default_context", MagicMock(return_value=context))
    return dns, factory, connection, context, secured


@pytest.mark.parametrize(
    "url",
    [
        "",
        "a" * 2049,
        "https://a.invalid/\r\nHost:x",
        "ftp://example.invalid/",
        "https://user:secret@example.invalid/",
        "https://@example.invalid/",
        "https://example.invalid/?token=secret",
        "https://example.invalid/#secret",
        "https://example.invalid/?",
        "https://example.invalid/#",
        "https://example.invalid:7001/",
        "http://example.invalid:443/",
        "https://example.invalid:0/",
        "https://example.invalid:-1/",
        "https://example.invalid:99999/",
        "https://[broken/",
        "https://-bad.invalid/",
        "https://bad-.invalid/",
        "https://x..invalid/",
        "https://localhost/",
        "https://example.invalid\\@127.0.0.1/",
        "https://[2606:4700::1111%25eth0]/",
        "https://a.invalid/ secret",
        None,
        {},
    ],
)
def test_invalid_origins_fail_before_dns(monkeypatch, url):
    dns = MagicMock(side_effect=AssertionError("DNS must not run"))
    monkeypatch.setattr(web.socket, "getaddrinfo", dns)
    with pytest.raises(ConfigError):
        web.check(url, lambda _: False)
    dns.assert_not_called()


def test_origin_normalises_idna_and_discards_path_without_retaining_it():
    result = web.target("https://BÜCHER.invalid./private-name")
    assert result == {
        "scheme": "https",
        "host": "xn--bcher-kva.invalid",
        "port": 443,
        "origin": "https://xn--bcher-kva.invalid/",
        "path_discarded": True,
    }
    assert web.target("example.invalid")["origin"] == "https://example.invalid/"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:93.184.215.14",
        "2002:5db8:d70e::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::7f00:1",
    ],
)
def test_nonpublic_and_transition_addresses_never_connect(monkeypatch, address):
    _, factory, *_ = transport(monkeypatch, addresses=[PUBLIC, address])
    with pytest.raises(ConfigError):
        web.check("https://synthetic.invalid", lambda _: False)
    factory.assert_not_called()


def test_public_canary_rejected_and_no_scanner_scope_is_widened(monkeypatch):
    _, factory, *_ = transport(monkeypatch)
    with pytest.raises(ConfigError, match="canary"):
        web.check("https://synthetic.invalid", lambda ip: ip == PUBLIC)
    factory.assert_not_called()


def test_https_uses_pinned_ip_hostname_validation_and_minimised_metadata(monkeypatch):
    dns, factory, connection, context, secured = transport(
        monkeypatch,
        wire(
            "Content-Type: text/html",
            "Set-Cookie: DO_NOT_RETAIN_COOKIE=SECRET; Secure; HttpOnly",
            "Location: http://169.254.169.254/SECRET",
            "Server: DO_NOT_RETAIN_BANNER",
            "Content-Security-Policy: script-src 'nonce-DO_NOT_RETAIN_NONCE'",
            body=b"DO_NOT_RETAIN_BODY",
        ),
    )
    result = web.check("https://synthetic.invalid/private-name", lambda _: False)
    assert result["state"] == "complete"
    connection.connect.assert_called_once_with((PUBLIC, 443))
    context.wrap_socket.assert_called_once_with(connection, server_hostname="synthetic.invalid")
    sent = secured.sendall.call_args.args[0]
    assert sent.startswith(b"HEAD / HTTP/1.1\r\nHost: synthetic.invalid\r\n")
    assert b"Cookie:" not in sent and b"private-name" not in sent
    retained = json.dumps(result)
    for secret in ["DO_NOT_RETAIN", "SECRET", "169.254.169.254", "PRIVATE", "private-name"]:
        assert secret not in retained
    assert result["tls"]["certificate_expires_at"] == "2030-01-01T00:00:00+00:00"
    assert result["metadata"]["cookies"]["issued"] == 1
    assert "Literal-IP" not in retained
    assert "redirect following" in result["coverage"]["not_run"]
    assert [row["id"] for row in result["evidence"]] == [f"W{i}" for i in range(1, 12)]
    dns.assert_called_once()
    factory.assert_called_once()


def test_plain_http_is_explicitly_not_tls_checked(monkeypatch):
    _, _, connection, context, _ = transport(monkeypatch)
    result = web.check("http://synthetic.invalid", lambda _: False)
    assert result["state"] == "complete" and result["tls"]["state"] == "not_checked"
    connection.connect.assert_called_once_with((PUBLIC, 80))
    context.wrap_socket.assert_not_called()


def test_public_ipv6_is_pinned_without_dns(monkeypatch):
    dns, factory, connection, _, _ = transport(monkeypatch)
    result = web.check(f"http://[{PUBLIC6}]/", lambda _: False)
    dns.assert_not_called()
    factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
    connection.connect.assert_called_once_with((PUBLIC6, 80))
    assert f"Host: [{PUBLIC6}]\r\n".encode() in connection.sendall.call_args.args[0]
    assert result["selected_address"] == PUBLIC6


def test_tls_failure_has_no_insecure_retry_or_fake_http_completion(monkeypatch):
    _, _, connection, context, _ = transport(monkeypatch)
    context.wrap_socket.side_effect = ssl.SSLCertVerificationError("secret-detail")
    result = web.check("https://synthetic.invalid", lambda _: False)
    assert result["state"] == "incomplete" and result["metadata"] is None
    assert result["tls"]["state"] == "validation_failed"
    assert result["coverage"]["executed"] == ["public destination validation"]
    assert "secret-detail" not in json.dumps(result)
    connection.sendall.assert_not_called()
    context.wrap_socket.assert_called_once()


@pytest.mark.parametrize("raw", [b"not HTTP\r\n\r\n", b"HTTP/1.1 200 OK\r\n", wire("bad"), b""])
def test_malformed_response_is_incomplete_no_partial_metadata(monkeypatch, raw):
    *_, secured = transport(monkeypatch, raw)
    secured.recv.side_effect = [raw, b""]
    result = web.check("https://synthetic.invalid", lambda _: False)
    assert result["state"] == "incomplete" and result["metadata"] is None


def test_header_budget_and_connection_failure_are_explicit(monkeypatch):
    *_, secured = transport(monkeypatch)
    secured.recv.side_effect = [b"x" * 1024] * 9
    assert web.check("https://synthetic.invalid", lambda _: False)["state"] == "incomplete"
    _, _, connection, _, _ = transport(monkeypatch)
    connection.connect.side_effect = OSError("private-detail")
    result = web.check("https://synthetic.invalid", lambda _: False)
    assert result["state"] == "incomplete"
    assert "private-detail" not in json.dumps(result)


@pytest.mark.parametrize("rows", [[], [(0, 0, 0, "", (PUBLIC, 80))] * 33])
def test_dns_empty_or_excess_answers_rejected(monkeypatch, rows):
    monkeypatch.setattr(web.socket, "getaddrinfo", lambda *a, **kw: rows)
    with pytest.raises(ConfigError, match="DNS resolution"):
        web._resolve("synthetic.invalid", 80)


def test_dns_failure_and_worker_capacity_are_fail_closed(monkeypatch):
    monkeypatch.setattr(web.socket, "getaddrinfo", MagicMock(side_effect=OSError("secret")))
    with pytest.raises(ConfigError, match="DNS resolution"):
        web._resolve("synthetic.invalid", 80)
    web._DNS_LOCK.acquire()
    try:
        with pytest.raises(ConfigError, match="busy"):
            web._resolve("synthetic.invalid", 80)
    finally:
        web._DNS_LOCK.release()


def test_dns_timeout_and_worker_start_failure_do_not_make_http_requests(monkeypatch):
    worker = MagicMock()
    monkeypatch.setattr(web, "Thread", MagicMock(return_value=worker))
    event = MagicMock()
    event.wait.return_value = False
    monkeypatch.setattr(web, "Event", MagicMock(return_value=event))
    try:
        with pytest.raises(ConfigError, match="deadline"):
            web._resolve("synthetic.invalid", 80)
        assert web._DNS_LOCK.locked()
    finally:
        web._DNS_LOCK.release()
    worker.start.side_effect = RuntimeError("cannot start")
    with pytest.raises(ConfigError, match="could not start"):
        web._resolve("synthetic.invalid", 80)
    assert not web._DNS_LOCK.locked()


@pytest.fixture
def app():
    return UiApplication(DATABASE, ROOT / "config", "demo")


def post(app, body, trusted=True, additional=""):
    raw = json.dumps(body).encode()
    headers = f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n" + additional
    if trusted:
        headers += "Origin: http://127.0.0.1:8765\r\nX-VulnAssess-Action: public-website\r\n"
    status, _, response = request(
        app, "/api/public-website/check", "POST", extra_headers=headers, body=raw
    )
    return status, json.loads(response)


def test_public_page_and_links_are_reachable_without_touching_deep_scope(app):
    response = app.get("/website-check")
    assert response.status == 200 and b"Public Website Check" in response.body
    assert b"/website-check" in app.get("/workflow").body
    assert b"confirm_metadata_only" in app.get("/static/website-check.js").body
    assert b"innerHTML" not in app.get("/static/website-check.js").body


def test_same_origin_and_confirmation_fail_before_transport(app, monkeypatch):
    check = MagicMock()
    monkeypatch.setattr(web, "check", check)
    body = {"target": "https://synthetic.invalid", "confirm_metadata_only": True}
    assert post(app, body, trusted=False)[0] == 403
    for invalid in [
        [],
        {},
        body | {"confirm_metadata_only": 1},
        body | {"extra": True},
        body | {"target": {}},
    ]:
        assert post(app, invalid)[0] == 400
    assert post(app, body, additional="Transfer-Encoding: chunked\r\n")[0] == 400
    check.assert_not_called()


def test_endpoint_serialises_and_rates_limits_without_bypassing_canary(app, monkeypatch):
    body = {"target": "https://synthetic.invalid", "confirm_metadata_only": True}
    check = MagicMock(return_value={"schema_version": web.VERSION})
    monkeypatch.setattr(web, "check", check)
    app._live_lock.acquire()
    try:
        assert post(app, body)[0] == 409
    finally:
        app._live_lock.release()
    assert post(app, body)[0] == 200
    assert callable(check.call_args.args[1])
    assert check.call_args.args[1]("172.28.0.250") is True
    assert post(app, body)[0] == 429
    check.assert_called_once()


def test_destination_refusal_unlocks_without_leaking_raw_error(app, monkeypatch):
    monkeypatch.setattr(web, "check", MagicMock(side_effect=ConfigError("PRIVATE-DNS")))
    status, result = post(
        app, {"target": "https://synthetic.invalid", "confirm_metadata_only": True}
    )
    assert status == 400 and "PRIVATE-DNS" not in json.dumps(result)
    assert not app._live_lock.locked()


def test_public_mode_does_not_authorise_deep_scanners(app, monkeypatch):
    before = (ROOT / "config" / "scope.yaml").read_bytes()
    monkeypatch.setattr("vulnassess.ui.server.resolve_addresses", lambda *args: [PUBLIC])
    result = app.target_check("https://synthetic.invalid")
    assert result["status"] == "blocked"
    assert "outside the authorised scope" in result["reason"]
    assert (ROOT / "config" / "scope.yaml").read_bytes() == before


def test_socket_read_deadline_and_final_deadline_reject_partial_success(monkeypatch):
    _, _, _, _, secured = transport(monkeypatch)
    clock = MagicMock(side_effect=[0.0, 0.0, 0.0, 0.0, 11.0])
    monkeypatch.setattr(web.time, "monotonic", clock)
    result = web.check("https://synthetic.invalid", lambda _: False)
    assert result["state"] == "incomplete" and result["metadata"] is None
    secured.recv.assert_not_called()
    transport(monkeypatch)
    monkeypatch.setattr(web.time, "monotonic", MagicMock(side_effect=[0, 0, 0, 0, 0, 11]))
    result = web.check("https://synthetic.invalid", lambda _: False)
    assert result["state"] == "incomplete" and result["metadata"] is None


def test_missing_certificate_expiry_stays_unknown(monkeypatch):
    *_, secured = transport(monkeypatch)
    secured.getpeercert.return_value = {}
    result = web.check("https://synthetic.invalid", lambda _: False)
    assert result["state"] == "complete"
    assert result["tls"]["certificate_expires_at"] is None

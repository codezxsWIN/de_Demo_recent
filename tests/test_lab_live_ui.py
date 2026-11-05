"""Same-origin live operations and immutable evidence routes without sockets."""

import io
import json
from types import SimpleNamespace

import pytest

from vulnassess.ui.server import UiApplication, UiRequestHandler


class MemoryConnection:
    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = bytearray()

    def makefile(self, *_args, **_kwargs):
        return self.input

    def sendall(self, data):
        self.output.extend(data)

    def settimeout(self, _):
        pass


def request(
    app,
    *,
    path="/api/network-live/check",
    body=b'{"environment":"office","operation":"ftp-file"}',
    headers=None,
    method="POST",
):
    fields = {
        "Host": "127.0.0.1:8765",
        "Origin": "http://127.0.0.1:8765",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "X-VulnAssess-Action": "network-live",
    }
    fields.update(headers or {})
    raw = (
        f"{method} {path} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in fields.items())
        + "\r\n"
    )
    connection = MemoryConnection(raw.encode() + body)
    server = SimpleNamespace(application=app, server_address=("127.0.0.1", 8765))
    UiRequestHandler(connection, ("127.0.0.1", 50000), server)
    head, result = bytes(connection.output).split(b"\r\n\r\n", 1)
    return int(head.split()[1]), result


@pytest.fixture
def app():
    instance = object.__new__(UiApplication)
    instance.calls = []

    def check(*args):
        instance.calls.append(args)
        return {"status": "SYNTHETIC-OFFLINE-RESPONSE"}

    instance.network_live = lambda: SimpleNamespace(
        check=check,
        change=check,
        explain=check,
        full_assessment=check,
        publish_assessment=check,
        report_assessment=check,
    )
    return instance


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "evil.invalid"},
        {"Origin": "http://evil.invalid"},
        {"X-VulnAssess-Action": ""},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_wrong_origin_cannot_run_checks_or_mutate_containers(app, headers):
    assert request(app, headers=headers)[0] == 403
    assert not app.calls


@pytest.mark.parametrize(
    "body,headers",
    [
        (b'{"environment":"office","environment":"iot","operation":"ftp-file"}', {}),
        (b'{"environment":"office","operation":"ftp-file","target":"192.0.2.1"}', {}),
        (b"[]", {}),
        (b"null", {}),
        (b"{}", {}),
        (b"{}", {"Content-Length": "3000"}),
        (b"{}", {"Content-Type": "text/plain"}),
        (b"{}", {"Transfer-Encoding": "chunked"}),
    ],
)
def test_malformed_or_expanded_input_cannot_dispatch(app, body, headers):
    assert request(app, body=body, headers=headers)[0] == 409
    assert not app.calls


def test_fixed_check_dispatches_only_explicit_environment_and_operation(app):
    status, result = request(app)
    assert status == 200 and app.calls == [("office", "ftp-file")]
    assert json.loads(result)["status"] == "SYNTHETIC-OFFLINE-RESPONSE"


def test_only_named_remediation_profiles_are_available(app):
    body = b'{"environment":"iot"}'
    assert request(app, path="/api/network-live/remediate", body=body)[0] == 200
    assert app.calls == [("iot", "restricted")]
    app.calls.clear()
    assert request(app, path="/api/network-live/restore", body=body)[0] == 200
    assert app.calls == [("iot", "baseline")]
    assert request(app, path="/api/network-live/exec", body=body)[0] == 405
    assert request(app, path="/api/network-live/nested/check", body=body)[0] == 405


@pytest.mark.parametrize(
    "path",
    [
        "/api/network-live/capture/../../config.pcap",
        "/api/network-live/capture/external.pcap",
        "/api/network-live/status?environment=office&environment=iot",
        "/api/network-live/status?environment=office&target=192.0.2.1",
    ],
)
def test_capture_and_status_urls_cannot_expand_scope(app, path):
    assert app.get(path).status in {400, 404}
    assert not app.calls


def test_live_page_exposes_real_evidence_and_no_simulated_success_defaults(app):
    response = app.get("/network-live")
    assert response.status == 200
    text = response.body.decode()
    assert "Captured packets" in text and "Download current PCAP" in text
    assert "Same FTP endpoint" in text and 'id="cloud-consent" type="checkbox"' in text
    assert 'id="explain" class="primary" disabled' in text


def test_full_assessment_is_a_same_origin_fixed_environment_action(app):
    body = b'{"environment":"office"}'
    assert request(app, path="/api/network-live/assess", body=body)[0] == 200
    assert app.calls == [("office",)]
    app.calls.clear()
    assert (
        request(
            app,
            path="/api/network-live/assess",
            body=body,
            headers={"Origin": "https://untrusted.invalid"},
        )[0]
        == 403
    )
    assert (
        request(
            app, path="/api/network-live/assess", body=b'{"environment":"office","ports":[22]}'
        )[0]
        == 409
    )
    assert not app.calls


def test_publication_requires_same_origin_and_an_exact_retained_assessment_request(app):
    body = b'{"assessment_id":"full-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    path = "/api/network-live/publish"
    assert request(app, path=path, body=body)[0] == 200
    assert app.calls == [("full-" + "a" * 32,)]
    app.calls.clear()
    assert (
        request(app, path=path, body=body, headers={"Origin": "https://untrusted.invalid"})[0]
        == 403
    )
    assert (
        request(app, path=path, body=b'{"assessment_id":"full-a","target":"192.0.2.1"}')[0] == 409
    )
    assert request(app, path=path, body=b'{"environment":"office"}')[0] == 409
    assert not app.calls

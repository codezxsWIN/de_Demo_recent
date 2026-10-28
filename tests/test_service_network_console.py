"""Offline HTTP boundaries for the interactive console, with no protocol traffic."""

import io
import json
from types import SimpleNamespace

import pytest

from labs.service_networks import console


def request(
    application,
    *,
    method="POST",
    path="/api/action",
    body=b'{"action":"ftp-anonymous"}',
    headers=None,
):
    fields = {
        "Host": "127.0.0.1:8798",
        "X-VulnAssess-Lab": "service-demo",
        "Content-Length": str(len(body)),
    }
    fields.update(headers or {})
    wire = (
        f"{method} {path} HTTP/1.1\r\n"
        + "".join(f"{key}: {value}\r\n" for key, value in fields.items())
        + "\r\n"
    ).encode() + body
    output = io.BytesIO()

    class Handler(console.handler(application)):
        def setup(self):
            self.rfile = io.BytesIO(wire)
            self.wfile = output

        def finish(self):
            pass

    Handler(None, ("127.0.0.1", 42000), SimpleNamespace(server_port=8798))
    head, data = output.getvalue().split(b"\r\n\r\n", 1)
    return int(head.split()[1]), head, data


@pytest.fixture
def application(monkeypatch, tmp_path):
    app = console.Console(tmp_path)
    app.calls = []

    def action(name):
        app.calls.append(name)
        return {"operation": name, "synthetic": True}

    monkeypatch.setattr(app, "action", action)
    return app


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "evil.example"},
        {"Host": "localhost:8798"},
        {"Origin": "https://evil.example"},
        {"Origin": "http://127.0.0.1:8765"},
        {"X-VulnAssess-Lab": ""},
    ],
)
def test_wrong_origin_host_or_action_marker_never_dispatches(application, headers):
    status, _, _ = request(application, headers=headers)
    assert status == 403 and application.calls == []


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b"[]",
        b"null",
        b'{"action":3}',
        b'{"action":"arbitrary-shell"}',
        b'{"action":"ftp-anonymous","target":"192.0.2.1"}',
        b'{"action":"ftp-anonymous","action":"mqtt-exchange"}',
        b"\xff",
        b"{",
    ],
)
def test_malformed_or_expanded_operation_is_rejected_before_dispatch(application, body):
    status, _, _ = request(application, body=body)
    assert status == 400 and application.calls == []


@pytest.mark.parametrize("length", ["-1", "0", "1025", "not-a-number"])
def test_operation_body_is_bounded(application, length):
    assert request(application, headers={"Content-Length": length})[0] == 400
    assert application.calls == []


def test_valid_local_action_returns_no_cache_and_frame_protection(application):
    status, head, body = request(application, headers={"Origin": "http://127.0.0.1:8798"})
    assert status == 200 and application.calls == ["ftp-anonymous"]
    assert json.loads(body)["synthetic"] is True
    assert b"Cache-Control: no-store" in head and b"frame-ancestors 'none'" in head


def test_concurrent_action_limit_and_error_both_preserve_slot_ownership(application, monkeypatch):
    application.slots.acquire()
    application.slots.acquire()
    assert request(application)[0] == 429
    assert application.calls == []
    application.slots.release()
    application.slots.release()

    def failure(_):
        raise ValueError("SYNTHETIC operation failed")

    monkeypatch.setattr(application, "action", failure)
    assert request(application)[0] == 409
    assert application.slots.acquire(blocking=False)
    assert application.slots.acquire(blocking=False)
    assert not application.slots.acquire(blocking=False)


def test_fixed_static_paths_cannot_read_arbitrary_files_or_execute_actions(application):
    for path in ("/../../.env", "/config/network-services.json", "/api/action"):
        assert request(application, method="GET", path=path)[0] == 404
    status, _, body = request(application, method="GET", path="/office")
    assert status == 200 and b"Actual service response" in body
    assert application.calls == []


def test_unknown_operation_cannot_open_a_socket_even_when_called_directly(tmp_path):
    with pytest.raises(ValueError, match="Unknown fixed"):
        console.Console(tmp_path).action("scan-anywhere")


def test_each_operation_reloads_owner_policy_and_refuses_revocation(monkeypatch, tmp_path):
    app = console.Console(tmp_path)
    scope = SimpleNamespace(contains=lambda _: True, is_canary=lambda _: False)
    monkeypatch.setattr(
        console, "Settings", lambda _: SimpleNamespace(config_dir=tmp_path, scope=scope)
    )
    replies = iter([{"endpoints": [{"port": 2121, "service": "ftp"}]}, None])
    monkeypatch.setattr(console.network_service_policy, "load", lambda *_: next(replies))
    assert app.endpoint("office", 2121)[0] == "127.0.0.2"
    with pytest.raises(ValueError, match="not authorised"):
        app.endpoint("office", 2121)

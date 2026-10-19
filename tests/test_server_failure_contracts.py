"""HTTP failure contracts without opening a socket or launching an assessment."""

import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import ROOT, prepared_store
from vulnassess.errors import ConfigError, LLMUnavailable, NeedsReview
from vulnassess.ui import server


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.delenv(server.ENV_VAR, raising=False)
    with prepared_store(str(tmp_path)):
        pass
    return server.UiApplication(tmp_path / "assessment.db", ROOT / "config", "snapshot")


@pytest.mark.parametrize(
    "target",
    [
        "",
        "a" * 513,
        "http://[broken",
        "http://example.invalid:bad",
        "http://example.invalid:0",
        "http:///",
        "not a domain",
        "ftp://example.invalid",
        "https://u:p@example.invalid",
        "https://example.invalid/?query=x",
        "https://example.invalid/#fragment",
    ],
    ids=[
        "empty",
        "too-long",
        "ipv6",
        "port-text",
        "port-zero",
        "no-host",
        "domain",
        "scheme",
        "credentials",
        "query",
        "fragment",
    ],
)
def test_target_validation_precedes_dns_and_execution(app, target, monkeypatch):
    resolve = Mock(side_effect=AssertionError("DNS must not run"))
    monkeypatch.setattr(server, "resolve_addresses", resolve)
    with pytest.raises(ConfigError):
        app.target_check(target)
    resolve.assert_not_called()


@pytest.mark.parametrize("addresses", [[], ["192.0.2.1"] * 33, OSError("dns failure")])
def test_dns_failure_is_not_scope_approval(app, addresses, monkeypatch):
    resolve = (
        Mock(side_effect=addresses)
        if isinstance(addresses, Exception)
        else Mock(return_value=addresses)
    )
    monkeypatch.setattr(server, "resolve_addresses", resolve)
    with pytest.raises(ConfigError, match="resolved|resolution"):
        app.target_check("example.invalid")


def test_missing_entry_and_unreadable_run_do_not_render_success(app, monkeypatch):
    monkeypatch.setattr(app, "_static", Mock(return_value=server.error_response(404, "missing")))
    assert app._entry().status == 404
    monkeypatch.setattr(app, "_static", Mock(return_value=server.Response(200, b"template")))
    monkeypatch.setattr(
        server, "open_read_store", Mock(side_effect=ConfigError("invalid stored run"))
    )
    assert app._entry().status == 409


@pytest.mark.parametrize(
    "url,status",
    [
        ("/%ff", 404),
        ("//external.invalid/", 404),
        ("/?run=", 400),
        ("/?other=x", 400),
        ("/api/target-check", 400),
        ("/api/target-check?target=", 400),
        ("/api/captures?page=bad", 400),
        ("/api/captures?page=1&page=2", 400),
        ("/captures/id?unexpected=x", 400),
    ],
)
def test_invalid_routes_return_explicit_errors(app, url, status):
    response = app.get(url)
    assert response.status == status
    assert json.loads(response.body)["error"]["message"]


@pytest.mark.parametrize("resource", ["cvss-fixture", "static/app.js"])
def test_resource_failures_are_not_success(app, resource, monkeypatch):
    if resource == "cvss-fixture":
        monkeypatch.setattr(app, "cvss_fixture", Mock(side_effect=ConfigError("missing fixture")))
        assert app.get("/api/cvss-fixture").status == 409
    else:
        monkeypatch.setattr(server.Path, "read_bytes", Mock(side_effect=OSError("denied")))
        assert app.get("/static/app.js").status == 404


def handler(application):
    request = object.__new__(server.UiRequestHandler)
    request.server = SimpleNamespace(application=application, server_address=("127.0.0.1", 9999))
    request.wfile = io.BytesIO()
    request.send_response = Mock()
    request.send_header = Mock()
    request.end_headers = Mock()
    request._same_origin = Mock(return_value=True)
    request._reply = Mock()
    return request


@pytest.mark.parametrize("stream", ["live", "analyst"])
@pytest.mark.parametrize(
    "error,event_type",
    [
        (NeedsReview("rejected claim"), "needs-review"),
        (LLMUnavailable("provider down"), "provider"),
        (ConfigError("invalid request"), "error"),
        (RuntimeError("PRIVATE internals"), "error"),
    ],
)
def test_stream_failures_are_explicit_and_do_not_claim_completion(stream, error, event_type):
    app = SimpleNamespace(
        live_report=Mock(side_effect=error), analyst_report=Mock(side_effect=error)
    )
    request = handler(app)
    if stream == "live":
        request._stream_live("192.0.2.1", "ollama")
    else:
        request._stream_analyst("synthetic", "192.0.2.1")
    events = [json.loads(line) for line in request.wfile.getvalue().splitlines()]
    expected = (
        ("needs-review" if stream == "live" else "error")
        if event_type == "provider"
        else event_type
    )
    assert len(events) == 1 and events[0]["type"] == expected
    assert "PRIVATE" not in events[0]["message"]
    assert request.close_connection is True


@pytest.mark.parametrize("stream", ["live", "analyst"])
@pytest.mark.parametrize(
    "error",
    [
        BrokenPipeError(),
        ConnectionResetError(),
        NeedsReview("rejected"),
        LLMUnavailable("offline"),
        ConfigError("invalid"),
        RuntimeError("internal"),
    ],
)
def test_stream_disconnects_do_not_raise_secondary_errors(stream, error):
    app = SimpleNamespace(
        live_report=Mock(side_effect=error), analyst_report=Mock(side_effect=error)
    )
    request = handler(app)
    request.wfile = Mock()
    request.wfile.write.side_effect = BrokenPipeError()
    if stream == "live":
        request._stream_live("192.0.2.1", "ollama")
        app.live_report.assert_called_once()
    else:
        request._stream_analyst("synthetic", "192.0.2.1")
        app.analyst_report.assert_called_once()


@pytest.mark.parametrize("route", ["scan-plans", "evidence-requests"])
@pytest.mark.parametrize(
    "error,status",
    [(NeedsReview("review"), 422), (LLMUnavailable("offline"), 503), (ConfigError("invalid"), 400)],
)
def test_post_action_error_statuses(route, error, status):
    action = Mock(side_effect=error)
    app = SimpleNamespace(scan_plan_action=action, evidence_request_action=action)
    request = handler(app)
    request.path = f"/api/{route}/propose"
    request.headers = {
        "Origin": "http://127.0.0.1:9999",
        "X-VulnAssess-Action": "scan-plan" if route == "scan-plans" else "evidence-request",
        "Content-Type": "application/json",
        "Content-Length": "2",
    }
    request.rfile = io.BytesIO(b"{}")
    request.do_POST()
    assert request._reply.call_args.args[0].status == status
    action.assert_called_once_with("propose", {})


def test_post_rejects_unknown_route_without_execution():
    request = handler(SimpleNamespace())
    request.path = "/api/unknown"
    request.do_POST()
    assert request._reply.call_args.args[0].status == 405


def test_post_requires_same_origin():
    request = handler(SimpleNamespace())
    request.path = "/api/scan-plans/propose"
    request._same_origin.return_value = False
    request.do_POST()
    request._reply.assert_not_called()


def test_get_malformed_url_is_not_dispatched():
    app = SimpleNamespace(get=Mock())
    request = handler(app)
    request.path = "http://[broken"
    request.do_GET()
    assert request._reply.call_args.args[0].status == 404
    app.get.assert_not_called()


def test_server_bind_failure_is_actionable(monkeypatch):
    monkeypatch.setattr(
        server.ThreadingHTTPServer, "__init__", Mock(side_effect=OSError("occupied"))
    )
    with pytest.raises(ConfigError, match="choose another --port"):
        server.UiServer(Mock(), port=9999)

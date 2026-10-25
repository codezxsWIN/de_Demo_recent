import hashlib
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import share_readonly
from tests.test_assessment_report import setup_report
from vulnassess import capture_history


def request(path, auth=None):
    headers = Message()
    if auth:
        headers["Authorization"] = auth
    return SimpleNamespace(
        headers=headers,
        path=path,
        reply=Mock(),
        server=SimpleNamespace(
            auth_hash=hashlib.sha256(b"Basic approved").digest(),
            snapshot={"/": ("text/html", b"approved snapshot")},
        ),
    )


@pytest.mark.parametrize("auth", [None, "Basic wrong"])
def test_password_is_required_for_every_page(auth):
    handler = request("/", auth)
    share_readonly.Handler.do_GET(handler)
    assert handler.reply.call_args.args[0] == 401


def test_authenticated_visitors_cannot_access_any_executable_or_private_route():
    for path in (
        "/api/analyst/demo/127.0.0.1",
        "/api/target-check?target=localhost",
        "/api/device-recheck",
        "/api/captures/private",
        "/.env.google",
        "/static/../server.py",
        "/?unexpected=1",
        "http://127.0.0.1:8787/",
    ):
        handler = request(path, "Basic approved")
        share_readonly.Handler.do_GET(handler)
        assert handler.reply.call_args.args[0] == 403
    handler = request("/", "Basic approved")
    share_readonly.Handler.do_GET(handler)
    assert handler.reply.call_args.args == (200, "text/html", b"approved snapshot")


def test_every_mutation_is_blocked_without_consulting_application():
    for method in ("do_POST", "do_PUT", "do_DELETE", "do_PATCH", "do_OPTIONS"):
        handler = request("/api/live-assessment/events", "Basic approved")
        getattr(share_readonly.Handler, method)(handler)
        assert handler.reply.call_args.args[0] == 405
        assert handler.close_connection is True


def test_only_approved_capture_is_frozen_and_snapshot_does_not_change(tmp_path, monkeypatch):
    app, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    record["result"]["target"] = "http://127.0.0.1:8787/"
    app.run_id = "shared"
    monkeypatch.setattr(share_readonly.capture_history, "load", lambda *_: record)
    snapshot = share_readonly.freeze(app, directory.name)
    assert "/api/live-assessment/events" not in snapshot
    assert "/api/helpy" not in snapshot
    assert "/api/scanner-status" not in snapshot
    assert "/api/captures/private" not in snapshot
    assert b"share-readonly.js" in snapshot["/workflow"][1]
    frozen = snapshot["/api/vulnerability-findings"][1]
    record["result"]["target"] = "changed later"
    assert snapshot["/api/vulnerability-findings"][1] == frozen
    with pytest.raises(TypeError):
        snapshot["/new"] = ("text/plain", b"not allowed")

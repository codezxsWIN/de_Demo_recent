"""Local workbench startup and HTTP failures, without live sockets or scanners."""

import io
import json
import shutil
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import ROOT, prepared_store
from tests.test_server_failure_contracts import handler
from vulnassess import cli
from vulnassess.errors import ConfigError
from vulnassess.ui import runtime, server


@pytest.fixture
def local_inputs(tmp_path, monkeypatch):
    monkeypatch.delenv(server.ENV_VAR, raising=False)
    with prepared_store(str(tmp_path)):
        pass
    config = tmp_path / "config"
    shutil.copytree(ROOT / "config", config)
    return tmp_path / "assessment.db", config


@pytest.fixture
def app(local_inputs):
    return server.UiApplication(*local_inputs, "snapshot")


@pytest.mark.parametrize("failure", ["permission", "invalid_utf8", "changed"])
def test_configuration_cannot_change_between_validation_and_serving(
    local_inputs, monkeypatch, failure
):
    if failure == "changed":
        real_settings = server.Settings

        def changed_settings(path):
            settings = real_settings(path)
            (path / "scope.yaml").write_text("changed: synthetic\n")
            return settings

        monkeypatch.setattr(server, "Settings", changed_settings)
    elif failure == "permission":
        monkeypatch.setattr(Path, "read_bytes", Mock(side_effect=PermissionError("synthetic")))
    else:
        monkeypatch.setattr(Path, "read_bytes", Mock(return_value=b"\xff"))
    with pytest.raises(ConfigError, match="configuration file"):
        server.UiApplication(*local_inputs, "snapshot")


def test_configuration_resolving_outside_directory_is_rejected(local_inputs, monkeypatch):
    local_path = server.local_path

    def redirected_path(value):
        value = Path(value)
        return value.parent.parent / value.name if value.name == "scope.yaml" else local_path(value)

    monkeypatch.setattr(server, "local_path", redirected_path)
    with pytest.raises(ConfigError, match="leaves its local directory"):
        server.UiApplication(*local_inputs, "snapshot")


def test_missing_ui_entry_is_reported_at_startup(local_inputs, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "STATIC_ROOT", tmp_path)
    with pytest.raises(ConfigError, match="MISSING: UI entry point"):
        server.UiApplication(*local_inputs, "snapshot")


def test_database_environment_override_does_not_expose_connection_string(local_inputs, monkeypatch):
    monkeypatch.setenv(server.ENV_VAR, "postgresql://synthetic.invalid/test")
    read_store = Mock(return_value=nullcontext(SimpleNamespace(run_info=lambda _: {})))
    monkeypatch.setattr(server, "open_read_store", read_store)
    app = server.UiApplication(*local_inputs, "snapshot")
    assert app.database == f"env:{server.ENV_VAR}"
    read_store.assert_called_once_with(f"env:{server.ENV_VAR}")


def test_oversized_static_asset_is_not_served(app, tmp_path, monkeypatch):
    (tmp_path / "synthetic.js").write_bytes(b"123")
    monkeypatch.setattr(server, "STATIC_ROOT", tmp_path)
    monkeypatch.setattr(server, "MAX_STATIC_BYTES", 2)
    assert app.get("/static/synthetic.js").status == 404


@pytest.mark.parametrize("failure", ["missing", "malformed", "permission"])
def test_unusable_arithmetic_fixture_returns_conflict(app, monkeypatch, failure):
    if failure == "missing":
        monkeypatch.setattr(Path, "is_file", Mock(return_value=False))
    elif failure == "malformed":
        monkeypatch.setattr(Path, "read_text", Mock(return_value="["))
    else:
        monkeypatch.setattr(Path, "read_text", Mock(side_effect=PermissionError("synthetic")))
    response = app.get("/api/cvss-fixture")
    assert response.status == 409
    assert "fixture" in json.loads(response.body)["error"]["message"]


def test_history_storage_error_does_not_leak_local_details(app, monkeypatch):
    monkeypatch.setattr(server.capture_history, "listing", Mock(side_effect=OSError("PRIVATE")))
    response = app.get("/api/captures")
    assert response.status == 409
    assert "PRIVATE" not in response.body.decode()
    assert "unavailable" in response.body.decode()


@pytest.mark.parametrize("route", ["scan-plans", "evidence-requests"])
@pytest.mark.parametrize("content_type,size", [("text/plain", "2"), ("application/json", "32769")])
def test_invalid_action_envelope_never_reaches_executor(route, content_type, size):
    action = Mock(side_effect=AssertionError("must not execute"))
    request = handler(SimpleNamespace(scan_plan_action=action, evidence_request_action=action))
    request.path = f"/api/{route}/propose"
    request.headers = {
        "Origin": "http://127.0.0.1:9999",
        "X-VulnAssess-Action": "scan-plan" if route == "scan-plans" else "evidence-request",
        "Content-Type": content_type,
        "Content-Length": size,
    }
    request.rfile = io.BytesIO(b"{}")
    request.do_POST()
    assert request._reply.call_args.args[0].status == 400
    action.assert_not_called()


def test_invalid_cloud_json_does_not_start_analysis():
    request = handler(SimpleNamespace())
    request.path = "/api/analyst/synthetic/192.0.2.1"
    request.headers = {
        "Origin": "http://127.0.0.1:9999",
        "X-VulnAssess-Action": "cloud-analyst",
        "Content-Type": "application/json",
        "Content-Length": "1",
    }
    request.rfile = io.BytesIO(b"{")
    request.do_POST()
    assert request._reply.call_args.args[0].status == 400


def test_cli_server_normal_shutdown_closes_context(local_inputs, monkeypatch, capsys):
    database, config = local_inputs
    instance = Mock(server_port=9876)
    exits = []

    class LocalServer:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return instance

        def __exit__(self, *args):
            exits.append(args)

    monkeypatch.setattr(server, "UiServer", LocalServer)
    assert (
        cli.main(
            ["--db", str(database), "--config", str(config), "ui", "--run", "snapshot", "--json"]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["url"] == "http://127.0.0.1:9876/"
    assert exits == [(None, None, None)]
    instance.serve_forever.assert_called_once()


def test_local_role_model_status_is_read_only():
    status = runtime.model_status(ROOT / "models/synthetic-role-model.json")
    assert status["status"] == "ready"
    assert status["model"]["score_influence"] == "none; shadow predictions only"


@pytest.mark.parametrize("hosts", [[], [{}] * 1025], ids=["empty", "over-budget"])
def test_role_inference_rejects_invalid_workload_before_predictions(monkeypatch, hosts):
    reader = SimpleNamespace(run=lambda _: {"hosts": hosts})
    monkeypatch.setattr(runtime, "ReadOnlyStore", Mock(return_value=nullcontext(reader)))
    with pytest.raises(ConfigError, match="stored hosts|1024"):
        runtime.run_model(
            Path("synthetic.db"), ROOT / "models/synthetic-role-model.json", "synthetic"
        )

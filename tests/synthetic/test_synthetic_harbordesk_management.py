"""Pure-logic network-management tests using fake connections, never live sockets."""

import json
import threading
from email.parser import Parser
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from labs.harbordesk import app, management, verify
from tests.synthetic.test_synthetic_harbordesk_impact import Client, Opener, Response
from tests.test_harbordesk_lab import Connection
from vulnassess import context, harbordesk_probe, scoring
from vulnassess.schema import Host, Service
from vulnassess.settings import Settings

ROOT = Path(__file__).resolve().parents[2]


class ManagementClient:
    def __init__(self) -> None:
        self.servers = {
            port: SimpleNamespace(
                server_address=("127.0.0.1", port),
                workspace=app.Workspace(),
                policy_lock=threading.RLock(),
                paused=False,
            )
            for port in (management.PORT, management.COMPARISON_PORT)
        }
        self.requests: list[tuple[str, int, str]] = []

    def raw(
        self,
        port: int,
        path: str,
        *,
        method: str = "GET",
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> Response:
        fields = {
            "Host": f"127.0.0.1:{port}",
            "Content-Length": str(len(body)),
            **(headers or {}),
        }
        raw = (
            f"{method} {path} HTTP/1.1\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in fields.items())
            + "\r\n"
        ).encode() + body
        connection = Connection(raw)
        handler = (
            management.ProtectedManagementHandler
            if port == management.COMPARISON_PORT
            else management.ManagementHandler
        )
        self.requests.append((method, port, path))
        handler(connection, ("127.0.0.1", 1), self.servers[port])
        header, content = bytes(connection.output).split(b"\r\n\r\n", 1)
        status, rest = header.decode().split("\r\n", 1)
        return Response(content, int(status.split()[1]), Parser().parsestr(rest))

    def open(self, req: Any, timeout: int) -> Response:
        if req.host not in ("127.0.0.1:8791", "127.0.0.1:8792"):
            raise AssertionError("Unexpected network destination")
        port = int(req.host.rsplit(":", 1)[1])
        return self.raw(
            port, req.selector, method=req.get_method(),
            body=req.data or b"", headers=dict(req.header_items()),
        )


def test_unauthed_backup_and_queue_control_are_actual_stateful_operations() -> None:
    client = ManagementClient()
    backup = client.raw(8791, "/backup")
    assert backup.status == 200
    assert {key: len(rows) for key, rows in json.loads(backup.read())["backup"].items()} == {
        "customers": 3, "orders": 2, "tickets": 2, "documents": 2
    }
    assert client.raw(8791, "/dispatch").status == 200
    assert client.raw(8791, "/config", method="POST", body=b"paused=true").status == 200
    assert client.raw(8791, "/dispatch").status == 503
    assert json.loads(client.raw(8791, "/config").read())["paused"] is True
    assert client.raw(8791, "/config", method="POST", body=b"paused=false").status == 200
    assert client.raw(8791, "/dispatch").status == 200
    assert b"Pause fictional queue" in client.raw(8791, "/").read()


def test_protected_listener_rejects_unauthorized_data_and_changes() -> None:
    client = ManagementClient()
    for path in ("/backup", "/config", "/dispatch"):
        assert client.raw(8792, path).status == 403
    assert client.raw(8792, "/config", method="POST", body=b"paused=true").status == 403
    assert client.servers[8792].paused is False
    headers = {"X-Lab-Access": "training-admin"}
    assert client.raw(8792, "/backup", headers=headers).status == 200
    assert client.raw(
        8792, "/config", method="POST", body=b"paused=true", headers=headers
    ).status == 200
    assert client.raw(8792, "/dispatch", headers=headers).status == 503
    assert client.servers[8791].paused is False


@pytest.mark.parametrize("body", [b"", b"paused=maybe", b"paused=true&host=x", b"command=stop", b"x" * 513])
def test_management_surface_cannot_control_hosts_or_accept_arbitrary_fields(body: bytes) -> None:
    client = ManagementClient()
    assert client.raw(8791, "/config", method="POST", body=body).status == 400
    assert client.servers[8791].paused is False
    for path in ("/.env", "/../../config/scope.yaml", "/exec", "/api/orders/2002"):
        assert client.raw(8791, path).status == 404


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "localhost", "192.168.0.1"])
def test_management_binding_preserves_exact_loopback_boundary(host: str) -> None:
    with pytest.raises(ValueError, match="ONLY"):
        management.ManagementServer((host, 8791), management.ManagementHandler)


def test_host_and_origin_checks_precede_all_management_state_changes() -> None:
    client = ManagementClient()
    for headers in ({"Host": "attacker.invalid:8791"}, {"Origin": "https://attacker.invalid"}):
        assert client.raw(
            8791, "/config", method="POST", body=b"paused=true", headers=headers
        ).status == 403
    assert client.servers[8791].paused is False


def test_identity_gate_precedes_every_management_write(monkeypatch: pytest.MonkeyPatch) -> None:
    client = ManagementClient()

    def spoofed_open(req: Any, timeout: int) -> Response:
        response = client.open(req, timeout)
        if req.selector == "/__lab__/health":
            data = json.loads(response.getvalue())
            data["service_id"] = "not-the-management-lab"
            return Response(json.dumps(data).encode(), 200, response.headers)
        return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=spoofed_open))
    checks, controls = verify.verify_management()
    assert len(checks) == 2 and controls == []
    assert all(not row["observed_intentional_weakness"] for row in checks)
    assert all("identity failed" in row["evidence"]["check_error"] for row in checks)
    assert not any(method == "POST" for method, _, _ in client.requests)


def test_management_verifier_restores_state_after_a_lost_write_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ManagementClient()
    interrupted = False

    def losing_open(req: Any, timeout: int) -> Response:
        nonlocal interrupted
        response = client.open(req, timeout)
        if not interrupted and req.host.endswith(":8791") and req.data == b"paused=true":
            interrupted = True
            response.close()
            raise OSError("Synthetic lost management response")
        return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=losing_open))
    checks, _ = verify.verify_management()
    assert interrupted and client.servers[8791].paused is False
    assert any("Synthetic lost" in row["evidence"].get("check_error", "") for row in checks)


def test_high_network_cases_are_canonical_scored_and_visible_without_optional_ftp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = Client()
    client.server.management_lab = True
    portal = Opener(client)
    network = ManagementClient()

    def routed_open(req: Any, timeout: int) -> Response:
        return portal.open(req, timeout) if req.host.endswith(":8787") else network.open(req, timeout)

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=routed_open))
    settings = Settings(ROOT / "config")
    endpoint = {"host": "127.0.0.1", "scheme": "http", "port": 8787, "path": "/"}
    findings, receipt = harbordesk_probe.run(settings.scope, "127.0.0.1", endpoint, tmp_path)
    assert len(findings) == receipt["passed"] == receipt["total"] == 19
    assert len(receipt["secure_controls"]) == 17
    assert all(row["passed"] for row in receipt["secure_controls"])
    assert receipt["management_status"] == "enabled"
    assert receipt["network_status"] == "not started"
    assert harbordesk_probe.confirmed_services(receipt) == (
        Service(8791, "tcp", name="http"), Service(8792, "tcp", name="http")
    )
    host = Host("127.0.0.1", services=(Service(8787, "tcp", name="http"),))
    profile = context.build_profile(host, findings, settings.scope, settings.roles, settings.controls)
    selected = [item for item in findings if item.tool_native_id in ("HD-23", "HD-24")]
    assert len(selected) == 2
    for finding in selected:
        assert finding.native_severity == "High" and finding.port == 8791
        result = scoring.score(finding, None, profile, host.services, settings.weights)
        assert result.risk == 60 and result.band == "High" and result.cve_id is None
        assert json.loads(finding.evidence)["evidence"]["http_response_observed"] is True
    assert network.servers[8791].paused is False

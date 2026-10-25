"""Regression checks for meaningful vulnerable/controlled fixture comparisons."""

import io
import json
from datetime import datetime, timedelta, timezone
from email.message import Message
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from labs.harbordesk import app, verify
from tests.test_harbordesk_lab import request
from vulnassess import harbordesk_probe as probe


def test_new_fixture_resources_are_real_and_secure_ownership_is_enforced():
    for resource, identity, key in [("tickets", 3002, "ticket"), ("documents", 4002, "document")]:
        status, _, raw = request(f"/api/{resource}/{identity}")
        assert status == 200 and json.loads(raw)[key]["owner"] == "other-demo"
        assert (
            request(
                f"/secure/api/{resource}/{identity}",
                headers={"Cookie": "secure_lab_session=harbor-demo-session"},
            )[0]
            == 404
        )
    assert (
        request(
            "/secure/api/orders/2001", headers={"Cookie": "secure_lab_session=harbor-demo-session"}
        )[0]
        == 200
    )


def test_safe_comparison_rejects_sql_and_escapes_html():
    status, _, raw = request("/secure/api/customers?q=%27%20OR%20%271%27%3D%271%27%20--%20")
    assert status == 200 and json.loads(raw)["customers"] == []
    assert (
        request("/secure/api/login", method="POST", body=b"username=admin%27+--+&password=wrong")[0]
        == 401
    )
    status, headers, raw = request("/secure/search?q=%3Cem%3Efixture%3C%2Fem%3E")
    assert b"&lt;em&gt;" in raw and b"<em>fixture</em>" not in raw
    assert headers["Content-Security-Policy"] and headers["X-Content-Type-Options"] == "nosniff"


def test_comparison_does_not_accept_vulnerable_cookie_and_has_no_host_file_access():
    for path in ("/secure/admin", "/secure/debug/config", "/secure/api/profile"):
        assert request(path, headers={"Cookie": "lab_session=admin"})[0] in (401, 403)
    for path in ("/api/documents/../../.env", "/secure/api/documents/../.env"):
        assert request(path)[0] in (401, 404)


def test_full_web_comparison_verifies_without_network_claims(monkeypatch):
    class Response(io.BytesIO):
        status: int
        headers: Message

    class Opener:
        def __init__(self):
            self.server = SimpleNamespace(
                server_address=("127.0.0.1", 8787),
                workspace=app.Workspace(),
                secure_workspace=app.Workspace(),
            )

        def open(self, req, timeout):
            parsed = urlsplit(req.full_url)
            status, headers, body = request(
                parsed.path + ("?" + parsed.query if parsed.query else ""),
                method=req.get_method(),
                body=req.data or b"",
                headers=dict(req.header_items()),
                server=self.server,
            )
            response = Response(body)
            response.status, response.headers = status, headers
            return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: Opener())
    report = verify.verify("http://127.0.0.1:8787/", extended=True, include_network=True)
    assert report["passed"] == report["total"] == 17
    assert len(report["secure_controls"]) == 15
    assert {row["id"] for row in report["checks"]} >= {
        "HD-17",
        "HD-18",
        "HD-19",
        "HD-20",
        "HD-21",
        "HD-22",
    }
    assert all(row["passed"] for row in report["secure_controls"])
    assert report["network_status"] == "not started"
    assert not any(row["id"] == "HD-13" for row in report["checks"])
    assert report["requested_checks"] == list(verify.WEB_CHECKS)
    assert report["requested_controls"] == list(verify.WEB_CONTROLS)
    assert probe.coverage(report).startswith("complete: 17/17")


def test_inventory_does_not_claim_network_running_by_default():
    status, _, raw = request("/__lab__/inventory")
    inventory = json.loads(raw)
    assert status == 200 and inventory["network_enabled"] is False
    assert len(inventory["services"]) == 1


@pytest.fixture
def offline_verifier_transport(monkeypatch):
    """Run the real HTTP handler through memory streams; no socket exemptions."""
    calls = []

    def install(fault=None, *, network=False):
        server = SimpleNamespace(
            server_address=("127.0.0.1", 8787),
            workspace=app.Workspace(),
            secure_workspace=app.Workspace(),
        )

        class Response(io.BytesIO):
            status: int
            headers: Message

        class Opener:
            def open(self, req, timeout):
                parsed = urlsplit(req.full_url)
                calls.append(parsed.path)
                status, headers, body = request(
                    parsed.path + ("?" + parsed.query if parsed.query else ""),
                    method=req.get_method(),
                    body=req.data or b"",
                    headers=dict(req.header_items()),
                    server=server,
                )
                if parsed.path == "/__lab__/health" and network:
                    body = json.dumps({**json.loads(body), "network_lab": True}).encode()
                if fault:
                    body = fault(parsed.path, body)
                response = Response(body)
                response.status, response.headers = status, headers
                return response

        monkeypatch.setattr(verify, "build_opener", lambda *args: Opener())
        return calls

    return install


@pytest.mark.parametrize(
    "path,identity",
    [
        ("/secure/api/customers", "HC-01"),
        ("/api/documents/4002", "HD-10"),
    ],
)
@pytest.mark.parametrize("failure", ["timeout", "invalid-json"])
def test_late_check_failure_keeps_completed_findings_and_receipt(
    tmp_path, offline_verifier_transport, path, identity, failure
):
    def fault(actual, body):
        if actual == path:
            if failure == "timeout":
                raise TimeoutError("injected offline failure")
            return b"invalid-json"
        return body

    offline_verifier_transport(fault)
    scope = SimpleNamespace(contains=lambda ip: True, is_canary=lambda ip: False)
    endpoint = {"host": "127.0.0.1", "scheme": "http", "port": 8787, "path": "/"}
    findings, receipt = probe.run(scope, "127.0.0.1", endpoint, tmp_path)
    checks = {row["id"]: row for row in receipt["checks"]}
    controls = {row["id"]: row for row in receipt["secure_controls"]}
    failed = (controls if identity.startswith("HC") else checks)[identity]
    evidence = failed if identity.startswith("HC") else failed["evidence"]
    assert evidence["check_error"] == (
        "TimeoutError" if failure == "timeout" else "JSONDecodeError"
    )
    assert checks["HD-02"]["observed_intentional_weakness"] is True
    assert checks["HD-03"]["observed_intentional_weakness"] is True
    assert checks["HD-11"]["observed_intentional_weakness"] is True
    assert controls["HC-10"]["passed"] is True
    assert {row["id"] for row in receipt["checks"]} == set(receipt["requested_checks"])
    assert {row["id"] for row in receipt["secure_controls"]} == set(receipt["requested_controls"])
    assert {item.tool_native_id for item in findings} >= {"HD-02", "HD-03", "HD-11"}
    assert len(findings) == (17 if identity.startswith("HC") else 16)
    assert probe.coverage(receipt).startswith("partial:")
    assert identity in probe.coverage(receipt)
    assert json.loads((tmp_path / "harbordesk-checks.json").read_text()) == receipt


def test_failed_identity_gate_performs_no_checks(monkeypatch, offline_verifier_transport):
    def fault(path, body):
        return json.dumps({"lab_id": "wrong", "fixtures_only": True}).encode()

    calls = offline_verifier_transport(fault, network=True)
    network = Mock(side_effect=AssertionError("identity gate must precede network checks"))
    monkeypatch.setattr(verify, "verify_network", network)
    with pytest.raises(ValueError, match="Not the identified"):
        verify.verify(probe.BASE, extended=True, include_network=True)
    assert calls == ["/__lab__/health"]
    network.assert_not_called()


@pytest.fixture
def offline_network_transport(monkeypatch):
    """Inject FTP and TLS objects, retaining the global no-network guard."""
    from cryptography import x509

    def install(*, tls_failure=None, ftp_failure=None):
        class FTP:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                if ftp_failure == "cleanup":
                    raise EOFError("cleanup failed after observations")

            def connect(self, host, port, timeout):
                assert host == "127.0.0.1"
                self.port = port

            def getwelcome(self):
                return "220 HarborDesk fictional local training FTP"

            def login(self, *args):
                if self.port == 2122:
                    raise verify.ftplib.error_perm("530 denied")
                if ftp_failure == "login":
                    raise EOFError("login failed")
                return "230 logged in"

            def retrbinary(self, command, callback):
                if ftp_failure == "retrieve":
                    raise TimeoutError("transfer failed")
                callback(b"HARBORDESK-FICTIONAL-OPERATIONS")

        class TLS:
            def __init__(self, port):
                self.port = port

            def __enter__(self):
                if tls_failure == "handshake":
                    raise OSError("handshake failed")
                return self

            def __exit__(self, *args):
                pass

            def getpeercert(self, binary_form):
                if tls_failure == "missing-certificate":
                    return None
                return str(self.port).encode()

            def version(self):
                return "TLSv1.3"

            def sendall(self, data):
                assert data.startswith(b"GET /admin HTTP/1.0")
                if tls_failure == "send":
                    raise TimeoutError("HTTP send failed")

            def recv(self, limit):
                if tls_failure == "receive":
                    raise TimeoutError("HTTP receive failed")
                if getattr(self, "sent", False):
                    return b""
                self.sent = True
                if tls_failure == "parse":
                    return b"malformed"
                return (
                    b"HTTP/1.0 "
                    + (b"200" if self.port == 8443 else b"403")
                    + b" OK\r\n\r\nharbordesk-local-v1"
                )

        class Raw:
            def __init__(self, port):
                self.port = port

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        class Context:
            def __init__(self, *args):
                pass

            def wrap_socket(self, raw, server_hostname):
                assert server_hostname == "127.0.0.1"
                return TLS(raw.port)

        def connect(address, timeout):
            assert address[0] == "127.0.0.1"
            return Raw(address[1])

        def certificate(data):
            if tls_failure == "certificate":
                raise ValueError("certificate parse failed")
            offset = 1 if data == b"8444" else -1
            return SimpleNamespace(
                not_valid_after_utc=datetime.now(timezone.utc) + timedelta(hours=offset)
            )

        monkeypatch.setattr(verify.ftplib, "FTP", FTP)
        monkeypatch.setattr(verify.socket, "create_connection", connect)
        monkeypatch.setattr(verify.ssl, "SSLContext", Context)
        monkeypatch.setattr(x509, "load_der_x509_certificate", certificate)

    return install


@pytest.mark.parametrize("failure", ["send", "receive", "parse"])
def test_tls_certificate_survives_management_http_failure(
    offline_verifier_transport, offline_network_transport, failure
):
    offline_verifier_transport(network=True)
    offline_network_transport(tls_failure=failure)
    receipt = verify.verify(probe.BASE, extended=True, include_network=True)
    checks = {row["id"]: row for row in receipt["checks"]}
    controls = {row["id"]: row for row in receipt["secure_controls"]}
    assert checks["HD-15"]["observed_intentional_weakness"] is True
    assert checks["HD-15"]["evidence"]["certificate_expired"] is True
    assert "check_error" not in checks["HD-15"]["evidence"]
    assert checks["HD-16"]["observed_intentional_weakness"] is False
    assert "check_error" in checks["HD-16"]["evidence"]
    assert "check_error" not in controls["HC-12"]
    assert "check_error" in controls["HC-13"]
    assert set(receipt["requested_checks"]) == set(checks)
    assert set(receipt["requested_controls"]) == set(controls)
    assert probe.coverage(receipt).startswith("partial:")
    assert 8443 in {service.port for service in probe.confirmed_services(receipt)}


@pytest.mark.parametrize("failure", ["handshake", "certificate", "missing-certificate"])
def test_tls_setup_failure_records_both_requested_checks(offline_network_transport, failure):
    offline_network_transport(tls_failure=failure)
    checks, controls = verify.verify_network()
    checks = {row["id"]: row for row in checks}
    controls = {row["id"]: row for row in controls}
    for identity in ("HD-15", "HD-16"):
        assert checks[identity]["observed_intentional_weakness"] is False
        assert "check_error" in checks[identity]["evidence"]
    for identity in ("HC-12", "HC-13"):
        assert controls[identity]["passed"] is False
        assert "check_error" in controls[identity]


@pytest.mark.parametrize("failure", ["retrieve", "cleanup", "login"])
def test_ftp_late_failure_preserves_independent_transport_evidence(
    offline_network_transport, failure
):
    offline_network_transport(ftp_failure=failure)
    rows, _ = verify.verify_network()
    checks = {row["id"]: row for row in rows}
    assert len(checks) == len(rows) == 4
    assert checks["HD-14"]["observed_intentional_weakness"] is (failure != "login")
    if failure == "retrieve":
        assert checks["HD-13"]["evidence"]["check_error"] == "TimeoutError"
        receipt = {"checks": rows, "network_status": "enabled"}
        assert 2121 in {service.port for service in probe.confirmed_services(receipt)}
    elif failure == "cleanup":
        assert checks["HD-13"]["observed_intentional_weakness"] is True
        assert "check_error" not in checks["HD-14"]["evidence"]
    else:
        assert "check_error" in checks["HD-13"]["evidence"]
        assert checks["HD-14"]["evidence"]["check_error"] == "EOFError"


@pytest.mark.parametrize("failure", ["normalization", "role", "order"])
def test_write_response_failure_returns_partial_receipt_after_restoration(monkeypatch, failure):
    from tests.synthetic.test_synthetic_harbordesk_impact import Client, Opener

    client = Client()
    original_role = "admin" if failure == "normalization" else "customer"
    client.server.workspace.update_profile("demo", {"role": original_role})
    opener = Opener(client)
    interrupted = False

    def losing_open(req, timeout):
        nonlocal interrupted
        response = opener.open(req, timeout)
        path = urlsplit(req.full_url).path
        form = parse_qs((req.data or b"").decode())
        if not interrupted and (
            (
                failure == "normalization"
                and path == "/api/profile"
                and form.get("role") == ["customer"]
            )
            or (failure == "role" and path == "/api/profile" and form.get("role") == ["admin"])
            or (failure == "order" and path == "/api/orders/2002" and form.get("total") == ["0"])
        ):
            interrupted = True
            response.close()
            raise OSError("Synthetic lost write response")
        return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=losing_open))
    receipt = verify.verify(probe.BASE, extended=True)
    checks = {row["id"]: row for row in receipt["checks"]}
    identity = "HD-19" if failure == "order" else "HD-18"
    assert interrupted
    assert checks[identity]["observed_intentional_weakness"] is False
    assert checks[identity]["evidence"]["check_error"] == "OSError"
    assert checks["HD-17"]["observed_intentional_weakness"] is True
    assert checks["HD-22"]["observed_intentional_weakness"] is True
    assert client.server.workspace.profile("demo")["role"] == original_role
    assert client.server.workspace.order(2002)["total"] == 280
    assert probe.coverage(receipt).startswith("partial:")
    assert len(receipt["checks"]) == len(receipt["requested_checks"]) == 17


@pytest.mark.parametrize("failure", ["backup", "write", "comparison"])
def test_management_check_failure_preserves_independent_proofs(monkeypatch, failure):
    from tests.synthetic.test_synthetic_harbordesk_management import ManagementClient

    client = ManagementClient()
    interrupted = False

    def failing_open(req, timeout):
        nonlocal interrupted
        if failure == "backup" and req.host.endswith(":8791") and req.selector == "/backup":
            raise TimeoutError("Synthetic backup failure")
        if failure == "comparison" and req.host.endswith(":8792") and req.selector == "/backup":
            raise TimeoutError("Synthetic comparison failure")
        response = client.open(req, timeout)
        if (
            failure == "write"
            and not interrupted
            and req.host.endswith(":8791")
            and req.data == b"paused=true"
        ):
            interrupted = True
            response.close()
            raise OSError("Synthetic lost management write response")
        return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=failing_open))
    rows, controls = verify.verify_management()
    checks = {row["id"]: row for row in rows}
    secure = {row["id"]: row for row in controls}
    assert set(checks) == {"HD-23", "HD-24"}
    assert set(secure) == {"HC-19", "HC-20"}
    failed = "HD-23" if failure == "backup" else "HD-24" if failure == "write" else "HC-19"
    for identity, row in checks.items():
        assert row["observed_intentional_weakness"] is (identity != failed)
        assert ("check_error" in row["evidence"]) is (identity == failed)
    assert secure["HC-20"]["passed"] is True
    assert client.servers[8791].paused is False
    assert client.servers[8792].paused is False


def test_full_twenty_three_check_receipt_retains_all_upstream_proofs(
    monkeypatch, tmp_path, offline_network_transport
):
    from tests.synthetic.test_synthetic_harbordesk_impact import Client, Opener
    from tests.synthetic.test_synthetic_harbordesk_management import ManagementClient

    offline_network_transport()
    client = Client()
    client.server.management_lab = True
    client.server.network_lab = True
    portal = Opener(client)
    management = ManagementClient()

    def routed_open(req, timeout):
        return (
            portal.open(req, timeout)
            if req.host.endswith(":8787")
            else management.open(req, timeout)
        )

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=routed_open))
    scope = SimpleNamespace(contains=lambda ip: True, is_canary=lambda ip: False)
    endpoint = {"host": "127.0.0.1", "scheme": "http", "port": 8787, "path": "/"}
    findings, receipt = probe.run(scope, "127.0.0.1", endpoint, tmp_path)
    assert len(findings) == receipt["passed"] == receipt["total"] == 23
    assert {finding.tool_native_id for finding in findings} == set(probe.CHECKS)
    assert set(receipt["requested_checks"]) == set(probe.CHECKS)
    assert len(receipt["secure_controls"]) == len(receipt["requested_controls"]) == 20
    assert all(row["passed"] for row in receipt["secure_controls"])
    assert probe.coverage(receipt).startswith("complete: 23/23")
    assert client.server.workspace.profile("demo")["role"] == "customer"
    assert client.server.workspace.order(2002)["total"] == 280
    assert management.servers[8791].paused is False
    receipt["checks"] = [row for row in receipt["checks"] if row["id"] != "HD-24"]
    assert "missing requested checks=HD-24" in probe.coverage(receipt)
    assert probe.coverage(receipt).startswith("partial:")

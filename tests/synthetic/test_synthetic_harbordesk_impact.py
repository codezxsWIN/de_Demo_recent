"""Synthetic pure-logic checks with fake HTTP transports, never scanner evidence."""

import io
import json
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from labs.harbordesk import app, verify
from tests.test_harbordesk_lab import request
from vulnassess import harbordesk_guidance, harbordesk_probe, scoring
from vulnassess.schema import ContextProfile, Feature, Finding, Service
from vulnassess.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
DEMO = "lab_session=demo"
SECURE_DEMO = "secure_lab_session=harbor-demo-session"
SECURE_ADMIN = "secure_lab_session=harbor-admin-session"
NEW_IDS = {"HD-17", "HD-18", "HD-19"}


class Client:
    def __init__(self) -> None:
        self.server = SimpleNamespace(
            server_address=("127.0.0.1", 8787),
            workspace=app.Workspace(),
            secure_workspace=app.Workspace(),
        )

    def api(
        self,
        path: str,
        form: dict[str, Any] | None = None,
        *,
        cookie: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        fields = dict(headers or {})
        if cookie:
            fields["Cookie"] = cookie
        status, _, body = request(
            path,
            method="POST" if form is not None else "GET",
            body=urlencode(form, doseq=True).encode() if form is not None else b"",
            headers=fields,
            server=self.server,
        )
        return status, json.loads(body)


class Response(io.BytesIO):
    def __init__(self, body: bytes, status: int, headers: Message) -> None:
        super().__init__(body)
        self.status = status
        self.headers = headers


class Opener:
    def __init__(self, client: Client) -> None:
        self.client = client

    def open(self, req: Any, timeout: int) -> Response:
        parsed = urlsplit(req.full_url)
        status, headers, body = request(
            parsed.path + ("?" + parsed.query if parsed.query else ""),
            method=req.get_method(),
            body=req.data or b"",
            headers=dict(req.header_items()),
            server=self.client.server,
        )
        return Response(body, status, headers)


@pytest.fixture
def client() -> Client:
    return Client()


def test_bulk_export_has_real_fixture_collections_and_admin_comparison(client: Client) -> None:
    status, data = client.api("/api/admin/export")
    assert status == 200 and data["fixture"] is True
    assert {key: len(rows) for key, rows in data["export"].items()} == {
        "customers": 3,
        "orders": 2,
        "tickets": 2,
        "documents": 2,
    }
    assert {row["owner"] for row in data["export"]["orders"]} == {"demo", "other-demo"}
    assert "users" not in data["export"] and "password" not in json.dumps(data)
    for cookie in (None, DEMO, SECURE_DEMO):
        assert client.api("/secure/api/admin/export", cookie=cookie)[0] == 403
    assert client.api("/secure/api/admin/export", cookie=SECURE_ADMIN) == (200, data)


def test_mass_assignment_changes_a_separate_administrator_authorization_decision(
    client: Client,
) -> None:
    assert client.api("/api/admin/summary", cookie=DEMO)[0] == 403
    assert client.api("/api/profile", {"role": "admin"})[0] == 401
    assert client.api("/api/profile", {"role": "admin"}, cookie=DEMO)[0] == 200
    assert client.api("/api/profile", cookie=DEMO)[1]["profile"]["role"] == "admin"
    assert client.api("/api/admin/summary", cookie=DEMO)[0] == 200
    status, data = client.api(
        "/api/login", {"username": "demo", "password": "training-demo"}
    )
    assert status == 200 and data["user"]["role"] == "admin"
    assert client.api("/secure/api/admin/summary", cookie=SECURE_DEMO)[0] == 403
    assert client.api("/secure/api/profile", cookie=SECURE_DEMO)[1]["profile"]["role"] == "customer"
    assert client.api("/api/profile", {"role": "customer"}, cookie=DEMO)[0] == 200
    assert client.api("/api/admin/summary", cookie=DEMO)[0] == 403


def test_secure_profile_rejects_role_without_partial_updates_and_allows_names(
    client: Client,
) -> None:
    before = client.api("/secure/api/profile", cookie=SECURE_DEMO)[1]
    assert client.api(
        "/secure/api/profile", {"name": "Changed", "role": "admin"}, cookie=SECURE_DEMO
    )[0] == 400
    assert client.api("/secure/api/profile", cookie=SECURE_DEMO)[1] == before
    assert client.api(
        "/secure/api/profile", {"name": "Updated Fixture"}, cookie=SECURE_DEMO
    )[0] == 200
    profile = client.api("/secure/api/profile", cookie=SECURE_DEMO)[1]["profile"]
    assert profile["name"] == "Updated Fixture" and profile["role"] == "customer"
    assert client.api("/api/profile")[1]["profile"]["name"] == "Avery Demo"
    assert client.api("/secure/api/profile", {"name": "Guest"})[0] == 401


@pytest.mark.parametrize("cookie", [None, DEMO])
def test_cross_account_write_is_retained_but_secure_workspace_is_unchanged(
    client: Client, cookie: str | None
) -> None:
    assert client.api("/api/orders/2002")[1]["order"]["total"] == 280
    assert client.api("/api/orders/2002", {"total": 0}, cookie=cookie)[0] == 200
    order = client.api("/api/orders/2002")[1]["order"]
    assert order["owner"] == "other-demo" and order["total"] == 0
    assert client.api("/secure/api/orders/2002", {"total": 0})[0] == 401
    assert client.api(
        "/secure/api/orders/2002", {"total": 0}, cookie=SECURE_DEMO
    )[0] == 404
    secure_orders = client.api("/secure/api/admin/export", cookie=SECURE_ADMIN)[1]["export"]["orders"]
    assert next(row for row in secure_orders if row["id"] == 2002)["total"] == 280


@pytest.mark.parametrize("total", [0, 1_000_000])
def test_secure_owner_can_change_and_read_back_its_own_order(client: Client, total: int) -> None:
    status, data = client.api("/secure/api/orders/2001", {"total": total}, cookie=SECURE_DEMO)
    assert status == 200 and data["order"]["owner"] == "demo"
    assert client.api("/secure/api/orders/2001", cookie=SECURE_DEMO)[1]["record"]["total"] == total
    assert client.api("/api/orders/2001")[1]["order"]["total"] == 120


@pytest.mark.parametrize(
    "form",
    [
        {"total": -1},
        {"total": "1.5"},
        {"total": "NaN"},
        {"total": 1_000_001},
        {"total": "00000000"},
        {"total": "\u0661"},
        {"total": ["0", "1"]},
        {"total": 0, "owner": "demo"},
        {},
    ],
)
def test_invalid_order_writes_fail_explicitly_without_mutation(
    client: Client, form: dict[str, Any]
) -> None:
    assert client.api("/api/orders/2002", form)[0] == 400
    assert client.api("/api/orders/2002")[1]["order"]["total"] == 280


@pytest.mark.parametrize("identity", ["9999", "-1", "2002/extra", "123456789", "%2e%2e"])
def test_order_writes_cannot_address_other_resources(client: Client, identity: str) -> None:
    assert client.api("/api/orders/" + identity, {"total": 0})[0] == 404
    assert client.api("/api/orders/2002")[1]["order"]["total"] == 280


@pytest.mark.parametrize(
    "form",
    [
        {"role": "superuser"},
        {"role": ["admin", "customer"]},
        {"username": "admin"},
        {"name": ""},
        {"name": "x" * 81},
        {"name": "line\nbreak"},
        {"name": "control\x7f"},
        {},
    ],
)
def test_profile_changes_are_bounded_to_the_intended_training_fields(
    client: Client, form: dict[str, Any]
) -> None:
    before = client.api("/api/profile", cookie=DEMO)[1]
    assert client.api("/api/profile", form, cookie=DEMO)[0] == 400
    assert client.api("/api/profile", cookie=DEMO)[1] == before


@pytest.mark.parametrize(
    "headers", [{"Origin": "https://untrusted.invalid"}, {"Host": "attacker.invalid:8787"}]
)
def test_new_write_routes_preserve_origin_and_host_fences(
    client: Client, headers: dict[str, str]
) -> None:
    for path, form in [
        ("/api/profile", {"role": "admin"}),
        ("/api/orders/2002", {"total": "0"}),
    ]:
        status, _, _ = request(
            path,
            method="POST",
            body=urlencode(form).encode(),
            headers={"Cookie": DEMO, **headers},
            server=client.server,
        )
        assert status == 403
    assert client.server.workspace.profile("demo")["role"] == "customer"
    assert client.server.workspace.order(2002)["total"] == 280


def test_workspace_rejects_missing_order_without_a_success_shaped_fallback(client: Client) -> None:
    with pytest.raises(ValueError, match="Unknown fixture order: 9999"):
        client.server.workspace.update_order(9999, 0)
    assert client.server.workspace.order(9999) is None


def test_extended_verification_is_repeatable_and_restores_preexisting_state(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client.server.workspace.update_profile("demo", {"role": "admin", "name": "Original Fixture"})
    client.server.workspace.update_order(2002, 999)
    opener = Opener(client)
    monkeypatch.setattr(verify, "build_opener", lambda *args: opener)
    for _ in range(2):
        receipt = verify.verify(harbordesk_probe.BASE, extended=True)
        assert receipt["passed"] == receipt["total"] == 17
        assert len(receipt["secure_controls"]) == 15
        assert all(row["passed"] for row in receipt["secure_controls"])
        assert client.server.workspace.profile("demo") == {
            "username": "demo", "name": "Original Fixture", "role": "admin"
        }
        assert client.server.workspace.order(2002)["total"] == 999
        assert client.server.secure_workspace.profile("demo")["role"] == "customer"


def test_verifier_does_not_claim_weaknesses_when_their_operations_are_denied(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    opener = Opener(client)

    def guarded_open(req: Any, timeout: int) -> Response:
        path = urlsplit(req.full_url).path
        form = parse_qs((req.data or b"").decode())
        if (
            path == "/api/admin/export"
            or (path == "/api/profile" and form.get("role") == ["admin"])
            or (path == "/api/orders/2002" and req.get_method() == "POST")
        ):
            return Response(b'{"error":"Synthetic denied operation"}', 403, Message())
        return opener.open(req, timeout)

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=guarded_open))
    receipt = verify.verify(harbordesk_probe.BASE, extended=True)
    assert receipt["total"] == 17 and receipt["passed"] == 14
    assert all(
        row["observed_intentional_weakness"] is False
        for row in receipt["checks"] if row["id"] in NEW_IDS
    )
    assert all(row["passed"] for row in receipt["secure_controls"])
    assert client.server.workspace.profile("demo")["role"] == "customer"
    assert client.server.workspace.order(2002)["total"] == 280


@pytest.mark.parametrize("failure", ["role", "order"])
def test_interrupted_verification_restores_the_original_fixture_value(
    client: Client, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    opener = Opener(client)

    def failing_open(req: Any, timeout: int) -> Response:
        path = urlsplit(req.full_url).path
        if (
            failure == "role"
            and path == "/api/admin/summary"
            and client.server.workspace.profile("demo")["role"] == "admin"
        ) or (
            failure == "order"
            and path == "/api/orders/2002"
            and req.get_method() == "GET"
            and client.server.workspace.order(2002)["total"] != 280
        ):
            raise OSError("Synthetic interrupted verification")
        return opener.open(req, timeout)

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=failing_open))
    with pytest.raises(OSError, match="Synthetic interrupted"):
        verify.verify(harbordesk_probe.BASE, extended=True)
    assert client.server.workspace.profile("demo")["role"] == "customer"
    assert client.server.workspace.order(2002)["total"] == 280


def test_failed_restoration_is_explicit_not_a_successful_receipt(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    opener = Opener(client)

    def refusing_open(req: Any, timeout: int) -> Response:
        form = parse_qs((req.data or b"").decode())
        if (
            urlsplit(req.full_url).path == "/api/profile"
            and form.get("role") == ["customer"]
            and client.server.workspace.profile("demo")["role"] == "admin"
        ):
            return Response(b'{"error":"Synthetic restoration refused"}', 403, Message())
        return opener.open(req, timeout)

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=refusing_open))
    with pytest.raises(ValueError, match="could not restore /api/profile role"):
        verify.verify(harbordesk_probe.BASE, extended=True)


@pytest.mark.parametrize("failure", ["normalization", "role", "order"])
def test_lost_write_response_still_restores_original_state(
    client: Client, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    original_role = "admin" if failure == "normalization" else "customer"
    client.server.workspace.update_profile("demo", {"role": original_role})
    opener = Opener(client)
    interrupted = False

    def losing_open(req: Any, timeout: int) -> Response:
        nonlocal interrupted
        response = opener.open(req, timeout)
        path = urlsplit(req.full_url).path
        form = parse_qs((req.data or b"").decode())
        if not interrupted and (
            (failure == "normalization" and path == "/api/profile" and form.get("role") == ["customer"])
            or (failure == "role" and path == "/api/profile" and form.get("role") == ["admin"])
            or (failure == "order" and path == "/api/orders/2002" and form.get("total") == ["0"])
        ):
            interrupted = True
            response.close()
            raise OSError("Synthetic lost write response")
        return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=losing_open))
    with pytest.raises(OSError, match="Synthetic lost write response"):
        verify.verify(harbordesk_probe.BASE, extended=True)
    assert interrupted
    assert client.server.workspace.profile("demo")["role"] == original_role
    assert client.server.workspace.order(2002)["total"] == 280


def test_new_checks_produce_provenance_guidance_and_unchanged_deterministic_priorities(
    client: Client, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify, "build_opener", lambda *args: Opener(client))
    settings = Settings(ROOT / "config")
    endpoint = {"host": "127.0.0.1", "scheme": "http", "port": 8787, "path": "/"}
    findings, receipt = harbordesk_probe.run(settings.scope, "127.0.0.1", endpoint, tmp_path)
    new_findings = [finding for finding in findings if finding.tool_native_id in NEW_IDS]
    assert {finding.tool_native_id for finding in new_findings} == NEW_IDS
    assert len(findings) == receipt["passed"] == 17
    assert json.loads((tmp_path / "harbordesk-checks.json").read_text()) == receipt
    profile = ContextProfile(
        host_ip="127.0.0.1",
        role=Feature("web_frontend", 1.0, "rule", "synthetic HTTP fixture"),
        exposure=Feature("internal", 1.0, "rule", "synthetic loopback fixture"),
        segment=None,
        controls={},
        manual={},
    )
    services = (Service(8787, "tcp", name="http"),)
    for finding in new_findings:
        assert Finding.from_json(finding.to_json()) == finding
        assert finding.native_severity == "High" and finding.native_confidence == "high"
        assert finding.cve_ids == ()
        assert finding.provenance.tool == "harbordesk"
        assert finding.provenance.raw_path == str((tmp_path / "harbordesk-checks.json").resolve())
        assert len(finding.evidence) <= 2048
        row = receipt["checks"][finding.provenance.record_index - 1]
        assert json.loads(finding.evidence)["evidence"] == row["evidence"]
        result = scoring.score(finding, None, profile, services, settings.weights)
        repeated = scoring.score(finding, None, profile, services, settings.weights)
        assert result == repeated
        assert result.risk == 60 and result.band == "High"
        assert result.cve_id is None and result.epss_percentile is None
        assert result.cvss_version_used is None and result.kev is False
        guidance = harbordesk_guidance.guidance({
            "tool": finding.tool, "tool_native_id": finding.tool_native_id
        })
        assert guidance and guidance["patch"] and guidance["verify"]
        assert "No vendor CVE" in guidance["source"]


def test_all_original_and_added_cases_remain_present_and_executable(client: Client) -> None:
    cases = client.api("/__lab__/ground-truth")[1]["cases"]
    identities = [case["id"] for case in cases]
    assert len(identities) == len(set(identities))
    assert {f"HD-{number:02}" for number in range(1, 25) if number != 12} == set(identities)
    assert {case["id"] for case in cases if case.get("category") == "network"} == {
        "HD-13", "HD-14", "HD-15", "HD-16", "HD-20", "HD-21", "HD-22", "HD-23", "HD-24"
    }
    assert client.api("/api/admin/export")[0] == 200
    assert client.api("/api/profile", {"role": "admin"}, cookie=DEMO)[0] == 200
    assert client.api("/api/admin/summary", cookie=DEMO)[0] == 200
    assert client.api("/api/orders/2002", {"total": 0}, cookie=DEMO)[0] == 200
    assert client.api("/api/orders/2002")[1]["order"]["total"] == 0


def test_network_observations_use_actual_responses_not_catalog_claims(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(verify, "build_opener", lambda *args: Opener(client))
    receipt = verify.verify(harbordesk_probe.BASE, extended=True, include_network=True)
    checks = {row["id"]: row for row in receipt["checks"]}
    assert checks["HD-20"]["evidence"]["request_scheme"] == "http"
    assert checks["HD-20"]["evidence"]["tls_negotiated"] is False
    assert checks["HD-21"]["evidence"]["declared_service_ports"] == [8787]
    assert checks["HD-21"]["evidence"]["listener_reachability_tested"] is False
    assert "Python/" in checks["HD-22"]["evidence"]["observed_server_header"]
    assert all(checks[identity]["observed_intentional_weakness"] for identity in ("HD-20", "HD-21", "HD-22"))
    assert not {"HD-13", "HD-14", "HD-15", "HD-16"} & checks.keys()
    assert receipt["network_status"] == "not started"
    assert "HTTP transport/inventory/banner observations=3/3" in harbordesk_probe.coverage(receipt)
    assert "no FTP/TLS coverage claimed" in harbordesk_probe.coverage(receipt)


def test_minimized_banner_and_denied_inventory_are_not_reported_as_present(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    opener = Opener(client)

    def hardened_open(req: Any, timeout: int) -> Response:
        path = urlsplit(req.full_url).path
        if path == "/__lab__/inventory":
            return Response(b'{"error":"Synthetic protected inventory"}', 403, Message())
        response = opener.open(req, timeout)
        if path == "/":
            response.headers.replace_header("Server", "HarborDesk")
        return response

    monkeypatch.setattr(verify, "build_opener", lambda *args: SimpleNamespace(open=hardened_open))
    receipt = verify.verify(harbordesk_probe.BASE, extended=True)
    checks = {row["id"]: row for row in receipt["checks"]}
    assert checks["HD-20"]["observed_intentional_weakness"] is True
    assert checks["HD-21"]["observed_intentional_weakness"] is False
    assert checks["HD-22"]["observed_intentional_weakness"] is False
    assert receipt["passed"] == 15 and receipt["total"] == 17


def test_network_comparisons_protect_inventory_and_minimize_only_the_banner(
    client: Client,
) -> None:
    for cookie in (None, DEMO, SECURE_DEMO):
        assert client.api("/secure/__lab__/inventory", cookie=cookie)[0] == 403
    assert client.api("/secure/__lab__/inventory", cookie=SECURE_ADMIN)[0] == 200
    _, vulnerable_headers, _ = request("/")
    _, comparison_headers, _ = request("/secure/search?q=training")
    assert "Python/" in vulnerable_headers["Server"]
    assert comparison_headers["Server"] == "HarborDesk"
    assert client.api("/__lab__/health")[1]["network_lab"] is False
    status, _, page = request("/")
    assert status == 200 and b"network-cases" in page and b"role-form" in page


def test_network_findings_have_native_priorities_without_cve_or_listener_invention(
    client: Client, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify, "build_opener", lambda *args: Opener(client))
    settings = Settings(ROOT / "config")
    endpoint = {"host": "127.0.0.1", "scheme": "http", "port": 8787, "path": "/"}
    findings, receipt = harbordesk_probe.run(settings.scope, "127.0.0.1", endpoint, tmp_path)
    expected = {"HD-20": ("Medium", 40), "HD-21": ("Low", 20), "HD-22": ("Low", 20)}
    profile = ContextProfile(
        host_ip="127.0.0.1",
        role=Feature("web_frontend", 1.0, "rule", "synthetic HTTP fixture"),
        exposure=Feature("internal", 1.0, "rule", "synthetic loopback fixture"),
        segment=None,
        controls={},
        manual={},
    )
    selected = [finding for finding in findings if finding.tool_native_id in expected]
    assert len(selected) == 3
    for finding in selected:
        severity, priority = expected[finding.tool_native_id]
        assert finding.native_severity == severity and finding.cve_ids == ()
        assert finding.port == 8787 and finding.url.startswith(harbordesk_probe.BASE)
        result = scoring.score(finding, None, profile, (), settings.weights)
        assert result.risk == priority and result.cvss_version_used is None
        assert result.cve_id is None and result.kev is False
        guidance = harbordesk_guidance.guidance({
            "tool": "harbordesk", "tool_native_id": finding.tool_native_id
        })
        assert guidance and guidance["patch"] and guidance["verify"]
        row = receipt["checks"][finding.provenance.record_index - 1]
        assert json.loads(finding.evidence)["evidence"] == row["evidence"]
    assert harbordesk_probe.confirmed_services(receipt) == ()

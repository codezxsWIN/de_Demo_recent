"""Regression checks for meaningful vulnerable/controlled fixture comparisons."""

import io
import json
from urllib.parse import urlsplit

from labs.harbordesk import verify
from tests.test_harbordesk_lab import request


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
    report = verify.verify("http://127.0.0.1:8787/", extended=True, include_network=True)
    assert report["passed"] == report["total"] == 11
    assert len(report["secure_controls"]) == 10
    assert all(row["passed"] for row in report["secure_controls"])
    assert report["network_status"] == "not started"
    assert not any(row["id"] == "HD-13" for row in report["checks"])


def test_inventory_does_not_claim_network_running_by_default():
    status, _, raw = request("/__lab__/inventory")
    inventory = json.loads(raw)
    assert status == 200 and inventory["network_enabled"] is False
    assert len(inventory["services"]) == 1

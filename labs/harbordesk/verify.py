"""Bounded checks against the identified loopback training app, never arbitrary sites."""

import argparse
import ftplib
import json
import socket
import ssl
from contextlib import contextmanager
from datetime import datetime, timezone
from http.client import HTTPException
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from labs.harbordesk.app import LAB_ID


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Lab verification never follows redirects")


# Identity failures remain fatal. Only checks after that gate use these guards.
CHECK_ERRORS = (
    OSError,
    ValueError,
    KeyError,
    TypeError,
    IndexError,
    AttributeError,
    EOFError,
    HTTPException,
    ftplib.Error,
    ImportError,
)
WEB_CHECKS = tuple(f"HD-{number:02}" for number in (*range(1, 12), *range(17, 23)))
NETWORK_CHECKS = ("HD-13", "HD-14", "HD-15", "HD-16")
WEB_CONTROLS = tuple(f"HC-{number:02}" for number in (*range(1, 11), *range(14, 19)))
NETWORK_CONTROLS = ("HC-11", "HC-12", "HC-13")


class RestorationError(ValueError):
    """An unverified rollback must remain explicit and stop further stateful checks."""


def _error(rows, identity, error, *, name=None, port=None):
    # A later transport cleanup failure must not replace an already observed fact.
    if any(row["id"] == identity for row in rows):
        return
    if name is None:
        row = {
            "id": identity,
            "observed_intentional_weakness": False,
            "evidence": {"check_error": type(error).__name__},
        }
        if port is not None:
            row["port"] = port
    else:
        row = {"id": identity, "name": name, "passed": False, "check_error": type(error).__name__}
    rows.append(row)


@contextmanager
def _capture(rows, identity, *, name=None, port=None, detailed=False):
    try:
        yield
    except RestorationError:
        raise
    except CHECK_ERRORS as error:
        _error(rows, identity, error, name=name, port=port)
        if detailed:
            row = next(item for item in rows if item["id"] == identity)
            evidence = row["evidence"] if name is None else row
            if "check_error" in evidence:
                evidence["check_error"] = f"{type(error).__name__}: {str(error)[:300]}"


@contextmanager
def _restoration(message):
    try:
        yield
    except CHECK_ERRORS as error:
        raise RestorationError(message) from error


def verify(base, *, extended=False, include_network=False):
    parsed = urlsplit(base)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Verifier accepts only http://127.0.0.1:<port>/")
    origin = f"http://127.0.0.1:{parsed.port or 80}"
    opener = build_opener(ProxyHandler({}), NoRedirects())

    def fetch(path, form=None, cookie=None):
        headers = {"Origin": origin}
        if cookie:
            headers["Cookie"] = cookie
        request = Request(
            origin + path, data=urlencode(form).encode() if form else None, headers=headers
        )
        try:
            response = opener.open(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            return response.status, response.read(65536).decode(), response.headers

    status, body, _ = fetch("/__lab__/health")
    health = json.loads(body)
    if status != 200 or health.get("lab_id") != LAB_ID or health.get("fixtures_only") is not True:
        raise ValueError("Not the identified HarborDesk fixture lab. No active checks performed.")
    results = []

    def record(identity, passed, evidence):
        results.append(
            {"id": identity, "observed_intentional_weakness": bool(passed), "evidence": evidence}
        )

    def login(*, secure=False):
        path = "/secure/api/login" if secure else "/api/login"
        status, _, headers = fetch(path, {"username": "demo", "password": "training-demo"})
        cookie = headers.get("Set-Cookie", "").split(";", 1)[0]
        if status != 200 or not cookie:
            raise ValueError("Fixture login did not establish a session")
        return cookie, headers

    with _capture(results, "HD-01"):
        _, _, headers = fetch("/")
        missing = [
            key
            for key in (
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            )
            if not headers.get(key)
        ]
        record("HD-01", len(missing) == 5, {"missing_headers": missing})
    with _capture(results, "HD-02"):
        _, baseline, _ = fetch("/api/customers?" + urlencode({"q": "Avery"}))
        _, injected, _ = fetch("/api/customers?" + urlencode({"q": "' OR '1'='1' -- "}))
        counts = [len(json.loads(data)["customers"]) for data in (baseline, injected)]
        record(
            "HD-02",
            counts == [1, 3],
            {
                "baseline_customers": counts[0],
                "injected_customers": counts[1],
                "boundary": "read-only disposable fixtures",
            },
        )
    with _capture(results, "HD-03"):
        rejected, _, _ = fetch("/api/login", {"username": "admin", "password": "wrong"})
        accepted, body, _ = fetch("/api/login", {"username": "admin' -- ", "password": "wrong"})
        record(
            "HD-03",
            rejected == 401 and accepted == 200 and json.loads(body)["user"]["role"] == "admin",
            {"normal_wrong_password_status": rejected, "injected_fixture_login_status": accepted},
        )
    with _capture(results, "HD-04"):
        cookie, _ = login()
        _, order, _ = fetch("/api/orders/2002", cookie=cookie)
        owner = json.loads(order)["order"]["owner"]
        record(
            "HD-04",
            cookie == "lab_session=demo" and owner == "other-demo",
            {"signed_in_fixture": "demo", "returned_order_owner": owner},
        )
    marker = '<em data-lab-proof="reflection">LAB-REFLECTION</em>'
    with _capture(results, "HD-05"):
        _, reflected, _ = fetch("/search?" + urlencode({"q": marker}))
        record(
            "HD-05",
            marker in reflected,
            {
                "raw_html_marker_reflected": marker in reflected,
                "browser_script_execution_tested": False,
            },
        )
    with _capture(results, "HD-06"):
        status, body, _ = fetch("/admin")
        record(
            "HD-06",
            status == 200 and "Operations administration" in body,
            {"unauthenticated_status": status},
        )
    with _capture(results, "HD-07"):
        status, body, _ = fetch("/debug/config")
        record(
            "HD-07",
            status == 200 and json.loads(body)["demo_token"] == "NOT-A-REAL-SECRET",
            {"unauthenticated_status": status, "real_secrets": False},
        )
    with _capture(results, "HD-08"):
        _, login_headers = login()
        cookie_header = login_headers.get("Set-Cookie", "")
        record(
            "HD-08",
            bool(cookie_header)
            and not any(
                flag in cookie_header.lower() for flag in ("httponly", "secure", "samesite")
            ),
            {"fixture_cookie": cookie_header},
        )
    controls = []
    if extended:
        for identity, path, key in (
            ("HD-09", "/api/tickets/3002", "ticket"),
            ("HD-10", "/api/documents/4002", "document"),
        ):
            with _capture(results, identity):
                cookie, _ = login()
                status, body, _ = fetch(path, cookie=cookie)
                owner = json.loads(body)[key]["owner"]
                record(
                    identity,
                    status == 200 and owner == "other-demo",
                    {
                        "path": path,
                        "authenticated_fixture": "demo",
                        "returned_owner": owner,
                        "status": status,
                    },
                )
        with _capture(results, "HD-11"):
            status, body, _ = fetch("/api/profile")
            record(
                "HD-11",
                status == 200 and json.loads(body)["profile"]["account"] == "HD-1001",
                {
                    "path": "/api/profile",
                    "unauthenticated_status": status,
                    "data_classification": "fictional profile only",
                },
            )
        name = "Parameterized SQL rejects predicate injection"
        with _capture(controls, "HC-01", name=name):
            _, body, _ = fetch("/secure/api/customers?" + urlencode({"q": "' OR '1'='1' -- "}))
            controls.append(
                {"id": "HC-01", "name": name, "passed": len(json.loads(body)["customers"]) == 0}
            )
        name = "Parameterized login rejects bypass"
        with _capture(controls, "HC-02", name=name):
            status, _, _ = fetch(
                "/secure/api/login", {"username": "admin' -- ", "password": "wrong"}
            )
            controls.append({"id": "HC-02", "name": name, "passed": status == 401})
        for identity, path in (
            ("HC-03", "/secure/api/orders/2002"),
            ("HC-04", "/secure/api/tickets/3002"),
            ("HC-05", "/secure/api/documents/4002"),
        ):
            name = "Object ownership enforced: " + path
            with _capture(controls, identity, name=name):
                secure_cookie, _ = login(secure=True)
                status, _, _ = fetch(path, cookie=secure_cookie)
                controls.append({"id": identity, "name": name, "passed": status == 404})
        name = "HTML output escaped"
        with _capture(controls, "HC-06", name=name):
            _, escaped, _ = fetch("/secure/search?" + urlencode({"q": marker}))
            controls.append(
                {
                    "id": "HC-06",
                    "name": name,
                    "passed": marker not in escaped and "&lt;em" in escaped,
                }
            )
        for identity, path in (
            ("HC-07", "/secure/admin"),
            ("HC-08", "/secure/debug/config"),
            ("HC-09", "/secure/api/profile"),
        ):
            name = "Unauthenticated access denied: " + path
            with _capture(controls, identity, name=name):
                status, _, _ = fetch(path)
                controls.append({"id": identity, "name": name, "passed": status in (401, 403)})
        name = "Comparison cookie has HttpOnly and SameSite=Strict"
        with _capture(controls, "HC-10", name=name):
            _, secure_headers = login(secure=True)
            controls.append(
                {
                    "id": "HC-10",
                    "name": name,
                    "passed": all(
                        flag in secure_headers.get("Set-Cookie", "")
                        for flag in ("HttpOnly", "SameSite=Strict")
                    ),
                }
            )
        expected_counts = {"customers": 3, "orders": 2, "tickets": 2, "documents": 2}
        with _capture(results, "HD-17"):
            status, body, _ = fetch("/api/admin/export")
            exported = json.loads(body).get("export", {})
            counts = {key: len(rows) for key, rows in exported.items() if isinstance(rows, list)}
            record(
                "HD-17",
                status == 200 and counts == expected_counts,
                {"unauthenticated_status": status, "exported_fixture_counts": counts},
            )
        with _capture(results, "HD-18"):
            cookie, _ = login()
            _, body, _ = fetch("/api/profile", cookie=cookie)
            original_role = json.loads(body)["profile"]["role"]
            try:
                normalized, _, _ = fetch("/api/profile", {"role": "customer"}, cookie=cookie)
                baseline_admin, _, _ = fetch("/api/admin/summary", cookie=cookie)
                elevated, _, _ = fetch("/api/profile", {"role": "admin"}, cookie=cookie)
                _, body, _ = fetch("/api/profile", cookie=cookie)
                elevated_role = json.loads(body)["profile"]["role"]
                elevated_admin, _, _ = fetch("/api/admin/summary", cookie=cookie)
                record(
                    "HD-18",
                    normalized == 200
                    and baseline_admin == 403
                    and elevated == 200
                    and elevated_role == "admin"
                    and elevated_admin == 200,
                    {
                        "authenticated_fixture": "demo",
                        "baseline_admin_status": baseline_admin,
                        "role_assignment_status": elevated,
                        "elevated_role": elevated_role,
                        "elevated_admin_status": elevated_admin,
                        "boundary": "fictional process-local role only",
                    },
                )
            finally:
                with _restoration("HarborDesk verifier could not restore /api/profile role"):
                    restored, _, _ = fetch("/api/profile", {"role": original_role}, cookie=cookie)
                    restored_read, body, _ = fetch("/api/profile", cookie=cookie)
                    if restored_read != 200 or json.loads(body)["profile"]["role"] != original_role:
                        raise RestorationError(
                            f"HarborDesk verifier could not restore /api/profile role (HTTP {restored})"
                        )
        with _capture(results, "HD-19"):
            cookie, _ = login()
            _, body, _ = fetch("/api/orders/2002", cookie=cookie)
            original_order = json.loads(body)["order"]
            original_total = original_order["total"]
            changed_total = 0 if original_total != 0 else 1
            try:
                modified, _, _ = fetch("/api/orders/2002", {"total": changed_total}, cookie=cookie)
                read_status, body, _ = fetch("/api/orders/2002", cookie=cookie)
                retained_total = json.loads(body)["order"]["total"]
                record(
                    "HD-19",
                    original_order["owner"] == "other-demo"
                    and modified == 200
                    and read_status == 200
                    and retained_total == changed_total,
                    {
                        "authenticated_fixture": "demo",
                        "order_owner": original_order["owner"],
                        "original_total": original_total,
                        "submitted_total": changed_total,
                        "read_back_total": retained_total,
                        "write_status": modified,
                        "read_back_status": read_status,
                        "boundary": "fictional process-local order only; no payment operation",
                    },
                )
            finally:
                with _restoration("HarborDesk verifier could not restore /api/orders/2002"):
                    restored, _, _ = fetch(
                        "/api/orders/2002", {"total": original_total}, cookie=cookie
                    )
                    restored_read, body, _ = fetch("/api/orders/2002", cookie=cookie)
                    if restored_read != 200 or json.loads(body)["order"]["total"] != original_total:
                        raise ValueError(
                            f"HarborDesk verifier could not restore /api/orders/2002 (HTTP {restored})"
                        )
        with _capture(
            controls,
            "HC-14",
            name="Bulk export requires an administrator, not just a customer session",
        ):
            secure_cookie, _ = login(secure=True)
            anonymous_export, _, _ = fetch("/secure/api/admin/export")
            customer_export, _, _ = fetch("/secure/api/admin/export", cookie=secure_cookie)
            admin_login, _, admin_headers = fetch(
                "/secure/api/login", {"username": "admin", "password": "training-admin"}
            )
            admin_cookie = admin_headers.get("Set-Cookie", "").split(";", 1)[0]
            admin_export, body, _ = fetch("/secure/api/admin/export", cookie=admin_cookie)
            secure_export = json.loads(body).get("export", {})
            controls.append(
                {
                    "id": "HC-14",
                    "name": "Bulk export requires an administrator, not just a customer session",
                    "passed": anonymous_export == customer_export == 403
                    and admin_login == admin_export == 200
                    and {key: len(rows) for key, rows in secure_export.items()} == expected_counts,
                }
            )
        with _capture(
            controls,
            "HC-15",
            name="Self-service permits display names, never protected role assignment",
        ):
            secure_cookie, _ = login(secure=True)
            _, body, _ = fetch("/secure/api/profile", cookie=secure_cookie)
            secure_profile = json.loads(body)["profile"]
            role_status, _, _ = fetch(
                "/secure/api/profile", {"role": "admin"}, cookie=secure_cookie
            )
            secure_admin, _, _ = fetch("/secure/api/admin/summary", cookie=secure_cookie)
            name_status, body, _ = fetch(
                "/secure/api/profile", {"name": secure_profile["name"]}, cookie=secure_cookie
            )
            controls.append(
                {
                    "id": "HC-15",
                    "name": "Self-service permits display names, never protected role assignment",
                    "passed": role_status == 400
                    and secure_admin == 403
                    and name_status == 200
                    and json.loads(body).get("profile", {}).get("role") == "customer",
                }
            )
        with _capture(
            controls,
            "HC-16",
            name="Order writes enforce ownership and preserve legitimate owner updates",
        ):
            secure_cookie, _ = login(secure=True)
            _, _, admin_headers = fetch(
                "/secure/api/login", {"username": "admin", "password": "training-admin"}
            )
            admin_cookie = admin_headers.get("Set-Cookie", "").split(";", 1)[0]
            _, body, _ = fetch("/secure/api/admin/export", cookie=admin_cookie)
            secure_export = json.loads(body)["export"]
            changed_total = 0
            cross_account, _, _ = fetch(
                "/secure/api/orders/2002", {"total": changed_total}, cookie=secure_cookie
            )
            _, body, _ = fetch("/secure/api/admin/export", cookie=admin_cookie)
            secure_orders = json.loads(body).get("export", {}).get("orders", [])
            _, body, _ = fetch("/secure/api/orders/2001", cookie=secure_cookie)
            owned_order = json.loads(body)["record"]
            owned_write, body, _ = fetch(
                "/secure/api/orders/2001", {"total": owned_order["total"]}, cookie=secure_cookie
            )
            controls.append(
                {
                    "id": "HC-16",
                    "name": "Order writes enforce ownership and preserve legitimate owner updates",
                    "passed": cross_account == 404
                    and secure_orders == secure_export.get("orders")
                    and owned_write == 200
                    and json.loads(body).get("order", {}).get("owner") == "demo",
                }
            )
        with _capture(results, "HD-20"):
            http_status, _, http_headers = fetch("/")
            record(
                "HD-20",
                http_status == 200 and parsed.scheme == "http",
                {
                    "request_scheme": parsed.scheme,
                    "response_status": http_status,
                    "tls_negotiated": False,
                    "boundary": "identified loopback HTTP service; no interception performed",
                },
            )
        with _capture(results, "HD-21"):
            inventory_status, body, _ = fetch("/__lab__/inventory")
            inventory = json.loads(body)
            services = inventory.get("services", [])
            declared_ports = (
                [
                    item["port"]
                    for item in services
                    if isinstance(item, dict) and type(item.get("port")) is int
                ]
                if isinstance(services, list)
                else []
            )
            record(
                "HD-21",
                inventory_status == 200 and (parsed.port or 80) in declared_ports,
                {
                    "unauthenticated_status": inventory_status,
                    "declared_service_ports": declared_ports,
                    "listener_reachability_tested": False,
                },
            )
        with _capture(results, "HD-22"):
            http_status, _, http_headers = fetch("/")
            banner = http_headers.get("Server", "")[:256]
            record(
                "HD-22",
                http_status == 200 and "Python/" in banner and "BaseHTTP/" in banner,
                {"response_status": http_status, "observed_server_header": banner},
            )
        with _capture(
            controls,
            "HC-17",
            name="Inventory comparison requires fixture administrator authorization",
        ):
            secure_cookie, _ = login(secure=True)
            _, _, admin_headers = fetch(
                "/secure/api/login", {"username": "admin", "password": "training-admin"}
            )
            admin_cookie = admin_headers.get("Set-Cookie", "").split(";", 1)[0]
            anonymous_inventory, _, _ = fetch("/secure/__lab__/inventory")
            customer_inventory, _, _ = fetch("/secure/__lab__/inventory", cookie=secure_cookie)
            admin_inventory, _, _ = fetch("/secure/__lab__/inventory", cookie=admin_cookie)
            controls.append(
                {
                    "id": "HC-17",
                    "name": "Inventory comparison requires fixture administrator authorization",
                    "passed": anonymous_inventory == customer_inventory == 403
                    and admin_inventory == 200,
                }
            )
        with _capture(
            controls, "HC-18", name="Comparison response minimizes the service version banner"
        ):
            _, _, comparison_headers = fetch("/secure/search?q=training")
            controls.append(
                {
                    "id": "HC-18",
                    "name": "Comparison response minimizes the service version banner",
                    "passed": comparison_headers.get("Server") == "HarborDesk",
                }
            )
    requested_checks = list(WEB_CHECKS if extended else WEB_CHECKS[:8])
    requested_controls = list(WEB_CONTROLS if extended else ())
    management_status = "not started"
    if health.get("management_lab") is True:
        requested_checks.extend(("HD-23", "HD-24"))
        requested_controls.extend(("HC-19", "HC-20"))
        management_checks, management_controls = verify_management()
        results.extend(management_checks)
        controls.extend(management_controls)
        management_status = (
            "partial"
            if any("check_error" in row["evidence"] for row in management_checks)
            or any("check_error" in row for row in management_controls)
            else "enabled"
        )
    network_status = "not requested"
    if include_network:
        network_status = "not started" if not health.get("network_lab") else "enabled"
        if health.get("network_lab"):
            requested_checks.extend(NETWORK_CHECKS)
            requested_controls.extend(NETWORK_CONTROLS)
            network_checks, network_controls = verify_network()
            results.extend(network_checks)
            controls.extend(network_controls)
    return {
        "lab_id": LAB_ID,
        "target": origin,
        "checks": results,
        "requested_checks": requested_checks,
        "requested_controls": requested_controls,
        "passed": sum(row["observed_intentional_weakness"] for row in results),
        "total": len(results),
        "secure_controls": controls,
        "network_status": network_status,
        "management_status": management_status,
        "meaning": "Verifier observed known intentional weaknesses; these are not claimed scanner detections or assigned CVEs.",
    }


def verify_management() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Check only the two fixed identified loopback services; never touch host settings."""
    from labs.harbordesk.management import COMPARISON_PORT, PORT, SERVICE_ID

    results: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    opener = build_opener(ProxyHandler({}), NoRedirects())

    def fetch(
        port: int, path: str, form: dict[str, str] | None = None, *, authorized: bool = False
    ) -> tuple[int, dict[str, Any]]:
        if port not in (PORT, COMPARISON_PORT):
            raise ValueError("Management verification accepts only fixed loopback ports")
        origin = f"http://127.0.0.1:{port}"
        headers = {"Origin": origin}
        if authorized:
            headers["X-Lab-Access"] = "training-admin"
        request = Request(
            origin + path,
            data=urlencode(form).encode() if form is not None else None,
            headers=headers,
        )
        try:
            response = opener.open(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            data = json.loads(response.read(65536))
            if not isinstance(data, dict):
                raise ValueError("Expected a bounded management JSON object")
            status = response.status
            if type(status) is not int:
                raise ValueError("Expected an HTTP management response status")
            return status, data

    try:
        for port, comparison in ((PORT, False), (COMPARISON_PORT, True)):
            status, health = fetch(port, "/__lab__/health")
            if (
                status != 200
                or health.get("lab_id") != LAB_ID
                or health.get("service_id") != SERVICE_ID
                or health.get("fixtures_only") is not True
                or health.get("comparison") is not comparison
            ):
                raise ValueError(f"Management identity failed at 127.0.0.1:{port}; no write checks")
    except CHECK_ERRORS as error:
        for identity in ("HD-23", "HD-24"):
            _error(results, identity, error, port=PORT)
            results[-1]["evidence"]["check_error"] = f"{type(error).__name__}: {str(error)[:300]}"
        return results, controls

    expected = {"customers": 3, "orders": 2, "tickets": 2, "documents": 2}
    with _capture(results, "HD-23", port=PORT, detailed=True):
        backup_status, data = fetch(PORT, "/backup")
        backup = data.get("backup", {})
        if backup_status == 200 and (
            not isinstance(backup, dict)
            or not all(isinstance(rows, list) for rows in backup.values())
        ):
            raise ValueError("Invalid fictional backup collections at /backup")
        counts = (
            {key: len(rows) for key, rows in backup.items()} if isinstance(backup, dict) else {}
        )
        results.append(
            {
                "id": "HD-23",
                "port": PORT,
                "observed_intentional_weakness": backup_status == 200 and counts == expected,
                "evidence": {
                    "unauthenticated_status": backup_status,
                    "fixture_backup_counts": counts,
                    "service_id": SERVICE_ID,
                    "http_response_observed": True,
                },
            }
        )
    with _capture(results, "HD-24", port=PORT, detailed=True):
        config_status, config = fetch(PORT, "/config")
        if config_status != 200 or type(config.get("paused")) is not bool:
            raise ValueError("Missing boolean management fixture state at /config")
        original = config["paused"]
        try:
            baseline_write, _ = fetch(PORT, "/config", {"paused": "false"})
            baseline_status, _ = fetch(PORT, "/dispatch")
            write_status, _ = fetch(PORT, "/config", {"paused": "true"})
            affected_status, affected = fetch(PORT, "/dispatch")
            results.append(
                {
                    "id": "HD-24",
                    "port": PORT,
                    "observed_intentional_weakness": baseline_write == write_status == 200
                    and baseline_status == 200
                    and affected_status == 503
                    and affected.get("dispatch") == "paused",
                    "evidence": {
                        "unauthenticated_write_status": write_status,
                        "baseline_dispatch_status": baseline_status,
                        "modified_dispatch_status": affected_status,
                        "modified_dispatch_state": affected.get("dispatch"),
                        "boundary": "fictional in-memory queue only; original state restored",
                        "service_id": SERVICE_ID,
                        "http_response_observed": True,
                    },
                }
            )
        finally:
            with _restoration("Could not restore fictional management state at /config"):
                fetch(PORT, "/config", {"paused": "true" if original else "false"})
                restored_status, restored = fetch(PORT, "/config")
                if restored_status != 200 or restored.get("paused") is not original:
                    raise ValueError("Could not restore fictional management state at /config")
    with _capture(
        controls,
        "HC-19",
        name="Network backup comparison requires fixture administrator authorization",
        port=PORT,
        detailed=True,
    ):
        denied_backup, _ = fetch(COMPARISON_PORT, "/backup")
        allowed_backup, data = fetch(COMPARISON_PORT, "/backup", authorized=True)
        protected_backup = data.get("backup")
        if not isinstance(protected_backup, dict) or not all(
            isinstance(rows, list) for rows in protected_backup.values()
        ):
            raise ValueError("Invalid protected fictional backup collections at /backup")
        controls.append(
            {
                "id": "HC-19",
                "name": "Network backup comparison requires fixture administrator authorization",
                "passed": denied_backup == 403
                and allowed_backup == 200
                and {key: len(rows) for key, rows in protected_backup.items()} == expected,
            }
        )
    with _capture(
        controls,
        "HC-20",
        name="Network configuration comparison denies unauthenticated changes",
        port=PORT,
        detailed=True,
    ):
        _, before = fetch(COMPARISON_PORT, "/config", authorized=True)
        if type(before.get("paused")) is not bool:
            raise ValueError("Missing protected management fixture state at /config")
        denied_write, _ = fetch(COMPARISON_PORT, "/config", {"paused": "true"})
        _, after = fetch(COMPARISON_PORT, "/config", authorized=True)
        allowed_write, _ = fetch(
            COMPARISON_PORT,
            "/config",
            {"paused": "true" if before["paused"] else "false"},
            authorized=True,
        )
        controls.append(
            {
                "id": "HC-20",
                "name": "Network configuration comparison denies unauthenticated changes",
                "passed": denied_write == 403 and before == after and allowed_write == 200,
            }
        )
    return results, controls


def verify_network():
    """Fixed loopback service checks, only called after the portal identity gate."""
    results, controls = [], []
    with _capture(results, "HD-14", port=2121):
        with ftplib.FTP() as ftp:
            ftp.connect("127.0.0.1", 2121, timeout=5)
            welcome = ftp.getwelcome()
            login = ftp.login("anonymous", "training@example.invalid")
            # Plaintext login is independently observed before attempting the file read.
            results.append(
                {
                    "id": "HD-14",
                    "port": 2121,
                    "observed_intentional_weakness": True,
                    "evidence": {
                        "protocol": "FTP",
                        "tls_negotiated": False,
                        "authenticated_session_observed": login,
                        "banner": welcome,
                    },
                }
            )
            with _capture(results, "HD-13", port=2121):
                data = bytearray()
                ftp.retrbinary("RETR operations.csv", data.extend)
                observed = b"HARBORDESK-FICTIONAL-OPERATIONS" in data
                results.append(
                    {
                        "id": "HD-13",
                        "port": 2121,
                        "observed_intentional_weakness": observed,
                        "evidence": {
                            "login_response": login,
                            "banner": welcome,
                            "fixture_file_read": observed,
                            "encrypted_control_channel": False,
                        },
                    }
                )
    _error(results, "HD-13", ValueError("FTP session unavailable"), port=2121)
    name = "Comparison FTP denies anonymous login"
    with _capture(controls, "HC-11", name=name):
        with ftplib.FTP() as ftp:
            ftp.connect("127.0.0.1", 2122, timeout=5)
            try:
                ftp.login("anonymous", "training@example.invalid")
                denied = False
            except ftplib.error_perm:
                denied = True
            controls.append({"id": "HC-11", "name": name, "passed": denied})

    for port in (8443, 8444):
        certificate_id, management_id = ("HD-15", "HD-16") if port == 8443 else ("HC-12", "HC-13")
        certificate_name = (
            "Comparison TLS certificate within validity period" if port == 8444 else None
        )
        management_name = (
            "Comparison TLS management denies unauthenticated client" if port == 8444 else None
        )
        rows = results if port == 8443 else controls
        with _capture(rows, certificate_id, name=certificate_name, port=port):
            from cryptography import x509

            # These fixed loopback endpoints alone permit certificate inspection.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    certificate_bytes = tls.getpeercert(binary_form=True)
                    if certificate_bytes is None:
                        raise ValueError("TLS peer supplied no certificate")
                    cert = x509.load_der_x509_certificate(certificate_bytes)
                    expired = cert.not_valid_after_utc < datetime.now(timezone.utc)
                    version = tls.version()
                    # Retain certificate evidence before any management HTTP operation.
                    if port == 8443:
                        results.append(
                            {
                                "id": certificate_id,
                                "port": port,
                                "observed_intentional_weakness": expired,
                                "evidence": {
                                    "tls_version": version,
                                    "certificate_not_after": cert.not_valid_after_utc.isoformat(),
                                    "certificate_expired": expired,
                                    "certificate_verification": "disabled only for this fixed loopback certificate inspection",
                                },
                            }
                        )
                    else:
                        controls.append(
                            {
                                "id": certificate_id,
                                "name": certificate_name,
                                "passed": not expired,
                            }
                        )
                    with _capture(rows, management_id, name=management_name, port=port):
                        tls.sendall(
                            f"GET /admin HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
                        )
                        response = bytearray()
                        while len(response) < 65536:
                            chunk = tls.recv(min(8192, 65536 - len(response)))
                            if not chunk:
                                break
                            response.extend(chunk)
                        status = int(bytes(response).split(b" ", 2)[1])
                        if port == 8443:
                            results.append(
                                {
                                    "id": management_id,
                                    "port": port,
                                    "observed_intentional_weakness": status == 200
                                    and b"harbordesk-local-v1" in response,
                                    "evidence": {
                                        "tls_version": version,
                                        "unauthenticated_status": status,
                                        "fixture_only": True,
                                    },
                                }
                            )
                        else:
                            controls.append(
                                {
                                    "id": management_id,
                                    "name": management_name,
                                    "passed": status == 403,
                                }
                            )
        _error(
            rows,
            management_id,
            ValueError("TLS session unavailable"),
            name=management_name,
            port=port,
        )
    # Stable identity order keeps provenance easy to compare across captures.
    return (
        sorted(results, key=lambda row: row["id"]),
        sorted(controls, key=lambda row: row["id"]),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8787/")
    parser.add_argument("--extended", action="store_true")
    parser.add_argument("--network", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        help="Save a new verification receipt; never overwrites an existing file",
    )
    args = parser.parse_args()
    result = verify(args.url, extended=args.extended, include_network=args.network)
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(result, output, indent=2)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] == result["total"] else 1)


if __name__ == "__main__":
    main()

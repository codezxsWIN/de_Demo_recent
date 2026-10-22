"""Bounded checks against the identified loopback training app, never arbitrary sites."""

import argparse
import ftplib
import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from labs.harbordesk.app import LAB_ID


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Lab verification never follows redirects")


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

    _, _, headers = fetch("/")
    missing = [
        key
        for key in [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        if not headers.get(key)
    ]
    record("HD-01", len(missing) == 5, {"missing_headers": missing})
    _, baseline, _ = fetch("/api/customers?" + urlencode({"q": "Avery"}))
    _, injected, _ = fetch("/api/customers?" + urlencode({"q": "' OR '1'='1' -- "}))
    counts = [len(json.loads(data).get("customers", [])) for data in (baseline, injected)]
    record(
        "HD-02",
        counts == [1, 3],
        {
            "baseline_customers": counts[0],
            "injected_customers": counts[1],
            "boundary": "read-only disposable fixtures",
        },
    )
    rejected, _, _ = fetch("/api/login", {"username": "admin", "password": "wrong"})
    accepted, body, _ = fetch("/api/login", {"username": "admin' -- ", "password": "wrong"})
    record(
        "HD-03",
        rejected == 401 and accepted == 200 and json.loads(body)["user"]["role"] == "admin",
        {"normal_wrong_password_status": rejected, "injected_fixture_login_status": accepted},
    )
    _, _, login_headers = fetch("/api/login", {"username": "demo", "password": "training-demo"})
    cookie = login_headers.get("Set-Cookie", "").split(";", 1)[0]
    _, order, _ = fetch("/api/orders/2002", cookie=cookie)
    record(
        "HD-04",
        cookie == "lab_session=demo" and json.loads(order)["order"]["owner"] == "other-demo",
        {"signed_in_fixture": "demo", "returned_order_owner": json.loads(order)["order"]["owner"]},
    )
    marker = '<em data-lab-proof="reflection">LAB-REFLECTION</em>'
    _, reflected, _ = fetch("/search?" + urlencode({"q": marker}))
    record(
        "HD-05",
        marker in reflected,
        {
            "raw_html_marker_reflected": marker in reflected,
            "browser_script_execution_tested": False,
        },
    )
    status, body, _ = fetch("/admin")
    record(
        "HD-06",
        status == 200 and "Operations administration" in body,
        {"unauthenticated_status": status},
    )
    status, body, _ = fetch("/debug/config")
    record(
        "HD-07",
        status == 200 and json.loads(body).get("demo_token") == "NOT-A-REAL-SECRET",
        {"unauthenticated_status": status, "real_secrets": False},
    )
    cookie_header = login_headers.get("Set-Cookie", "")
    record(
        "HD-08",
        bool(cookie_header)
        and not any(flag in cookie_header.lower() for flag in ("httponly", "secure", "samesite")),
        {"fixture_cookie": cookie_header},
    )
    controls = []
    if extended:
        for identity, path, key in [
            ("HD-09", "/api/tickets/3002", "ticket"),
            ("HD-10", "/api/documents/4002", "document"),
        ]:
            status, body, _ = fetch(path, cookie=cookie)
            owner = json.loads(body).get(key, {}).get("owner")
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
        status, body, _ = fetch("/api/profile")
        record(
            "HD-11",
            status == 200 and json.loads(body).get("profile", {}).get("account") == "HD-1001",
            {
                "path": "/api/profile",
                "unauthenticated_status": status,
                "data_classification": "fictional profile only",
            },
        )
        _, body, _ = fetch("/secure/api/customers?" + urlencode({"q": "' OR '1'='1' -- "}))
        controls.append(
            {
                "id": "HC-01",
                "name": "Parameterized SQL rejects predicate injection",
                "passed": len(json.loads(body).get("customers", [])) == 0,
            }
        )
        status, _, _ = fetch("/secure/api/login", {"username": "admin' -- ", "password": "wrong"})
        controls.append(
            {"id": "HC-02", "name": "Parameterized login rejects bypass", "passed": status == 401}
        )
        status, _, secure_headers = fetch(
            "/secure/api/login", {"username": "demo", "password": "training-demo"}
        )
        secure_cookie = secure_headers.get("Set-Cookie", "").split(";", 1)[0]
        for identity, path in [
            ("HC-03", "/secure/api/orders/2002"),
            ("HC-04", "/secure/api/tickets/3002"),
            ("HC-05", "/secure/api/documents/4002"),
        ]:
            status, _, _ = fetch(path, cookie=secure_cookie)
            controls.append(
                {
                    "id": identity,
                    "name": "Object ownership enforced: " + path,
                    "passed": bool(secure_cookie) and status == 404,
                }
            )
        _, escaped, _ = fetch("/secure/search?" + urlencode({"q": marker}))
        controls.append(
            {
                "id": "HC-06",
                "name": "HTML output escaped",
                "passed": marker not in escaped and "&lt;em" in escaped,
            }
        )
        for identity, path in [
            ("HC-07", "/secure/admin"),
            ("HC-08", "/secure/debug/config"),
            ("HC-09", "/secure/api/profile"),
        ]:
            status, _, _ = fetch(path)
            controls.append(
                {
                    "id": identity,
                    "name": "Unauthenticated access denied: " + path,
                    "passed": status in (401, 403),
                }
            )
        controls.append(
            {
                "id": "HC-10",
                "name": "Comparison cookie has HttpOnly and SameSite=Strict",
                "passed": all(
                    flag in secure_headers.get("Set-Cookie", "")
                    for flag in ("HttpOnly", "SameSite=Strict")
                ),
            }
        )
    network_status = "not requested"
    if include_network:
        network_status = "not started" if not health.get("network_lab") else "enabled"
        if health.get("network_lab"):
            network_checks, network_controls = verify_network()
            results.extend(network_checks)
            controls.extend(network_controls)
    return {
        "lab_id": LAB_ID,
        "target": origin,
        "checks": results,
        "passed": sum(row["observed_intentional_weakness"] for row in results),
        "total": len(results),
        "secure_controls": controls,
        "network_status": network_status,
        "meaning": "Verifier observed known intentional weaknesses; these are not claimed scanner detections or assigned CVEs.",
    }


def verify_network():
    """Fixed loopback service checks, only called after the portal identity gate."""
    results, controls = [], []
    try:
        with ftplib.FTP() as ftp:
            ftp.connect("127.0.0.1", 2121, timeout=5)
            welcome = ftp.getwelcome()
            login = ftp.login("anonymous", "training@example.invalid")
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
            results.append(
                {
                    "id": "HD-14",
                    "port": 2121,
                    "observed_intentional_weakness": observed,
                    "evidence": {
                        "protocol": "FTP",
                        "tls_negotiated": False,
                        "transfer": "fictional fixture only",
                        "authenticated_session_observed": login,
                    },
                }
            )
    except (OSError, ftplib.Error) as error:
        results.append(
            {
                "id": "HD-13",
                "port": 2121,
                "observed_intentional_weakness": False,
                "evidence": {"check_error": type(error).__name__},
            }
        )
    try:
        with ftplib.FTP() as ftp:
            ftp.connect("127.0.0.1", 2122, timeout=5)
            try:
                ftp.login("anonymous", "training@example.invalid")
                denied = False
            except ftplib.error_perm:
                denied = True
            controls.append(
                {"id": "HC-11", "name": "Comparison FTP denies anonymous login", "passed": denied}
            )
    except (OSError, ftplib.Error):
        controls.append(
            {"id": "HC-11", "name": "Comparison FTP denies anonymous login", "passed": False}
        )
    from cryptography import x509

    for port in (8443, 8444):
        try:
            # Only these identified loopback training endpoints: inspect the certificate
            # without changing verification settings for any other caller or target.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                    expired = cert.not_valid_after_utc < datetime.now(timezone.utc)
                    version = tls.version()
                    tls.sendall(f"GET /admin HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
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
                        "id": "HD-15",
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
                results.append(
                    {
                        "id": "HD-16",
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
                controls.extend(
                    [
                        {
                            "id": "HC-12",
                            "name": "Comparison TLS certificate within validity period",
                            "passed": not expired,
                        },
                        {
                            "id": "HC-13",
                            "name": "Comparison TLS management denies unauthenticated client",
                            "passed": status == 403,
                        },
                    ]
                )
        except (OSError, ValueError, IndexError) as error:
            if port == 8443:
                results.append(
                    {
                        "id": "HD-15",
                        "port": port,
                        "observed_intentional_weakness": False,
                        "evidence": {"check_error": type(error).__name__},
                    }
                )
            else:
                controls.append({"id": "HC-12", "name": "Comparison TLS checks", "passed": False})
    return results, controls


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

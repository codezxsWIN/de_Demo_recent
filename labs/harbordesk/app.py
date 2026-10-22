"""INTENTIONALLY VULNERABLE training application. Never expose beyond loopback.

All accounts, orders, configuration and credentials are fictional fixtures.
SQL injection is confined to a read-only, disposable in-memory SQLite database.
No host files, subprocesses, external network requests or real secrets are exposed.
"""

import argparse
import json
import sqlite3
from contextlib import ExitStack
from html import escape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
LAB_ID = "harbordesk-local-v1"


def database():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
    CREATE TABLE users(id INTEGER, username TEXT, password TEXT, role TEXT);
    INSERT INTO users VALUES(1,'admin','training-admin','admin'),(2,'demo','training-demo','customer');
    CREATE TABLE customers(id INTEGER,name TEXT,email TEXT,account TEXT);
    INSERT INTO customers VALUES(1,'Avery Demo','avery@example.invalid','HD-1001'),
    (2,'Jordan Fixture','jordan@example.invalid','HD-1002'),(3,'Morgan Sample','morgan@example.invalid','HD-1003');
    CREATE TABLE orders(id INTEGER,owner TEXT,item TEXT,total INTEGER);
    INSERT INTO orders VALUES(2001,'demo','Training parcel A',120),(2002,'other-demo','Training parcel B',280);
    CREATE TABLE tickets(id INTEGER,owner TEXT,subject TEXT,body TEXT,status TEXT);
    INSERT INTO tickets VALUES(3001,'demo','Delivery question','Fictional shipment HD-1001 needs a status update.','Open'),
    (3002,'other-demo','Billing adjustment','Fictional account HD-1002 invoice review.','Pending');
    CREATE TABLE documents(id INTEGER,owner TEXT,title TEXT,body TEXT);
    INSERT INTO documents VALUES(4001,'demo','Delivery receipt','TRAINING ONLY: HD-1001 receipt, no personal data.'),
    (4002,'other-demo','Account statement','TRAINING ONLY: HD-1002 statement, no financial data.');
    PRAGMA query_only=ON;
    """)
    return db


def query(sql, parameters=()):
    db = database()
    try:
        return [dict(row) for row in db.execute(sql, parameters).fetchall()]
    finally:
        db.close()


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler=None):
        if address[0] != "127.0.0.1":
            raise ValueError("This intentionally vulnerable lab may bind ONLY to 127.0.0.1")
        super().__init__(address, handler or Handler)


class Handler(BaseHTTPRequestHandler):
    # The real Python HTTP server identity lets service detection recognise HTTP.
    server_version = BaseHTTPRequestHandler.server_version
    sys_version = BaseHTTPRequestHandler.sys_version

    def log_message(self, *_args):
        pass  # Do not record question strings, SQL payloads or cookies in terminal logs.

    def allowed(self):
        expected = f"127.0.0.1:{self.server.server_address[1]}"
        discovery = (
            not self.headers.get("Host")
            and self.request_version == "HTTP/1.0"
            and self.command in ("GET", "HEAD")
            and self.path == "/"
        )
        if self.client_address[0] != "127.0.0.1" or (
            self.headers.get("Host") != expected and not discovery
        ):
            self.reply(403, "Loopback training access only", "text/plain")
            return False
        return True

    def reply(self, status, body, content_type="application/json", cookie=None):
        raw = (json.dumps(body) if isinstance(body, (dict, list)) else body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Training-Lab", LAB_ID)
        if urlsplit(self.path).path.startswith("/secure/"):
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # Deliberately no CSP, frame protection, nosniff, referrer or permissions policy.
        if cookie:
            self.send_header("Set-Cookie", cookie)  # Deliberately missing protection flags.
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_HEAD(self):
        if self.allowed():
            self.reply(200, "HarborDesk local training lab", "text/plain")

    def do_GET(self):
        if not self.allowed():
            return
        parsed = urlsplit(self.path)
        args = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path
        if path.startswith("/secure/"):
            self.secure_get(path.removeprefix("/secure"), args)
            return
        if path in ("/", "/index.html"):
            self.reply(200, (ROOT / "index.html").read_text(encoding="utf-8"), "text/html")
        elif path == "/assets/site.css":
            self.reply(200, (ROOT / "site.css").read_text(encoding="utf-8"), "text/css")
        elif path == "/assets/site.js":
            self.reply(200, (ROOT / "site.js").read_text(encoding="utf-8"), "text/javascript")
        elif path == "/__lab__/health":
            self.reply(
                200,
                {
                    "lab_id": LAB_ID,
                    "fixtures_only": True,
                    "binding": "127.0.0.1",
                    "cve_claims": False,
                    "network_lab": bool(getattr(self.server, "network_lab", False)),
                },
            )
        elif path == "/__lab__/ground-truth":
            self.reply(200, json.loads((ROOT / "ground-truth.json").read_text(encoding="utf-8")))
        elif path == "/__lab__/inventory":
            enabled = bool(getattr(self.server, "network_lab", False))
            services = [
                {
                    "name": "HarborDesk portal",
                    "port": self.server.server_address[1],
                    "transport": "HTTP",
                    "mode": "Vulnerable application fixtures",
                    "endpoint": f"http://127.0.0.1:{self.server.server_address[1]}/",
                }
            ]
            if enabled:
                services.extend(
                    [
                        {
                            "name": "Operations file service",
                            "port": 2121,
                            "transport": "FTP",
                            "mode": "Anonymous read-only access / plaintext transport",
                            "endpoint": "ftp://127.0.0.1:2121",
                        },
                        {
                            "name": "File-service comparison",
                            "port": 2122,
                            "transport": "FTP",
                            "mode": "Authentication required; plaintext transport still needs remediation",
                            "endpoint": "ftp://127.0.0.1:2122",
                        },
                        {
                            "name": "Management API",
                            "port": 8443,
                            "transport": "TLS / HTTP",
                            "mode": "Expired certificate / unauthenticated fixture administration",
                            "endpoint": "https://127.0.0.1:8443/admin",
                        },
                        {
                            "name": "Management comparison",
                            "port": 8444,
                            "transport": "TLS / HTTP",
                            "mode": "Current self-signed certificate / fixture authorization required",
                            "endpoint": "https://127.0.0.1:8444/admin",
                        },
                    ]
                )
            self.reply(
                200,
                {
                    "network_enabled": enabled,
                    "services": services,
                    "boundary": "Loopback-only fixture network. Inventory describes configuration, not scanner findings.",
                },
            )
        elif path == "/api/customers":
            # Deliberately injectable; SELECT only on throwaway fixture tables.
            term = args.get("q", [""])[0][:250]
            try:
                self.reply(
                    200,
                    {
                        "customers": query(
                            "SELECT id,name,email,account FROM customers WHERE name LIKE '%"
                            + term
                            + "%'"
                        ),
                        "fixture": True,
                    },
                )
            except sqlite3.Error:
                self.reply(400, {"error": "Training SQL query failed", "fixture": True})
        elif path == "/api/tickets":
            self.reply(
                200,
                {"tickets": query("SELECT id,owner,subject,status FROM tickets"), "fixture": True},
            )
        elif path.startswith("/api/tickets/") or path.startswith("/api/documents/"):
            resource, _, identity = path.removeprefix("/api/").partition("/")
            if not identity.isdigit() or len(identity) > 8:
                self.reply(404, {"error": "Unknown fixture record"})
                return
            table = "tickets" if resource == "tickets" else "documents"
            rows = query("SELECT * FROM " + table + " WHERE id=?", (int(identity),))
            self.reply(
                200 if rows else 404,
                {resource.rstrip("s"): rows[0] if rows else None, "fixture": True},
            )
        elif path == "/api/profile":
            self.reply(
                200,
                {
                    "profile": {
                        "username": "demo",
                        "name": "Avery Demo",
                        "email": "avery@example.invalid",
                        "account": "HD-1001",
                    },
                    "fixture": True,
                },
            )
        elif path.startswith("/api/orders/") and path.removeprefix("/api/orders/").isdigit():
            # INTENTIONAL IDOR: ignores the authenticated fixture user's ownership.
            order = query("SELECT * FROM orders WHERE id=" + str(int(path.rsplit("/", 1)[1])))
            self.reply(
                200 if order else 404, {"order": order[0] if order else None, "fixture": True}
            )
        elif path == "/search":
            term = args.get("q", [""])[0][:500]
            # INTENTIONAL reflected HTML/XSS sink. Do not copy into production code.
            self.reply(
                200,
                '<!doctype html><title>HarborDesk search · training</title><link rel="stylesheet" href="/assets/site.css"><main><p class="lab-banner">LOCAL VULNERABLE TRAINING LAB · FICTIONAL DATA</p><h1>Search results for: '
                + term
                + '</h1><p>This deliberately unescaped result is a training weakness.</p><a href="/">Return to HarborDesk</a></main>',
                "text/html",
            )
        elif path == "/admin":
            self.reply(
                200,
                '<!doctype html><title>HarborDesk admin · training</title><link rel="stylesheet" href="/assets/site.css"><main><p class="lab-banner">INTENTIONALLY UNPROTECTED TRAINING ADMIN</p><h1>Operations administration</h1><p>This endpoint deliberately omits its login check. No real operations are available.</p><pre>'
                + escape(json.dumps(query("SELECT id,username,role FROM users"), indent=2))
                + '</pre><a href="/">Back to portal</a></main>',
                "text/html",
            )
        elif path == "/debug/config":
            self.reply(
                200,
                {
                    "environment": "training-only",
                    "debug": True,
                    "demo_token": "NOT-A-REAL-SECRET",
                    "database": "disposable-in-memory-fixtures",
                    "fixture": True,
                },
            )
        elif path == "/robots.txt":
            self.reply(
                200, "User-agent: *\nDisallow: /admin\nDisallow: /debug/config\n", "text/plain"
            )
        else:
            self.reply(404, {"error": "Not found", "fixture": True})

    def secure_user(self):
        """Fixed comparison fixtures, never production authentication tokens."""
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        token = cookies.get("secure_lab_session")
        return {"harbor-demo-session": "demo", "harbor-admin-session": "admin"}.get(
            token.value if token else ""
        )

    def secure_get(self, path, args):
        if path == "/api/customers":
            term = args.get("q", [""])[0][:250]
            self.reply(
                200,
                {
                    "customers": query(
                        "SELECT id,name,email,account FROM customers WHERE name LIKE ?",
                        ("%" + term + "%",),
                    ),
                    "fixture": True,
                },
            )
        elif path == "/search":
            self.reply(
                200,
                "<!doctype html><title>HarborDesk secure comparison</title><h1>Search results for: "
                + escape(args.get("q", [""])[0][:500])
                + "</h1><p>Training comparison: output escaped.</p>",
                "text/html",
            )
        elif path in ("/admin", "/debug/config"):
            if self.secure_user() != "admin":
                self.reply(403, {"error": "Administrator authorization required", "fixture": True})
            else:
                self.reply(200, {"status": "Authorized fixture administrator", "fixture": True})
        elif path == "/api/profile":
            if not self.secure_user():
                self.reply(401, {"error": "Authentication required", "fixture": True})
            else:
                self.reply(200, {"username": self.secure_user(), "fixture": True})
        elif path.startswith(("/api/orders/", "/api/tickets/", "/api/documents/")):
            resource, _, identity = path.removeprefix("/api/").partition("/")
            if not self.secure_user():
                self.reply(401, {"error": "Authentication required", "fixture": True})
                return
            if not identity.isdigit() or len(identity) > 8:
                self.reply(404, {"error": "Not found", "fixture": True})
                return
            # The table comes only from this fixed allowlist; values are bound.
            table = {"orders": "orders", "tickets": "tickets", "documents": "documents"}[resource]
            rows = query(
                "SELECT * FROM " + table + " WHERE id=? AND owner=?",
                (int(identity), self.secure_user()),
            )
            self.reply(200 if rows else 404, {"record": rows[0] if rows else None, "fixture": True})
        else:
            self.reply(404, {"error": "Not found", "fixture": True})

    def do_POST(self):
        if not self.allowed():
            return
        origin = self.headers.get("Origin")
        if origin and origin != f"http://127.0.0.1:{self.server.server_address[1]}":
            self.reply(403, {"error": "Cross-origin lab writes refused"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096 or self.headers.get("Transfer-Encoding"):
                raise ValueError
            form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
            path = urlsplit(self.path).path
            if path not in ("/api/login", "/secure/api/login"):
                self.reply(404, {"error": "Not found"})
                return
            username = form.get("username", [""])[0][:100]
            password = form.get("password", [""])[0][:100]
            # INTENTIONAL authentication bypass through SQL injection, dummy users only.
            if path == "/secure/api/login":
                rows = query(
                    "SELECT username,role FROM users WHERE username=? AND password=?",
                    (username, password),
                )
                cookie = (
                    (
                        "secure_lab_session=harbor-"
                        + rows[0]["username"]
                        + "-session; HttpOnly; SameSite=Strict; Path=/secure"
                    )
                    if rows
                    else None
                )
                self.reply(
                    200 if rows else 401,
                    {"user": rows[0] if rows else None, "fixture": True},
                    cookie=cookie,
                )
                return
            rows = query(
                "SELECT username,role FROM users WHERE username='"
                + username
                + "' AND password='"
                + password
                + "'"
            )
            self.reply(
                200 if rows else 401,
                {"user": rows[0] if rows else None, "fixture": True},
                cookie="lab_session=" + rows[0]["username"] + "; Path=/" if rows else None,
            )
        except (ValueError, UnicodeError, sqlite3.Error):
            self.reply(400, {"error": "Invalid training request"})


def main():
    parser = argparse.ArgumentParser(description="Loopback-only vulnerable HarborDesk training lab")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--network", action="store_true", help="Also start the isolated FTP and TLS service lab"
    )
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a non-privileged port between 1024 and 65535")
    with ExitStack() as stack:
        if args.network:
            from labs.harbordesk.network import NetworkLab

            network = stack.enter_context(NetworkLab())
            print("Network services: " + str(network.services), flush=True)
        server = stack.enter_context(LabServer(("127.0.0.1", args.port)))
        server.network_lab = args.network
        print(
            f"HarborDesk LOCAL VULNERABLE LAB: http://127.0.0.1:{server.server_port}/", flush=True
        )
        print(
            "Dummy data only. Do not proxy, tunnel or publish this application. Ctrl+C to stop.",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

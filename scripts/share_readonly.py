"""Password-gated, frozen demo. No upstream proxy or executable API routes."""

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import MappingProxyType
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnassess import capture_history  # noqa: E402
from vulnassess.ui import environment, vulnerability_findings  # noqa: E402
from vulnassess.ui.entry import render_entry  # noqa: E402
from vulnassess.ui.server import (  # noqa: E402
    CONTENT_TYPES,
    CSP,
    STATIC_ROOT,
    UiApplication,
    json_response,
)

READONLY_JS = b"""
const lock = () => {
  for (const id of ['run-assessment','start-live-run','open-device-check','check-target',
    'propose-scan-plan','import-nessus','open-run','helpy-send','helpy-voice']) {
    const el = document.getElementById(id);
    if (el) { el.disabled = true; el.title = 'Read-only shared demo'; }
  }
};
const banner = document.createElement('p');
banner.textContent = 'SHARED READ-ONLY DEMO - saved results only. Scanning, AI chat, uploads and device checks are disabled.';
banner.className = 'share-notice'; document.body.prepend(banner);
lock(); new MutationObserver(lock).observe(document.body, {childList:true,subtree:true});
document.addEventListener('submit', event => event.preventDefault(), true);
"""
READONLY_CSS = b".share-notice{margin:0;padding:12px 20px;background:#fff1cd;color:#332900;font:14px/1.5 system-ui;border-bottom:1px solid #d2b564;position:relative;z-index:9999}"


def freeze(application, capture_id):
    root = application.config_dir.parent / "data/live/raw"
    record = capture_history.load(root, capture_id)
    if record["result"].get("ai_status") != "validated":
        raise ValueError("Select a reviewed capture with validated AI")
    if record["result"].get("target") != "http://127.0.0.1:8787/":
        raise ValueError("This demo shares only the approved fictional HarborDesk capture")
    if record["payload"].get("self_defence"):
        raise ValueError("Device observations must not be shared")
    run = application.run_id
    responses = {}

    def add(path, response):
        if response.status != 200:
            raise ValueError(f"Cannot freeze demo route: {path}")
        body = response.body
        if response.content_type.startswith("text/html"):
            body = body.replace(
                b"</head>",
                b'<link rel="stylesheet" href="/static/share-readonly.css">'
                b'<script type="module" src="/static/share-readonly.js"></script></head>',
            )
        responses[path] = (response.content_type, body)

    for route in ("/", "/workflow", "/findings", "/vulnerabilities"):
        add(route, application._static(["index.html"]) if route == "/" else application.get(route))
    # The workflow run is reconstructed from the same approved capture, not the
    # operator's database history. No scope configuration or machine paths leak.
    payload = record["payload"]
    stored = {
        **payload,
        "run": {"run_id": run, "started_at": record["captured_at"], "summary": {}},
        "history": {},
        "rationales": [],
        "refusals": [],
        "config_hashes": {},
        "feeds_meta": [],
    }
    # The homepage needs its non-executable JSON bootstrap as well as HTML.
    template = application._static(["index.html"]).body.decode("utf-8")
    homepage = render_entry(template, None, [stored["run"]], {})
    homepage = homepage.replace(
        "</head>",
        '<link rel="stylesheet" href="/static/share-readonly.css">'
        '<script type="module" src="/static/share-readonly.js"></script></head>',
    )
    responses["/"] = ("text/html; charset=utf-8", homepage.encode())
    add("/api/cvss-fixture", json_response(200, application.cvss_fixture()))
    add("/api/runs", json_response(200, {"runs": [stored["run"]], "selected_run": run}))
    add(f"/api/run/{run}", json_response(200, stored))
    add("/api/scope", json_response(200, {"values": {"allowed_cidrs": [], "lab_targets": []}}))
    add(
        "/api/weights",
        json_response(200, {"values": application.configurations["weights"]["values"]}),
    )
    add("/api/vulnerability-findings", json_response(200, vulnerability_findings.build(record)))
    # Only one explicitly chosen capture is visible. No discovery of other runs.
    public_record = {key: record[key] for key in ("capture_id", "captured_at", "payload", "result")}
    add(f"/api/captures/{capture_id}", json_response(200, public_record))
    summary = {
        "capture_id": capture_id,
        "status": "recorded",
        "target": record["result"]["target"],
        "scan_status": record["result"]["scan_status"],
        "ai_status": "validated",
    }
    add("/api/captures", json_response(200, {"captures": [summary], "total": 1, "page": 1}))
    report = application.get(f"/captures/{capture_id}/report")
    add(f"/captures/{capture_id}/report", report)
    responses["/captures"] = (
        "text/html; charset=utf-8",
        f'<html><head><title>Shared assessment</title></head><body><h1>Shared assessment</h1><p>One approved saved lab run; no live actions.</p><a href="/captures/{capture_id}/report">Open report</a></body></html>'.encode(),
    )
    responses[f"/captures/{capture_id}"] = responses[f"/captures/{capture_id}/report"]
    responses["/environment"] = ("text/html; charset=utf-8", environment.render(record).encode())
    for path in STATIC_ROOT.rglob("*"):
        if path.is_file() and path.suffix in {".js", ".css", ".svg", ".png", ".woff2"}:
            responses["/static/" + path.relative_to(STATIC_ROOT).as_posix()] = (
                CONTENT_TYPES[path.suffix],
                path.read_bytes(),
            )
    responses["/static/share-readonly.js"] = ("text/javascript", READONLY_JS)
    responses["/static/share-readonly.css"] = ("text/css", READONLY_CSS)
    for route in ("/", "/workflow"):
        responses[f"{route}?run={run}"] = responses[route]
    responses["/api/captures?page=1"] = responses["/api/captures"]
    return MappingProxyType(responses)


class ShareServer(ThreadingHTTPServer):
    auth_hash: bytes
    snapshot: MappingProxyType


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnAssessReadOnly"
    sys_version = ""

    def log_message(self, format, *args):
        pass  # Never log credentials, visitor URLs or report contents.

    def reply(self, status, content_type, body, challenge=False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if challenge:
            self.send_header("WWW-Authenticate", 'Basic realm="VulnAssess demo", charset="UTF-8"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        server = cast(ShareServer, self.server)
        supplied = self.headers.get_all("Authorization", [])
        if len(supplied) != 1 or not hmac.compare_digest(
            hashlib.sha256(supplied[0].encode()).digest(), server.auth_hash
        ):
            return self.reply(401, "text/plain", b"Sign in to view this read-only demo.", True)
        entry = server.snapshot.get(self.path)
        if entry is None:
            return self.reply(
                403, "application/json", b'{"error":{"message":"Disabled in read-only demo"}}'
            )
        self.reply(200, *entry)

    def do_POST(self):
        self.close_connection = True
        self.reply(
            405,
            "application/json",
            b'{"error":{"message":"All actions disabled in read-only demo"}}',
        )

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_POST
    do_HEAD = do_GET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    app = UiApplication("data/vulnassess.db", "config", "scanme-2026-09-24")
    snapshot = freeze(app, args.capture)
    credential_file = Path("data/share-demo/access.json")
    credential_file.parent.mkdir(parents=True, exist_ok=True)
    if credential_file.exists():
        credentials = json.loads(credential_file.read_text())
    else:
        credentials = {"username": "viewer", "password": secrets.token_urlsafe(24)}
        credential_file.write_text(json.dumps(credentials), encoding="utf-8")
    expected = (
        "Basic "
        + base64.b64encode(f"{credentials['username']}:{credentials['password']}".encode()).decode()
    )
    server = ShareServer(("127.0.0.1", args.port), Handler)
    server.auth_hash = hashlib.sha256(expected.encode()).digest()
    server.snapshot = snapshot
    print(f"Read-only snapshot: 127.0.0.1:{args.port}; capture {args.capture}", flush=True)
    print(
        f"Login saved locally in {credential_file.resolve()}; not logged or published", flush=True
    )
    server.serve_forever()


if __name__ == "__main__":
    main()

"""Real bounded TCP exchanges using SMTP, Memcached text and Modbus framing.

All data is fictional. No mail delivery, command execution, arbitrary cache keys,
register writes, outbound connections or non-loopback binding is implemented.
"""

import json
import socketserver
import struct
import threading
from collections import Counter, deque
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
LAB_ID = "vulnassess-network-environments-v1"
ENVIRONMENTS = (
    {"id": "mail", "name": "Office mail", "protocol": "smtp", "port": 8825, "control": 8826},
    {
        "id": "cache",
        "name": "Application cache",
        "protocol": "memcached",
        "port": 11211,
        "control": 11212,
    },
    {
        "id": "industrial",
        "name": "Industrial telemetry",
        "protocol": "modbus",
        "port": 1502,
        "control": 1503,
    },
)
CACHE_VALUE = b"FICTIONAL-SHIPMENT-2401"
SMTP_USER = b"250 training@example.invalid\r\n"
REGISTERS = (2401, 42)


class Activity:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = Counter()
        self.events = deque(maxlen=60)

    def record(self, protocol, port, request, response):
        with self.lock:
            self.counts[protocol] += 1
            self.events.append(
                {
                    "protocol": protocol,
                    "port": port,
                    "request_bytes": len(request),
                    "response_bytes": len(response),
                    "request_hex": request[:64].hex(),
                    "response_hex": response[:64].hex(),
                }
            )

    def snapshot(self):
        with self.lock:
            return {"counts": dict(self.counts), "events": list(self.events)}


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProtocolHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(2)
        protocol = self.server.protocol
        protected = self.server.protected
        port = self.server.server_address[1]
        try:
            if protocol == "smtp":
                self.wfile.write(b"220 network-lab.local ESMTP fictional training service\r\n")
                self.wfile.flush()
            for _ in range(12):
                if protocol == "modbus":
                    header = self.rfile.read(7)
                    if len(header) != 7:
                        return
                    transaction, protocol_id, length, unit = struct.unpack(">HHHB", header)
                    if protocol_id != 0 or not 2 <= length <= 16:
                        return
                    pdu = self.rfile.read(length - 1)
                    if len(pdu) != length - 1:
                        return
                    if pdu == b"\x03\x00\x00\x00\x02" and not protected:
                        answer = b"\x03\x04" + struct.pack(">HH", *REGISTERS)
                    else:
                        # Modbus exception: private fixture registers denied.
                        answer = bytes([(pdu[0] | 0x80), 2])
                    request = header + pdu
                    response = struct.pack(">HHHB", transaction, 0, len(answer) + 1, unit) + answer
                else:
                    request = self.rfile.readline(513)
                    if not request or len(request) > 512 or not request.endswith(b"\n"):
                        return
                    command = request.strip().lower()
                    if protocol == "smtp":
                        if command.startswith((b"ehlo ", b"helo ")):
                            response = b"250 network-lab.local\r\n"
                        elif command == b"vrfy training@example.invalid":
                            response = b"550 Verification disabled\r\n" if protected else SMTP_USER
                        elif command == b"quit":
                            response = b"221 Bye\r\n"
                        else:
                            response = (
                                b"502 Training service: no relay, authentication or delivery\r\n"
                            )
                    else:
                        if command == b"version":
                            response = b"VERSION network-lab-custom-training\r\n"
                        elif command == b"get fixture:shipment":
                            response = (
                                b"END\r\n"
                                if protected
                                else (
                                    b"VALUE fixture:shipment 0 "
                                    + str(len(CACHE_VALUE)).encode()
                                    + b"\r\n"
                                    + CACHE_VALUE
                                    + b"\r\nEND\r\n"
                                )
                            )
                        elif command == b"quit":
                            return
                        else:
                            response = b"ERROR\r\n"
                self.wfile.write(response)
                self.wfile.flush()
                self.server.activity.record(protocol, port, request, response)
                if protocol == "smtp" and command == b"quit":
                    return
        except (OSError, ValueError):
            return


class RegistryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/__lab__/health":
            body = json.dumps(
                {
                    "lab_id": LAB_ID,
                    "binding": HOST,
                    "fixtures_only": True,
                    "environments": ENVIRONMENTS,
                    "traffic": self.server.activity.snapshot(),
                }
            ).encode()
            content_type = "application/json"
        elif self.path == "/":
            body = (
                '<!doctype html><html lang="en"><meta charset="utf-8"><title>Network environments</title>'
                "<h1>Network protocol environments</h1><p>Real loopback TCP services. Custom training "
                "implementations, not vendor products, separate hosts or operating systems.</p><ul>"
                + "".join(
                    f"<li>{item['name']}: {HOST}:{item['port']}; access-denied comparison: "
                    f"{HOST}:{item['control']}</li>"
                    for item in ENVIRONMENTS
                )
                + "</ul><p>Run the bounded verifier to exchange protocol messages. "
                "No real credentials, mail delivery, arbitrary data or register writes.</p>"
                '<p><a href="/__lab__/health">View actual protocol traffic counters and byte transcripts</a></p>'
                '<button id="verify" type="button">Send fixed read-only protocol checks</button>'
                '<p id="result" role="status">No checks launched by opening this page.</p>'
                '<h2>Recent protocol exchanges</h2><pre id="traffic">Waiting for traffic counters.</pre>'
                "<p>Transcripts describe application bytes sent and received, not a packet capture.</p>"
                '<script src="/activity.js" defer></script></html>'
            ).encode()
            content_type = "text/html; charset=utf-8"
        elif self.path == "/activity.js":
            body = b"""
const traffic = document.getElementById('traffic');
async function refresh() {
  try { const response = await fetch('/__lab__/health', {cache:'no-store'});
    if (!response.ok) throw Error('Status unavailable');
    const data = await response.json(); traffic.textContent = JSON.stringify(data.traffic, null, 2);
  } catch { traffic.textContent = 'Traffic status unavailable'; }
}
document.getElementById('verify').addEventListener('click', async event => {
  event.target.disabled = true; const result = document.getElementById('result');
  result.textContent = 'Sending bounded loopback protocol requests...';
  try { const response = await fetch('/verify', {method:'POST',headers:{'X-VulnAssess-Lab-Action':'verify'}});
    if (!response.ok) throw Error('Verification failed'); const data = await response.json();
    result.textContent = data.checks.filter(item => item.observed).length + '/3 fixture conditions; '
      + data.checks.filter(item => item.control_passed).length + '/3 access-denied comparisons passed.';
  } catch { result.textContent = 'Verification unavailable. No external target was contacted.'; }
  finally {event.target.disabled = false; refresh();}
});
refresh(); setInterval(refresh, 3000);
"""
            content_type = "text/javascript"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if (
            self.path != "/verify"
            or self.headers.get("Host") != "127.0.0.1:8800"
            or self.headers.get("Origin") != "http://127.0.0.1:8800"
            or self.headers.get("X-VulnAssess-Lab-Action") != "verify"
            or self.headers.get("Content-Length", "0") != "0"
            or self.headers.get("Transfer-Encoding") is not None
        ):
            self.close_connection = True
            self.send_error(403)
            return
        from .verify import verify

        try:
            body = json.dumps(verify()).encode()
        except (OSError, ValueError):
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def start():
    """Start atomically; occupied ports close all earlier listeners on failure."""
    stack = ExitStack()
    activity = Activity()
    try:
        servers = []
        for item in ENVIRONMENTS:
            for key in ("port", "control"):
                server = stack.enter_context(TCPServer((HOST, item[key]), ProtocolHandler))
                server.protocol = item["protocol"]
                server.protected = key == "control"
                server.activity = activity
                servers.append(server)
        registry = stack.enter_context(ThreadingHTTPServer((HOST, 8800), RegistryHandler))
        registry.activity = activity
        servers.append(registry)
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(server.shutdown)
        return stack
    except BaseException:
        stack.close()
        raise

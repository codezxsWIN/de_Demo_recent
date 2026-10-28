"""Interactive, loopback-only sites for the real Office and IoT service labs.

Run with the optional network-labs Python: python -m labs.service_networks.console
Only fixed lab endpoints/operations are supported. No shell, arbitrary targets,
credentials or file paths are accepted from the browser. The demonstration sensor
uses fictional readings and sends real MQTT packets through the published gateway.
"""

import argparse
import ftplib
import hashlib
import json
import logging
import socket
import struct
import threading
import time
from collections import deque
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from vulnassess import network_service_checks as checks
from vulnassess import network_service_policy
from vulnassess.settings import Settings
from vulnassess.ui.network_labs import latest_records

ROOT = Path(__file__).resolve().parents[2]
ACTIONS = {
    "ftp-anonymous": ("office", 2121),
    "ftp-file": ("office", 2121),
    "ftp-protected": ("office", 2122),
    "ssh-credential": ("office", 2222),
    "ssh-protected": ("office", 2223),
    "smb-read": ("office", 1445),
    "smb-protected": ("office", 1446),
    "mqtt-exchange": ("iot", 1883),
    "mqtt-protected": ("iot", 1884),
    "snmp-public": ("iot", 1161),
    "snmp-protected": ("iot", 1162),
    "tls-certificate": ("iot", 8883),
}
IPS = {"office": "127.0.0.2", "iot": "127.0.0.3"}
TOPIC = b"vulnassess/training/telemetry"


class Console:
    def __init__(self, root=ROOT):
        self.root = root
        self.events = deque(maxlen=60)
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(2)
        self.stop = threading.Event()
        self.sensor_sequence = 0
        self.sensor_error = None
        self.worker = None

    def endpoint(self, environment, port):
        settings = Settings(self.root / "config")
        ip = IPS[environment]
        policy = network_service_policy.load(settings.config_dir, settings.scope, ip)
        if policy is None or not settings.scope.contains(ip) or settings.scope.is_canary(ip):
            raise ValueError("Lab endpoint is not authorised by the current local policy")
        entry = next((e for e in policy["endpoints"] if e["port"] == port), None)
        if entry is None:
            raise ValueError("Operation is outside the declared lab endpoints")
        return ip, entry

    def event(self, operation, ip, port, detail):
        row = {
            "at": datetime.now(UTC).isoformat(),
            "operation": operation,
            "destination": f"{ip}:{port}",
            "detail": detail,
        }
        with self.lock:
            self.events.appendleft(row)

    def mqtt_connection(self):
        ip, _ = self.endpoint("iot", 1883)
        wire = socket.create_connection((ip, 1883), timeout=3)
        try:
            identity = ("lab-console-" + uuid4().hex[:8]).encode()
            checks._send(
                wire,
                0x10,
                b"\x00\x04MQTT\x04\x02\x00\x0a" + struct.pack("!H", len(identity)) + identity,
            )
            header, reply = checks._packet(wire)
            if header != 0x20 or reply != b"\x00\x00":
                raise ValueError(
                    "The broker did not accept this anonymous demonstration connection"
                )
            return wire
        except BaseException:
            wire.close()
            raise

    def publish(self, sequence):
        reading = {
            "device": "training-sensor-01",
            "source": "simulated sensor",
            "sequence": sequence,
            "temperature_c": round(21 + (sequence % 15) / 10, 1),
            "humidity_pct": 40 + sequence % 12,
            "sent_at": datetime.now(UTC).isoformat(),
        }
        with self.mqtt_connection() as wire:
            body = struct.pack("!H", len(TOPIC)) + TOPIC + json.dumps(reading).encode()
            checks._send(
                wire, 0x31, body
            )  # QoS 0 retained PUBLISH, sent over the real TCP connection.
            checks._send(wire, 0xC0, b"")
            if checks._packet(wire) != (0xD0, b""):
                raise ValueError("MQTT liveness acknowledgement was not received")
            checks._send(wire, 0xE0, b"")
        self.event(
            "MQTT PUBLISH",
            IPS["iot"],
            1883,
            f"Simulated reading sequence {sequence}; real packet sent",
        )

    def start_sensor(self):
        def produce():
            while not self.stop.is_set():
                try:
                    self.publish(self.sensor_sequence + 1)
                    self.sensor_sequence += 1
                    self.sensor_error = None
                except Exception as error:
                    self.sensor_error = f"{type(error).__name__}: sensor delivery failed"
                self.stop.wait(3)

        self.worker = threading.Thread(target=produce, name="lab-demo-sensor", daemon=True)
        self.worker.start()

    def telemetry(self):
        with self.mqtt_connection() as wire:
            checks._send(wire, 0x82, b"\x00\x01" + struct.pack("!H", len(TOPIC)) + TOPIC + b"\x00")
            for _ in range(4):
                header, payload = checks._packet(wire)
                if header >> 4 == 3:
                    length = int.from_bytes(payload[:2])
                    if payload[2 : 2 + length] != TOPIC or (header >> 1) & 3:
                        raise ValueError("Unexpected topic or delivery mode")
                    reading = json.loads(payload[2 + length :].decode())
                    if not isinstance(reading, dict) or reading.get("source") != "simulated sensor":
                        raise ValueError(
                            "No live demonstration sensor reading has been received yet"
                        )
                    checks._send(wire, 0xE0, b"")
                    self.event(
                        "MQTT SUBSCRIBE",
                        IPS["iot"],
                        1883,
                        f"Broker delivered sequence {reading.get('sequence')}",
                    )
                    return reading
        raise ValueError("No telemetry publication was delivered by the broker")

    def action(self, name):
        if name not in ACTIONS:
            raise ValueError("Unknown fixed lab operation")
        environment, port = ACTIONS[name]
        ip, entry = self.endpoint(environment, port)
        if name == "ftp-file":
            content = bytearray()
            deadline = time.monotonic() + 6

            def receive(chunk):
                if len(content) + len(chunk) > 1024 or time.monotonic() > deadline:
                    raise ValueError("Training document exceeded the bounded read")
                content.extend(chunk)

            with ftplib.FTP(timeout=3) as client:
                greeting = client.connect(ip, port)
                login = client.login("anonymous", "lab@example.invalid")
                reply = client.retrbinary("RETR network-proof.txt", receive, blocksize=512)
            proof = {
                "protocol_confirmed": True,
                "anonymous_accepted": True,
                "greeting": greeting,
                "login_response": login,
                "retrieval_response": reply,
                "filename": "network-proof.txt",
                "training_document": content.decode("utf-8", errors="replace"),
                "bytes_received": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        else:
            proof = checks.TRANSPORTS[entry["service"]](ip, entry)
        self.event(name, ip, port, json.dumps(proof)[:900])
        return {
            "operation": name,
            "destination": f"{ip}:{port}",
            "observed_at": datetime.now(UTC).isoformat(),
            "proof": proof,
            "decision": {
                "violations": [row[1] for row in checks.violations(entry, proof)],
                "inconclusive": bool(
                    proof.get("inconclusive")
                    or proof.get("authentication_check_error")
                    or proof.get("protocol_confirmed") is not True
                ),
                "limit": "This result covers only the displayed protocol operation and endpoint policy; it is not a complete security verdict.",
            },
        }

    def reports(self):
        records = latest_records(self.root / "data/live/raw")
        return {
            name: f"http://127.0.0.1:8765/captures/{records[ip]['capture_id']}/report"
            for name, ip in IPS.items()
            if ip in records
        }


def handler(application):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass

        def reply(self, status, body, mime="application/json; charset=utf-8"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def allowed(self):
            expected = f"127.0.0.1:{self.server.server_port}"
            origin = self.headers.get("Origin")
            return (
                self.client_address[0] == "127.0.0.1"
                and self.headers.get("Host") == expected
                and (origin is None or origin == "http://" + expected)
            )

        def do_GET(self):
            if not self.allowed():
                self.reply(403, {"error": "This console is available only on its local origin"})
                return
            path = urlsplit(self.path).path
            files = {
                "/": ("console.html", "text/html"),
                "/office": ("console.html", "text/html"),
                "/iot": ("console.html", "text/html"),
                "/console.js": ("console.js", "text/javascript"),
                "/console.css": ("console.css", "text/css"),
            }
            if path in files:
                filename, mime = files[path]
                self.reply(
                    200, (Path(__file__).parent / filename).read_bytes(), mime + "; charset=utf-8"
                )
                return
            if path == "/tokens.css":
                self.reply(
                    200,
                    (ROOT / "vulnassess/ui/static/tokens.css").read_bytes(),
                    "text/css; charset=utf-8",
                )
                return
            if path == "/api/status":
                with application.lock:
                    events = list(application.events)
                self.reply(
                    200,
                    {
                        "sensor_packets_sent": application.sensor_sequence,
                        "sensor_error": application.sensor_error,
                        "events": events,
                        "reports": application.reports(),
                    },
                )
                return
            if path != "/api/telemetry":
                self.reply(404, {"error": "Unknown console page"})
                return
            self.perform(application.telemetry)

        def perform(self, operation):
            if not application.slots.acquire(blocking=False):
                self.reply(429, {"error": "Two lab operations are already running"})
                return
            try:
                self.reply(200, operation())
            except Exception as error:
                self.reply(409, {"error": str(error)[:180], "type": type(error).__name__})
            finally:
                application.slots.release()

        def do_POST(self):
            if (
                not self.allowed()
                or self.path != "/api/action"
                or self.headers.get("X-VulnAssess-Lab") != "service-demo"
            ):
                self.reply(403, {"error": "A local, explicit lab action is required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024:
                    raise ValueError("Invalid request length")

                def unique(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value:
                            raise ValueError("Duplicate operation key")
                        value[key] = item
                    return value

                data = json.loads(self.rfile.read(length), object_pairs_hook=unique)
                if (
                    not isinstance(data, dict)
                    or set(data) != {"action"}
                    or not isinstance(data["action"], str)
                    or data["action"] not in ACTIONS
                ):
                    raise ValueError("Only one fixed action identifier is accepted")
            except (ValueError, TypeError):
                self.reply(400, {"error": "Invalid fixed-operation request"})
                return
            self.perform(lambda: application.action(data["action"]))

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8798)
    args = parser.parse_args()
    application = Console()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(application))
    server.daemon_threads = True
    application.start_sensor()
    print(f"Office lab site: http://127.0.0.1:{args.port}/office", flush=True)
    print(f"IoT lab site: http://127.0.0.1:{args.port}/iot", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        application.stop.set()
        server.server_close()
        if application.worker:
            application.worker.join(timeout=5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    main()

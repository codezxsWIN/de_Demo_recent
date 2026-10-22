"""Real, loopback-only network services with entirely fictional fixtures."""

from __future__ import annotations

import argparse
import ipaddress
import json
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.ioloop import IOLoop
from pyftpdlib.servers import FTPServer

LAB_ID = "harbordesk-local-v1"
HOST = "127.0.0.1"
FTP_USERNAME = "training"
FTP_PASSWORD = "training-readonly"
FIXTURE = b"marker,operation\nHARBORDESK-FICTIONAL-OPERATIONS,dummy-shipment\n"


class _StrictPassiveDTP(FTPHandler.passive_dtp):
    def bind(self, addr):
        # pyftpdlib normally falls back to an ephemeral port on exhaustion.
        if addr[0] != HOST or addr[1] not in self.cmd_channel.passive_ports:
            raise OSError("Lab passive port range exhausted")
        return super().bind(addr)


class _ReadOnlyFTP(FTPHandler):
    permit_foreign_addresses = False
    permit_privileged_ports = False
    passive_dtp = _StrictPassiveDTP
    auth_failed_timeout = 0
    timeout = 5
    banner = "HarborDesk fictional local training FTP"

    def ftp_PORT(self, line):
        self.respond("502 Active FTP disabled in this lab.")

    def ftp_EPRT(self, line):
        self.respond("502 Active FTP disabled in this lab.")

    def ftp_PASV(self, line):
        try:
            super().ftp_PASV(line)
        except OSError:
            self.respond("425 Lab passive ports unavailable.")

    def ftp_EPSV(self, line):
        try:
            super().ftp_EPSV(line)
        except OSError:
            self.respond("425 Lab passive ports unavailable.")


def _certificate(directory: Path, name: str, expired: bool) -> tuple[Path, Path]:
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HarborDesk local lab")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1) if expired else now - timedelta(minutes=5))
        .not_valid_after(now - timedelta(hours=1) if expired else now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(HOST))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _ManagementHandler(BaseHTTPRequestHandler):
    server_version = "HarborDeskLab/1"
    sys_version = ""
    comparison = False

    def setup(self):
        self.request.settimeout(2)
        super().setup()

    def log_message(self, *_args):
        pass

    def _json(self, status, value):
        body = json.dumps({"lab_id": LAB_ID, "fixture": True, **value}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Training-Lab", LAB_ID)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        # Exact Host matching prevents use through DNS rebinding or a proxy.
        expected = f"{HOST}:{self.server.server_address[1]}"
        if self.headers.get_all("Host") != [expected]:
            return self._json(403, {"error": "loopback Host required"})
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            return self._json(413, {"error": "request bodies are disabled"})
        if self.path == "/health":
            return self._json(200, {"status": "ok"})
        if self.path not in ("/", "/info", "/admin"):
            return self._json(404, {"error": "not found"})
        if self.comparison and self.headers.get_all("X-Lab-Access") != ["training-admin"]:
            return self._json(403, {"error": "lab access header required"})
        return self._json(
            200,
            {
                "management": {
                    "environment": "fictional-training",
                    "backup_target": "dummy-backup",
                    "credential": "DUMMY-NOT-A-REAL-SECRET",
                }
            },
        )


class _TLSServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = False

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2)
        try:
            return self.tls_context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise


class NetworkLab:
    """Own four local services; enter/start returns self, with actual ports in services.

    Port zero requests an OS-assigned port. No host or fixture-root override exists.
    Comparison FTP credentials are training / training-readonly (virtual accounts).
    """

    def __init__(self, ftp_port=2121, secure_ftp_port=2122, tls_port=8443, secure_tls_port=8444):
        for port in (ftp_port, secure_ftp_port, tls_port, secure_tls_port):
            if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
                raise ValueError("Ports must be integers from 0 to 65535")
        self.ftp_port, self.secure_ftp_port = ftp_port, secure_ftp_port
        self.tls_port, self.secure_tls_port = tls_port, secure_tls_port
        self.services = {}
        self._temp = None
        self._loop = None
        self._ftp_thread = None
        self._https = []
        self._stop = threading.Event()

    def start(self):
        if self._temp is not None:
            return self
        self._stop.clear()
        try:
            self._temp = tempfile.TemporaryDirectory(prefix="harbordesk-network-")
            directory = Path(self._temp.name)
            self.fixture_root = directory / "ftp-fixtures"
            self.fixture_root.mkdir()
            (self.fixture_root / "operations.csv").write_bytes(FIXTURE)
            self._loop = IOLoop()
            for name, comparison, ports in (
                ("ftp", False, range(32100, 32110)),
                ("secure_ftp", True, range(32110, 32120)),
            ):
                authorizer = DummyAuthorizer()
                if comparison:
                    authorizer.add_user(
                        FTP_USERNAME, FTP_PASSWORD, str(self.fixture_root), perm="elr"
                    )
                else:
                    authorizer.add_anonymous(str(self.fixture_root), perm="elr")
                handler = type(
                    f"{name}Handler",
                    (_ReadOnlyFTP,),
                    {
                        "authorizer": authorizer,
                        "passive_ports": ports,
                    },
                )
                server = FTPServer(
                    (HOST, getattr(self, f"{name}_port")), handler, ioloop=self._loop
                )
                server.max_cons = 32
                server.max_cons_per_ip = 16
                port = server.socket.getsockname()[1]
                setattr(self, f"{name}_port", port)
                self.services[name] = {
                    "host": HOST,
                    "port": port,
                    "protocol": "ftp",
                    "anonymous": not comparison,
                    "passive_ports": list(ports),
                    "lab_id": LAB_ID,
                }
            for name, comparison in (("tls", False), ("secure_tls", True)):
                cert, key = _certificate(directory, name, expired=not comparison)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(cert, key)
                handler = type(f"{name}Handler", (_ManagementHandler,), {"comparison": comparison})
                server = _TLSServer((HOST, getattr(self, f"{name}_port")), handler)
                server.tls_context = context
                self._https.append((server, None))
                port = server.server_address[1]
                setattr(self, f"{name}_port", port)
                self.services[name] = {
                    "host": HOST,
                    "port": port,
                    "protocol": "https",
                    "expired": not comparison,
                    "lab_id": LAB_ID,
                }
            self._ftp_thread = threading.Thread(target=self._run_ftp, daemon=True)
            self._ftp_thread.start()
            for index, (server, _) in enumerate(self._https):
                thread = threading.Thread(
                    target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
                )
                self._https[index] = (server, thread)
                thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def _run_ftp(self):
        while not self._stop.is_set():
            self._loop.loop(timeout=0.02, blocking=False)

    def close(self):
        self._stop.set()
        for server, thread in self._https:
            if thread is not None and thread.is_alive():
                server.shutdown()
                thread.join()
            server.server_close()
        self._https.clear()
        if self._ftp_thread is not None:
            self._ftp_thread.join()
            self._ftp_thread = None
        if self._loop is not None:
            self._loop.close()
            self._loop = None
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_exc):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name, default in (("ftp", 2121), ("secure-ftp", 2122), ("tls", 8443), ("secure-tls", 8444)):
        parser.add_argument(f"--{name}-port", type=int, default=default)
    args = parser.parse_args()
    try:
        with NetworkLab(**vars(args)) as lab:
            print(json.dumps({"lab_id": LAB_ID, "services": lab.services}), flush=True)
            print("Fictional loopback training services; Ctrl+C to stop.", flush=True)
            threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

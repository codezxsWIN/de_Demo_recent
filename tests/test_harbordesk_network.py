"""Socket-level checks for the isolated, real network training services."""

import ftplib
import http.client
import io
import json
import socket
import ssl
from datetime import datetime, timezone

import pytest
from cryptography import x509

from labs.harbordesk.network import (
    FIXTURE,
    FTP_PASSWORD,
    FTP_USERNAME,
    HOST,
    LAB_ID,
    NetworkLab,
)

_SOCKET_OPERATIONS = {
    name: getattr(socket.socket, name)
    for name in ("connect", "connect_ex", "bind", "send", "sendall", "sendto")
}
_GETADDRINFO = socket.getaddrinfo
_CREATE_CONNECTION = socket.create_connection


@pytest.fixture(autouse=True)
def offline_transport_guard(monkeypatch):
    """Override the global offline guard only here, retaining a loopback boundary."""
    for name, original in _SOCKET_OPERATIONS.items():

        def local_operation(sock, *args, _name=name, _original=original, **kwargs):
            if _name in ("connect", "connect_ex", "bind"):
                address = args[0]
            elif _name == "sendto":
                address = args[-1]
            else:
                address = sock.getpeername()
            assert address[0] == HOST, "only literal IPv4 loopback is allowed"
            return _original(sock, *args, **kwargs)

        monkeypatch.setattr(socket.socket, name, local_operation)

    def local_resolve(host, *args, **kwargs):
        assert host == HOST, "external name resolution is forbidden"
        return _GETADDRINFO(host, *args, **kwargs)

    def local_connection(address, *args, **kwargs):
        assert address[0] == HOST
        return _CREATE_CONNECTION(address, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", local_resolve)
    monkeypatch.setattr(socket, "create_connection", local_connection)


@pytest.fixture
def lab():
    with NetworkLab(ftp_port=0, secure_ftp_port=0, tls_port=0, secure_tls_port=0) as running:
        yield running


def ftp_client(port):
    client = ftplib.FTP(timeout=3)
    client.connect(HOST, port)
    return client


def inspection_context(receipt, port):
    # Deliberate local certificate inspection only; never changes global trust.
    assert isinstance(port, int)
    receipt.update(
        host=HOST,
        port=port,
        verification_disabled=True,
        reason="Inspect the deliberately expired/self-signed local lab certificate",
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def request(port, path="/admin", headers=None, method="GET", body=None):
    receipt = {}
    connection = http.client.HTTPSConnection(
        HOST, port, timeout=3, context=inspection_context(receipt, port)
    )
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        return response.status, dict(response.getheaders()), payload, receipt
    finally:
        connection.close()


def test_actual_ftp_anonymous_and_authenticated_comparison(lab):
    for port, comparison in ((lab.ftp_port, False), (lab.secure_ftp_port, True)):
        with ftp_client(port) as client:
            if comparison:
                with pytest.raises(ftplib.error_perm, match="530"):
                    client.login()
                client.login(FTP_USERNAME, FTP_PASSWORD)
            else:
                client.login()
            host, passive_port = client.makepasv()
            assert host == HOST
            assert passive_port in range(
                32110 if comparison else 32100, 32120 if comparison else 32110
            )
            content = bytearray()
            client.retrbinary("RETR operations.csv", content.extend)
            assert content == FIXTURE
            assert b"HARBORDESK-FICTIONAL-OPERATIONS" in content


def test_ftp_writes_deletes_and_active_connections_refused(lab):
    before = {path.name: path.read_bytes() for path in lab.fixture_root.iterdir()}
    for port, comparison in ((lab.ftp_port, False), (lab.secure_ftp_port, True)):
        with ftp_client(port) as client:
            client.login(FTP_USERNAME, FTP_PASSWORD) if comparison else client.login()
            for filename in ("operations.csv", "new.csv"):
                with pytest.raises(ftplib.error_perm, match="550"):
                    client.storbinary(f"STOR {filename}", io.BytesIO(b"overwrite"))
            with pytest.raises(ftplib.error_perm, match="550"):
                client.delete("operations.csv")
            for command in ("PORT 127,0,0,1,100,100", "EPRT |1|127.0.0.1|25600|"):
                with pytest.raises(ftplib.error_perm, match="502"):
                    client.sendcmd(command)
            client.cwd("/")
            client.cwd("..")
            assert client.nlst() == ["operations.csv"]
    assert before == {path.name: path.read_bytes() for path in lab.fixture_root.iterdir()}


def test_tls_certificates_dates_san_and_real_verification(lab):
    now = datetime.now(timezone.utc)
    for port, expired in ((lab.tls_port, True), (lab.secure_tls_port, False)):
        receipt = {}
        with socket.create_connection((HOST, port), timeout=3) as raw:
            with inspection_context(receipt, port).wrap_socket(raw, server_hostname=HOST) as tls:
                cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                assert tls.version() in ("TLSv1.2", "TLSv1.3")
        assert receipt["verification_disabled"] and receipt["reason"]
        assert cert.not_valid_before_utc < now
        assert (cert.not_valid_after_utc < now) is expired
        if expired:
            assert 3500 < (now - cert.not_valid_after_utc).total_seconds() < 3700
        assert (
            str(
                cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.IPAddress)[0]
            )
            == HOST
        )
        # Trust this exact certificate explicitly, so expiry is checked independently
        # of the fact that the lab certificate is self-signed.
        context = ssl.create_default_context(
            cafile=str(lab.fixture_root.parent / ("tls.pem" if expired else "secure_tls.pem"))
        )
        with socket.create_connection((HOST, port), timeout=3) as raw:
            if expired:
                with pytest.raises(ssl.SSLCertVerificationError, match="expired"):
                    context.wrap_socket(raw, server_hostname=HOST)
            else:
                with context.wrap_socket(raw, server_hostname=HOST):
                    pass


def test_management_identity_authentication_and_boundary(lab):
    for port in (lab.tls_port, lab.secure_tls_port):
        status, headers, body, _ = request(port, "/health")
        assert status == 200
        assert headers["X-Training-Lab"] == LAB_ID
        assert json.loads(body)["lab_id"] == LAB_ID
        for host in ("attacker.invalid", f"localhost:{port}", f"127.0.0.1:{port + 1}"):
            assert request(port, headers={"Host": host})[0] == 403
        assert request(port, body=b"unexpected")[0] == 413
        assert request(port, method="POST")[0] == 501
    status, _, body, _ = request(lab.tls_port)
    assert status == 200
    assert json.loads(body)["fixture"] is True
    assert json.loads(body)["management"]["credential"] == "DUMMY-NOT-A-REAL-SECRET"
    assert request(lab.secure_tls_port)[0] == 403
    assert request(lab.secure_tls_port, headers={"X-Lab-Access": "wrong"})[0] == 403
    status, _, body, _ = request(lab.secure_tls_port, headers={"X-Lab-Access": "training-admin"})
    assert status == 200 and json.loads(body)["management"]


def test_cleanup_idempotence_and_actual_metadata():
    with NetworkLab(0, 0, 0, 0) as lab:
        root = lab.fixture_root.parent
        ports = [item["port"] for item in lab.services.values()]
        assert len(set(ports)) == 4
        assert all(item["host"] == HOST for item in lab.services.values())
    lab.close()
    assert not root.exists()
    for port in ports:
        with pytest.raises(OSError):
            socket.create_connection((HOST, port), timeout=0.2)


def test_startup_failure_closes_previously_opened_services():
    with socket.socket() as occupied:
        occupied.bind((HOST, 0))
        occupied.listen()
        lab = NetworkLab(0, 0, 0, occupied.getsockname()[1])
        with pytest.raises(OSError):
            lab.start()
        assert lab._temp is None
        assert not lab.fixture_root.parent.exists()
        for service in lab.services.values():
            with pytest.raises(OSError):
                socket.create_connection((HOST, service["port"]), timeout=0.2)


@pytest.mark.parametrize("port", [-1, 65536, True, "2121"])
def test_invalid_port_rejected(port):
    with pytest.raises(ValueError):
        NetworkLab(ftp_port=port)

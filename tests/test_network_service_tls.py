import ipaddress
import json
import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vulnassess import network_service_checks as checks
from vulnassess import network_service_policy as policy
from vulnassess.errors import ConfigError
from vulnassess.settings import Scope


def certificate(expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other.example")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("service.example"),
                    x509.IPAddress(ipaddress.ip_address("192.0.2.77")),
                ]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def simulate(monkeypatch, raw, verification, expected_name="service.example"):
    class Wire:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def getpeercert(self, binary_form=False):
            return raw if binary_form else {}

        def version(self):
            return "TLSv1.3"

    class Context:
        check_hostname = False
        verify_mode = ssl.CERT_NONE

        def __init__(self, checked=False):
            self.checked = checked

        def wrap_socket(self, connection, server_hostname):
            assert server_hostname == expected_name
            if self.checked and isinstance(verification, Exception):
                raise verification
            if self.checked and isinstance(verification, bytes):
                connection.getpeercert = lambda binary_form=False: verification
            return connection

    def connect(address, timeout):
        assert address == ("192.0.2.77", 443)
        assert timeout == checks.TIMEOUT
        return Wire()

    monkeypatch.setattr(checks.socket, "create_connection", connect)
    monkeypatch.setattr(checks.ssl, "SSLContext", lambda _: Context())
    monkeypatch.setattr(checks.ssl, "create_default_context", lambda: Context(True))


@pytest.mark.parametrize("outcome", ["valid", "rejected", "timeout", "different"])
def test_tls_verification_is_separate_and_bound_to_inspected_certificate(monkeypatch, outcome):
    raw = certificate(expired=True)
    verification = {
        "valid": None,
        "rejected": ssl.SSLCertVerificationError(1, "rejected"),
        "timeout": TimeoutError(),
        "different": b"different",
    }[outcome]
    simulate(monkeypatch, raw, verification)
    proof = checks._tls("192.0.2.77", {"port": 443, "server_name": "service.example"})
    assert proof["expired"] is True
    assert proof["hostname_matches"] is True
    assert proof["certificate_chain_valid"] is (True if outcome == "valid" else None)
    assert (
        proof["chain_verification_succeeded"]
        is {"valid": True, "rejected": False, "timeout": None, "different": True}[outcome]
    )
    assert proof["trust_and_hostname_validated"] is (True if outcome == "valid" else None)
    controls = {"require_unexpired_certificate": True, "require_valid_certificate_chain": True}
    kinds = [v[0] for v in checks.violations(controls, proof)]
    assert kinds == (["certificate", "chain"] if outcome == "rejected" else ["certificate"])
    assert checks.violations({}, proof) == []


@pytest.mark.parametrize("outcome", [TimeoutError(), b"different"])
def test_required_chain_check_is_inconclusive_if_it_cannot_be_bound(monkeypatch, outcome):
    simulate(monkeypatch, certificate(), outcome)
    proof = checks._tls(
        "192.0.2.77",
        {"port": 443, "server_name": "service.example", "require_valid_certificate_chain": True},
    )
    assert proof["inconclusive"] is True
    assert checks.violations({"require_valid_certificate_chain": True}, proof) == []


def test_tls_hostname_mismatch_and_unknown_do_not_get_conflated(monkeypatch):
    raw = certificate()
    simulate(monkeypatch, raw, None, "other.example")
    # Certificate SAN takes precedence over its common name.
    proof = checks._tls("192.0.2.77", {"port": 443, "server_name": "other.example"})
    assert proof["hostname_matches"] is False
    assert proof["trust_and_hostname_validated"] is False
    entry = {"require_matching_hostname": True}
    assert checks.violations(entry, {"protocol_confirmed": True, "hostname_matches": None}) == []
    assert (
        checks.violations(entry, {"protocol_confirmed": True, "hostname_matches": False})[0][0]
        == "hostname"
    )


def test_tls_default_ip_identity_is_matched_against_ip_san(monkeypatch):
    simulate(monkeypatch, certificate(), None, "192.0.2.77")
    proof = checks._tls("192.0.2.77", {"port": 443})
    assert proof["hostname_matches"] is True


@pytest.mark.parametrize(
    "extra,valid",
    [
        (
            {
                "server_name": "service.example",
                "require_matching_hostname": True,
                "require_valid_certificate_chain": True,
            },
            True,
        ),
        ({"server_name": "https://service.example"}, False),
        ({"require_matching_hostname": "true"}, False),
        ({"require_valid_certificate_chain": 1}, False),
    ],
)
def test_tls_policy_validation(tmp_path, extra, valid):
    ip = "192.0.2.77"
    entry = {"port": 443, "transport": "tcp", "service": "tls", **extra}
    (tmp_path / policy.FILENAME).write_text(json.dumps({"version": 1, "targets": {ip: [entry]}}))
    scope = Scope({"allowed_cidrs": [ip + "/32"]}, tmp_path / "scope.yaml")
    if valid:
        assert policy.load(tmp_path, scope, ip)["endpoints"] == [entry]
    else:
        with pytest.raises(ConfigError):
            policy.load(tmp_path, scope, ip)

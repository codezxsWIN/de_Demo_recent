"""Bounded network checks for two exact, owner-authorised loopback environments.

Findings come from protocol exchanges, never from the lab catalogue or open ports
alone. Optional clients are loaded only for this opt-in local assessment path.
"""

import asyncio
import ftplib
import hashlib
import json
import socket
import ssl
import struct
from datetime import UTC, datetime
from uuid import uuid4

from labs.service_networks.catalog import ENVIRONMENTS
from vulnassess.errors import ScopeError
from vulnassess.schema import Finding, Provenance, Service

TIMEOUT = 4
PROOF_FILE = "network-proof.txt"
PROOF_BYTES = b"VulnAssess office network proof\n"
TOPIC = "vulnassess/training/assessment"

CHECKS = {
    "ftp-anonymous": (
        2121,
        "tcp",
        "ftp",
        "Anonymous FTP permits reading a share file",
        "Medium",
        "CWE-306",
        "Disable anonymous access to non-public shares; prefer SFTP or authenticated FTPS. Re-run the same anonymous read and require rejection.",
    ),
    "smb-guest": (
        1445,
        "tcp",
        "microsoft-ds",
        "SMB share permits unauthenticated file access",
        "Medium",
        "CWE-306",
        "Disable guest access and require named least-privilege share accounts. Re-run the same anonymous file read and require access denied.",
    ),
    "smb-signing": (
        1445,
        "tcp",
        "microsoft-ds",
        "SMB signing is not required by the server",
        "Medium",
        "CWE-345",
        "Require SMB signing on clients and servers where supported. Re-negotiate and require the signing-required flag; this observation alone does not prove a relay attack.",
    ),
    "ssh-default-credential": (
        2222,
        "tcp",
        "ssh",
        "SSH accepts a known lab default credential",
        "Medium",
        "CWE-1392",
        "Remove default credentials and enforce unique credentials or public-key-only SSH. Repeat the single designated lab login and require rejection; no password spraying is needed.",
    ),
    "mqtt-anonymous": (
        1883,
        "tcp",
        "mqtt",
        "MQTT permits anonymous publish and subscription",
        "Medium",
        "CWE-306",
        "Require broker authentication and topic-level publish/subscribe ACLs; use TLS. Repeat the bounded anonymous message exchange and require refusal.",
    ),
    "snmp-public": (
        1161,
        "udp",
        "snmp",
        "SNMPv2c discloses management information using public community",
        "Medium",
        "CWE-1392",
        "Disable default communities, restrict management-plane clients and prefer SNMPv3 authPriv. Repeat the same public-community GET and require denial while approved monitoring still works.",
    ),
    "mqtt-expired-certificate": (
        8883,
        "tcp",
        "mqtts",
        "TLS service presents an expired certificate",
        "Medium",
        "CWE-295",
        "Install a current certificate trusted by clients with the correct endpoint identity. Re-run certificate validity and trust checks without disabling validation.",
    ),
}


def eligible(ip, endpoint=None):
    return ip in ENVIRONMENTS and endpoint is None


def _ftp_read(ip, port):
    with ftplib.FTP(timeout=TIMEOUT) as client:
        greeting = client.connect(ip, port)
        try:
            login = client.login("anonymous", "training@example.invalid")
        except ftplib.error_perm as error:
            return {"greeting": greeting, "access": "denied", "response": str(error)[:200]}
        chunks = []

        def bounded(chunk):
            chunks.append(chunk)
            if sum(map(len, chunks)) > 1024:
                raise ValueError("FTP proof exceeds the fixed read limit")

        client.retrbinary("RETR " + PROOF_FILE, bounded, blocksize=256)
        raw = b"".join(chunks)
        return {
            "greeting": greeting,
            "login": login,
            "access": "read",
            "file": PROOF_FILE,
            "response_text": raw.decode("ascii", errors="replace"),
            "matches_training_file": raw == PROOF_BYTES,
            "transport": "plaintext FTP; no TLS negotiation performed",
        }


def _ftp(ip):
    proof = _ftp_read(ip, 2121)
    control = _comparison(lambda: _ftp_read(ip, 2122))
    return (
        proof.get("matches_training_file") is True,
        proof,
        control.get("access") == "denied",
        control,
    )


def _smb_read(ip, port):
    from impacket.smbconnection import (  # pyright: ignore[reportMissingImports]
        SessionError,
        SMBConnection,
    )

    client = SMBConnection(ip, ip, sess_port=port, timeout=TIMEOUT)
    proof = {
        "signing_required": bool(client.isSigningRequired()),
        "dialect": str(client.getDialect()),
    }
    try:
        client.login("", "")
        chunks = []

        def bounded(chunk):
            chunks.append(chunk)
            if sum(map(len, chunks)) > 1024:
                raise ValueError("SMB proof exceeds the fixed read limit")

        client.getFile("TRAINING", PROOF_FILE, bounded)
        raw = b"".join(chunks)
        proof.update(
            access="read",
            share="TRAINING",
            file=PROOF_FILE,
            response_text=raw.decode("ascii", errors="replace"),
            matches_training_file=raw == PROOF_BYTES,
        )
    except SessionError as error:
        # Only explicit access/logon failures establish denial, not disconnects.
        if error.getErrorCode() not in {0xC0000022, 0xC000006D, 0xC0000064, 0xC000006A}:
            raise
        proof.update(access="denied", status=f"0x{error.getErrorCode():08x}")
    finally:
        client.close()
    return proof


def _smb(ip):
    proof = _smb_read(ip, 1445)
    control = _comparison(lambda: _smb_read(ip, 1446))
    return (
        proof.get("matches_training_file") is True,
        proof,
        control.get("access") == "denied",
        control,
    )


async def _ssh_login(ip, port):
    import asyncssh  # pyright: ignore[reportMissingImports]

    try:
        async with asyncssh.connect(
            ip,
            port,
            username="admin",
            password="admin",
            known_hosts=None,
            config=None,
            client_keys=None,
            agent_path=None,
            tunnel=None,
            proxy_command=None,
            canonicalize_hostname=False,
            public_key_auth=False,
            host_based_auth=False,
            kbdint_auth=False,
            gss_auth=False,
            gss_kex=False,
            preferred_auth="password",
            login_timeout=TIMEOUT,
            connect_timeout=TIMEOUT,
        ) as connection:
            return {
                "access": "authenticated",
                "host_key_sha256": connection.get_server_host_key().get_fingerprint(),
                "method": "one fixed training credential; no commands or shell requested",
            }
    except asyncssh.PermissionDenied:
        return {
            "access": "denied",
            "method": "fixed training password rejected by SSH authentication",
        }


def _ssh(ip):
    async def check():
        proof = await _ssh_login(ip, 2222)
        try:
            control = await _ssh_login(ip, 2223)
        except Exception as error:
            control = {
                "access": "error",
                "error": f"{type(error).__name__}: comparison unavailable",
            }
        return proof, control

    proof, control = asyncio.run(check())
    return proof["access"] == "authenticated", proof, control["access"] == "denied", control


def _comparison(call):
    """A comparison outage must not discard independently observed primary proof."""
    try:
        return call()
    except Exception as error:
        return {"access": "error", "error": f"{type(error).__name__}: comparison unavailable"}


def _receive(sock, size):
    output = b""
    while len(output) < size:
        data = sock.recv(size - len(output))
        if not data:
            raise ValueError("Protocol response ended early")
        output += data
    return output


def _mqtt_packet(sock):
    header, length, multiplier = _receive(sock, 1)[0], 0, 1
    for _ in range(4):
        digit = _receive(sock, 1)[0]
        length += (digit & 127) * multiplier
        if length > 4096:
            raise ValueError("MQTT response exceeds the fixed read limit")
        if not digit & 128:
            return header, _receive(sock, length)
        multiplier *= 128
    raise ValueError("Invalid MQTT length")


def _send_mqtt(sock, header, payload):
    length, encoded = len(payload), bytearray()
    while True:
        digit = length % 128
        length //= 128
        encoded.append(digit | (128 if length else 0))
        if not length:
            break
    sock.sendall(bytes([header]) + encoded + payload)


def _mqtt_exchange(ip, port, *, exchange):
    client_id = ("vulnassess-" + uuid4().hex[:12]).encode()
    with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
        _send_mqtt(
            sock,
            0x10,
            b"\x00\x04MQTT\x04\x02\x00\x0a" + struct.pack("!H", len(client_id)) + client_id,
        )
        header, connack = _mqtt_packet(sock)
        if header != 0x20 or len(connack) != 2:
            raise ValueError("MQTT CONNECT acknowledgement is invalid")
        proof = {"connack_hex": connack.hex(), "anonymous": True}
        if connack[1] != 0:
            proof["access"] = "denied" if connack[1] in {4, 5} else "other refusal"
            return proof
        proof["access"] = "connected"
        if exchange:
            topic = TOPIC.encode()
            _send_mqtt(sock, 0x82, b"\x00\x01" + struct.pack("!H", len(topic)) + topic + b"\x00")
            header, suback = _mqtt_packet(sock)
            if header != 0x90 or suback != b"\x00\x01\x00":
                raise ValueError("MQTT subscription was not granted at QoS zero")
            marker = ("VulnAssess network proof " + uuid4().hex).encode()
            _send_mqtt(sock, 0x30, struct.pack("!H", len(topic)) + topic + marker)
            header, message = _mqtt_packet(sock)
            expected = struct.pack("!H", len(topic)) + topic + marker
            proof.update(
                topic=TOPIC,
                publish_received=header == 0x30 and message == expected,
                payload_sha256=hashlib.sha256(marker).hexdigest(),
                suback_hex=suback.hex(),
                transport="plaintext MQTT/TCP",
            )
        _send_mqtt(sock, 0xE0, b"")
        return proof


def _mqtt(ip):
    proof = _mqtt_exchange(ip, 1883, exchange=True)
    control = _comparison(lambda: _mqtt_exchange(ip, 1884, exchange=False))
    return proof.get("publish_received") is True, proof, control["access"] == "denied", control


async def _snmp_get(ip, port, community):
    from pysnmp.hlapi.v3arch.asyncio import (  # pyright: ignore[reportMissingImports]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((ip, port), timeout=1, retries=0)
        indication, status, _, bindings = await get_cmd(
            engine,
            CommunityData(community, mpModel=1),
            target,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )
        if indication or status:
            return {
                "access": "no response" if indication else "error",
                "error": str(indication or status)[:150],
            }
        return {
            "access": "read",
            "version": "SNMPv2c",
            "oid": str(bindings[0][0]),
            "value": str(bindings[0][1])[:300],
        }
    finally:
        engine.close_dispatcher()


def _snmp(ip):
    async def check():
        proof = await _snmp_get(ip, 1161, "public")
        try:
            denied = await _snmp_get(ip, 1162, "public")
            authorized = await _snmp_get(ip, 1162, "vulnassess-private-training-2026")
        except Exception as error:
            denied = authorized = {
                "access": "error",
                "error": f"{type(error).__name__}: comparison unavailable",
            }
        return proof, denied, authorized

    proof, denied, authorized = asyncio.run(check())
    observed = proof.get("access") == "read" and proof.get("value", "").startswith("VulnAssess")
    control = {"public_request": denied, "authorized_monitoring": authorized}
    passed = denied["access"] == "no response" and authorized["access"] == "read"
    return observed, proof, passed, control


def _certificate(ip):
    from cryptography import x509

    # Inspection-only handshake on the exact training listener. Normal trust
    # validation is independently attempted below; this is not a browser bypass.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, 8883), timeout=TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=ip) as tls:
            der = tls.getpeercert(binary_form=True)
            protocol = tls.version()
    if not der:
        raise ValueError("TLS handshake provided no certificate")
    certificate = x509.load_der_x509_certificate(der)
    proof = {
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "tls_protocol": protocol,
        "not_valid_after": certificate.not_valid_after_utc.isoformat(),
        "expired": certificate.not_valid_after_utc < datetime.now(UTC),
    }
    try:
        with socket.create_connection((ip, 8883), timeout=TIMEOUT) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=ip):
                validation = {"trust_validation": "accepted"}
    except ssl.SSLCertVerificationError as error:
        validation = {
            "trust_validation": "rejected",
            "verify_code": error.verify_code,
            "reason": error.verify_message,
        }
    except OSError as error:
        validation = {
            "trust_validation": "error",
            "error": f"{type(error).__name__}: comparison unavailable",
        }
    return proof["expired"], proof, validation["trust_validation"] == "rejected", validation


def run(scope, target_ip, endpoint, directory):
    if (
        not eligible(target_ip, endpoint)
        or not scope.contains(target_ip)
        or scope.is_canary(target_ip)
    ):
        raise ScopeError(
            "Service-network checks require one exact authorised loopback lab IP without a URL"
        )
    specification = ENVIRONMENTS[target_ip]
    checks = []
    functions = {
        "ftp-anonymous": _ftp,
        "smb-guest": _smb,
        "ssh-default-credential": _ssh,
        "mqtt-anonymous": _mqtt,
        "snmp-public": _snmp,
        "mqtt-expired-certificate": _certificate,
    }
    for identity in specification["checks"]:
        if identity == "smb-signing":
            previous = next(row for row in checks if row["id"] == "smb-guest")
            row = {**previous, "id": identity}
            row["observed"] = previous.get("proof", {}).get("signing_required") is False
            if "error" not in row:
                row["status"] = "observed" if row["observed"] else "not observed"
            # Guest denial is not a signing-policy comparison.
            row["comparison"] = {
                "note": "Guest access comparison is separate; no signing-required server comparison claimed"
            }
            row["comparison_passed"] = None
        else:
            row = {
                "id": identity,
                "observed": False,
                "status": "error",
                "port": CHECKS[identity][0],
            }
            try:
                observed, proof, passed, comparison = functions[identity](target_ip)
                row.update(
                    observed=bool(observed),
                    proof=proof,
                    comparison=comparison,
                    comparison_passed=bool(passed),
                    status="observed" if observed else "not observed",
                )
                if proof.get("access") in {"no response", "error"}:
                    row["status"] = "error"
                    row["error"] = (
                        "Primary protocol check returned no usable response; service state not established"
                    )
            except Exception as error:
                # Optional protocol libraries use their own exception hierarchies;
                # failed checks must remain failed, never abort/erase other evidence.
                row["error"] = f"{type(error).__name__}: protocol check could not be completed"
        checks.append(row)
    receipt = {
        "environment": specification["id"],
        "target_ip": target_ip,
        "captured_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "limits": "Exact loopback endpoints only; bounded protocol exchanges. No web tests, brute force, OS commands, CVE inference or external network reachability claim.",
    }
    path = directory / "service-network-checks.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
    findings, services = [], []
    snmp_row = next((row for row in checks if row["id"] == "snmp-public"), {})
    if snmp_row.get("comparison", {}).get("authorized_monitoring", {}).get("access") == "read":
        services.append(
            Service(
                port=1162,
                protocol="udp",
                name="snmp",
                banner="SNMPv2c GET response received using the designated protected lab community",
            )
        )
    for index, row in enumerate(checks):
        port, transport, name, title, severity, cwe, action = CHECKS[row["id"]]
        if row.get("proof") and row["proof"].get("access") not in {"no response", "error"}:
            services.append(
                Service(
                    port=port,
                    protocol=transport,
                    name=name,
                    tls=row["id"] == "mqtt-expired-certificate",
                    banner="Confirmed by bounded service protocol exchange; lab library implementation",
                )
            )
        if not row["observed"]:
            continue
        findings.append(
            Finding.make(
                host_ip=target_ip,
                port=port,
                protocol=transport,
                tool="service-network",
                tool_native_id=row["id"],
                title=title,
                native_severity=severity,
                native_confidence="high",
                description="Observed in a locally isolated real-protocol library lab, using fictional data. "
                + action,
                evidence=json.dumps(
                    {
                        "id": row["id"],
                        "target_ip": target_ip,
                        "port": port,
                        "proof": row["proof"],
                        "comparison": row.get("comparison"),
                    },
                    ensure_ascii=True,
                ),
                cwe_ids=[cwe],
                provenance=Provenance(
                    tool="service-network",
                    raw_path=str(path.resolve()),
                    record_index=index,
                    run_id="live",
                ),
            )
        )
    partial = any(
        row["status"] == "error" or row.get("comparison_passed") is False for row in checks
    )
    coverage = (
        f"{'partial' if partial else 'complete'}: {len(checks)} fixed network-service checks; "
        f"{len(findings)} observed conditions; " + receipt["limits"]
    )
    return findings, services, coverage


def guidance(finding):
    if finding.get("tool") != "service-network" or finding.get("tool_native_id") not in CHECKS:
        return None
    _, _, name, title, _, _, action = CHECKS[finding["tool_native_id"]]
    return {
        "category": title,
        "meaning": finding.get("description"),
        "scenario": f"A client reaching the {name} listener can reproduce the retained protocol observation. This is a service configuration assessment, not SQL injection or an established OS compromise.",
        "prerequisites": ["Network reachability and the observed endpoint access policy."],
        "impact": "The report establishes the specific access, signing or certificate condition recorded in its proof; wider production impact is not established.",
        "patch": [action],
        "mitigations": [
            "Keep these intentionally insecure lab listeners loopback-only; do not expose or tunnel them."
        ],
        "verify": [
            "Repeat the same fixed protocol check after remediation and compare the retained before/after evidence."
        ],
        "example": None,
        "source": "Protocol-specific reviewed guidance; no automated exploitation or invented CVE.",
    }

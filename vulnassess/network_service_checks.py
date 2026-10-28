"""Policy-led checks of authorised endpoints, independent of lab names and proof data."""

import asyncio
import ftplib
import hashlib
import json
import socket
import ssl
import struct
import time
from datetime import UTC, datetime
from uuid import uuid4

from vulnassess.errors import ScopeError
from vulnassess.schema import Finding, Provenance, Service

TIMEOUT = 4


def _ftp(ip, entry):
    with ftplib.FTP(timeout=TIMEOUT) as client:
        greeting = client.connect(ip, entry["port"])
        try:
            response = client.login("anonymous", "assessment@example.invalid")
        except ftplib.error_perm as error:
            return {
                "protocol_confirmed": True,
                "anonymous_accepted": False,
                "response": str(error)[:200],
                "greeting": greeting,
            }
        return {
            "protocol_confirmed": True,
            "anonymous_accepted": True,
            "response": response,
            "greeting": greeting,
            "files_read": False,
            "note": "Login only; no directory listing, file contents or data connection requested",
        }


def _smb(ip, entry):
    from impacket.smbconnection import (  # pyright: ignore[reportMissingImports]
        SessionError,
        SMBConnection,
    )

    connection = SMBConnection(ip, ip, sess_port=entry["port"], timeout=TIMEOUT)
    proof = {
        "protocol_confirmed": True,
        "signing_required": bool(connection.isSigningRequired()),
        "dialect": str(connection.getDialect()),
        "files_read": False,
    }
    try:
        connection.login("", "")
        proof["anonymous_session_accepted"] = True
        if entry.get("share") and entry.get("read_path"):
            count, digest = 0, hashlib.sha256()

            class ReadLimit(Exception):
                pass

            def receive(chunk):
                nonlocal count
                remaining = max(0, 1024 - count)
                digest.update(chunk[:remaining])
                count += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    raise ReadLimit()

            try:
                connection.getFile(entry["share"], entry["read_path"], receive)
            except ReadLimit:
                proof["read_truncated_at_1024_bytes"] = True
            proof.update(
                anonymous_accepted=True,
                files_read=True,
                read_bytes=count,
                read_sha256=digest.hexdigest(),
                content_persisted=False,
            )
    except SessionError as error:
        if error.getErrorCode() in {0xC0000022, 0xC000006D, 0xC0000064, 0xC000006A}:
            proof.update(
                anonymous_accepted=False, authentication_status=f"0x{error.getErrorCode():08x}"
            )
        else:
            proof["authentication_check_error"] = f"0x{error.getErrorCode():08x}"
    except Exception as error:
        # Retain independently completed negotiation even if authentication fails operationally.
        proof["authentication_check_error"] = type(error).__name__
    finally:
        connection.close()
    return proof


def _ssh(ip, entry):
    import asyncssh  # pyright: ignore[reportMissingImports]

    options = dict(
        config=None,
        client_keys=None,
        agent_path=None,
        tunnel=None,
        proxy_command=None,
        known_hosts=None,
        public_key_auth=False,
        host_based_auth=False,
        kbdint_auth=False,
        gss_auth=False,
        gss_kex=False,
        connect_timeout=TIMEOUT,
        login_timeout=TIMEOUT,
    )

    async def check():
        if "credential" not in entry:
            # Do not guess credentials just because SSH was discovered.
            methods = await asyncssh.get_server_auth_methods(
                ip, entry["port"], username="assessment", **options
            )
            return {
                "protocol_confirmed": True,
                "advertised_auth_methods": methods,
                "login_attempted": False,
            }
        try:
            async with asyncssh.connect(
                ip, entry["port"], **entry["credential"], **options
            ) as connection:
                return {
                    "protocol_confirmed": True,
                    "test_credential_accepted": True,
                    "host_key_sha256": connection.get_server_host_key().get_fingerprint(),
                    "commands_executed": False,
                }
        except asyncssh.PermissionDenied:
            return {
                "protocol_confirmed": True,
                "test_credential_accepted": False,
                "commands_executed": False,
            }

    return asyncio.run(check())


def _read(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ValueError("Truncated protocol response")
        data.extend(chunk)
    return bytes(data)


def _packet(sock):
    header, size, multiplier = _read(sock, 1)[0], 0, 1
    for _ in range(4):
        digit = _read(sock, 1)[0]
        size += (digit & 127) * multiplier
        if size > 4096:
            raise ValueError("MQTT response exceeds 4 KiB")
        if not digit & 128:
            return header, _read(sock, size)
        multiplier *= 128
    raise ValueError("Invalid MQTT framing")


def _send(sock, header, payload):
    size, prefix = len(payload), bytearray([header])
    while True:
        digit = size % 128
        size //= 128
        prefix.append(digit | (128 if size else 0))
        if not size:
            break
    sock.sendall(prefix + payload)


def _mqtt(ip, entry):
    with socket.create_connection((ip, entry["port"]), timeout=TIMEOUT) as connection:
        name = ("assessment-" + uuid4().hex[:12]).encode()
        _send(
            connection, 0x10, b"\x00\x04MQTT\x04\x02\x00\x0a" + struct.pack("!H", len(name)) + name
        )
        header, acknowledgement = _packet(connection)
        if header != 0x20 or len(acknowledgement) != 2 or acknowledgement[1] > 5:
            raise ValueError("Invalid MQTT CONNACK")
        proof = {"protocol_confirmed": True, "connack_hex": acknowledgement.hex()}
        if acknowledgement[1] != 0:
            if acknowledgement[1] in {4, 5}:
                proof["anonymous_accepted"] = False
            else:
                proof["authentication_check_error"] = (
                    "Broker refused CONNECT for a non-authentication reason"
                )
            return proof
        proof["anonymous_accepted"] = True
        if entry.get("publish_topic"):
            topic = entry["publish_topic"].encode()
            _send(connection, 0x82, b"\x00\x01" + struct.pack("!H", len(topic)) + topic + b"\x00")
            deadline = time.monotonic() + TIMEOUT
            marker = uuid4().hex.encode()
            expected = struct.pack("!H", len(topic)) + topic + marker
            subscribed = False
            proof["message_exchange_confirmed"] = False
            # MQTT may interleave retained/publications with acknowledgements.
            # Match our packet ID and exact nonce, never whichever frame arrives next.
            for _ in range(8):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                connection.settimeout(remaining)
                header, response = _packet(connection)
                if not subscribed and header == 0x90:
                    if response != b"\x00\x01\x00":
                        break
                    subscribed = True
                    _send(connection, 0x30, expected)
                    proof["message_sha256"] = hashlib.sha256(marker).hexdigest()
                elif subscribed and header == 0x30 and response == expected:
                    proof["message_exchange_confirmed"] = True
                    break
                elif header >> 4 != 3:
                    break
            proof["topic"] = entry["publish_topic"]
        _send(connection, 0xE0, b"")
        return proof


def _snmp(ip, entry):
    from pysnmp.hlapi.v3arch.asyncio import (  # pyright: ignore[reportMissingImports]
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )
    from pysnmp.proto.rfc1905 import (  # pyright: ignore[reportMissingImports]
        EndOfMibView,
        NoSuchInstance,
        NoSuchObject,
    )

    async def check():
        engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create((ip, entry["port"]), timeout=1, retries=0)
            indication, status, _, bindings = await get_cmd(
                engine,
                CommunityData("public", mpModel=1),
                target,
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            )
            if indication or status:
                if entry.get("monitoring_community"):
                    monitor_error, monitor_status, _, monitor_bindings = await get_cmd(
                        engine,
                        CommunityData(entry["monitoring_community"], mpModel=1),
                        target,
                        ContextData(),
                        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
                    )
                    if not monitor_error and not monitor_status:
                        return {
                            "protocol_confirmed": True,
                            "public_community_read": False,
                            "approved_monitoring_read": True,
                            "oid": str(monitor_bindings[0][0]),
                            "note": "Public query returned no successful response while the authorised monitoring query succeeded; this does not establish permanent filtering",
                        }
                return {
                    "protocol_confirmed": False,
                    "inconclusive": True,
                    "reason": "No successful SNMP GET response; cannot distinguish filtering, credential rejection or unavailable service",
                }
            if isinstance(bindings[0][1], (NoSuchObject, NoSuchInstance, EndOfMibView)):
                return {
                    "protocol_confirmed": True,
                    "inconclusive": True,
                    "reason": "SNMP replied but did not return the requested management value; no information read established",
                }
            return {
                "protocol_confirmed": True,
                "public_community_read": True,
                "oid": str(bindings[0][0]),
                "response_length": len(str(bindings[0][1]).encode()),
                "response_sha256": hashlib.sha256(str(bindings[0][1]).encode()).hexdigest(),
            }
        finally:
            engine.close_dispatcher()

    return asyncio.run(check())


def _tls(ip, entry):
    import ipaddress

    from cryptography import x509

    server_name = entry.get("server_name", ip)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, entry["port"]), timeout=TIMEOUT) as connection:
        with context.wrap_socket(connection, server_hostname=server_name) as encrypted:
            raw, version = encrypted.getpeercert(binary_form=True), encrypted.version()
    if not raw:
        raise ValueError("No certificate received")
    certificate = x509.load_der_x509_certificate(raw)
    proof = {
        "protocol_confirmed": True,
        "tls_version": version,
        "certificate_sha256": hashlib.sha256(raw).hexdigest(),
        "not_valid_after": certificate.not_valid_after_utc.isoformat(),
        "expired": certificate.not_valid_after_utc < datetime.now(UTC),
        "server_name": server_name,
        "hostname_matches": None,
        "certificate_chain_valid": None,
        "chain_verification_succeeded": None,
        "trust_and_hostname_validated": None,
    }
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        try:
            address = ipaddress.ip_address(server_name)
        except ValueError:
            expected = server_name.lower().rstrip(".")

            def matches(name):
                labels = name.lower().rstrip(".").split(".")
                target = expected.split(".")
                if labels and labels[0] == "*":
                    return (
                        len(labels) >= 3 and len(labels) == len(target) and labels[1:] == target[1:]
                    )
                return labels == target and "*" not in name

            proof["hostname_matches"] = any(
                matches(name) for name in names.get_values_for_type(x509.DNSName)
            )
        else:
            proof["hostname_matches"] = address in names.get_values_for_type(x509.IPAddress)
    except x509.ExtensionNotFound:
        proof["hostname_matches"] = False
    except (ValueError, TypeError, x509.DuplicateExtension):
        pass

    # A second connection can select a different backend; bind successful validation
    # to the inspected leaf certificate before combining either result.
    try:
        verified = ssl.create_default_context()
        verified.check_hostname = False
        with socket.create_connection((ip, entry["port"]), timeout=TIMEOUT) as connection:
            with verified.wrap_socket(connection, server_hostname=server_name) as encrypted:
                verified_raw = encrypted.getpeercert(binary_form=True)
        if verified_raw == raw:
            proof["certificate_chain_valid"] = True
        else:
            proof["chain_check_reason"] = "Verified connection presented a different certificate"
        proof["chain_verification_succeeded"] = True
    except ssl.SSLCertVerificationError as error:
        # No authenticated leaf is available on a failed handshake. Report the
        # endpoint attempt separately, without attributing failure to the first leaf.
        proof["chain_check_reason"] = "Certificate verification failed on a separate connection"
        proof["chain_verification_failed"] = True
        proof["chain_verification_succeeded"] = False
        proof["chain_verify_code"] = getattr(error, "verify_code", None)
    except (OSError, ssl.SSLError, ValueError):
        proof["chain_check_reason"] = "Certificate verification could not be completed"
    if proof["certificate_chain_valid"] is True:
        proof["trust_and_hostname_validated"] = proof["hostname_matches"]
    if (entry.get("require_matching_hostname") is True and proof["hostname_matches"] is None) or (
        entry.get("require_valid_certificate_chain") is True
        and proof["certificate_chain_valid"] is None
        and proof["chain_verification_succeeded"] is not False
    ):
        proof["inconclusive"] = True
        proof["reason"] = "A required certificate check could not be established"
    return proof


def _redis_identity(ip, entry):
    from vulnassess.redis_identity import probe

    return probe(ip, entry)


TRANSPORTS = {
    "ftp": _ftp,
    "smb": _smb,
    "ssh": _ssh,
    "mqtt": _mqtt,
    "snmp": _snmp,
    "tls": _tls,
    "redis": _redis_identity,
}


def violations(entry, proof):
    """Apply stated policy only; successful public access alone is not a vulnerability."""
    result = []
    if proof.get("protocol_confirmed") is not True:
        return result
    if entry.get("require_auth") is True:
        if proof.get("anonymous_accepted") is True or proof.get("public_community_read") is True:
            result.append(
                (
                    "authentication",
                    "Unauthenticated service access violates the required access policy",
                    "CWE-306",
                )
            )
    if entry.get("require_signing") is True and proof.get("signing_required") is False:
        result.append(
            ("signing", "SMB signing is not required despite the endpoint policy", "CWE-345")
        )
    if (
        entry.get("reject_test_credential") is True
        and proof.get("test_credential_accepted") is True
    ):
        result.append(
            (
                "credential",
                "SSH accepts a designated credential forbidden by endpoint policy",
                "CWE-1392",
            )
        )
    if entry.get("require_unexpired_certificate") is True and proof.get("expired") is True:
        result.append(
            (
                "certificate",
                "TLS certificate is expired against the endpoint validity policy",
                "CWE-295",
            )
        )
    if entry.get("require_matching_hostname") is True and proof.get("hostname_matches") is False:
        result.append(
            ("hostname", "TLS certificate does not match the required endpoint identity", "CWE-297")
        )
    if (
        entry.get("require_valid_certificate_chain") is True
        and proof.get("chain_verification_failed") is True
    ):
        result.append(
            (
                "chain",
                "TLS certificate verification failed against the system trust policy",
                "CWE-295",
            )
        )
    return result


def run(scope, ip, policy, discovered, directory):
    if not scope.contains(ip) or scope.is_canary(ip) or policy.get("target_ip") != ip:
        raise ScopeError("Network service checks require an exactly authorised policy target")
    open_endpoints = {(service.port, service.protocol) for service in discovered}
    rows, findings, services = [], [], []
    for entry in policy["endpoints"]:
        port, transport = entry["port"], entry["transport"]
        # Do not persist trial credentials or arbitrary service payloads.
        intended = {
            key: value
            for key, value in entry.items()
            if key not in {"credential", "monitoring_community"}
        }
        row = {
            "port": port,
            "transport": transport,
            "service": entry["service"],
            "policy": intended,
        }
        if transport == "tcp" and (port, transport) not in open_endpoints:
            row.update(
                status="not_discovered_open",
                note="No active protocol check; TCP endpoint was not recorded open by discovery",
            )
            rows.append(row)
            continue
        try:
            proof = TRANSPORTS[entry["service"]](ip, entry)
            row.update(
                proof=proof,
                status="inconclusive"
                if proof.get("inconclusive") or proof.get("authentication_check_error")
                else "observed",
            )
            if proof.get("protocol_confirmed"):
                name = {"smb": "microsoft-ds", "tls": "ssl"}.get(entry["service"], entry["service"])
                services.append(
                    Service(
                        port=port,
                        protocol=transport,
                        name=name,
                        product="Redis"
                        if entry["service"] == "redis" and proof.get("identity_established")
                        else None,
                        version=proof.get("redis_version") if entry["service"] == "redis" else None,
                        cpe=proof.get("cpe") if entry["service"] == "redis" else None,
                        tls=entry["service"] == "tls",
                        banner="Protocol confirmed by an authorised endpoint exchange; see network-service-observations.json",
                    )
                )
            row["violations"] = [item[0] for item in violations(entry, proof)]
            for key, title, cwe in violations(entry, proof):
                findings.append(
                    Finding.make(
                        host_ip=ip,
                        port=port,
                        protocol=transport,
                        tool="service-network",
                        tool_native_id=f"policy:{entry['service']}:{port}:{key}",
                        title=title,
                        description="A protocol observation contradicts the explicit owner-supplied endpoint policy. No file confidentiality, OS compromise or CVE applicability is inferred.",
                        evidence=json.dumps(
                            {
                                "target_ip": ip,
                                "port": port,
                                "protocol": transport,
                                "policy_sha256": policy["policy_sha256"],
                                "expected_policy": intended,
                                "observed": proof,
                            }
                        ),
                        native_severity="Medium",
                        native_confidence="high",
                        cwe_ids=[cwe],
                        provenance=Provenance(
                            "service-network",
                            str((directory / "network-service-observations.json").resolve()),
                            len(rows),
                            "live",
                        ),
                    )
                )
        except Exception as error:
            row.update(
                status="error", error=f"{type(error).__name__}: endpoint check did not complete"
            )
        rows.append(row)
    with (directory / "network-service-observations.json").open("x", encoding="utf-8") as stream:
        json.dump(
            {"target_ip": ip, "policy_sha256": policy["policy_sha256"], "observations": rows},
            stream,
            indent=2,
        )
    skipped = sum(row["status"] == "not_discovered_open" for row in rows)
    attempted = len(rows) - skipped
    partial = any(row["status"] != "observed" for row in rows)
    coverage = f"{'partial' if partial else 'complete'}: {attempted} owner-authorised endpoint checks attempted; {skipped} skipped because TCP endpoints were not recorded open; {len(findings)} observed policy violations; no lab answer-key matching, file-content persistence, commands or CVE inference"
    return findings, services, coverage


def guidance(finding):
    if finding.get("tool") != "service-network" or not str(
        finding.get("tool_native_id", "")
    ).startswith("policy:"):
        return None
    parts = str(finding["tool_native_id"]).split(":")
    if len(parts) != 4:
        return None
    service, condition = parts[1], parts[3]
    actions = {
        ("ftp", "authentication"): (
            "An anonymous FTP login was accepted where the owner requires authentication. This check did not list directories or read files.",
            "Disable anonymous login on this FTP endpoint and grant named accounts only the required directory permissions.",
            "Repeat anonymous login: expect an authentication rejection. Confirm a named authorised account still logs in. No file retrieval is required for this check.",
        ),
        ("smb", "authentication"): (
            "An anonymous client read the explicitly authorised proof file. Its byte count and hash were retained; this does not establish that sensitive shares are accessible.",
            "Remove guest/anonymous access from this share and apply named-account share and filesystem permissions.",
            "Repeat the same anonymous file read: expect access denied. Confirm an authorised account can read the intended file. A successful session alone is not an access-control pass or failure.",
        ),
        ("smb", "signing"): (
            "SMB negotiation reports that signing is optional. No relay, interception, credential theft or successful tampering was demonstrated.",
            "Require SMB signing in the server policy and compatible client policy; check client compatibility before applying the change.",
            "Repeat negotiation: expect signing_required=true. Confirm legitimate signed clients still connect. Authentication restrictions alone do not resolve optional signing.",
        ),
        ("ssh", "credential"): (
            "The one explicitly forbidden training credential was accepted. No commands, shell, forwarding or host compromise were demonstrated.",
            "Remove or rotate the designated training credential. Prefer authorised public keys and disable password login where operationally appropriate.",
            "Repeat only the designated credential test: expect rejection. Confirm the owner's approved key still authenticates. Do not broaden this into password guessing.",
        ),
        ("mqtt", "authentication"): (
            "An anonymous MQTT connection was accepted. Publish/subscribe permission is established only if message_exchange_confirmed=true in the retained proof; device control was not tested.",
            "Require broker authentication and restrict publish/subscribe ACLs to the exact topics each client needs. Configure verified TLS for clients crossing untrusted networks.",
            "Repeat anonymous CONNECT: expect refusal. Use an approved account to verify its permitted topic and confirm unauthorised topics are denied. The existing probe exchanges only a nonce on the owner-authorised topic.",
        ),
        ("snmp", "authentication"): (
            "A sysDescr value was returned to an SNMPv2c GET using the public community. This establishes a management-information read, not write access or device takeover.",
            "Disable the public community, restrict monitoring to approved source addresses and use SNMPv3 authPriv where supported.",
            "Repeat the public-community GET: expect no management value. Independently confirm authorised monitoring still works; silence alone does not distinguish filtering, rejection and an unavailable service.",
        ),
        ("tls", "certificate"): (
            "A real TLS handshake supplied a certificate whose expiry precedes the observation time. Expiry alone does not establish issuer trust, hostname validity or the absence of other certificate problems; see the separate certificate checks.",
            "Install a current certificate with the correct service identity and trusted chain, then configure renewal monitoring. Do not bypass certificate verification in production clients.",
            "Repeat expiry inspection and confirm expired=false. Separately connect using normal issuer and hostname verification and confirm legitimate clients succeed without verification bypasses.",
        ),
        ("tls", "hostname"): (
            "The inspected certificate does not match the configured service identity.",
            "Install a certificate that matches the intended service identity.",
            "Repeat the hostname check and confirm authorised clients connect using that identity.",
        ),
        ("tls", "chain"): (
            "A separate TLS connection failed certificate verification using the system trust store. The failing connection could not be bound to the inspected certificate and the verification failure may have several causes.",
            "Correct the certificate chain or validity problem and configure the appropriate trust anchors for clients.",
            "Repeat verification using the intended client trust store and service identity.",
        ),
    }
    action = actions.get((service, condition))
    if action is None:
        return None
    meaning, patch, verify = action
    return {
        "category": finding.get("title"),
        "meaning": meaning,
        "scenario": "A network client reproduced the retained service condition. It violates the recorded endpoint policy; wider impact requires separate evidence.",
        "prerequisites": [
            "Reachability to this endpoint and the recorded access or cryptographic policy."
        ],
        "impact": "The evidence establishes only the specific policy violation, not host compromise or sensitive-data theft.",
        "patch": [patch],
        "mitigations": [
            "Limit access to authorised clients while applying the configuration change."
        ],
        "verify": [verify],
        "example": None,
        "source": "Protocol observation plus explicit owner policy; not an AI-invented vulnerability.",
    }

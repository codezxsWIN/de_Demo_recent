"""Explicit endpoint/check authorisation and intended access policy, not an answer key."""

import ipaddress
import json
import re
from hashlib import sha256

from vulnassess.errors import ConfigError

FILENAME = "network-services.json"
SERVICES = {"ftp", "smb", "ssh", "mqtt", "snmp", "tls", "redis"}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("Duplicate network-service policy key")
        result[key] = value
    return result


def load(config_dir, scope, target_ip):
    path = config_dir / FILENAME
    if not path.exists():
        return None
    if path.stat().st_size > 65536:
        raise ConfigError("Network-service policy exceeds 64 KiB")
    try:
        raw = path.read_bytes()
        data = json.loads(raw, object_pairs_hook=_unique)
    except (OSError, ValueError) as error:
        raise ConfigError("Cannot read network-service policy") from error
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "targets"}
        or type(data["version"]) is not int
        or data["version"] != 1
        or not isinstance(data["targets"], dict)
    ):
        raise ConfigError("Network-service policy requires version 1 and exact-IP targets")
    if target_ip not in data["targets"]:
        return None
    for ip, entries in [(target_ip, data["targets"][target_ip])]:
        try:
            canonical = str(ipaddress.ip_address(ip))
        except ValueError as error:
            raise ConfigError("Network-service policy targets must be IP literals") from error
        if ip != canonical or not scope.contains(ip) or scope.is_canary(ip):
            raise ConfigError("Network-service policy target is not authorised by scope")
        if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
            raise ConfigError("Network-service policy requires 1 to 16 endpoints per target")
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) - {
                "port",
                "transport",
                "service",
                "require_auth",
                "require_signing",
                "require_unexpired_certificate",
                "require_valid_certificate_chain",
                "require_matching_hostname",
                "server_name",
                "publish_topic",
                "credential",
                "reject_test_credential",
                "monitoring_community",
                "share",
                "read_path",
            }:
                raise ConfigError("Unsupported network-service endpoint policy")
            service, port, transport = (
                entry.get("service"),
                entry.get("port"),
                entry.get("transport"),
            )
            if (
                not isinstance(service, str)
                or service not in SERVICES
                or type(port) is not int
                or not 1 <= port <= 65535
                or transport != ("udp" if service == "snmp" else "tcp")
            ):
                raise ConfigError("Invalid network-service endpoint identity")
            identity = (port, transport)
            if identity in seen:
                raise ConfigError("Duplicate network-service endpoint")
            seen.add(identity)
            controls = (
                "require_auth",
                "require_signing",
                "require_unexpired_certificate",
                "require_valid_certificate_chain",
                "require_matching_hostname",
            )
            for name in controls:
                if name in entry and type(entry[name]) is not bool:
                    raise ConfigError("Network-service policy controls must be booleans")
            allowed = {
                "ftp": {"require_auth"},
                "smb": {"require_auth", "require_signing"},
                "ssh": {"require_auth"},
                "mqtt": {"require_auth"},
                "snmp": {"require_auth"},
                "tls": {
                    "require_unexpired_certificate",
                    "require_valid_certificate_chain",
                    "require_matching_hostname",
                },
                "redis": set(),
            }[service]
            if any(name in entry and name not in allowed for name in controls):
                raise ConfigError("Control is not applicable to this protocol")
            if "server_name" in entry:
                name = entry["server_name"]
                if (
                    service != "tls"
                    or not isinstance(name, str)
                    or len(name) > 253
                    or not re.fullmatch(
                        r"(?=.{1,253}$)[A-Za-z0-9]+(?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9]+(?:[A-Za-z0-9-]*[A-Za-z0-9])?)*",
                        name,
                    )
                    or any(len(label) > 63 for label in name.split("."))
                ):
                    raise ConfigError("TLS server_name must be a DNS name")
            topic = entry.get("publish_topic")
            if topic is not None and (
                service != "mqtt"
                or not isinstance(topic, str)
                or not 1 <= len(topic.encode()) <= 128
                or re.search(r"[+#\x00-\x1f]", topic)
            ):
                raise ConfigError("MQTT verification requires one explicit non-wildcard topic")
            credential = entry.get("credential")
            share, read_path = entry.get("share"), entry.get("read_path")
            if share is not None or read_path is not None:
                if (
                    service != "smb"
                    or not isinstance(share, str)
                    or not re.fullmatch(r"[A-Za-z0-9_ -]{1,64}", share)
                    or not isinstance(read_path, str)
                    or not re.fullmatch(r"[A-Za-z0-9_. -]{1,128}", read_path)
                    or read_path in {".", ".."}
                ):
                    raise ConfigError(
                        "SMB reads require one explicit share and a single relative filename"
                    )
            if service == "smb" and entry.get("require_auth") is True and not share:
                raise ConfigError(
                    "SMB authentication policy needs an owner-authorised file read; anonymous session acceptance alone is insufficient"
                )
            community = entry.get("monitoring_community")
            if community is not None and (
                service != "snmp"
                or not ipaddress.ip_address(ip).is_loopback
                or not isinstance(community, str)
                or not 1 <= len(community) <= 64
                or re.search(r"[\x00-\x1f]", community)
            ):
                raise ConfigError(
                    "Fixed monitoring-community examples are allowed only on exact loopback SNMP endpoints"
                )
            if "reject_test_credential" in entry and (
                service != "ssh"
                or type(entry["reject_test_credential"]) is not bool
                or not credential
            ):
                raise ConfigError(
                    "SSH credential-rejection policy requires an explicit test credential"
                )
            if credential is not None:
                # Committed demonstration credentials may never be tried on non-loopback hosts.
                if (
                    service != "ssh"
                    or not ipaddress.ip_address(ip).is_loopback
                    or not isinstance(credential, dict)
                    or set(credential) != {"username", "password"}
                    or any(
                        not isinstance(value, str)
                        or not 1 <= len(value) <= 64
                        or re.search(r"[\x00-\x1f]", value)
                        for value in credential.values()
                    )
                ):
                    raise ConfigError(
                        "Fixed demonstration SSH credentials are permitted only on exact loopback endpoints"
                    )
    if target_ip not in data["targets"]:
        return None
    return {
        "target_ip": target_ip,
        "endpoints": data["targets"][target_ip],
        "policy_sha256": sha256(raw).hexdigest(),
    }

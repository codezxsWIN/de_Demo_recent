"""Read-only display of dated Docker lab verification, never a live-status claim."""

import hashlib
import json
import re
from datetime import datetime

from vulnassess.errors import ConfigError


def digest(document):
    content = {key: value for key, value in document.items() if key != "receipt_hash"}
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate(document):
    try:
        if (
            document["schema_version"] != 1
            or type(document["schema_version"]) is not int
            or document["receipt_hash"] != digest(document)
        ):
            raise ValueError("Receipt schema or integrity check failed")
        if document["status"] != "passed" or document["project"] != "vulnassess-service-networks":
            raise ValueError("No successful verification of the declared lab project")
        if datetime.fromisoformat(document["verified_at"]).tzinfo is None:
            raise ValueError("Verification time must include a timezone")
        servers, gateways = document["containers"], document["gateways"]
        if set(servers) != {"office", "iot"} or set(gateways) != {"office", "iot"}:
            raise ValueError("Both declared environments and gateways are required")
        namespaces = set()
        for name, ip, loopback in (
            ("office", "172.30.41.2", "127.0.0.2"),
            ("iot", "172.30.42.2", "127.0.0.3"),
        ):
            server, gateway = servers[name], gateways[name]
            if (
                server["private_ip"] != ip
                or server["health"] != "healthy"
                or server["read_only_rootfs"] is not True
            ):
                raise ValueError("Backend verification does not match declared environment")
            if any(server["published_ports"].values()) or gateway["ip_forward"] is not False:
                raise ValueError("Backend publishing or gateway forwarding contradicts isolation")
            for row in (server, gateway):
                if not re.fullmatch(r"[a-f0-9]{64}", row["id"]):
                    raise ValueError("Invalid retained container identity")
                namespace = row["runtime"]["network_namespace"]
                if type(namespace) is not int or namespace <= 0:
                    raise ValueError("Invalid retained network namespace")
                namespaces.add(namespace)
            if not gateway["published_ports"] or any(
                not bindings or any(p["HostIp"] != loopback for p in bindings)
                for bindings in gateway["published_ports"].values()
            ):
                raise ValueError("Gateway publishing is not restricted to its declared loopback")
        if len(namespaces) != 4:
            raise ValueError("Four distinct live-at-verification network namespaces are required")
        controls = document["client_controls"]
        if len(controls) != 2 or {row["client_segment"] for row in controls} != {"office", "iot"}:
            raise ValueError("Both paired segment controls are required")
        for row in controls:
            own = (
                ("172.30.41.2", 2121)
                if row["client_segment"] == "office"
                else ("172.30.42.2", 1883)
            )
            peer = (
                ("172.30.42.2", 1883)
                if row["client_segment"] == "office"
                else ("172.30.41.2", 2121)
            )
            if (row["positive_control"]["target"], row["positive_control"]["port"]) != own or (
                row["cross_segment_control"]["target"],
                row["cross_segment_control"]["port"],
            ) != peer:
                raise ValueError("Segment controls target an undeclared endpoint")
            if (
                row["positive_control"]["protocol_exchange_succeeded"] is not True
                or row["cross_segment_control"]["tcp_connected"] is not False
            ):
                raise ValueError("Paired segment controls did not pass")
        udp = next(row for row in controls if row["client_segment"] == "iot")[
            "udp_gateway_controls"
        ]
        if (
            udp["public_get_returned_value"] is not True
            or udp["protected_public_get_returned_value"] is not False
            or udp["protected_authorised_get_returned_value"] is not True
        ):
            raise ValueError("Paired SNMP gateway controls did not pass")
        return document
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        StopIteration,
        RecursionError,
    ) as error:
        raise ConfigError(
            "Container verification is missing, malformed or contradicts its recorded checks"
        ) from error


def load_latest(root):
    if not root.is_dir():
        return None
    if root.is_symlink():
        raise ConfigError("Container verification directory must not be a symbolic link")
    candidates = sorted(
        root.glob("container-verification-*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True
    )
    if not candidates:
        return None
    path = candidates[0]
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
        raise ConfigError("Container verification receipt is not a bounded local file")
    try:

        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Duplicate receipt key")
                value[key] = item
            return value

        document = validate(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique))
    except (OSError, ValueError, UnicodeError) as error:
        raise ConfigError("Container verification receipt cannot be read") from error
    return {**document, "filename": path.name}

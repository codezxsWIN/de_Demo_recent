"""Two exact lab-only reachability controls, executed from separate client containers.

Paired positive controls distinguish an unreachable peer from a stopped service.
This tests these TCP paths from these client namespaces; it is not a claim that
all protocols, all ports or container escapes have been assessed.
"""

import argparse
import asyncio
import ftplib
import json
import os
import socket
from pathlib import Path

TARGETS = {"office": ("172.30.41.2", 2121), "iot": ("172.30.42.2", 1883)}


async def udp_controls():
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )
    from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

    engine = SnmpEngine()
    try:
        outcomes = []
        for port, community in (
            (1161, "public"),
            (1162, "public"),
            (1162, "vulnassess-private-training-2026"),
        ):
            destination = await UdpTransportTarget.create(
                ("172.30.42.3", port), timeout=1, retries=0
            )
            indication, status, _, bindings = await get_cmd(
                engine,
                CommunityData(community, mpModel=1),
                destination,
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            )
            outcomes.append(
                bool(
                    not indication
                    and not status
                    and bindings
                    and str(bindings[0][0]) == "1.3.6.1.2.1.1.1.0"
                    and not isinstance(bindings[0][1], (NoSuchObject, NoSuchInstance, EndOfMibView))
                )
            )
        return {
            "gateway": "172.30.42.3",
            "public_get_returned_value": outcomes[0],
            "protected_public_get_returned_value": outcomes[1],
            "protected_authorised_get_returned_value": outcomes[2],
        }
    finally:
        engine.close_dispatcher()


def probe(environment):
    if not Path("/.dockerenv").is_file() or os.name != "posix":
        raise RuntimeError("Segmentation checks run only in the declared lab client containers")
    ip, port = TARGETS[environment]
    if environment == "office":
        with ftplib.FTP(timeout=3) as client:
            client.connect(ip, port)
            positive = client.login("anonymous", "assessment@example.invalid").startswith("230")
    else:
        with socket.create_connection((ip, port), timeout=3) as client:
            identity = b"segmentation-check"
            body = b"\x00\x04MQTT\x04\x02\x00\x0a" + len(identity).to_bytes(2) + identity
            client.sendall(b"\x10" + bytes([len(body)]) + body)
            response = bytearray()
            while len(response) < 4:
                chunk = client.recv(4 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
            positive = bytes(response) == b"\x20\x02\x00\x00"
            client.sendall(b"\xe0\x00")
    peer = "iot" if environment == "office" else "office"
    peer_ip, peer_port = TARGETS[peer]
    error = None
    try:
        with socket.create_connection((peer_ip, peer_port), timeout=3):
            cross_segment = True
    except OSError as exc:
        cross_segment = False
        error = type(exc).__name__
    result = {
        "client_segment": environment,
        "client_network_namespace": os.stat("/proc/self/ns/net").st_ino,
        "positive_control": {"target": ip, "port": port, "protocol_exchange_succeeded": positive},
        "cross_segment_control": {
            "target": peer_ip,
            "port": peer_port,
            "tcp_connected": cross_segment,
            "error_type": error,
        },
        "boundary": "Paired real protocol/TCP tests of these exact paths, not a complete firewall or host-isolation audit.",
    }
    if environment == "iot":
        result["udp_gateway_controls"] = asyncio.run(udp_controls())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", choices=tuple(TARGETS))
    args = parser.parse_args()
    result = probe(args.environment)
    print(json.dumps(result), flush=True)
    udp = result.get("udp_gateway_controls")
    udp_failed = udp and (
        not udp["public_get_returned_value"]
        or udp["protected_public_get_returned_value"]
        or not udp["protected_authorised_get_returned_value"]
    )
    raise SystemExit(
        int(
            not result["positive_control"]["protocol_exchange_succeeded"]
            or result["cross_segment_control"]["tcp_connected"]
            or bool(udp_failed)
        )
    )

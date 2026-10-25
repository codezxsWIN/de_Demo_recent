"""Fixed read-only protocol checks after validating the exact local registry."""

import argparse
import json
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

from .servers import CACHE_VALUE, ENVIRONMENTS, HOST, LAB_ID, REGISTERS, SMTP_USER

BASE = "http://127.0.0.1:8800/"


def exact(stream, count):
    value = stream.read(count)
    if len(value) != count:
        raise ValueError("Incomplete protocol frame")
    return value


def exchange(protocol, port):
    with socket.create_connection((HOST, port), timeout=2) as connection:
        connection.settimeout(2)
        with connection.makefile("rb") as stream:
            if protocol == "smtp":
                greeting = stream.readline(513)
                if not greeting.startswith(b"220 network-lab.local "):
                    raise ValueError("Unexpected SMTP identity")
                request = b"VRFY training@example.invalid\r\n"
                connection.sendall(request)
                response = stream.readline(513)
            elif protocol == "memcached":
                request = b"get fixture:shipment\r\n"
                connection.sendall(request)
                response = stream.readline(513)
                if response.startswith(b"VALUE "):
                    response += stream.readline(513) + stream.readline(513)
            elif protocol == "modbus":
                request = bytes.fromhex("000100000006010300000002")
                connection.sendall(request)
                header = exact(stream, 7)
                transaction, protocol_id, length, unit = struct.unpack(">HHHB", header)
                if (transaction, protocol_id, unit) != (1, 0, 1) or not 2 <= length <= 16:
                    raise ValueError("Unexpected Modbus transaction")
                response = header + exact(stream, length - 1)
            else:
                raise ValueError("Unsupported fixed lab protocol")
    return {
        "port": port,
        "request_hex": request.hex(),
        "response_hex": response.hex(),
        "response_text": response.decode("ascii", errors="replace"),
    }


def observed(protocol, response, protected=False):
    raw = bytes.fromhex(response["response_hex"])
    if protocol == "smtp":
        return raw == (b"550 Verification disabled\r\n" if protected else SMTP_USER)
    if protocol == "memcached":
        return raw == (
            b"END\r\n"
            if protected
            else b"VALUE fixture:shipment 0 "
            + str(len(CACHE_VALUE)).encode()
            + b"\r\n"
            + CACHE_VALUE
            + b"\r\nEND\r\n"
        )
    expected = b"\x83\x02" if protected else b"\x03\x04" + struct.pack(">HH", *REGISTERS)
    return raw[7:] == expected


def verify():
    with build_opener(ProxyHandler({})).open(BASE + "__lab__/health", timeout=2) as response:
        identity = json.loads(response.read(16385))
    if (
        identity.get("lab_id") != LAB_ID
        or identity.get("binding") != HOST
        or identity.get("fixtures_only") is not True
        or identity.get("environments") != list(ENVIRONMENTS)
    ):
        raise ValueError("Local network lab identity mismatch; no protocol probes sent")
    checks = []
    for item in ENVIRONMENTS:
        row = {
            "id": item["id"],
            "protocol": item["protocol"],
            "port": item["port"],
            "observed": False,
            "control_passed": False,
        }
        # Independent sides: a failed comparison must not erase observed proof.
        for key in ("port", "control"):
            try:
                proof = exchange(item["protocol"], item[key])
                row[key + "_evidence"] = proof
                row["control_passed" if key == "control" else "observed"] = observed(
                    item["protocol"], proof, protected=key == "control"
                )
            except (OSError, ValueError) as error:
                row[key + "_error"] = type(error).__name__ + ": " + str(error)[:160]
        checks.append(row)
    return {
        "lab_id": LAB_ID,
        "target": BASE,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "boundary": "Loopback fictional protocol services; not OS or vendor CVE verification",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        receipt = verify()
        json.dump(receipt, handle, indent=2)
    print(
        json.dumps(
            {
                "observed": sum(row["observed"] for row in receipt["checks"]),
                "controls_passed": sum(row["control_passed"] for row in receipt["checks"]),
                "receipt": str(args.output),
            }
        )
    )

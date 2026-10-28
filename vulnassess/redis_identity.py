"""One bounded INFO server exchange; no data keys, scripting or exploit requests."""

import hashlib
import re
import socket
import time


def probe(ip, entry):
    request = b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"
    with socket.create_connection((ip, entry["port"]), timeout=4) as wire:
        deadline = time.monotonic() + 4
        wire.sendall(request)

        def receive(size):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Redis identity deadline exceeded")
            wire.settimeout(remaining)
            data = wire.recv(size)
            if not data:
                raise ValueError("Truncated Redis INFO response")
            return data

        line = bytearray()
        while not line.endswith(b"\r\n"):
            if len(line) >= 128:
                raise ValueError("Redis INFO header exceeds its budget")
            line.extend(receive(1))
        if line.startswith(b"-NOAUTH") or line.startswith(b"-NOPERM"):
            return {
                "protocol_confirmed": True,
                "identity_established": False,
                "reason": "INFO server requires an approved authenticated inventory path",
            }
        if not re.fullmatch(rb"\$[0-9]{1,5}\r\n", line):
            raise ValueError("Redis INFO did not return a bounded RESP bulk string")
        length = int(line[1:-2])
        if not 1 <= length <= 16384:
            raise ValueError("Redis INFO response exceeds the identity budget")
        body = bytearray()
        while len(body) < length + 2:
            body.extend(receive(length + 2 - len(body)))
        if not body.endswith(b"\r\n"):
            raise ValueError("Truncated Redis INFO response")
    versions = re.findall(rb"(?m)^redis_version:([0-9]+\.[0-9]+\.[0-9]+)\r?$", body[:-2])
    if len(versions) != 1:
        raise ValueError("Redis INFO returned no unambiguous version")
    version = versions[0].decode("ascii")
    return {
        "protocol_confirmed": True,
        "identity_established": True,
        "redis_version": version,
        "cpe": f"cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*",
        "request": "INFO server",
        "response_sha256": hashlib.sha256(body[:-2]).hexdigest(),
        "retained_fields": ["redis_version"],
        "data_keys_read": False,
        "note": "Reported upstream version only; distribution, package revision and backported fixes are not established",
    }

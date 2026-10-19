"""Fixed Lua-environment inspection; never loads libraries or executes OS commands."""

import json
import socket
import time
from ipaddress import ip_address
from pathlib import Path

from vulnassess.errors import ScopeError
from vulnassess.schema import Finding, Provenance

# One constant expression, no keys, no redis.call, no loadlib invocation.
REQUEST = b"EVAL \"return type(package)..':'..type(package and package.loadlib)\" 0\r\n"
POSITIVE = b"$14\r\ntable:function\r\n"


def run(scope, target_ip: str, port: int, directory: Path) -> Finding | None:
    ip_address(target_ip)  # Never resolve an unpinned hostname here.
    if (
        not scope.contains(target_ip)
        or scope.is_canary(target_ip)
        or scope.tags(target_ip).get("environment") != "test"
    ):
        raise ScopeError("Redis inspection requires an authorized test asset")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ScopeError("Redis inspection port is invalid")
    response = b""
    deadline = time.monotonic() + 10
    with socket.create_connection((target_ip, port), timeout=5) as connection:
        connection.sendall(REQUEST)
        while len(response) < 4096:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Redis inspection deadline exceeded")
            connection.settimeout(min(5, remaining))
            part = connection.recv(4096 - len(response))
            if not part:
                break
            response += part
            if response.endswith(b"\r\n") and (
                response.startswith(b"-") or response.count(b"\r\n") >= 2
            ):
                break
    capture = Path(directory) / "redis-lua-check.json"
    with capture.open("x", encoding="utf-8") as handle:
        json.dump(
            {
                "target_ip": target_ip,
                "port": port,
                "check": "lua-package-type-v1",
                "request": REQUEST.decode("ascii"),
                "response": response.decode("utf-8", errors="replace"),
            },
            handle,
        )
    if response != POSITIVE:
        return None
    return Finding.make(
        host_ip=target_ip,
        port=port,
        protocol="tcp",
        tool="redis-check",
        tool_native_id="lua-package-type-v1",
        title="Redis Lua package.loadlib exposed (CVE-2022-0543)",
        description="The Lua sandbox exposes package.loadlib, the vulnerable configuration associated with CVE-2022-0543. OS command execution was not attempted.",
        evidence="Fixed EVAL type inspection returned table:function for package and package.loadlib; no keys accessed, library loaded, or OS command executed.",
        cve_ids=["CVE-2022-0543"],
        native_confidence="high",
        reference_urls=["https://www.debian.org/security/2022/dsa-5081"],
        provenance=Provenance(
            tool="redis-check", raw_path=str(capture), record_index=1, run_id="live"
        ),
    )

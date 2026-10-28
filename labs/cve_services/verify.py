"""Finite Docker/RESP proof for exactly 127.0.0.4:6379 and 127.0.0.5:6379.

From the repository root (prepend the Docker binary directory to PATH):
  .venv-network-labs/Scripts/python.exe labs/cve_services/verify.py --start
  .venv-network-labs/Scripts/python.exe labs/cve_services/verify.py

--start preflights conflicts, pulls only pinned project images, then starts this
Compose project. It refuses an existing project; use the second command to
verify it. No scanner integration is performed. The ignored JSON receipt keeps
actual observations separate from evaluation ground truth. To stop this pair:
  docker compose -f labs/cve_services/compose.yaml -p vulnassess-cve-services down
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROJECT = "vulnassess-cve-services"
ENDPOINTS = {"affected": ("127.0.0.4", 6379), "patched": ("127.0.0.5", 6379)}
IMAGES = {
    "affected": "redis:7.0.11@sha256:1008c73f08e9f913868e2fa2e843212b62ea5bf3c66435d87bc7a6207bc0f1b4",
    "patched": "redis:7.0.12@sha256:a030024d2b65447fba04de1e3b440226d78dfe6e4fbc8ab0ca9a44ca6eed0acd",
}
FORWARDER_IMAGE = (
    "alpine/socat:1.8.0.3@sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e"
)
SERVICE_IMAGES = {**IMAGES, **{role + "-ingress": FORWARDER_IMAGE for role in ENDPOINTS}}
RECEIPT = ROOT / "data/service-networks/cve-services-verification.json"
ALLOWED_COMMANDS = (("PING",), ("INFO", "server"))
MAX_REPLY = 16384


def require(condition, message):
    if not condition:
        raise ValueError(message)


def docker(*args, timeout=30):
    executable = shutil.which("docker")
    if not executable:
        raise RuntimeError("docker missing from PATH; prepend the Docker Desktop bin directory")
    try:
        result = subprocess.run(
            [executable, *args], capture_output=True, text=True, timeout=timeout, check=True
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Docker command failed: {exc.stderr or exc.stdout}") from exc
    return result.stdout


def compose(*args, timeout=30):
    return docker(
        "compose", "-f", str(HERE / "compose.yaml"), "-p", PROJECT, *args, timeout=timeout
    )


def preflight():
    """Inspect metadata globally; bind only the two authorized endpoints, no scans."""
    require(
        not docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}").strip(),
        "Project containers already exist; run verification without --start",
    )
    require(
        not docker(
            "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}"
        ).strip(),
        "Project network already exists; inspect it before starting",
    )
    ids = docker("ps", "-aq").split()
    if ids:
        for container in json.loads(docker("inspect", *ids)):
            for bindings in (container["HostConfig"].get("PortBindings") or {}).values():
                for binding in bindings or []:
                    conflict = any(
                        binding.get("HostPort") == str(port)
                        and binding.get("HostIp", "") in {"", "0.0.0.0", "::", address}
                        for address, port in ENDPOINTS.values()
                    )
                    require(not conflict, f"Docker port reservation conflicts: {container['Name']}")
    held = []
    try:
        for address, port in ENDPOINTS.values():
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(listener)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind((address, port))
    finally:
        for listener in held:
            listener.close()


def request(host, port, command):
    """Only two fixed, harmless commands; bounded time, bulk length and reads."""
    require((host, port) in ENDPOINTS.values(), "Endpoint outside authorized pair")
    require(tuple(command) in ALLOWED_COMMANDS, "Command outside read-only probe policy")
    wire = f"*{len(command)}\r\n".encode("ascii")
    for part in command:
        value = part.encode("ascii")
        wire += f"${len(value)}\r\n".encode("ascii") + value + b"\r\n"
    with socket.create_connection((host, port), timeout=3) as connection:
        deadline = time.monotonic() + 3
        connection.sendall(wire)

        def receive(size):
            remaining = deadline - time.monotonic()
            require(remaining > 0, "RESP deadline exceeded")
            connection.settimeout(remaining)
            chunk = connection.recv(size)
            require(bool(chunk), "Truncated RESP response")
            return chunk

        header = b""
        while not header.endswith(b"\r\n"):
            require(len(header) < 128, "RESP header exceeds bound")
            header += receive(1)
        if header.startswith(b"+"):
            return {
                "command": list(command),
                "resp_type": "simple",
                "response": header[1:-2].decode("ascii"),
            }
        require(header.startswith(b"$"), f"Unexpected RESP response: {header!r}")
        length = int(header[1:-2])
        require(0 <= length <= MAX_REPLY, "RESP bulk response exceeds bound")
        payload = b""
        while len(payload) < length + 2:
            payload += receive(length + 2 - len(payload))
        require(payload.endswith(b"\r\n"), "Truncated RESP bulk")
        return {
            "command": list(command),
            "resp_type": "bulk",
            "response": payload[:-2].decode("ascii"),
        }


def validate_container(container, role):
    """Fail closed before opening any service socket when isolation has drifted."""
    config, host = container["Config"], container["HostConfig"]
    forwarder = role.endswith("-ingress")
    backend = role.removesuffix("-ingress")
    labels = config.get("Labels") or {}
    require(labels.get("com.docker.compose.project") == PROJECT, "Wrong project")
    require(labels.get("com.docker.compose.service") == role, "Wrong service")
    require(config["Image"] == SERVICE_IMAGES[role], "Image reference differs from pin")
    require(config.get("User") == "10001:10001", "Container must run nonroot")
    require(
        config.get("Entrypoint") == ["socat" if forwarder else "redis-server"],
        "Unexpected entrypoint",
    )
    require(host.get("ReadonlyRootfs") is True, "Rootfs must be read-only")
    require(
        host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"), "Capabilities must be dropped"
    )
    require("no-new-privileges:true" in host.get("SecurityOpt", []), "Missing no-new-privileges")
    require(not host.get("Privileged"), "Privileged mode forbidden")
    require(not host.get("Binds") and not host.get("Mounts"), "Host mounts forbidden")
    require(
        not host.get("VolumesFrom") and not host.get("Devices") and not host.get("DeviceRequests"),
        "Shared volumes/devices forbidden",
    )
    require(
        host.get("PidMode", "") in {"", "private"} and host.get("IpcMode") == "private",
        "Shared host namespaces forbidden",
    )
    require(not host.get("PublishAllPorts"), "Automatic port publishing forbidden")
    require(not container.get("Mounts"), "Persistent/host mounts forbidden")
    require(host.get("Memory") == (32 if forwarder else 96) * 1024**2, "Memory bound drift")
    require(host.get("MemorySwap") == host["Memory"], "Swap bound drift")
    require(host.get("PidsLimit") == (16 if forwarder else 32), "PID bound drift")
    require(host.get("NanoCpus") == (250_000_000 if forwarder else 500_000_000), "CPU bound drift")
    tmpfs = (
        {}
        if forwarder
        else {"/data": "rw,nosuid,nodev,noexec,uid=10001,gid=10001,mode=0700,size=8m"}
    )
    require((host.get("Tmpfs") or {}) == tmpfs, "Only bounded /data tmpfs is allowed")
    address, port = ENDPOINTS[backend]
    expected_ports = {"6379/tcp": [{"HostIp": address, "HostPort": str(port)}]} if forwarder else {}
    require((host.get("PortBindings") or {}) == expected_ports, "Unexpected host port publication")
    actual_ports = {
        key: value
        for key, value in (container["NetworkSettings"].get("Ports") or {}).items()
        if value
    }
    require(actual_ports == expected_ports, "Actual port mapping drift")
    networks = {f"{PROJECT}_pair"} | ({f"{PROJECT}_ingress"} if forwarder else set())
    require(host.get("NetworkMode") in networks, "Unexpected network mode")
    require(set(container["NetworkSettings"]["Networks"]) == networks, "Extra network")
    if forwarder:
        require(
            host.get("Sysctls") == {"net.ipv4.ip_forward": "0"}, "IP forwarding must be disabled"
        )
    require(container["State"].get("Running") is True, "Container is not running")
    if not forwarder:
        require(
            container["State"].get("Health", {}).get("Status") == "healthy",
            "Container is unhealthy",
        )
    # Compare the actual command line, including deny-by-default ACL, with Compose.
    expected = yaml.safe_load((HERE / "compose.yaml").read_text())["services"][role]["command"]
    require(config.get("Cmd") == expected, "Redis configuration / ACL command line drift")


def verify():
    ids = compose("ps", "-aq").split()
    require(len(ids) == 4, "Expected two Redis containers and two fixed ingress forwarders")
    containers = json.loads(docker("inspect", *ids))
    observations = {}
    for container in containers:
        role = (container["Config"].get("Labels") or {}).get("com.docker.compose.service")
        require(role in SERVICE_IMAGES and role not in observations, "Unexpected/duplicate service")
        validate_container(container, role)
        observations[role] = {"docker_inspect": container}
    network = json.loads(docker("network", "inspect", f"{PROJECT}_pair"))[0]
    require(
        network.get("Internal") is True and not network.get("Attachable"), "Network isolation drift"
    )
    require(network.get("Driver") == "bridge", "Unexpected network driver")
    require(
        (network.get("Labels") or {}).get("com.docker.compose.project") == PROJECT,
        "Foreign network",
    )
    require(
        set(network.get("Containers", {})) == {c["Id"] for c in containers},
        "Foreign network member",
    )
    ingress = json.loads(docker("network", "inspect", f"{PROJECT}_ingress"))[0]
    require(not ingress.get("Internal") and not ingress.get("Attachable"), "Ingress topology drift")
    require(ingress.get("Driver") == "bridge", "Unexpected ingress driver")
    require(
        (ingress.get("Labels") or {}).get("com.docker.compose.project") == PROJECT,
        "Foreign ingress",
    )
    require(
        (ingress.get("Options") or {}).get("com.docker.network.bridge.enable_icc") == "false",
        "Ingress ICC drift",
    )
    require(
        set(ingress.get("Containers", {}))
        == {observations[r + "-ingress"]["docker_inspect"]["Id"] for r in ENDPOINTS},
        "Unexpected ingress network member",
    )
    for role, observation in observations.items():
        image = json.loads(docker("image", "inspect", SERVICE_IMAGES[role]))[0]
        require(
            image["Id"] == observation["docker_inspect"]["Image"], "Running image differs from pin"
        )
        digest = SERVICE_IMAGES[role].split("@", 1)[1]
        require(
            any(d.endswith("@" + digest) for d in image.get("RepoDigests", [])),
            "Missing registry digest",
        )
        require(
            image.get("Architecture") == "amd64" and image.get("Os") == "linux",
            "Wrong image platform",
        )
        observation["docker_image_inspect"] = image
        if role not in ENDPOINTS:
            continue
        address, port = ENDPOINTS[role]
        observation.update({"host": address, "port": port})
        ping = request(address, port, ("PING",))
        require(ping["response"] == "PONG", "PING did not return PONG")
        info = request(address, port, ("INFO", "server"))
        require(info["resp_type"] == "bulk", "INFO must be a real RESP bulk response")
        fields = dict(
            line.split(":", 1)
            for line in info["response"].splitlines()
            if line and not line.startswith("#") and ":" in line
        )
        require("redis_version" in fields and "run_id" in fields, "Missing Redis server identity")
        observation.update(
            {"ping": ping, "info_server": info, "redis_version": fields["redis_version"]}
        )
    evaluation = json.loads((HERE / "evaluation.json").read_text())
    evaluation["version_pair_matches"] = all(
        observations[role]["redis_version"] == version
        for role, version in evaluation["expected_versions"].items()
    )
    require(
        evaluation["version_pair_matches"],
        "Actual version pair differs from evaluation expectations",
    )
    return {
        "schema_version": 1,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "project": PROJECT,
        "observations": observations,
        "docker_network_inspect": network,
        "docker_ingress_network_inspect": ingress,
        "evaluation_ground_truth_only": evaluation,
        "verification": "passed",
    }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--start", action="store_true", help="Preflight, pull and start only this pair"
    )
    args = parser.parse_args()
    if args.start:
        preflight()
        compose("pull", timeout=180)
        compose("up", "-d", "--pull", "never", "--wait", "--wait-timeout", "60", timeout=90)
    receipt = verify()
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "verification": receipt["verification"],
                "receipt": str(RECEIPT),
                "versions": {
                    k: v["redis_version"]
                    for k, v in receipt["observations"].items()
                    if k in ENDPOINTS
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

"""Verify the running service deployment and retain exact isolation receipts.

Start with: docker compose -f labs/service_networks/compose.yaml up --build -d --wait
This verification runs two short-lived clients on the declared internal networks.
It never starts/stops HarborDesk, changes Windows firewall rules or scans external IPs.
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import mkstemp

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
COMPOSE = ROOT / "labs/service_networks/compose.yaml"
PROJECT = "vulnassess-service-networks"


def executable():
    found = shutil.which("docker")
    if found:
        return Path(found)
    candidate = (
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
    )
    if candidate.is_file():
        return candidate
    raise RuntimeError("MISSING: Docker CLI; install Docker Desktop and start its Linux engine")


def verify(docker):
    environment = dict(os.environ)
    environment["PATH"] = str(docker.parent) + os.pathsep + environment.get("PATH", "")

    def run(*arguments):
        result = subprocess.run(
            [str(docker), *arguments],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        if result.returncode:
            raise RuntimeError(
                f"Docker operation {arguments[0]} failed: {result.stderr.strip()[:300]}"
            )
        return result.stdout.strip()

    def compose(*arguments):
        return run("compose", "-f", str(COMPOSE), *arguments)

    def inspect_container(name):
        identifier = compose("ps", "-q", name)
        if not identifier or "\n" in identifier:
            raise RuntimeError(f"MISSING: one running {name} container in {PROJECT}")
        item = json.loads(run("inspect", identifier))[0]
        host, config = item["HostConfig"], item["Config"]
        if config.get("Labels", {}).get("com.docker.compose.project") != PROJECT:
            raise RuntimeError("Refusing an unrelated Docker project")
        if (
            not item["State"]["Running"]
            or item["State"].get("Health", {}).get("Status") != "healthy"
        ):
            raise RuntimeError(f"{name} container is not healthy")
        if (
            config["User"] != "10001:10001"
            or not host["ReadonlyRootfs"]
            or host["Privileged"]
            or "ALL" not in host["CapDrop"]
            or "no-new-privileges:true" not in host["SecurityOpt"]
            or item.get("Mounts")
            or host.get("NetworkMode") == "host"
            or host.get("PidMode") == "host"
            or host.get("IpcMode") == "host"
        ):
            raise RuntimeError(f"{name} does not meet the declared runtime isolation policy")
        ready = json.loads(run("exec", identifier, "cat", "/runtime/ready.json"))
        if ready["environment"] != name:
            raise RuntimeError("Container environment receipt does not match deployment")
        return item, ready

    from labs.cve_services import verify as redis_probe

    redis_probe.ENDPOINTS = {"office": ("127.0.0.2", 6379), "iot": ("127.0.0.3", 6379)}
    declared = __import__("yaml").safe_load(COMPOSE.read_text(encoding="utf-8"))
    rows, networks, gateways, redis_rows = {}, {}, {}, {}
    for name in ("office", "iot"):
        item, ready = inspect_container(name)
        host, config = item["HostConfig"], item["Config"]
        ports = item["NetworkSettings"]["Ports"]
        if any(bindings for bindings in ports.values()):
            raise RuntimeError(f"{name} backend must not publish ports directly")
        joined = item["NetworkSettings"]["Networks"]
        if len(joined) != 1:
            raise RuntimeError(f"{name} must join exactly one segment")
        network_name, membership = next(iter(joined.items()))
        if network_name != f"{PROJECT}_{name}":
            raise RuntimeError("Unexpected segment name")
        network = json.loads(run("network", "inspect", network_name))[0]
        expected_ip = "172.30.41.2" if name == "office" else "172.30.42.2"
        if not network["Internal"] or membership["IPAddress"] != expected_ip:
            raise RuntimeError(f"{name} is not on its declared internal IP/segment")
        networks[name] = network_name
        rows[name] = {
            "id": item["Id"],
            "image_id": item["Image"],
            "network_id": network["Id"],
            "private_ip": expected_ip,
            "published_ports": ports,
            "user": config["User"],
            "read_only_rootfs": True,
            "capabilities_dropped": host["CapDrop"],
            "memory_limit_bytes": host["Memory"],
            "pid_limit": host["PidsLimit"],
            "health": "healthy",
            "runtime": ready,
        }
        gateway, gateway_ready = inspect_container(name + "-gateway")
        expected_host = "127.0.0.2" if name == "office" else "127.0.0.3"
        published = gateway["NetworkSettings"]["Ports"]
        expected_ports = (
            {f"{p}/tcp" for p in (2121, 2122, 2222, 2223, 1445, 1446, 6379, *range(32200, 32210))}
            if name == "office"
            else {"1883/tcp", "1884/tcp", "8883/tcp", "6379/tcp", "1161/udp", "1162/udp"}
        )
        if set(published) != expected_ports or any(
            not bindings
            or any(
                p["HostIp"] != expected_host or int(p["HostPort"]) != int(port.split("/")[0])
                for p in bindings
            )
            for port, bindings in published.items()
        ):
            raise RuntimeError(f"{name} gateway has unexpected or non-loopback publishing")
        gateway_networks = gateway["NetworkSettings"]["Networks"]
        ingress_name = f"{PROJECT}_{name}-ingress"
        if set(gateway_networks) != {network_name, ingress_name}:
            raise RuntimeError("Gateway joins an unexpected segment")
        ingress = json.loads(run("network", "inspect", ingress_name))[0]
        if (
            ingress["Internal"]
            or gateway["HostConfig"].get("Sysctls", {}).get("net.ipv4.ip_forward") != "0"
            or gateway_ready["ip_forward"] != "0"
        ):
            raise RuntimeError("Gateway must use dedicated ingress with IP forwarding disabled")
        gateways[name] = {
            "id": gateway["Id"],
            "image_id": gateway["Image"],
            "published_ports": published,
            "ip_forward": False,
            "ingress_network_id": ingress["Id"],
            "runtime": gateway_ready,
        }
        redis_id = compose("ps", "-q", name + "-redis")
        if not redis_id or "\n" in redis_id:
            raise RuntimeError(f"Expected one {name} Redis container")
        redis = json.loads(run("inspect", redis_id))[0]
        redis_config, redis_host = redis["Config"], redis["HostConfig"]
        redis_networks = redis["NetworkSettings"]["Networks"]
        spec = declared["services"][name + "-redis"]
        if (
            redis_config.get("Labels", {}).get("com.docker.compose.project") != PROJECT
            or redis_config.get("Image") != spec["image"]
            or redis_config.get("Cmd") != spec["command"]
            or redis_config.get("Entrypoint") != ["redis-server"]
            or redis_config.get("User") != "10001:10001"
            or not redis_host.get("ReadonlyRootfs")
            or redis_host.get("Privileged")
            or "ALL" not in (redis_host.get("CapDrop") or [])
            or "no-new-privileges:true" not in (redis_host.get("SecurityOpt") or [])
            or redis.get("Mounts")
            or any((redis["NetworkSettings"].get("Ports") or {}).values())
            or set(redis_networks) != {network_name}
            or redis_networks[network_name]["IPAddress"] != ("172.30.41.4" if name == "office" else "172.30.42.4")
            or not redis["State"].get("Running")
            or redis["State"].get("Health", {}).get("Status") != "healthy"
        ):
            raise RuntimeError(f"{name} Redis isolation or configuration drift")
        ping = redis_probe.request(expected_host, 6379, ("PING",))
        info = redis_probe.request(expected_host, 6379, ("INFO", "server"))
        version = "7.0.11" if name == "office" else "7.0.12"
        if ping["response"] != "PONG" or f"redis_version:{version}" not in info["response"].splitlines():
            raise RuntimeError(f"{name} Redis endpoint did not return its expected identity")
        denied = run("exec", redis_id, "redis-cli", "--raw", "SET", "verification", "forbidden")
        if "NOPERM" not in denied:
            raise RuntimeError(f"{name} Redis ACL did not deny writes")
        redis_rows[name] = {"id": redis_id, "image": spec["image"], "version": version, "ping": ping, "info_server": info, "write_denied": True}
    if rows["office"]["network_id"] == rows["iot"]["network_id"]:
        raise RuntimeError("Office and IoT incorrectly share a Docker network")
    namespaces = {row["runtime"]["network_namespace"] for row in rows.values()}
    if len(namespaces) != 2:
        raise RuntimeError("Office and IoT incorrectly share a network namespace")
    namespaces.update(row["runtime"]["network_namespace"] for row in gateways.values())
    if len(namespaces) != 4:
        raise RuntimeError("Each backend and gateway must have a distinct network namespace")
    clients = []
    for name in ("office", "iot"):
        # Immutable image ID, not a mutable tag. No mounts, ports or host namespaces.
        result = json.loads(
            run(
                "run",
                "--rm",
                "--network",
                networks[name],
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                "10001:10001",
                "--memory",
                "128m",
                "--pids-limit",
                "32",
                "--entrypoint",
                "python",
                rows[name]["image_id"],
                "-m",
                "labs.service_networks.segmentation",
                name,
            )
        )
        if (
            not result["positive_control"]["protocol_exchange_succeeded"]
            or result["cross_segment_control"]["tcp_connected"]
            or result["client_network_namespace"] in namespaces
        ):
            raise RuntimeError(f"{name} did not pass paired protocol/segmentation controls")
        clients.append(result)
        if name == "iot":
            udp = result.get("udp_gateway_controls", {})
            if (
                udp.get("public_get_returned_value") is not True
                or udp.get("protected_public_get_returned_value") is not False
                or udp.get("protected_authorised_get_returned_value") is not True
            ):
                raise RuntimeError("IoT UDP gateway did not pass its paired SNMP controls")
    # Confirm both services stayed running after the paired negative controls.
    for row in [*rows.values(), *gateways.values(), *redis_rows.values()]:
        if run("inspect", "--format", "{{.State.Running}}", row["id"]) != "true":
            raise RuntimeError("A positive-control server stopped during verification")
    return {
        "verified_at": datetime.now(UTC).isoformat(),
        "project": PROJECT,
        "containers": rows,
        "gateways": gateways,
        "redis": redis_rows,
        "client_controls": clients,
        "status": "passed",
        "boundary": "Distinct container network namespaces and internal bridges; paired TCP reachability controls only. Containers share the Docker/WSL Linux kernel, not separate OS kernels. No complete escape or firewall audit is claimed.",
    }


def main():
    from vulnassess.service_network_deployment import digest, validate

    result = verify(executable())
    result["schema_version"] = 1
    result["receipt_hash"] = digest(result)
    validate(result)
    destination = ROOT / "data/service-networks"
    destination.mkdir(parents=True, exist_ok=True)
    fd, path = mkstemp(prefix="container-verification-", suffix=".json", dir=destination)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(
        json.dumps(
            {
                "status": result["status"],
                "receipt": path,
                "client_controls": result["client_controls"],
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Container verification failed: {error}") from None

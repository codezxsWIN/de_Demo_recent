"""Offline boundary tests. Run labs/cve_services/verify.py for real Docker/RESP proof.
No test starts containers or sends exploit commands.
"""

import copy
import json
from unittest.mock import Mock

import pytest
import yaml

from labs.cve_services import verify as lab


@pytest.fixture
def deployment():
    return yaml.safe_load((lab.HERE / "compose.yaml").read_text())


def test_exact_publications_and_private_redis_pair(deployment):
    services = deployment["services"]
    assert set(services) == {"affected", "patched", "affected-ingress", "patched-ingress"}
    publications = {
        name: service["ports"] for name, service in services.items() if "ports" in service
    }
    assert publications == {
        "affected-ingress": ["127.0.0.4:6379:6379/tcp"],
        "patched-ingress": ["127.0.0.5:6379:6379/tcp"],
    }
    assert deployment["name"] == lab.PROJECT
    assert set(deployment["networks"]) == {"pair", "ingress"}
    assert deployment["networks"]["pair"]["internal"] is True
    for role in ("affected", "patched"):
        assert services[role]["networks"] == ["pair"]
        assert services[role]["entrypoint"] == ["redis-server"]
        assert services[role]["image"] == lab.IMAGES[role]
    for role in lab.ENDPOINTS:
        ingress = services[role + "-ingress"]
        assert ingress["command"] == [
            "-T",
            "5",
            "TCP4-LISTEN:6379,reuseaddr,fork,max-children=8",
            f"TCP4:{role}:6379,connect-timeout=2",
        ]
        assert ingress["entrypoint"] == ["socat"]
        assert ingress["networks"] == ["pair", "ingress"]
        assert ingress["sysctls"] == {"net.ipv4.ip_forward": "0"}


def test_every_container_is_bounded_unprivileged_and_mount_free(deployment):
    for service in deployment["services"].values():
        assert service["user"] == "10001:10001"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["platform"] == "linux/amd64"
        assert "@sha256:" in service["image"]
        assert len(service["image"].rsplit(":", 1)[1]) == 64
        assert 0 < service["pids_limit"] <= 32
        assert service["mem_limit"] in {"32m", "96m"}
        assert service["memswap_limit"] == service["mem_limit"]
        assert 0 < service["cpus"] <= 0.5
        assert service["restart"] == "no"
        assert not set(service) & {
            "volumes",
            "volumes_from",
            "devices",
            "privileged",
            "cap_add",
            "network_mode",
            "pid",
            "ipc",
            "uts",
            "build",
            "container_name",
            "labels",
            "env_file",
        }
    for role in lab.ENDPOINTS:
        assert deployment["services"][role]["tmpfs"] == [
            "/data:rw,nosuid,nodev,noexec,uid=10001,gid=10001,mode=0700,size=8m"
        ]


def test_acl_is_deny_by_default_identity_only(deployment):
    for role in lab.ENDPOINTS:
        args = deployment["services"][role]["command"]
        start = args.index("--user") + 1
        end = next(i for i in range(start, len(args)) if args[i].startswith("--"))
        assert args[start:end] == [
            "default",
            "on",
            "nopass",
            "resetkeys",
            "resetchannels",
            "-@all",
            "+ping",
            "+info|server",
        ]
        assert args[args.index("--save") + 1] == ""
        assert args[args.index("--appendonly") + 1] == "no"
        assert args[args.index("--enable-debug-command") + 1] == "no"
        assert args[args.index("--enable-module-command") + 1] == "no"
        assert all("+command" not in value and "~" not in value for value in args)


@pytest.mark.parametrize(
    "host,port",
    [
        ("127.0.0.3", 6379),
        ("127.0.0.3", 6380),
        ("127.0.0.4", 6380),
        ("127.0.0.5", 6380),
        ("0.0.0.0", 6379),
        ("localhost", 6379),
        ("192.0.2.1", 6379),
    ],
)
def test_probe_refuses_other_endpoints_before_connect(monkeypatch, host, port):
    connect = Mock(side_effect=AssertionError("Must not connect"))
    monkeypatch.setattr(lab.socket, "create_connection", connect)
    with pytest.raises(ValueError, match="Endpoint outside"):
        lab.request(host, port, ("PING",))
    connect.assert_not_called()


@pytest.mark.parametrize(
    "command",
    [
        ("COMMAND", "GETKEYS", "GET", "sample"),
        ("COMMAND", "GETKEYSANDFLAGS", "GET", "sample"),
        ("INFO",),
        ("INFO", "all"),
        ("INFO", "server", "memory"),
        ("GET", "sample"),
        ("SET", "sample", "value"),
        ("EVAL", "return 1", "0"),
        ("CONFIG", "GET", "*"),
        ("ACL", "LIST"),
    ],
)
def test_probe_refuses_unapproved_commands_before_connect(monkeypatch, command):
    connect = Mock(side_effect=AssertionError("Must not connect"))
    monkeypatch.setattr(lab.socket, "create_connection", connect)
    with pytest.raises(ValueError, match="read-only probe policy"):
        lab.request("127.0.0.4", 6379, command)
    connect.assert_not_called()


def socket_stub(monkeypatch, reply):
    # Byte-stream stub only; this never binds or runs a fabricated Redis server.
    stream = bytearray(reply)
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)

    def receive(size):
        value = bytes(stream[: min(size, 2)])
        del stream[: len(value)]
        return value

    connection.recv.side_effect = receive
    connect = Mock(return_value=connection)
    monkeypatch.setattr(lab.socket, "create_connection", connect)
    return connection, connect


def test_resp_encoding_and_fragmented_bulk_read(monkeypatch):
    connection, connect = socket_stub(monkeypatch, b"$6\r\nsample\r\n")
    result = lab.request("127.0.0.5", 6379, ("INFO", "server"))
    assert result == {"command": ["INFO", "server"], "resp_type": "bulk", "response": "sample"}
    connect.assert_called_once_with(("127.0.0.5", 6379), timeout=3)
    connection.sendall.assert_called_once_with(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")


@pytest.mark.parametrize(
    "reply", [b"$16385\r\n", b"$-1\r\n", b"$6\r\nx", b"x" * 128, b"-NOPERM denied\r\n"]
)
def test_resp_rejects_oversized_truncated_or_error_reply(monkeypatch, reply):
    socket_stub(monkeypatch, reply)
    with pytest.raises(ValueError):
        lab.request("127.0.0.4", 6379, ("INFO", "server"))


def test_resp_has_absolute_deadline(monkeypatch):
    connection, _ = socket_stub(monkeypatch, b"+PONG\r\n")
    monkeypatch.setattr(lab.time, "monotonic", Mock(side_effect=[0, 4]))
    with pytest.raises(ValueError, match="deadline"):
        lab.request("127.0.0.4", 6379, ("PING",))
    connection.recv.assert_not_called()


def test_preflight_refuses_existing_project(monkeypatch):
    docker = Mock(return_value="existing-container\n")
    monkeypatch.setattr(lab, "docker", docker)
    with pytest.raises(ValueError, match="already exist"):
        lab.preflight()
    assert docker.call_count == 1


@pytest.mark.parametrize(
    "binding",
    [
        {"HostIp": "0.0.0.0", "HostPort": "6379"},
        {"HostIp": "127.0.0.4", "HostPort": "6379"},
        {"HostIp": "127.0.0.5", "HostPort": "6379"},
    ],
)
def test_preflight_detects_docker_reservations_before_binding(monkeypatch, binding):
    container = {"Name": "other-project", "HostConfig": {"PortBindings": {"6379/tcp": [binding]}}}
    monkeypatch.setattr(lab, "docker", Mock(side_effect=["", "", "id", json.dumps([container])]))
    bind = Mock(side_effect=AssertionError("Must not bind"))
    monkeypatch.setattr(lab.socket, "socket", bind)
    with pytest.raises(ValueError, match="reservation conflicts"):
        lab.preflight()
    bind.assert_not_called()


def test_preflight_binds_only_exact_pair_and_closes_both(monkeypatch):
    container = {
        "Name": "iot",
        "HostConfig": {"PortBindings": {"6379/tcp": [{"HostIp": "127.0.0.3", "HostPort": "6379"}]}},
    }
    monkeypatch.setattr(lab, "docker", Mock(side_effect=["", "", "id", json.dumps([container])]))
    sockets = [Mock(), Mock()]
    monkeypatch.setattr(lab.socket, "socket", Mock(side_effect=sockets))
    lab.preflight()
    for connection, endpoint in zip(sockets, lab.ENDPOINTS.values(), strict=True):
        connection.bind.assert_called_once_with(endpoint)
        connection.close.assert_called_once()


def test_evaluation_is_separate_and_explicit_about_candidate_scope(deployment):
    evaluation = json.loads((lab.HERE / "evaluation.json").read_text())
    assert evaluation["expected_endpoints"] == {
        role: {"host": host, "port": port} for role, (host, port) in lab.ENDPOINTS.items()
    }
    assert "Version-only applicability candidate" in evaluation["conclusion_scope"]
    assert (
        "COMMAND" in evaluation["conclusion_scope"] and "denied" in evaluation["conclusion_scope"]
    )
    assert "CVE-" not in json.dumps(deployment)
    assert "CVE-" not in (lab.HERE / "verify.py").read_text()
    assert lab.RECEIPT == lab.ROOT / "data/service-networks/cve-services-verification.json"


@pytest.fixture
def inspection(deployment):
    """Docker metadata fixture only; never a simulated network service."""

    def make(role):
        spec = deployment["services"][role]
        forwarder = role.endswith("-ingress")
        backend = role.removesuffix("-ingress")
        address, port = lab.ENDPOINTS[backend]
        publications = (
            {"6379/tcp": [{"HostIp": address, "HostPort": str(port)}]} if forwarder else {}
        )
        memory = (32 if forwarder else 96) * 1024**2
        return {
            "Config": {
                "Labels": {
                    "com.docker.compose.project": lab.PROJECT,
                    "com.docker.compose.service": role,
                },
                "Image": spec["image"],
                "User": "10001:10001",
                "Entrypoint": spec["entrypoint"],
                "Cmd": spec["command"],
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "IpcMode": "private",
                "Memory": memory,
                "MemorySwap": memory,
                "PidsLimit": 16 if forwarder else 32,
                "NanoCpus": 250_000_000 if forwarder else 500_000_000,
                "Tmpfs": {} if forwarder else {"/data": spec["tmpfs"][0].split(":", 1)[1]},
                "PortBindings": publications,
                "NetworkMode": lab.PROJECT + "_pair",
                "Sysctls": spec.get("sysctls", {}),
            },
            "Mounts": [],
            "NetworkSettings": {
                "Ports": copy.deepcopy(publications),
                "Networks": {lab.PROJECT + "_" + name: {} for name in spec["networks"]},
            },
            "State": {"Running": True, "Health": {"Status": "healthy"}},
        }

    return make


@pytest.mark.parametrize("role", ["affected", "patched", "affected-ingress", "patched-ingress"])
def test_runtime_validator_accepts_intended_topology(inspection, role):
    lab.validate_container(inspection(role), role)


@pytest.mark.parametrize(
    "path,value",
    [
        (("HostConfig", "ReadonlyRootfs"), False),
        (("HostConfig", "CapAdd"), ["NET_ADMIN"]),
        (("HostConfig", "Privileged"), True),
        (("HostConfig", "Binds"), ["/host:/data"]),
        (("HostConfig", "PidsLimit"), 0),
        (("HostConfig", "Memory"), 0),
        (("HostConfig", "IpcMode"), "host"),
        (("HostConfig", "PublishAllPorts"), True),
        (("HostConfig", "NetworkMode"), "host"),
        (("Config", "User"), "0:0"),
        (("Config", "Cmd"), ["--user", "default", "on", "nopass", "+@all"]),
        (("NetworkSettings", "Networks"), {"unrelated": {}}),
        (("State", "Running"), False),
    ],
)
def test_runtime_validator_rejects_security_drift(inspection, path, value):
    for role in lab.SERVICE_IMAGES:
        actual = inspection(role)
        actual[path[0]][path[1]] = value
        with pytest.raises(ValueError):
            lab.validate_container(actual, role)


def test_runtime_validator_rejects_wildcard_or_old_publication(inspection):
    for address in ("0.0.0.0", "127.0.0.3"):
        actual = inspection("affected-ingress")
        actual["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostIp"] = address
        with pytest.raises(ValueError, match="Actual port mapping"):
            lab.validate_container(actual, "affected-ingress")

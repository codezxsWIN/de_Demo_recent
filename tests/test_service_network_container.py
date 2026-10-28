"""Offline deployment checks; actual isolation requires Docker runtime evidence."""

from pathlib import Path

import pytest
import yaml

from labs.service_networks import binding

ROOT = Path(__file__).resolve().parents[1]


def test_ordinary_lab_bindings_stay_on_their_exact_loopbacks():
    for host in ("127.0.0.2", "127.0.0.3"):
        binding.validate(host, host)
    for host in ("0.0.0.0", "127.0.0.1", "192.0.2.12", "::"):
        with pytest.raises(ValueError):
            binding.validate(host, "127.0.0.2")


def test_container_marker_alone_does_not_enable_wildcard_binding(monkeypatch):
    monkeypatch.setattr(binding.os, "name", "posix")
    monkeypatch.setattr(binding.Path, "is_file", lambda _: True)
    monkeypatch.delenv("VULNASSESS_CONTAINER_LAB", raising=False)
    with pytest.raises(ValueError):
        binding.validate("0.0.0.0", "127.0.0.2")
    monkeypatch.setenv("VULNASSESS_CONTAINER_LAB", "1")
    binding.validate("0.0.0.0", "127.0.0.2")


def test_deployment_has_separate_internal_networks_and_no_host_mounts():
    compose = yaml.safe_load((ROOT / "labs/service_networks/compose.yaml").read_text())
    assert set(compose["services"]) == {"office", "iot", "office-gateway", "iot-gateway", "office-redis", "iot-redis"}
    for name, service in compose["services"].items():
        assert service["read_only"] is True and service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert "volumes" not in service and "privileged" not in service
        assert "network_mode" not in service
        if name in {"office", "iot", "office-redis", "iot-redis"}:
            backend = name.removesuffix("-redis")
            assert set(service["networks"]) == {backend}
            assert compose["networks"][backend]["internal"] is True
            assert "ports" not in service
        else:
            backend = name.removesuffix("-gateway")
            assert set(service["networks"]) == {backend, backend + "-ingress"}
            assert service["sysctls"] == {"net.ipv4.ip_forward": "0"}
            prefix = "127.0.0.2:" if backend == "office" else "127.0.0.3:"
            assert all(port.startswith(prefix) for port in service["ports"])
            assert prefix + "6379:6379" in service["ports"]
            assert service["depends_on"][backend + "-redis"]["condition"] == "service_healthy"
    for name, version, address in (("office", "7.0.11", "172.30.41.4"), ("iot", "7.0.12", "172.30.42.4")):
        redis = compose["services"][name + "-redis"]
        assert redis["image"].startswith("redis:" + version + "@sha256:")
        assert redis["networks"][name]["ipv4_address"] == address
        assert redis["command"][redis["command"].index("-@all") + 1:][:2] == ["+ping", "+info|server"]
    dockerfile = (ROOT / "labs/service_networks/Dockerfile").read_text()
    assert "@sha256:" in dockerfile and "USER 10001:10001" in dockerfile
    assert "COPY . /app/labs/service_networks/" in dockerfile


def test_gateway_cannot_be_repurposed_as_a_general_proxy():
    from labs.service_networks.gateway import REDIS_ROUTES, ROUTES, command

    for name, (ip, tcp, udp) in ROUTES.items():
        for transport, ports in (("tcp", tcp), ("udp", udp)):
            for port in ports:
                args = command(name, port, transport)
                assert args[0] == "socat" and "max-children=4" in args[-2]
                assert f"{REDIS_ROUTES[name] if port == 6379 else ip}:{port}" in args[-1]
                assert args[-2].startswith("TCP4-LISTEN:" if transport == "tcp" else "UDP4-LISTEN:")
        with pytest.raises(ValueError):
            command(name, 80, "tcp")
        with pytest.raises(ValueError):
            command(name, 2121, "icmp")

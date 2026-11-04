"""Exercise the public controller with a Docker-process and live-policy double."""

import copy
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnassess import lab_control as control
from vulnassess.settings import Scope

_POLICY_LOAD = control.network_service_policy.load


def ident(number):
    return f"{number:064x}"


class Docker:
    def __init__(self):
        self.calls = []
        self.up = []
        self.fail_up = set()
        self.timeout_up = set()
        self.on_up = lambda *_: None
        self.on_config = lambda *_: None
        self.profiles = {"office": "baseline", "iot": "baseline"}
        self.rows = {}
        self.networks = {}
        self.unknown_ready = {}
        self.images = {
            "sha256:" + ident(100): {
                "Id": "sha256:" + ident(100),
                "Config": {
                    "User": "10001:10001",
                    "Entrypoint": ["python", "-m", "labs.service_networks.container"],
                    "Env": ["VULNASSESS_CONTAINER_LAB=1"],
                },
            }
        }
        self.images[control.LOCAL_IMAGE] = self.images["sha256:" + ident(100)]
        for offset, environment in enumerate(("office", "iot"), start=1):
            ip, port, _, private = control.ENDPOINTS[environment]
            network_name = control.PROJECT + "_" + environment
            network_id = ident(offset + 50)
            self.networks[network_name] = {
                "Name": network_name,
                "Id": network_id,
                "Internal": True,
                "Labels": {
                    "com.docker.compose.project": control.PROJECT,
                    "com.docker.compose.network": environment,
                },
            }
            for index, service in enumerate(
                (environment, environment + "-gateway", environment + "-redis")
            ):
                self.rows[service] = {
                    "Id": ident(offset * 10 + index),
                    "Image": "sha256:" + ident(100),
                    "Config": {
                        "Labels": {
                            "com.docker.compose.project": control.PROJECT,
                            "com.docker.compose.service": service,
                        },
                        "User": "10001:10001",
                        "Cmd": [environment],
                        "Entrypoint": ["python", "-m", "labs.service_networks.container"],
                        "Env": [],
                    },
                    "HostConfig": {
                        "ReadonlyRootfs": True,
                        "Privileged": False,
                        "CapDrop": ["ALL"],
                        "CapAdd": [],
                        "NetworkMode": network_name,
                        "SecurityOpt": ["no-new-privileges:true"],
                    },
                    "State": {"Running": True, "Health": {"Status": "healthy"}},
                    "Mounts": [],
                    "NetworkSettings": {
                        "Networks": {network_name: {"IPAddress": private, "NetworkID": network_id}},
                        "Ports": {}
                        if index != 1
                        else {
                            str(port) + "/tcp": [{"HostIp": ip, "HostPort": str(port)}],
                        },
                    },
                }
        # Live clients and observers are present and must keep their identities.
        for index, service in enumerate(sorted(control.LIVE_SERVICES), start=200):
            row = copy.deepcopy(
                self.rows["office-gateway" if service.startswith("office") else "iot-gateway"]
            )
            row["Id"] = ident(index)
            row["Config"]["Labels"]["com.docker.compose.service"] = service
            if service.endswith("capture"):
                gateway = "office-gateway" if service.startswith("office") else "iot-gateway"
                row["HostConfig"]["NetworkMode"] = "container:" + self.rows[gateway]["Id"]
            self.rows[service] = row

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        assert kwargs["shell"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] <= 90
        assert argv[0] == "fixed-docker.exe"
        args = argv[1:]
        code = 0
        if args[0] == "ps":
            assert args == [
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                "label=com.docker.compose.project=" + control.PROJECT,
            ]
            output = "\n".join(row["Id"] for row in self.rows.values())
        elif args[0] == "inspect":
            output = json.dumps(
                [next(row for row in self.rows.values() if row["Id"] == item) for item in args[1:]]
            )
        elif args[:2] == ["network", "inspect"]:
            output = json.dumps([self.networks[args[2]]])
        elif args[:2] == ["image", "inspect"]:
            assert len(args) == 3
            if args[2] in self.images:
                output = json.dumps([self.images[args[2]]])
            else:
                code, output = 1, ""
        elif args[0] == "exec":
            assert args[2:] == ["cat", "/runtime/ready.json"]
            service, row = next(
                (name, row) for name, row in self.rows.items() if row["Id"] == args[1]
            )
            _, port, protocol, _ = control.ENDPOINTS[service]
            output = json.dumps(
                {
                    "environment": service,
                    "access_profile": self.profiles[service],
                    "network_namespace": int(row["Id"], 16) + 1000,
                    "services": [
                        {
                            "port": port,
                            "protocol": protocol,
                            "protected": self.profiles[service] == "restricted",
                        }
                    ],
                    **self.unknown_ready,
                }
            )
        elif args[0] == "compose":
            files = [Path(args[index + 1]) for index, arg in enumerate(args) if arg == "-f"]
            override = json.loads(files[-1].read_text(encoding="utf-8"))
            assert files[-1].name.startswith(".control-override-")
            assert files[-1].stat().st_size <= 1024
            assert len(override["services"]) == 1
            service, spec = next(iter(override["services"].items()))
            profile = spec["environment"]["VULNASSESS_LAB_ACCESS_PROFILE"]
            assert set(spec) == {"image", "environment"}
            assert service in control.ENDPOINTS and profile in control.PROFILES
            if args[-3:] == ["config", "--format", "json"]:
                config = {
                    "name": control.PROJECT,
                    "services": {
                        service: {
                            "image": spec["image"],
                            "command": [service],
                            "read_only": True,
                            "cap_drop": ["ALL"],
                            "security_opt": ["no-new-privileges:true"],
                            "networks": {service: {"ipv4_address": control.ENDPOINTS[service][3]}},
                            "environment": spec["environment"],
                        }
                    },
                }
                self.on_config(config)
                output = json.dumps(config)
            else:
                assert args[-len(control.UP) - 1 :] == [*control.UP, service]
                self.up.append((service, profile, copy.deepcopy(override)))
                row = copy.deepcopy(self.rows.get(service, self.rows[service + "-redis"]))
                row["Id"] = ident(500 + len(self.up))
                assert spec["image"] in self.images, "up must never receive an unavailable image"
                row["Image"] = spec["image"]
                row["Config"]["Labels"]["com.docker.compose.service"] = service
                row["Config"]["Env"] = ["VULNASSESS_LAB_ACCESS_PROFILE=" + profile]
                row["State"] = {"Running": True, "Health": {"Status": "healthy"}}
                self.rows[service] = row
                self.profiles[service] = profile
                self.on_up(service, profile)
                if len(self.up) in self.timeout_up:
                    raise subprocess.TimeoutExpired(argv, 90, output="DO_NOT_LEAK")
                code = 1 if len(self.up) in self.fail_up else 0
                output = "DO_NOT_LEAK"
        else:
            raise AssertionError("unexpected Docker command")
        return SimpleNamespace(returncode=code, stdout=output, stderr="DO_NOT_LEAK")


@pytest.fixture
def lab(tmp_path, monkeypatch):
    directory = tmp_path / "labs" / "service_networks"
    directory.mkdir(parents=True)
    (directory / "compose.yaml").write_text("name: vulnassess-service-networks\n")
    (directory / "live.compose.yaml").write_text("services: {}\n")
    state = SimpleNamespace(
        authorised=True,
        digest=ident(99),
        scope_allowed=True,
        canary=False,
        port=None,
        service=None,
        target=None,
    )
    scope = SimpleNamespace(
        contains=lambda _: state.scope_allowed, is_canary=lambda _: state.canary
    )
    monkeypatch.setattr(
        control, "Settings", lambda path: SimpleNamespace(config_dir=path, scope=scope)
    )

    def policy(config_dir, supplied_scope, ip):
        assert config_dir == tmp_path / "config" and supplied_scope is scope
        assert ip in ("127.0.0.2", "127.0.0.3")
        if not state.authorised:
            return None
        port, service = (2121, "ftp") if ip == "127.0.0.2" else (1883, "mqtt")
        return {
            "target_ip": state.target or ip,
            "policy_sha256": state.digest,
            "endpoints": [
                {
                    "port": state.port or port,
                    "service": state.service or service,
                    "transport": "tcp",
                }
            ],
        }

    monkeypatch.setattr(control.network_service_policy, "load", policy)
    monkeypatch.setattr(
        control.shutil, "which", lambda name: "fixed-docker.exe" if name == "docker" else None
    )
    docker = Docker()
    monkeypatch.setattr(control.subprocess, "run", docker)
    return SimpleNamespace(
        controller=control.LabControl(tmp_path), docker=docker, policy=state, root=tmp_path
    )


def failed(controller, environment, profile):
    with pytest.raises(control.ConfigError) as caught:
        controller.set_profile(environment, profile)
    assert isinstance(caught.value, control.LabControlError)
    assert "DO_NOT_LEAK" not in str(caught.value)
    return caught.value.receipt


def receipt(lab, result):
    path = lab.root / result["receipt"]
    assert path.name.startswith("control-") and path.suffix == ".json"
    assert path.stat().st_size < 65536
    assert json.loads(path.read_text(encoding="utf-8")) == result
    assert not list(path.parent.glob(".control-override-*.json"))
    assert not list(path.parent.glob(".control-receipt-*.json"))
    return path


@pytest.mark.parametrize("environment", ["office", "iot"])
@pytest.mark.parametrize("profile", ["baseline", "restricted"])
def test_public_set_profile_recreates_only_backend_and_preserves_endpoint(
    lab, environment, profile
):
    lab.docker.profiles[environment] = "restricted" if profile == "baseline" else "baseline"
    others = {
        name: copy.deepcopy(row) for name, row in lab.docker.rows.items() if name != environment
    }
    result = lab.controller.set_profile(environment, profile)
    assert result["status"] == "verified", result
    assert result["profile"] == profile
    before, after = result["before"], result["after"]
    assert before["id"] != after["id"]
    assert before["network_namespace"] != after["network_namespace"]
    for key in ("image_id", "network_id", "private_ip", "project"):
        assert before[key] == after[key]
    assert after["access_profile"] == profile
    assert lab.docker.up[0][:2] == (environment, profile)
    assert all(lab.docker.rows[name] == row for name, row in others.items())
    assert result["rollback"] == {"attempted": False, "status": "not_needed"}
    assert "no security clearance" in result["verification_scope"]
    if environment == "iot":
        assert "deny-all containment" in result["meaning"]
        assert "not an authenticated production broker" in result["meaning"]
    receipt(lab, result)


def test_fixed_argv_no_shell_build_pull_or_environment_file_overrides(lab, monkeypatch):
    for name in ("COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES", "DOCKER_HOST"):
        monkeypatch.setenv(name, "DO_NOT_LEAK")
    result = lab.controller.set_profile("office", "restricted")
    assert result["status"] == "verified"
    argv, options = next((args, opts) for args, opts in lab.docker.calls if "up" in args)
    directory = lab.root / "labs/service_networks"
    assert argv[:12] == [
        "fixed-docker.exe",
        "compose",
        "--project-name",
        control.PROJECT,
        "--project-directory",
        str(directory),
        "--env-file",
        os.devnull,
        "-f",
        str(directory / "compose.yaml"),
        "-f",
        str(directory / "live.compose.yaml"),
    ]
    assert argv[12] == "-f"
    assert Path(argv[13]).parent == lab.root / "data/network-live"
    assert argv[14:] == [
        "up",
        "--no-deps",
        "--wait",
        "--wait-timeout",
        "60",
        "--force-recreate",
        "--no-build",
        "--pull",
        "never",
        "office",
    ]
    assert options["shell"] is False
    assert not any(key.startswith(("COMPOSE_", "DOCKER_")) for key in options["env"])
    assert "DO_NOT_LEAK" not in json.dumps(result)
    receipt(lab, result)


def test_optional_live_extension_is_not_required(lab):
    (lab.root / "labs/service_networks/live.compose.yaml").unlink()
    for service in control.LIVE_SERVICES:
        del lab.docker.rows[service]
    result = lab.controller.set_profile("iot", "restricted")
    assert result["status"] == "verified"
    assert all("live.compose.yaml" not in " ".join(argv) for argv, _ in lab.docker.calls)


def test_profile_reads_actual_runtime_without_starting_anything(lab):
    lab.docker.profiles["iot"] = "restricted"
    result = lab.controller.profile("iot")
    assert result["status"] == "verified" and result["profile"] == "restricted"
    assert result["after"]["network_namespace"] > 0
    assert not lab.docker.up
    assert not list((lab.root / "data/network-live").glob("control-*.json"))


@pytest.mark.parametrize(
    "environment", ["--project-name=evil", "office;whoami", "OFFICE", "", None, [], {}]
)
def test_no_arbitrary_environment_inputs(lab, environment):
    with pytest.raises(ValueError):
        lab.controller.set_profile(environment, "baseline")
    with pytest.raises(ValueError):
        lab.controller.profile(environment)
    assert not lab.docker.calls


@pytest.mark.parametrize(
    "profile", ["--force", "restricted;whoami", "RESTRICTED", "", None, [], {}]
)
def test_no_arbitrary_profile_inputs(lab, profile):
    with pytest.raises(ValueError):
        lab.controller.set_profile("office", profile)
    assert not lab.docker.calls


def test_no_public_executable_or_file_override(lab):
    with pytest.raises(TypeError):
        control.LabControl(lab.root, executable="evil")
    with pytest.raises(TypeError):
        lab.controller.set_profile("office", "restricted", compose="evil.yaml")
    assert not lab.docker.calls


def test_wrong_project_refused_before_mutation(lab):
    lab.docker.rows["office"]["Config"]["Labels"]["com.docker.compose.project"] = "harbordesk"
    result = failed(lab.controller, "office", "restricted")
    assert result["status"] == "failed" and result["error"] == "wrong_project"
    assert not lab.docker.up
    assert result["before"] is None
    receipt(lab, result)


@pytest.mark.parametrize("missing", ["office", "iot-gateway"])
def test_no_automatic_startup_of_missing_existing_lab(lab, missing):
    del lab.docker.rows[missing]
    result = failed(lab.controller, "office", "restricted")
    assert result["status"] == "failed" and result["error"] == "existing_project_required"
    assert not lab.docker.up


@pytest.mark.parametrize(
    "field,value",
    [
        ("authorised", False),
        ("scope_allowed", False),
        ("canary", True),
        ("port", 2122),
        ("service", "ssh"),
        ("target", "127.0.0.1"),
    ],
)
def test_exact_current_settings_and_endpoint_policy_required(lab, field, value):
    setattr(lab.policy, field, value)
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "endpoint_not_authorised"
    assert not lab.docker.calls
    receipt(lab, result)


def test_revocation_immediately_before_up_is_honoured(lab):
    lab.docker.on_config = lambda _: setattr(lab.policy, "authorised", False)
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "endpoint_not_authorised"
    assert not lab.docker.up
    assert not result["rollback"]["attempted"]
    receipt(lab, result)


@pytest.mark.parametrize("revoke", [True, False])
def test_policy_revocation_or_changed_hash_after_mutation_blocks_rollback(lab, revoke):
    def changed(*_):
        if revoke:
            lab.policy.authorised = False
        else:
            lab.policy.digest = ident(123)

    lab.docker.on_up = changed
    result = failed(lab.controller, "iot", "restricted")
    code = "endpoint_not_authorised" if revoke else "policy_changed"
    assert result["status"] == "failed" and result["error"] == code
    assert result["profile"] is None
    assert result["rollback"] == {
        "attempted": False,
        "status": "restoration_unverified",
        "error": code,
    }
    assert len(lab.docker.up) == 1
    receipt(lab, result)


@pytest.mark.parametrize("failure", ["exit", "timeout", "unhealthy", "metadata"])
def test_failure_attempts_one_verified_rollback_to_original_profile(lab, failure):
    if failure == "exit":
        lab.docker.fail_up = {1}
    elif failure == "timeout":
        lab.docker.timeout_up = {1}
    else:

        def corrupt(service, _profile):
            if len(lab.docker.up) == 1:
                if failure == "unhealthy":
                    lab.docker.rows[service]["State"]["Health"]["Status"] = "unhealthy"
                else:
                    lab.docker.profiles[service] = "baseline"

        lab.docker.on_up = corrupt
    result = failed(lab.controller, "office", "restricted")
    assert result["status"] == "failed", result
    assert result["rollback"]["attempted"] is True
    assert result["rollback"]["status"] == "restored"
    assert result["profile"] == "baseline"
    assert [row[:2] for row in lab.docker.up] == [("office", "restricted"), ("office", "baseline")]
    assert "DO_NOT_LEAK" not in json.dumps(result)
    receipt(lab, result)


def test_failed_restoration_is_not_claimed_as_restored_or_retried(lab):
    lab.docker.fail_up = {1, 2}
    result = failed(lab.controller, "iot", "restricted")
    assert result["status"] == "failed" and result["profile"] is None
    assert result["rollback"] == {
        "attempted": True,
        "status": "restoration_unverified",
        "error": "docker_compose_up_failed",
    }
    assert len(lab.docker.up) == 2
    receipt(lab, result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("User", "0:0"),
        ("ReadonlyRootfs", False),
        ("Privileged", True),
        ("CapDrop", []),
        ("CapAdd", ["NET_ADMIN"]),
        ("SecurityOpt", []),
    ],
)
def test_unsafe_backend_cannot_be_mutated_or_reported_verified(lab, field, value):
    row = lab.docker.rows["office"]
    (row["Config"] if field == "User" else row["HostConfig"])[field] = value
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "unsafe_backend_isolation" and result["profile"] is None
    assert lab.controller.profile("office")["status"] == "failed"
    assert not lab.docker.up


@pytest.mark.parametrize("drift", ["ip", "network", "network_project", "gateway"])
def test_wrong_network_or_endpoint_is_refused(lab, drift):
    name = control.PROJECT + "_office"
    if drift == "ip":
        lab.docker.rows["office"]["NetworkSettings"]["Networks"][name]["IPAddress"] = "172.30.41.6"
    elif drift == "network":
        lab.docker.rows["office"]["NetworkSettings"]["Networks"] = {}
    elif drift == "network_project":
        lab.docker.networks[name]["Labels"]["com.docker.compose.project"] = "wrong"
    else:
        lab.docker.rows["office-gateway"]["NetworkSettings"]["Ports"]["2121/tcp"][0]["HostIp"] = (
            "0.0.0.0"
        )
    result = failed(lab.controller, "office", "restricted")
    assert result["status"] == "failed"
    assert not lab.docker.up


@pytest.mark.parametrize(
    "field,value",
    [
        ("privileged", True),
        ("post_start", [{"command": "evil"}]),
        ("ports", ["0.0.0.0:2121:2121"]),
        ("command", ["other"]),
    ],
)
def test_effective_compose_is_checked_before_any_recreation(lab, field, value):
    lab.docker.on_config = lambda config: config["services"]["office"].update({field: value})
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "unsafe_compose_configuration"
    assert not lab.docker.up
    receipt(lab, result)


def test_nonblocking_mutation_lock_shared_across_controller_instances(lab):
    with lab.controller._lock():
        another = control.LabControl(lab.root)
        result = failed(another, "office", "restricted")
        assert result["status"] == "busy" and result["error"] == "control_busy"
        assert another.profile("office")["status"] == "busy"
    assert not lab.docker.calls
    assert lab.controller.set_profile("office", "restricted")["status"] == "verified"


def test_receipt_and_return_do_not_copy_unknown_ready_fields_or_secrets(lab):
    lab.docker.unknown_ready = {"password": "DO_NOT_LEAK", "private_key": "DO_NOT_LEAK"}
    lab.docker.rows["office"]["Config"]["Env"].append("PASSWORD=DO_NOT_LEAK")
    result = lab.controller.set_profile("office", "restricted")
    assert result["status"] == "verified"
    assert "DO_NOT_LEAK" not in receipt(lab, result).read_text(encoding="utf-8")


def test_atomic_receipt_publishes_only_complete_document(lab, monkeypatch):
    original = os.replace
    published = []

    def replace(source, destination):
        assert not Path(destination).exists()
        content = json.loads(Path(source).read_text(encoding="utf-8"))
        assert (
            content["status"] == "verified" and content["after"]["access_profile"] == "restricted"
        )
        published.append(destination)
        original(source, destination)

    monkeypatch.setattr(control.os, "replace", replace)
    result = lab.controller.set_profile("office", "restricted")
    assert len(published) == 1
    receipt(lab, result)


def test_temporary_cleanup_does_not_delete_a_replacement_file(lab):
    replaced = []

    def replace_override(*_):
        if len(lab.docker.up) == 1:
            path = next((lab.root / "data/network-live").glob(".control-override-*.json"))
            other = path.with_suffix(".replacement")
            other.write_text("unrelated file", encoding="utf-8")
            os.replace(other, path)
            replaced.append(path)

    lab.docker.on_up = replace_override
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "temporary_file_replaced"
    assert replaced[0].read_text(encoding="utf-8") == "unrelated file"
    assert result["rollback"]["status"] == "restored"


def test_real_policy_loader_and_scope_contract(lab, monkeypatch):
    # One boundary test uses the actual loader and Scope, with real local policy
    # bytes, while Docker remains mocked and all network access stays forbidden.
    directory = lab.root / "config"
    directory.mkdir()
    (directory / "network-services.json").write_text(
        json.dumps(
            {
                "version": 1,
                "targets": {
                    "127.0.0.2": [
                        {"port": 2121, "transport": "tcp", "service": "ftp", "require_auth": True},
                    ]
                },
            }
        )
    )
    scope = Scope({"allowed_hosts": ["127.0.0.2"]}, directory / "scope.yaml")
    monkeypatch.setattr(
        control, "Settings", lambda path: SimpleNamespace(config_dir=path, scope=scope)
    )
    monkeypatch.setattr(control.network_service_policy, "load", _POLICY_LOAD)
    assert lab.controller.set_profile("office", "restricted")["status"] == "verified"
    (directory / "network-services.json").unlink()
    result = failed(lab.controller, "office", "baseline")
    assert result["error"] == "endpoint_not_authorised"
    assert len(lab.docker.up) == 1


def test_failed_recreation_can_restore_a_disappeared_owned_backend(lab):
    def removed(service, _profile):
        if len(lab.docker.up) == 1:
            del lab.docker.rows[service]

    lab.docker.on_up = removed
    lab.docker.fail_up = {1}
    result = failed(lab.controller, "office", "restricted")
    assert result["rollback"]["status"] == "restored"
    assert result["profile"] == "baseline"
    assert len(lab.docker.up) == 2
    receipt(lab, result)


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("drift", ["id", "restart"])
def test_peer_change_prevents_further_mutation_including_rollback(lab, when, drift):
    def changed(*_):
        peer = lab.docker.rows["iot"]
        if drift == "id":
            peer["Id"] = ident(900)
        else:
            peer["RestartCount"] = 1

    if when == "before":
        lab.docker.on_config = changed
    else:
        lab.docker.on_up = changed
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "other_containers_changed"
    assert len(lab.docker.up) == (0 if when == "before" else 1)
    assert result["rollback"]["attempted"] is False
    if when == "after":
        assert result["rollback"]["status"] == "restoration_unverified"
        assert result["rollback"]["error"] == "other_containers_changed"
    receipt(lab, result)


def test_observer_sharing_backend_instead_of_gateway_blocks_mutation(lab):
    lab.docker.rows["office-capture"]["HostConfig"]["NetworkMode"] = (
        "container:" + lab.docker.rows["office"]["Id"]
    )
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "peer_shares_backend_namespace"
    assert not lab.docker.up


def test_missing_docker_and_malformed_runtime_raise_config_error(lab, monkeypatch):
    monkeypatch.setattr(control.shutil, "which", lambda _: None)
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "docker_unavailable"
    receipt(lab, result)
    monkeypatch.setattr(control.shutil, "which", lambda _: "fixed-docker.exe")
    lab.docker.unknown_ready = {"services": None}
    result = failed(lab.controller, "office", "restricted")
    assert result["error"] == "invalid_or_unavailable_runtime"
    assert not lab.docker.up


def test_receipt_write_failure_never_returns_a_success_dict(lab, monkeypatch):
    def unavailable(_result):
        raise OSError("DO_NOT_LEAK")

    monkeypatch.setattr(lab.controller, "_receipt", unavailable)
    result = failed(lab.controller, "office", "restricted")
    assert result["status"] == "failed"
    assert result["receipt_error"] == "invalid_or_unavailable_runtime"
    assert result["after"]["access_profile"] == "restricted"
    assert len(lab.docker.up) == 1


def observer_rebuild(lab):
    old_id = lab.docker.rows["office"]["Image"]
    new_id = "sha256:" + ident(2984)
    image = copy.deepcopy(lab.docker.images.pop(old_id))
    image["Id"] = new_id
    lab.docker.images[control.LOCAL_IMAGE] = image
    lab.docker.images[new_id] = image
    for environment in ("office", "iot"):
        lab.docker.profiles[environment] = "restricted"
        lab.docker.rows[environment]["Config"]["Env"] = ["VULNASSESS_LAB_ACCESS_PROFILE=restricted"]
        lab.docker.rows[environment + "-capture"]["Image"] = new_id
    return old_id, new_id


def test_observer_rebuild_missing_old_image_resolves_fixed_local_image_before_up(lab):
    old_id, new_id = observer_rebuild(lab)
    peers = copy.deepcopy(lab.docker.rows)
    result = lab.controller.set_profile("office", "baseline")
    assert result["before"]["image_id"] == old_id
    assert result["after"]["image_id"] == new_id
    assert result["image_selection"] == {"image_id": new_id, "source": "fixed_local_image"}
    assert result["before"]["access_profile"] == "restricted"
    assert result["after"]["access_profile"] == "baseline"
    assert lab.docker.up[0][2]["services"]["office"]["image"] == new_id
    assert all(lab.docker.rows[name] == row for name, row in peers.items() if name != "office")
    receipt(lab, result)


def test_rollback_after_observer_rebuild_restores_profile_on_pinned_available_image(lab):
    old_id, new_id = observer_rebuild(lab)
    lab.docker.fail_up = {1}
    result = failed(lab.controller, "office", "baseline")
    assert result["before"]["image_id"] == old_id
    assert result["rollback"]["status"] == "restored"
    assert result["rollback"]["after"]["image_id"] == new_id
    assert result["profile"] == "restricted"
    assert [row[1] for row in lab.docker.up] == ["baseline", "restricted"]
    assert all(row[2]["services"]["office"]["image"] == new_id for row in lab.docker.up)
    receipt(lab, result)


def test_available_original_image_is_preserved_despite_new_local_tag(lab):
    original_id = lab.docker.rows["office"]["Image"]
    image = copy.deepcopy(lab.docker.images[original_id])
    image["Id"] = "sha256:" + ident(2984)
    lab.docker.images[control.LOCAL_IMAGE] = image
    lab.docker.images[image["Id"]] = image
    result = lab.controller.set_profile("office", "restricted")
    assert result["image_selection"] == {"image_id": original_id, "source": "running_image"}
    assert result["after"]["image_id"] == original_id


@pytest.mark.parametrize("unavailable", [True, False])
def test_missing_or_invalid_rebuilt_lab_image_fails_before_any_up_or_rollback(lab, unavailable):
    observer_rebuild(lab)
    if unavailable:
        del lab.docker.images[control.LOCAL_IMAGE]
    else:
        lab.docker.images[control.LOCAL_IMAGE]["Config"]["Entrypoint"] = ["arbitrary"]
    result = failed(lab.controller, "office", "baseline")
    assert result["error"] == ("lab_image_unavailable" if unavailable else "invalid_lab_image")
    assert result["rollback"] == {"attempted": False, "status": "not_needed"}
    assert not lab.docker.up
    receipt(lab, result)


def test_selected_image_cannot_disappear_between_forward_and_rollback(lab):
    _, new_id = observer_rebuild(lab)
    lab.docker.fail_up = {1}

    def removed(*_):
        del lab.docker.images[new_id]

    lab.docker.on_up = removed
    result = failed(lab.controller, "office", "baseline")
    assert result["rollback"] == {
        "attempted": False,
        "status": "restoration_unverified",
        "error": "docker_inspect_image_failed",
    }
    assert len(lab.docker.up) == 1
    receipt(lab, result)

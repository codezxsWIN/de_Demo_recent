"""Fixed, authorised recreation of an already running service-network backend.

Verification covers Docker isolation and startup metadata, not security clearance
or a protocol authentication audit. No operation provisions a new lab project.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from vulnassess import network_service_policy
from vulnassess.errors import ConfigError
from vulnassess.settings import Settings

PROJECT = "vulnassess-service-networks"
LOCAL_IMAGE = "vulnassess-service-networks:local"
PROFILES = ("baseline", "restricted")
ENDPOINTS = {
    "office": ("127.0.0.2", 2121, "ftp", "172.30.41.2"),
    "iot": ("127.0.0.3", 1883, "mqtt", "172.30.42.2"),
}
BASE_SERVICES = {"office", "iot", "office-gateway", "iot-gateway", "office-redis", "iot-redis"}
LIVE_SERVICES = {
    "office-workstation",
    "iot-sensor",
    "iot-dashboard",
    "office-capture",
    "iot-capture",
}
UP = (
    "up",
    "--no-deps",
    "--wait",
    "--wait-timeout",
    "60",
    "--force-recreate",
    "--no-build",
    "--pull",
    "never",
)
_HEX = re.compile(r"[a-f0-9]{64}")
_IMAGE = re.compile(r"sha256:[a-f0-9]{64}")
_locks = {}
_locks_guard = threading.Lock()


class _Failure(Exception):
    """Only fixed error codes cross the public/receipt boundary."""


class LabControlError(ConfigError):
    """A failed mutation; receipt retains bounded failure/restoration evidence."""

    def __init__(self, receipt):
        self.receipt = receipt
        code = receipt.get("error") or receipt.get("receipt_error") or "control_failed"
        super().__init__(
            f"Lab reconfiguration failed: {code}; restoration: {receipt['rollback']['status']}"
        )


def _require(condition, code):
    if not condition:
        raise _Failure(code)


def _identifier(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    _require(len(raw) <= 1048576, "docker_output_too_large")
    return json.loads(raw, object_pairs_hook=unique)


def _plain(path):
    # is_junction is available on Python 3.12; the reparse bit also covers 3.11.
    if path.exists() or path.is_symlink():
        info = path.lstat()
        _require(
            not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 1024,
            "unsafe_local_path",
        )


@contextmanager
def _temporary(directory, prefix, payload):
    """Delete only the exact inode/file created by this invocation."""
    fd, name = tempfile.mkstemp(dir=directory, prefix=prefix, suffix=".json")
    path = Path(name)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        yield path
    finally:
        if path.exists() or path.is_symlink():
            current = path.lstat()
            _require(
                not path.is_symlink()
                and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                "temporary_file_replaced",
            )
            path.unlink()


class LabControl:
    """Public inputs are exactly root, environment and the two fixed profiles.

    set_profile returns a verified receipt or raises LabControlError (ConfigError)
    with its failure receipt in error.receipt. profile is read-only and returns
    verified/failed/busy status. Invalid enums raise ValueError before any IO.
    """

    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.directory = self.root / "data" / "network-live"
        self.compose_directory = self.root / "labs" / "service_networks"

    @staticmethod
    def _validate(environment, profile=None):
        if type(environment) is not str or environment not in ENDPOINTS:
            raise ValueError("environment must be office or iot")
        if profile is not None and (type(profile) is not str or profile not in PROFILES):
            raise ValueError("profile must be baseline or restricted")

    def _prepare(self):
        for path in (self.root / "data", self.directory):
            _plain(path)
            path.mkdir(exist_ok=True)

    @contextmanager
    def _lock(self):
        key = os.path.normcase(str(self.root))
        with _locks_guard:
            lock = _locks.setdefault(key, threading.Lock())
        _require(lock.acquire(blocking=False), "control_busy")
        stream = None
        acquired = False
        try:
            self._prepare()
            path = self.directory / ".control.lock"
            _plain(path)
            stream = path.open("a+b")
            if os.name == "nt":
                import msvcrt

                if stream.seek(0, os.SEEK_END) == 0:
                    stream.write(b"\0")
                    stream.flush()
                stream.seek(0)
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise _Failure("control_busy") from None
            else:
                import fcntl

                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise _Failure("control_busy") from None
            acquired = True
            yield
        finally:
            if stream is not None:
                try:
                    if acquired:
                        if os.name == "nt":
                            import msvcrt

                            stream.seek(0)
                            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                        else:
                            import fcntl

                            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                finally:
                    stream.close()
            lock.release()

    def _policy(self, environment, expected=None):
        settings = Settings(self.root / "config")  # Reload, never cache authorisation.
        ip, port, service, _ = ENDPOINTS[environment]
        _require(
            settings.scope.contains(ip) and not settings.scope.is_canary(ip),
            "endpoint_not_authorised",
        )
        policy = network_service_policy.load(settings.config_dir, settings.scope, ip)
        if policy is None:
            raise _Failure("endpoint_not_authorised")
        _require(
            policy.get("target_ip") == ip
            and any(
                type(row.get("port")) is int
                and row["port"] == port
                and row.get("transport") == "tcp"
                and row.get("service") == service
                for row in policy.get("endpoints", [])
            ),
            "endpoint_not_authorised",
        )
        digest = policy["policy_sha256"]
        _require(_identifier(digest), "invalid_policy_hash")
        _require(expected is None or digest == expected, "policy_changed")
        return digest

    def _files(self):
        for parent in (self.root / "labs", self.compose_directory):
            _plain(parent)
        files = [self.compose_directory / "compose.yaml"]
        live = self.compose_directory / "live.compose.yaml"
        _plain(live)
        if live.exists():
            files.append(live)
        for path in files:
            _plain(path)
            _require(path.is_file() and path.stat().st_size <= 65536, "invalid_compose_file")
        return files

    def _run(self, docker, arguments, commands, operation, environment, profile=None):
        # Receipts contain fixed argument enums, never stdout, stderr, paths,
        # credentials, environment values, or exception messages from Docker.
        commands.append(
            {
                "operation": operation,
                "environment": environment,
                **(
                    {"profile": profile, "arguments": [*UP, environment]}
                    if profile is not None
                    else {}
                ),
            }
        )
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("COMPOSE_", "DOCKER_"))
        }
        result = subprocess.run(
            [docker, *arguments],
            cwd=self.compose_directory,
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=90 if operation == "compose_up" else 20,
        )
        _require(result.returncode == 0, "docker_" + operation + "_failed")
        _require(len(result.stdout) <= 1048576, "docker_output_too_large")
        return result.stdout

    def _compose(self, files):
        # Explicit empty env file prevents implicit .env executable/file options.
        args = [
            "compose",
            "--project-name",
            PROJECT,
            "--project-directory",
            str(self.compose_directory),
            "--env-file",
            os.devnull,
        ]
        for path in files:
            args.extend(["-f", str(path)])
        return args

    def _inventory(self, docker, commands, environment, allow_missing=False):
        ids = self._run(
            docker,
            [
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                "label=com.docker.compose.project=" + PROJECT,
            ],
            commands,
            "list_containers",
            environment,
        ).split()
        _require(
            (5 if allow_missing else 6) <= len(ids) <= 11
            and len(set(ids)) == len(ids)
            and all(_identifier(item) for item in ids),
            "existing_project_required",
        )
        rows = _json(
            self._run(docker, ["inspect", *ids], commands, "inspect_containers", environment)
        )
        _require(isinstance(rows, list) and len(rows) == len(ids), "invalid_inventory")
        inventory = {}
        for row in rows:
            labels = row["Config"]["Labels"]
            service = labels.get("com.docker.compose.service")
            _require(labels.get("com.docker.compose.project") == PROJECT, "wrong_project")
            _require(
                service in BASE_SERVICES | LIVE_SERVICES
                and service not in inventory
                and labels.get("com.docker.compose.oneoff", "False").lower() == "false"
                and row["Id"] in ids,
                "unexpected_project_service",
            )
            inventory[service] = row
        required = BASE_SERVICES - {environment} if allow_missing else BASE_SERVICES
        _require(required <= inventory.keys(), "existing_project_required")
        if environment in inventory:
            namespace = "container:" + inventory[environment]["Id"]
            _require(
                all(
                    row["HostConfig"].get("NetworkMode")
                    not in (namespace, "service:" + environment)
                    for service, row in inventory.items()
                    if service != environment
                ),
                "peer_shares_backend_namespace",
            )
        return inventory

    @staticmethod
    def _siblings(inventory, environment):
        return {
            name: {
                "id": row["Id"],
                "image_id": row["Image"],
                "networks": row["NetworkSettings"]["Networks"],
                "network_mode": row["HostConfig"].get("NetworkMode"),
                "running": row["State"]["Running"],
                "started_at": row["State"].get("StartedAt"),
                "restart_count": row.get("RestartCount"),
                "sandbox_id": row["NetworkSettings"].get("SandboxID"),
            }
            for name, row in inventory.items()
            if name != environment
        }

    def _snapshot(self, docker, commands, environment, inventory):
        row = inventory[environment]
        host, config = row["HostConfig"], row["Config"]
        _require(
            _identifier(row["Id"])
            and isinstance(row["Image"], str)
            and _IMAGE.fullmatch(row["Image"]),
            "invalid_container_identity",
        )
        _require(
            config.get("User") == "10001:10001"
            and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False
            and "ALL" in (host.get("CapDrop") or [])
            and not host.get("CapAdd")
            and "no-new-privileges:true" in (host.get("SecurityOpt") or [])
            and host.get("NetworkMode") not in ("host", "none")
            and host.get("PidMode") != "host"
            and host.get("IpcMode") != "host"
            and not row.get("Mounts")
            and not host.get("Devices")
            and not any((row["NetworkSettings"].get("Ports") or {}).values()),
            "unsafe_backend_isolation",
        )
        _require(
            config.get("Cmd") == [environment]
            and config.get("Entrypoint") == ["python", "-m", "labs.service_networks.container"],
            "unexpected_backend_command",
        )
        name = PROJECT + "_" + environment
        joined = row["NetworkSettings"]["Networks"]
        _require(
            set(joined) == {name} and joined[name]["IPAddress"] == ENDPOINTS[environment][3],
            "unexpected_backend_network",
        )
        networks = _json(
            self._run(
                docker, ["network", "inspect", name], commands, "inspect_network", environment
            )
        )
        _require(isinstance(networks, list) and len(networks) == 1, "invalid_network")
        network = networks[0]
        _require(
            network.get("Name") == name
            and network.get("Internal") is True
            and _identifier(network.get("Id"))
            and network["Id"] == joined[name].get("NetworkID")
            and network.get("Labels", {}).get("com.docker.compose.project") == PROJECT
            and network.get("Labels", {}).get("com.docker.compose.network") == environment,
            "unexpected_network_project",
        )
        gateway = inventory[environment + "-gateway"]
        ip, port, _, _ = ENDPOINTS[environment]
        ports = gateway["NetworkSettings"].get("Ports") or {}
        _require(
            gateway["State"].get("Running") is True
            and ports.get(str(port) + "/tcp") == [{"HostIp": ip, "HostPort": str(port)}],
            "unexpected_gateway_endpoint",
        )
        _require(
            row["State"].get("Running") is True
            and row["State"].get("Health", {}).get("Status") == "healthy",
            "backend_not_healthy",
        )
        ready = _json(
            self._run(
                docker,
                ["exec", row["Id"], "cat", "/runtime/ready.json"],
                commands,
                "read_ready",
                environment,
            )
        )
        profile = ready.get("access_profile")
        _require(
            ready.get("environment") == environment
            and profile in PROFILES
            and type(ready.get("network_namespace")) is int
            and ready["network_namespace"] > 0,
            "invalid_startup_metadata",
        )
        primary = [
            service
            for service in ready["services"]
            if service.get("port") == port and service.get("protocol") == ENDPOINTS[environment][2]
        ]
        _require(
            len(primary) == 1 and primary[0].get("protected") is (profile == "restricted"),
            "startup_profile_mismatch",
        )
        configured = [
            entry.split("=", 1)[1]
            for entry in config.get("Env", [])
            if entry.startswith("VULNASSESS_LAB_ACCESS_PROFILE=")
        ]
        _require(configured in ([], [profile]), "configured_profile_mismatch")
        # Whitelist retained metadata: never copy the entire ready/inspect payload.
        return {
            "project": PROJECT,
            "id": row["Id"],
            "image_id": row["Image"],
            "network": name,
            "network_id": network["Id"],
            "private_ip": joined[name]["IPAddress"],
            "network_namespace": ready["network_namespace"],
            "access_profile": profile,
            "user": "10001:10001",
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "privileged": False,
            "health": "healthy",
        }

    def _inspect_image(self, docker, commands, environment, reference):
        images = _json(
            self._run(
                docker, ["image", "inspect", reference], commands, "inspect_image", environment
            )
        )
        _require(isinstance(images, list) and len(images) == 1, "invalid_lab_image")
        image = images[0]
        config = image.get("Config", {})
        _require(
            isinstance(image.get("Id"), str)
            and _IMAGE.fullmatch(image["Id"])
            and (reference == LOCAL_IMAGE or image["Id"] == reference)
            and config.get("User") == "10001:10001"
            and config.get("Entrypoint") == ["python", "-m", "labs.service_networks.container"]
            and "VULNASSESS_CONTAINER_LAB=1" in (config.get("Env") or []),
            "invalid_lab_image",
        )
        return image["Id"]

    def _select_image(self, docker, commands, environment, original):
        # Rebuilding the shared local tag can remove the old image record even
        # while containers still run from its layers. Never blindly pin that
        # unavailable ID, and never build/pull to recover it. Resolve only the
        # fixed local lab image and pin the inspected ID for forward + rollback.
        source = "running_image"
        try:
            identifier = self._inspect_image(docker, commands, environment, original["image_id"])
        except _Failure as error:
            if str(error) != "docker_inspect_image_failed":
                raise
            source = "fixed_local_image"
            try:
                identifier = self._inspect_image(docker, commands, environment, LOCAL_IMAGE)
            except _Failure as fallback_error:
                if str(fallback_error) == "docker_inspect_image_failed":
                    raise _Failure("lab_image_unavailable") from None
                raise
        return {"image_id": identifier, "source": source}

    def _check_config(self, docker, commands, environment, profile, files, original):
        document = _json(
            self._run(
                docker,
                [*self._compose(files), "config", "--format", "json"],
                commands,
                "compose_config",
                environment,
            )
        )
        spec = document["services"][environment]
        _require(
            document.get("name") == PROJECT
            and spec.get("image") == original["image_id"]
            and spec.get("command") == [environment]
            and spec.get("entrypoint")
            in (None, ["python", "-m", "labs.service_networks.container"])
            and spec.get("user") in (None, "10001:10001")
            and spec.get("read_only") is True
            and "ALL" in spec.get("cap_drop", [])
            and "no-new-privileges:true" in spec.get("security_opt", [])
            and not any(
                spec.get(key)
                for key in (
                    "privileged",
                    "cap_add",
                    "volumes",
                    "ports",
                    "devices",
                    "network_mode",
                    "post_start",
                    "pre_stop",
                    "use_api_socket",
                    "volumes_from",
                    "provider",
                )
            )
            and spec.get("pid") != "host"
            and spec.get("ipc") != "host"
            and set(spec.get("networks", {})) == {environment}
            and spec["networks"][environment].get("ipv4_address") == original["private_ip"]
            and spec.get("environment", {}).get("VULNASSESS_LAB_ACCESS_PROFILE") == profile,
            "unsafe_compose_configuration",
        )

    @staticmethod
    def _same_endpoint(original, current):
        _require(
            all(
                current[key] == original[key]
                for key in ("project", "image_id", "network", "network_id", "private_ip")
            ),
            "backend_identity_drift",
        )

    def _change(
        self,
        docker,
        commands,
        environment,
        profile,
        files,
        original,
        policy_hash,
        siblings,
        mark_mutated,
        rollback=False,
    ):
        payload = json.dumps(
            {
                "services": {
                    environment: {
                        "image": original["image_id"],
                        "environment": {"VULNASSESS_LAB_ACCESS_PROFILE": profile},
                    }
                }
            },
            separators=(",", ":"),
        )
        _require(len(payload) <= 1024, "override_too_large")
        with _temporary(self.directory, ".control-override-", payload) as override:
            self._inspect_image(docker, commands, environment, original["image_id"])
            selected = [*files, override]
            self._check_config(docker, commands, environment, profile, selected, original)
            current = self._inventory(docker, commands, environment, allow_missing=rollback)
            _require(self._siblings(current, environment) == siblings, "other_containers_changed")
            if not rollback:
                _require(
                    current[environment]["Id"] == original["id"], "backend_changed_before_mutation"
                )
            network = _json(
                self._run(
                    docker,
                    ["network", "inspect", original["network"]],
                    commands,
                    "inspect_network",
                    environment,
                )
            )
            _require(
                len(network) == 1
                and network[0].get("Id") == original["network_id"]
                and network[0].get("Internal") is True
                and network[0].get("Labels", {}).get("com.docker.compose.project") == PROJECT,
                "unexpected_network_project",
            )
            # No cached permission: this is the final check before each up, rollback included.
            self._policy(environment, policy_hash)
            mark_mutated()
            self._run(
                docker,
                [*self._compose(selected), *UP, environment],
                commands,
                "compose_up",
                environment,
                profile,
            )

    @staticmethod
    def _error(error):
        if isinstance(error, _Failure):
            return str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            return "docker_timeout"
        if isinstance(error, ConfigError):
            return "invalid_current_policy"
        return "invalid_or_unavailable_runtime"

    @staticmethod
    def _result(environment):
        return {
            "schema_version": 1,
            "environment": environment,
            "project": PROJECT,
            "at": datetime.now(UTC).isoformat(),
            "status": "failed",
            "profile": None,
            "before": None,
            "after": None,
            "commands": [],
            "verification_scope": "Docker isolation and startup configuration metadata only; no security clearance or protocol authentication audit.",
            "meaning": "IoT restricted is deny-all containment on 1883, with no provisioned accounts; it is not an authenticated production broker."
            if environment == "iot"
            else "Office restricted disables anonymous FTP on 2121; the runtime provisions named lab users. Startup generates fresh demonstration credentials.",
        }

    def profile(self, environment):
        self._validate(environment)
        result = self._result(environment)
        try:
            with self._lock():
                digest = self._policy(environment)
                docker = shutil.which("docker")
                _require(docker is not None, "docker_unavailable")
                inventory = self._inventory(docker, result["commands"], environment)
                snapshot = self._snapshot(docker, result["commands"], environment, inventory)
                self._policy(environment, digest)
                result.update(
                    status="verified",
                    profile=snapshot["access_profile"],
                    after=snapshot,
                    policy_sha256=digest,
                )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            RecursionError,
            ConfigError,
            _Failure,
            subprocess.SubprocessError,
        ) as error:
            result.update(status="failed", profile=None)
            result["error"] = self._error(error)
            if result["error"] == "control_busy":
                result["status"] = "busy"
        return result

    def _receipt(self, result):
        self._prepare()
        name = "control-" + uuid4().hex + ".json"
        result["receipt"] = "data/network-live/" + name
        payload = json.dumps(result, indent=2)
        _require(len(payload.encode("utf-8")) <= 65536, "receipt_too_large")
        with _temporary(self.directory, ".control-receipt-", payload) as temporary:
            os.replace(temporary, self.directory / name)

    def set_profile(self, environment, profile):
        result = self._set_profile(environment, profile)
        if result["status"] != "verified" or result.get("receipt_error"):
            if result.get("receipt_error"):
                result["status"] = "failed"
            raise LabControlError(result)
        return result

    def _set_profile(self, environment, profile):
        self._validate(environment)
        # None is invalid here, although profile() has no profile argument.
        if type(profile) is not str or profile not in PROFILES:
            raise ValueError("profile must be baseline or restricted")
        result = self._result(environment)
        result.update(
            requested_profile=profile, rollback={"attempted": False, "status": "not_needed"}
        )
        mutated = False
        rollback_context = None

        def mark_mutated():
            nonlocal mutated
            mutated = True  # A timeout/nonzero exit may already have replaced the container.

        try:
            with self._lock():
                try:
                    digest = self._policy(environment)
                    result["policy_sha256"] = digest
                    files = self._files()
                    docker = shutil.which("docker")
                    _require(docker is not None, "docker_unavailable")
                    inventory = self._inventory(docker, result["commands"], environment)
                    original = self._snapshot(docker, result["commands"], environment, inventory)
                    result["before"] = original
                    siblings = self._siblings(inventory, environment)
                    selection = self._select_image(
                        docker, result["commands"], environment, original
                    )
                    result["image_selection"] = selection
                    expected = {**original, "image_id": selection["image_id"]}
                    rollback_context = (digest, docker, original, files, expected, siblings)
                    self._change(
                        docker,
                        result["commands"],
                        environment,
                        profile,
                        files,
                        expected,
                        digest,
                        siblings,
                        mark_mutated,
                    )
                    inventory = self._inventory(docker, result["commands"], environment)
                    current = self._snapshot(docker, result["commands"], environment, inventory)
                    result["after"] = current
                    self._same_endpoint(expected, current)
                    _require(
                        self._siblings(inventory, environment) == siblings,
                        "other_containers_changed",
                    )
                    _require(current["access_profile"] == profile, "requested_profile_not_active")
                    _require(current["id"] != original["id"], "backend_not_recreated")
                    self._policy(environment, digest)
                    result.update(status="verified", profile=profile)
                except (
                    OSError,
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    RecursionError,
                    ConfigError,
                    _Failure,
                    subprocess.SubprocessError,
                ) as error:
                    result["error"] = self._error(error)
                    if mutated and rollback_context is not None:
                        digest, docker, original, files, expected, siblings = rollback_context
                        result["rollback"] = {
                            "attempted": False,
                            "status": "restoration_unverified",
                        }
                        try:
                            # A revoked/changed policy prevents another mutation. Do not
                            # retry, down, reset, prune or delete anything to recover.
                            self._policy(environment, digest)
                            self._change(
                                docker,
                                result["commands"],
                                environment,
                                original["access_profile"],
                                files,
                                expected,
                                digest,
                                siblings,
                                lambda: result["rollback"].update(attempted=True),
                                rollback=True,
                            )
                            restored_inventory = self._inventory(
                                docker, result["commands"], environment
                            )
                            restored = self._snapshot(
                                docker, result["commands"], environment, restored_inventory
                            )
                            result["rollback"]["after"] = restored
                            self._same_endpoint(expected, restored)
                            _require(
                                restored["access_profile"] == original["access_profile"],
                                "original_profile_not_restored",
                            )
                            _require(
                                self._siblings(restored_inventory, environment) == siblings,
                                "other_containers_changed",
                            )
                            self._policy(environment, digest)
                            result["rollback"]["status"] = "restored"
                            result["profile"] = restored["access_profile"]
                        except (
                            OSError,
                            ValueError,
                            TypeError,
                            KeyError,
                            AttributeError,
                            RecursionError,
                            ConfigError,
                            _Failure,
                            subprocess.SubprocessError,
                        ) as rollback_error:
                            result["rollback"]["error"] = self._error(rollback_error)
                self._receipt(result)
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            RecursionError,
            ConfigError,
            _Failure,
            subprocess.SubprocessError,
        ) as error:
            code = self._error(error)
            if code == "control_busy":
                result.update(status="busy", error=code)
                try:
                    self._receipt(result)
                except (OSError, ValueError, _Failure) as receipt_error:
                    result["receipt_error"] = self._error(receipt_error)
            else:
                result["receipt_error"] = code
        return result

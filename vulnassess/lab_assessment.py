"""Bounded full-lab runs and proof-gated comparison with reviewed configuration.

No detector is used to derive expected truth. Redis inventory does not establish
CVE applicability. This module never starts containers or invokes an AI provider.
"""

import copy
import hashlib
import json
import math
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

from vulnassess import network_service_policy
from vulnassess.errors import ConfigError
from vulnassess.schema import Finding
from vulnassess.settings import Settings

LIMIT = 1048576
SUITE_ID = re.compile(r"full-[a-f0-9]{32}\Z")
CASE_ID = re.compile(r"live-[a-f0-9]{32}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
PROJECT = "vulnassess-service-networks"
SOURCES = frozenset(
    {
        "labs/service_networks/office.py",
        "labs/service_networks/iot.py",
        "labs/service_networks/compose.yaml",
        "labs/service_networks/requirements.txt",
        "config/network-services.json",
    }
)
TARGETS = {"office": "127.0.0.2", "iot": "127.0.0.3"}
# Action -> immutable endpoint identity, in execution order.
ACTIONS = {
    "office": {
        "ftp-anonymous": (2121, "tcp", "ftp"),
        "ftp-protected": (2122, "tcp", "ftp"),
        "ssh-credential": (2222, "tcp", "ssh"),
        "ssh-protected": (2223, "tcp", "ssh"),
        "smb-read": (1445, "tcp", "smb"),
        "smb-protected": (1446, "tcp", "smb"),
        "redis-office": (6379, "tcp", "redis"),
    },
    "iot": {
        "mqtt-exchange": (1883, "tcp", "mqtt"),
        "mqtt-protected": (1884, "tcp", "mqtt"),
        "snmp-public": (1161, "udp", "snmp"),
        "snmp-protected": (1162, "udp", "snmp"),
        "tls-certificate": (8883, "tcp", "tls"),
        "redis-iot": (6379, "tcp", "redis"),
    },
}
FIELDS = {
    "authentication": {"anonymous_accepted", "public_community_read"},
    "signing": {"signing_required"},
    "credential": {"test_credential_accepted"},
    "certificate": {"expired"},
    "hostname": {"hostname_matches"},
    "chain": {"chain_verification_failed"},
}


def _now():
    return datetime.now(UTC).isoformat()


def _environment(environment):
    if type(environment) is not str or environment not in TARGETS:
        raise ConfigError("Choose the Office or IoT assessment")


def checksum(document):
    return hashlib.sha256(
        json.dumps(
            {key: value for key, value in document.items() if key != "sha256"},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _local(root, path):
    for part in (path, *path.parents):
        if part == root:
            return
        if part.is_symlink() or (
            part.exists() and getattr(part.lstat(), "st_file_attributes", 0) & 1024
        ):
            raise ConfigError("Assessment evidence must use local regular paths")
    raise ConfigError("Assessment path leaves the project")


def _read(root, path, limit=LIMIT):
    _local(root, path)
    if not path.is_file():
        raise ConfigError("Assessment source or evidence file is unavailable")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ConfigError("Assessment evidence exceeds its read budget")
    return raw


def _validate_inventory(inventory):
    if (
        not isinstance(inventory, dict)
        or type(inventory.get("schema_version")) is not int
        or inventory["schema_version"] != 1
        or inventory.get("inventory_id") != "office-iot-v1"
        or not isinstance(inventory.get("reviewed_by"), str)
        or not inventory["reviewed_by"].strip()
        or "pending" in inventory["reviewed_by"].lower()
        or set(inventory.get("sources", {})) != SOURCES
        or any(
            not isinstance(value, str) or not SHA.fullmatch(value)
            for value in inventory["sources"].values()
        )
        or set(inventory.get("environments", {})) != set(TARGETS)
    ):
        raise ValueError("Unsupported reviewed inventory")
    for environment, target in TARGETS.items():
        spec = inventory["environments"][environment]
        if not isinstance(spec.get("reviewed_image_id"), str) or not IMAGE_ID.fullmatch(
            spec["reviewed_image_id"]
        ):
            raise ValueError("Reviewed inventory requires an immutable image ID")
        if spec.get("target") != target or not isinstance(spec.get("conditions"), list):
            raise ValueError("Invalid inventory environment")
        if len(spec["conditions"]) != (8 if environment == "office" else 7):
            raise ValueError("Incomplete versioned inventory")
        seen = set()
        for row in spec["conditions"]:
            action = row["action"]
            identity = (row["port"], row["transport"], row["service"])
            key = (action, row["rule"])
            if (
                action not in ACTIONS[environment]
                or identity != ACTIONS[environment][action]
                or row["rule"] not in FIELDS
                or row["proof_field"] not in FIELDS[row["rule"]]
                or type(row["port"]) is not int
                or type(row["violation_value"]) is not bool
                or set(row["expected"]) != {"baseline", "restricted"}
                or any(type(value) is not bool for value in row["expected"].values())
                or not isinstance(row["id"], str)
                or not re.fullmatch(r"[a-z0-9-]{1,96}", row["id"])
                or row["id"] in seen
                or key in seen
                or not isinstance(row["description"], str)
                or len(row["description"]) > 1024
                or not isinstance(row["source"], str)
                or row["source"].split(":", 1)[0] != f"labs/service_networks/{environment}.py"
            ):
                raise ValueError("Invalid inventory condition")
            seen.update((key, row["id"]))
        rows = spec["inventory_only"]
        if (
            not isinstance(rows, list)
            or len(rows) != 1
            or rows[0].get("action") != "redis-" + environment
            or (rows[0].get("port"), rows[0].get("transport"), rows[0].get("service"))
            != (6379, "tcp", "redis")
        ):
            raise ValueError("Redis must remain inventory-only")
    return inventory


def _reviewed_image(inventory, environment):
    value = inventory["environments"][environment].get("reviewed_image_id") if inventory else None
    return value if isinstance(value, str) and IMAGE_ID.fullmatch(value) else None


def _case_matches(case, environment, action):
    return (
        isinstance(case, dict)
        and case.get("environment") == environment
        and case.get("action") == action
        and case.get("target") == TARGETS[environment]
        and (case.get("port"), case.get("transport")) == ACTIONS[environment][action][:2]
    )


def _proof(case):
    result = case.get("result")
    proof = result.get("proof") if isinstance(result, dict) else None
    return proof if isinstance(proof, dict) else {}


def _case_state(case):
    if case.get("policy_error") or case.get("error") or case.get("state") == "failed":
        return "failed"
    proof = _proof(case)
    result = case.get("result")
    decision = result.get("decision") if isinstance(result, dict) else None
    decision = decision if isinstance(decision, dict) else {}
    if proof.get("protocol_confirmed") is not True or decision.get("inconclusive"):
        return "inconclusive"
    if (
        str(case.get("action", "")).startswith("redis-")
        and proof.get("identity_established") is not True
    ):
        return "inconclusive"
    return "complete"


def _canonical(row):
    finding = row["finding"]
    fields = (
        finding["host_ip"],
        finding.get("port"),
        finding.get("protocol"),
        finding["tool"],
        finding["tool_native_id"],
        finding.get("url"),
    )
    return str(uuid5(NAMESPACE_URL, Finding.fingerprint(*fields)))


def _priority(row):
    score = row.get("score")
    risk = score.get("risk") if isinstance(score, dict) else None
    value = (
        risk
        if isinstance(risk, (int, float)) and not isinstance(risk, bool) and math.isfinite(risk)
        else 0
    )
    return -value, row["uid"]


def evaluate(inventory, environment, cases, ground_truth, endpoints=None):
    """Pure aggregation. Boolean protocol proof gates every confusion-matrix cell.

    A missing finding is a detector-negative prediction only after the condition
    has explicit boolean proof. Missing proof is never a negative observation.
    Individual completed fields survive a partially inconclusive protocol case.
    """
    _environment(environment)
    spec = inventory["environments"][environment] if inventory else {"conditions": []}
    profile = ground_truth.get("profile")
    reviewed_image = _reviewed_image(inventory, environment)
    verified = (
        ground_truth.get("status") == "verified"
        and profile in ("baseline", "restricted")
        and reviewed_image is not None
        and ground_truth.get("reviewed_image_id") == reviewed_image
    )
    conditions, aggregates, unexpected, warnings = [], {}, {}, []
    by_action = {
        action: [case for case in cases if _case_matches(case, environment, action)]
        for action in ACTIONS[environment]
    }
    definitions = {(row["action"], row["rule"]): row for row in spec["conditions"]}
    for case in cases:
        case_id = case.get("id")
        for row in case.get("findings", []):
            try:
                uid = _canonical(row)
                finding = row["finding"]
                rule = finding["tool_native_id"].rsplit(":", 1)[-1]
                definition = definitions.get((case.get("action"), rule))
                matched = (
                    definition is not None
                    and _case_matches(case, environment, case["action"])
                    and finding.get("host_ip") == TARGETS[environment]
                    and finding.get("port") == definition["port"]
                    and finding.get("protocol") == definition["transport"]
                )
                if uid not in aggregates:
                    aggregates[uid] = {
                        "uid": uid,
                        "case_id": case_id,
                        "case_ids": [],
                        "finding": copy.deepcopy(finding),
                        "score": copy.deepcopy(row.get("score", {})),
                        "guidance": copy.deepcopy(row.get("guidance", {})),
                        "score_observations": [],
                    }
                aggregate = aggregates[uid]
                if case_id and case_id not in aggregate["case_ids"]:
                    aggregate["case_ids"].append(case_id)
                observation = {"case_id": case_id, "score": copy.deepcopy(row.get("score", {}))}
                if observation not in aggregate["score_observations"]:
                    aggregate["score_observations"].append(observation)
                if row.get("score", {}) != aggregate["score"]:
                    warnings.append("duplicate_finding_scores_differ")
                if not matched:
                    unexpected[uid] = {
                        "uid": uid,
                        "case_ids": aggregate["case_ids"],
                        "rule": rule,
                        "reason": "not_in_reviewed_conditions",
                    }
            except (KeyError, TypeError, AttributeError, ValueError):
                warnings.append("malformed_finding_retained_in_case_reference")
    counts = {
        "true_positive": 0,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 0,
        "missed_untested": 0,
    }
    for definition in spec["conditions"]:
        candidates = by_action[definition["action"]]
        known, predicted = [], False
        for case in candidates:
            if case.get("policy_error"):
                continue
            proof = _proof(case)
            value = proof.get(definition["proof_field"])
            if proof.get("protocol_confirmed") is True and type(value) is bool:
                known.append(value == definition["violation_value"])
            for row in case.get("findings", []):
                finding = row.get("finding", {})
                if (
                    finding.get("host_ip") == TARGETS[environment]
                    and finding.get("port") == definition["port"]
                    and finding.get("protocol") == definition["transport"]
                    and str(finding.get("tool_native_id", "")).rsplit(":", 1)[-1]
                    == definition["rule"]
                ):
                    predicted = True
        observed = known[0] if known and len(set(known)) == 1 else None
        expected = definition["expected"].get(profile)
        reason = (
            "proof_unavailable" if not known else "conflicting_proof" if observed is None else None
        )
        state = "untested"
        if not verified:
            reason = "ground_truth_unverified"
        elif observed is not None:
            state = (
                ("true_positive" if predicted else "false_negative")
                if expected
                else ("false_positive" if predicted else "true_negative")
            )
            counts[state] += 1
        if verified and state == "untested" and expected is True:
            counts["missed_untested"] += 1
        conditions.append(
            {
                key: copy.deepcopy(definition[key])
                for key in ("id", "action", "port", "transport", "service", "rule", "description")
            }
            | {
                "expected": expected,
                "observed": observed,
                "predicted": predicted if observed is not None else None,
                "state": state,
                "reason": reason,
                "case_id": candidates[0].get("id") if candidates else None,
                "case_ids": [case["id"] for case in candidates if case.get("id")],
            }
        )
    tested = sum(row["observed"] is not None for row in conditions)
    untested = len(conditions) - tested
    metrics = None
    if verified:
        tp, fp, fn = (counts[key] for key in ("true_positive", "false_positive", "false_negative"))
        metrics = {
            **counts,
            "untested": untested,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "recall_scope": "tested conditions only; missed_untested is excluded from recall",
        }
    endpoints = (
        endpoints
        if endpoints is not None
        else [
            {"port": port, "transport": transport, "service": service}
            for port, transport, service in ACTIONS[environment].values()
        ]
    )
    endpoint_rows = []
    for endpoint in endpoints:
        action = next(
            (
                key
                for key, value in ACTIONS[environment].items()
                if value == (endpoint["port"], endpoint["transport"], endpoint["service"])
            ),
            None,
        )
        selected = by_action.get(action, []) if action is not None else []
        rows = [row for row in conditions if row["action"] == action]
        identity_only = endpoint["service"] == "redis"
        state = "skipped" if action is None else "untested"
        if identity_only and any(
            _proof(case).get("protocol_confirmed") is True
            and _proof(case).get("identity_established") is True
            and not case.get("policy_error")
            for case in selected
        ):
            state = "identity_only"
        elif rows and all(row["observed"] is not None for row in rows):
            state = "checked"
        endpoint_rows.append(
            {key: endpoint[key] for key in ("port", "transport", "service")}
            | {
                "action": action,
                "state": state,
                "case_id": selected[0].get("id") if selected else None,
                "cve_detection": "not_tested" if identity_only else "not_claimed",
            }
        )
    return {
        "conditions": conditions,
        "findings": sorted(aggregates.values(), key=_priority),
        "unexpected_findings": list(unexpected.values()),
        "warnings": sorted(set(warnings)),
        "metrics": metrics,
        "endpoints": endpoint_rows,
        "coverage": {
            "declared_endpoints": len(endpoints),
            "attempted_endpoints": len(
                {(case.get("port"), case.get("transport")) for case in cases}
            ),
            "known_conditions": len(conditions),
            "tested_conditions": tested,
            "untested_conditions": untested,
            "identity_only_endpoints": sum(row["service"] == "redis" for row in endpoints),
            "cve_detection": "not_tested",
            "complete_security_assessment": False,
        },
    }


class LabAssessment:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.directory = self.root / "data/network-live/assessments"
        # Publish fresh dictionaries so status readers obtain coherent snapshots.
        self.progress = {
            "running": False,
            "environment": None,
            "completed": 0,
            "total": 0,
            "action": None,
        }

    def _inventory(self):
        try:
            raw = _read(self.root, self.root / "labs/service_networks/expectations.json", 262144)
            inventory = _validate_inventory(json.loads(raw, object_pairs_hook=_unique))
            return inventory, hashlib.sha256(raw).hexdigest(), []
        except (
            ConfigError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            RecursionError,
        ):
            return None, None, ["inventory_unavailable_or_invalid"]

    def _sources(self, inventory):
        if inventory is None:
            return ["inventory_unavailable_or_invalid"]
        issues = []
        for source in sorted(SOURCES):
            try:
                digest = hashlib.sha256(_read(self.root, self.root / source)).hexdigest()
                if digest != inventory["sources"][source]:
                    issues.append("host_source_mismatch:" + source)
            except (ConfigError, OSError):
                issues.append("host_source_unavailable:" + source)
        return issues

    @staticmethod
    def _runtime(lab, environment):
        try:
            result = lab.control.profile(environment)
            snapshot = result.get("after") or {}
            return {
                "status": result.get("status"),
                "profile": result.get("profile"),
                "policy_sha256": result.get("policy_sha256"),
                "after": {
                    key: snapshot.get(key)
                    for key in (
                        "project",
                        "id",
                        "image_id",
                        "access_profile",
                        "network_id",
                        "network_namespace",
                        "private_ip",
                    )
                },
            }
        except Exception:
            return {"status": "unavailable", "after": {}}

    @staticmethod
    def _source(lab, environment):
        try:
            receipt = lab.traffic.source_receipt(environment)
            return {key: receipt.get(key) for key in ("available", "container_id", "source_sha256")}
        except Exception:
            return {"available": False, "container_id": None, "source_sha256": None}

    @staticmethod
    def _ground_truth(inventory, before, after, source_before, source_after, issues, policy_hash):
        issues = list(issues)
        reviewed_image = _reviewed_image(inventory, before["environment"])
        if reviewed_image is None:
            issues.append("reviewed_image_unavailable")
        for label, runtime, source in (
            ("before", before, source_before),
            ("after", after, source_after),
        ):
            row = runtime.get("after", {})
            if (
                runtime.get("status") != "verified"
                or runtime.get("profile") not in ("baseline", "restricted")
                or row.get("access_profile") != runtime.get("profile")
                or row.get("project") != PROJECT
                or not isinstance(row.get("id"), str)
                or not SHA.fullmatch(row["id"])
                or not isinstance(row.get("image_id"), str)
                or not IMAGE_ID.fullmatch(row["image_id"])
                or not isinstance(row.get("network_id"), str)
                or not SHA.fullmatch(row["network_id"])
                or type(row.get("network_namespace")) is not int
                or row["network_namespace"] <= 0
                or row.get("private_ip")
                != {"office": "172.30.41.2", "iot": "172.30.42.2"}.get(before.get("environment"))
            ):
                issues.append("runtime_profile_unverified:" + label)
            if reviewed_image is not None and row.get("image_id") != reviewed_image:
                issues.append("runtime_image_not_reviewed:" + label)
            if runtime.get("policy_sha256") != policy_hash or not policy_hash:
                issues.append("runtime_policy_mismatch:" + label)
            if (
                source.get("available") is not True
                or source.get("container_id") != row.get("id")
                or inventory is None
                or source.get("source_sha256")
                != inventory["sources"].get(
                    f"labs/service_networks/{before.get('environment', '')}.py"
                )
            ):
                # Environment is supplied on the capture by run().
                issues.append("runtime_source_unverified:" + label)
        for key in (
            "id",
            "image_id",
            "access_profile",
            "network_id",
            "network_namespace",
            "private_ip",
        ):
            if before.get("after", {}).get(key) != after.get("after", {}).get(key):
                issues.append("runtime_drift:" + key)
        if before.get("profile") != after.get("profile"):
            issues.append("runtime_drift:profile")
        if inventory and inventory["sources"]["config/network-services.json"] != policy_hash:
            issues.append("policy_manifest_mismatch")
        return {
            "status": "unverified" if issues else "verified",
            "issues": sorted(set(issues)),
            "profile": before.get("profile"),
            "inventory_id": inventory["inventory_id"] if inventory else None,
            "reviewed_by": inventory["reviewed_by"] if inventory else None,
            "reviewed_image_id": reviewed_image,
        }

    def _save(self, suite):
        _local(self.root, self.directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        suite["sha256"] = checksum(suite)
        raw = json.dumps(suite, indent=2, allow_nan=False).encode()
        if len(raw) > LIMIT:
            raise ConfigError("Assessment exceeds the 1 MiB evidence budget")
        destination = self.directory / (suite["id"] + ".json")
        _local(self.root, destination)
        temporary = self.directory / ("." + suite["id"] + "." + uuid4().hex + ".tmp")
        identity = None
        try:
            with temporary.open("xb") as stream:
                identity = os.fstat(stream.fileno())
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            if identity is not None and temporary.exists():
                current = temporary.lstat()
                if not temporary.is_symlink() and (identity.st_dev, identity.st_ino) == (
                    current.st_dev,
                    current.st_ino,
                ):
                    temporary.unlink()

    def load(self, identifier):
        if type(identifier) is not str or not SUITE_ID.fullmatch(identifier):
            raise ConfigError("Unknown full-lab assessment")
        try:
            suite = json.loads(
                _read(self.root, self.directory / (identifier + ".json")), object_pairs_hook=_unique
            )
            if (
                suite.get("id") != identifier
                or type(suite.get("schema_version")) is not int
                or suite["schema_version"] != 1
                or suite.get("environment") not in TARGETS
                or suite.get("sha256") != checksum(suite)
                or not isinstance(suite.get("finished_at"), str)
                or not isinstance(suite.get("checks"), list)
                or not isinstance(suite.get("ground_truth"), dict)
            ):
                raise ValueError("Assessment integrity failed")
            return suite
        except (OSError, ValueError, TypeError, AttributeError, RecursionError) as error:
            raise ConfigError("Full-lab assessment is unavailable or has changed") from error

    def history(self, environment):
        _environment(environment)
        _local(self.root, self.directory)
        if not self.directory.exists():
            return []
        candidates = []
        for path in self.directory.glob("full-*.json"):
            try:
                _local(self.root, path)
                candidates.append((path.lstat().st_mtime_ns, path.name, path))
            except (ConfigError, OSError):
                continue
        paths = [item[2] for item in sorted(candidates, reverse=True)[:200]]
        rows = []
        for path in paths:
            try:
                suite = self.load(path.stem)
                if suite["environment"] == environment:
                    rows.append(suite)
            except ConfigError:
                continue
        return sorted(rows, key=lambda row: row["finished_at"], reverse=True)[:12]

    @staticmethod
    def _recover(lab, environment, action, seen, started):
        try:
            candidates = [
                case
                for case in lab.history(environment)
                if _case_matches(case, environment, action)
                and case.get("id") not in seen
                and case.get("started_at", "") >= started
            ]
            return candidates[0] if len(candidates) == 1 else None
        except Exception:
            return None

    @staticmethod
    def _compact(case):
        # No capture packets/PCAP, AI output, arbitrary response text or credentials.
        fields = {field for values in FIELDS.values() for field in values} | {
            "protocol_confirmed",
            "identity_established",
            "redis_version",
            "cpe",
            "response_sha256",
        }
        proof = _proof(case)
        return {
            key: copy.deepcopy(case.get(key))
            for key in (
                "id",
                "action",
                "environment",
                "target",
                "port",
                "transport",
                "policy_sha256",
                "started_at",
                "finished_at",
                "sha256",
                "evidence_sha256",
                "evidence_url",
            )
        } | {
            "state": _case_state(case),
            "policy_error": bool(case.get("policy_error")),
            "result": {"proof": {key: value for key, value in proof.items() if key in fields}},
        }

    def run(self, lab, environment):
        _environment(environment)
        _local(self.root, self.directory)
        settings = Settings(self.root / "config")
        if not settings.scope.contains(TARGETS[environment]) or settings.scope.is_canary(
            TARGETS[environment]
        ):
            raise ConfigError("This lab is not authorised by current scope")
        if not lab.lock.acquire(blocking=False):
            raise ConfigError("A lab operation is already running")
        try:
            self.progress = {
                "running": True,
                "environment": environment,
                "completed": 0,
                "total": len(ACTIONS[environment]),
                "action": None,
            }
            suite = {
                "schema_version": 1,
                "id": "full-" + uuid4().hex,
                "environment": environment,
                "target": TARGETS[environment],
                "started_at": _now(),
                "status": "recorded",
                "checks": [],
                "cases": [],
            }
            inventory, inventory_sha, issues = self._inventory()
            issues += self._sources(inventory)
            try:
                policy = network_service_policy.load(
                    settings.config_dir, settings.scope, TARGETS[environment]
                )
            except (ConfigError, OSError, ValueError):
                policy = None
            if not policy:
                issues.append("endpoint_policy_unavailable")
            endpoints = (
                [
                    {key: row[key] for key in ("port", "transport", "service")}
                    for row in policy["endpoints"]
                ]
                if policy
                else []
            )
            policy_hash = policy["policy_sha256"] if policy else None
            unsupported = [
                row
                for row in endpoints
                if (row["port"], row["transport"], row["service"])
                not in ACTIONS[environment].values()
            ]
            self.progress = {**self.progress, "total": len(ACTIONS[environment]) + len(unsupported)}
            before = self._runtime(lab, environment)
            before["environment"] = environment
            source_before = self._source(lab, environment)
            cases = []
            try:
                seen = {row["id"] for row in lab.history(environment)}
            except Exception:
                seen = set()
            for index, (action, (port, transport, service)) in enumerate(
                ACTIONS[environment].items()
            ):
                self.progress = {**self.progress, "completed": index, "action": action}
                check = {
                    "action": action,
                    "port": port,
                    "transport": transport,
                    "service": service,
                    "state": "skipped",
                    "case_id": None,
                    "error": None,
                    "findings_count": 0,
                }
                suite["checks"].append(check)
                if {"port": port, "transport": transport, "service": service} not in endpoints:
                    check["error"] = "endpoint_not_authorised"
                    continue
                if hasattr(lab, "actions") and action not in lab.actions:
                    check["error"] = "operation_unsupported"
                    continue
                started = _now()
                try:
                    case = lab._operation(environment, action, kind="full_assessment")
                    if not isinstance(case, dict) or not _case_matches(case, environment, action):
                        raise ValueError("Operation returned unrelated evidence")
                    check["state"] = _case_state(case)
                except Exception as error:
                    check.update(
                        state="failed", error="operation_failed:" + type(error).__name__[:64]
                    )
                    case = self._recover(lab, environment, action, seen, started)
                if case is not None:
                    if not isinstance(case.get("id"), str) or not CASE_ID.fullmatch(case["id"]):
                        check.update(state="failed", error="invalid_case_identifier")
                        continue
                    seen.add(case["id"])
                    cases.append(case)
                    check.update(case_id=case["id"], findings_count=len(case.get("findings", [])))
                    compact = self._compact(case)
                    compact["state"] = check["state"]
                    suite["cases"].append(compact)
            suite["checks"].extend(
                {
                    **row,
                    "action": None,
                    "state": "skipped",
                    "case_id": None,
                    "error": "operation_unsupported",
                    "findings_count": 0,
                }
                for row in unsupported
            )
            self.progress = {**self.progress, "completed": self.progress["total"], "action": None}
            after = self._runtime(lab, environment)
            source_after = self._source(lab, environment)
            issues += self._sources(inventory)
            _, current_inventory_sha, current_issues = self._inventory()
            issues += current_issues
            if current_inventory_sha != inventory_sha:
                issues.append("inventory_changed_during_run")
            for case in cases:
                if case.get("policy_sha256") != policy_hash:
                    issues.append("case_policy_mismatch")
            truth = self._ground_truth(
                inventory, before, after, source_before, source_after, issues, policy_hash
            )
            truth["inventory_sha256"] = inventory_sha
            suite.update(evaluate(inventory, environment, cases, truth, endpoints))
            suite["ground_truth"] = truth
            suite["runtime"] = {
                "before": before,
                "after": after,
                "source_before": source_before,
                "source_after": source_after,
            }
            suite["warnings"] = sorted(
                set(
                    suite["warnings"]
                    + truth["issues"]
                    + [
                        "Redis INFO server provides identity only; CVE applicability and exploitability are not tested.",
                        "Configuration expectations are a reviewed local fixture, not an external benchmark or security clearance.",
                    ]
                )
            )
            suite["coverage"]["attempted_endpoints"] = sum(
                row["state"] != "skipped" for row in suite["checks"]
            )
            if any(row["state"] != "complete" for row in suite["checks"]):
                suite["status"] = "partial"
            suite["finished_at"] = _now()
            suite["evidence_url"] = f"/api/network-live/assessment/{suite['id']}.json"
            self._save(suite)
            return suite
        finally:
            self.progress = {**self.progress, "running": False, "action": None}
            lab.lock.release()

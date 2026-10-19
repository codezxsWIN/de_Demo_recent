"""Blind, hash-bound expert-evaluation cohorts.

Cohorts expose raw scanner and host evidence, never system scores, ranks,
rationales, inferred context, or learned-model predictions.
"""

import json
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from pathlib import Path
from typing import Any, Sequence

import yaml

from vulnassess.assessment_snapshot import validate_snapshot as validate_assessment_snapshot
from vulnassess.audit import load_json_payload
from vulnassess.errors import ConfigError

COHORT_SCHEMA_VERSION = 1
MIN_CONFIRMATORY_FINDINGS = 20
MAX_CONFIRMATORY_FINDINGS = 50
MAX_COHORT_BYTES = 64 * 1024 * 1024
METRICS = (
    "kendall_tau_b_per_expert",
    "kendall_w_tie_corrected",
    "ndcg_at_10",
    "critical_queue_at_full_recall",
)
TIE_POLICY = (
    "experts may use nested lists for tied findings; system score ties are whole queue blocks; "
    "critical queue includes every item in the terminal tied block"
)


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(payload: Any) -> str:
    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _is_hex_digest(value: str, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _is_sha256(value: str) -> bool:
    return _is_hex_digest(value, 64)


def _flatten(order: Sequence[Any]) -> list[str]:
    result: list[str] = []
    for entry in order:
        if isinstance(entry, (list, tuple)):
            result.extend(str(item) for item in entry)
        else:
            result.append(str(entry))
    return result


@dataclass(frozen=True)
class CohortManifest:
    cohort_id: str
    run_id: str
    finding_ids: tuple[str, ...]
    item_hashes: dict[str, str]
    snapshot_hash: str
    config_hash: str
    weights_hash: str
    feed_snapshot_hash: str
    model_hash: str | None
    grouping_map: dict[str, tuple[str, ...]]
    evidence_status: str
    created_on: str
    reviewer: str | None = None
    approval_id: str | None = None
    finding_mode: str = "raw"
    metrics: tuple[str, ...] = METRICS
    ndcg_k: int = 10
    tie_policy: str = TIE_POLICY
    schema_version: int = COHORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        # Validate before stripping, iterating, or comparing. Coercion would let
        # distinct JSON values reuse the digest of a different valid manifest.
        if type(self.schema_version) is not int or self.schema_version != COHORT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {COHORT_SCHEMA_VERSION}")
        if type(self.ndcg_k) is not int or self.ndcg_k != 10:
            raise ValueError("the preregistered NDCG cutoff is integer 10")
        for name in (
            "cohort_id",
            "run_id",
            "snapshot_hash",
            "config_hash",
            "weights_hash",
            "feed_snapshot_hash",
            "finding_mode",
            "evidence_status",
            "created_on",
            "tie_policy",
        ):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"{name} must be a string")
        for name in ("reviewer", "approval_id", "model_hash"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string or null")
        for name in ("finding_ids", "metrics"):
            values = getattr(self, name)
            if not isinstance(values, (list, tuple)) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise ValueError(f"{name} must be a sequence of nonblank strings")
        if not isinstance(self.item_hashes, dict) or any(
            not isinstance(key, str) or not key.strip() or not isinstance(value, str)
            for key, value in self.item_hashes.items()
        ):
            raise ValueError("item_hashes must map string finding IDs to string digests")
        if not isinstance(self.grouping_map, dict) or any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(values, (list, tuple))
            or any(not isinstance(value, str) or not value.strip() for value in values)
            for key, values in self.grouping_map.items()
        ):
            raise ValueError("grouping_map must map string finding IDs to string sequences")
        if not self.cohort_id.strip() or not self.run_id.strip():
            raise ValueError("cohort_id and run_id are required")
        if not _is_hex_digest(self.config_hash, 16):
            raise ValueError("config_hash must be a 16-character lowercase hexadecimal digest")
        for name, value in (
            ("snapshot_hash", self.snapshot_hash),
            ("weights_hash", self.weights_hash),
            ("feed_snapshot_hash", self.feed_snapshot_hash),
        ):
            if not _is_sha256(value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if any(not _is_sha256(value) for value in self.item_hashes.values()):
            raise ValueError("every item_hash must be a lowercase SHA-256 digest")
        if self.model_hash is not None and not _is_hex_digest(self.model_hash, 16):
            raise ValueError("model_hash must be a 16-character lowercase hexadecimal digest")
        if self.finding_mode != "raw":
            raise ValueError("only raw cohorts are supported until unification is approved")
        if len(self.finding_ids) != len(set(self.finding_ids)):
            raise ValueError("finding_ids contains duplicates")
        if not self.finding_ids:
            raise ValueError("cohort must contain at least one finding")
        if set(self.item_hashes) != set(self.finding_ids):
            raise ValueError("item_hashes must cover exactly the cohort finding IDs")
        if set(self.grouping_map) != set(self.finding_ids):
            raise ValueError("grouping_map must cover exactly the cohort finding IDs")
        if any(tuple(raw_ids) != (cohort_id,) for cohort_id, raw_ids in self.grouping_map.items()):
            raise ValueError("raw cohort grouping_map entries must map each finding to itself")
        if tuple(self.metrics) != METRICS or self.tie_policy != TIE_POLICY:
            raise ValueError("cohort metric definitions or tie policy differ from preregistration")
        try:
            date.fromisoformat(self.created_on)
        except ValueError as error:
            raise ValueError("created_on must be an ISO date") from error
        if self.evidence_status not in ("VERIFIED", "NOT RUN"):
            raise ValueError("evidence_status must be VERIFIED or NOT RUN")
        if self.evidence_status == "VERIFIED":
            if not MIN_CONFIRMATORY_FINDINGS <= len(self.finding_ids) <= MAX_CONFIRMATORY_FINDINGS:
                raise ValueError(
                    f"VERIFIED cohort size must be {MIN_CONFIRMATORY_FINDINGS}-"
                    f"{MAX_CONFIRMATORY_FINDINGS} findings"
                )
            if not (self.reviewer or "").strip() or not (self.approval_id or "").strip():
                raise ValueError("VERIFIED cohort requires reviewer and approval_id")

    def core_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "cohort_id": self.cohort_id,
            "run_id": self.run_id,
            "finding_mode": self.finding_mode,
            "finding_ids": list(self.finding_ids),
            "item_hashes": dict(sorted(self.item_hashes.items())),
            "snapshot_hash": self.snapshot_hash,
            "config_hash": self.config_hash,
            "weights_hash": self.weights_hash,
            "feed_snapshot_hash": self.feed_snapshot_hash,
            "model_hash": self.model_hash,
            "grouping_map": {key: list(value) for key, value in sorted(self.grouping_map.items())},
            "evidence_status": self.evidence_status,
            "created_on": self.created_on,
            "reviewer": self.reviewer,
            "approval_id": self.approval_id,
            "metrics": list(self.metrics),
            "ndcg_k": self.ndcg_k,
            "tie_policy": self.tie_policy,
        }

    @property
    def manifest_hash(self) -> str:
        return _digest(self.core_json())

    def to_json(self) -> dict[str, Any]:
        return {**self.core_json(), "manifest_hash": self.manifest_hash}


def blinded_items(snapshot: dict[str, Any], finding_ids: Sequence[str]) -> list[dict[str, Any]]:
    """Select stable raw evidence without leaking any system output."""
    findings = {item["id"]: item for item in snapshot.get("findings", [])}
    hosts = {item["ip"]: item for item in snapshot.get("hosts", [])}
    requested = tuple(sorted(set(finding_ids)))
    if len(requested) != len(finding_ids):
        raise ConfigError("cohort finding IDs contain duplicates")
    missing = sorted(set(requested) - set(findings))
    if missing:
        raise ConfigError(f"cohort finding {missing[0]!r} is not in the assessment snapshot")
    result = []
    for finding_id in requested:
        finding = findings[finding_id]
        host = hosts.get(finding["host_ip"])
        if host is None:
            raise ConfigError(
                f"cohort finding {finding_id!r} references missing host {finding['host_ip']!r}"
            )
        result.append(
            {
                "finding_id": finding_id,
                "finding": {
                    key: finding.get(key)
                    for key in (
                        "host_ip",
                        "port",
                        "protocol",
                        "url",
                        "tool",
                        "tool_native_id",
                        "title",
                        "description",
                        "evidence",
                        "cve_ids",
                        "cwe_ids",
                        "reference_urls",
                        "native_severity",
                        "native_confidence",
                        "first_seen",
                        "last_seen",
                        "provenance",
                    )
                },
                "host_evidence": {
                    "ip": host.get("ip"),
                    "hostname": host.get("hostname"),
                    "os_guess": host.get("os_guess"),
                    "services": host.get("services", []),
                },
            }
        )
    return result


def freeze_cohort(
    snapshot: dict[str, Any],
    finding_ids: Sequence[str],
    *,
    cohort_id: str,
    created_on: str,
    evidence_status: str,
    reviewer: str | None = None,
    approval_id: str | None = None,
    finding_mode: str = "raw",
) -> tuple[CohortManifest, list[dict[str, Any]]]:
    validate_assessment_snapshot(snapshot)
    items = blinded_items(snapshot, finding_ids)
    item_hashes = {item["finding_id"]: _digest(item) for item in items}
    feed_snapshot_hash = _digest(snapshot.get("feed_snapshot", {}))
    config = snapshot.get("configuration", {})
    try:
        manifest = CohortManifest(
            cohort_id=cohort_id,
            run_id=str(snapshot["run"]["run_id"]),
            finding_mode=finding_mode,
            finding_ids=tuple(item["finding_id"] for item in items),
            item_hashes=item_hashes,
            snapshot_hash=str(snapshot["snapshot_hash"]),
            config_hash=str(config["hash_at_run_start"]),
            weights_hash=_digest(config["validated"]["weights.yaml"]),
            feed_snapshot_hash=feed_snapshot_hash,
            model_hash=snapshot.get("model_hash"),
            grouping_map={item["finding_id"]: (item["finding_id"],) for item in items},
            evidence_status=evidence_status,
            created_on=created_on,
            reviewer=reviewer,
            approval_id=approval_id,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigError(f"cannot freeze cohort: {error}") from error
    return manifest, items


def save_cohort(
    manifest: CohortManifest,
    items: Sequence[dict[str, Any]],
    directory: str | Path,
) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    expected = {item["finding_id"]: _digest(item) for item in items}
    if expected != manifest.item_hashes:
        raise ConfigError("cohort item content does not match the manifest hashes")
    manifest_path = directory / "manifest.json"
    evidence_path = directory / "evidence.json"
    template_path = directory / "expert-ranking-template.yaml"
    manifest_path.write_text(_canonical(manifest.to_json()) + "\n", encoding="utf-8")
    evidence_path.write_text(_canonical(list(items)) + "\n", encoding="utf-8")
    template = {
        "cohort_id": manifest.cohort_id,
        "cohort_hash": manifest.manifest_hash,
        "evidence_status": "NOT RUN",
        "data_kind": "human_input_pending",
        "experts": [
            {
                "name": None,
                "reviewer": None,
                "provenance": None,
                "ranking": [],
                "critical": [],
            }
        ],
    }
    template_path.write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
    return directory


def load_manifest(path: str | Path) -> CohortManifest:
    path = Path(path)
    payload = load_json_payload(path, "cohort manifest", max_bytes=MAX_COHORT_BYTES)
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid cohort manifest {path}: expected an object")
    claimed = payload.pop("manifest_hash", None)
    allowed = set(CohortManifest.__dataclass_fields__)
    extra = sorted(set(payload) - allowed)
    if extra:
        raise ConfigError(f"invalid cohort manifest {path}: unknown key {extra[0]!r}")
    try:
        for name in ("finding_ids", "metrics"):
            if not isinstance(payload[name], list):
                raise ValueError(f"{name} must be a JSON array")
        if not isinstance(payload["grouping_map"], dict) or any(
            not isinstance(values, list) for values in payload["grouping_map"].values()
        ):
            raise ValueError("grouping_map must be an object of JSON arrays")
        manifest = CohortManifest(
            schema_version=payload["schema_version"],
            cohort_id=payload["cohort_id"],
            run_id=payload["run_id"],
            finding_mode=payload["finding_mode"],
            finding_ids=tuple(payload["finding_ids"]),
            item_hashes=payload["item_hashes"],
            snapshot_hash=payload["snapshot_hash"],
            config_hash=payload["config_hash"],
            weights_hash=payload["weights_hash"],
            feed_snapshot_hash=payload["feed_snapshot_hash"],
            model_hash=payload.get("model_hash"),
            grouping_map={key: tuple(values) for key, values in payload["grouping_map"].items()},
            evidence_status=payload["evidence_status"],
            created_on=payload["created_on"],
            reviewer=payload.get("reviewer"),
            approval_id=payload.get("approval_id"),
            metrics=tuple(payload["metrics"]),
            ndcg_k=payload["ndcg_k"],
            tie_policy=payload["tie_policy"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigError(f"invalid cohort manifest {path}: {error}") from error
    if claimed != manifest.manifest_hash:
        raise ConfigError(
            f"cohort manifest hash mismatch: artifact says {claimed!r}, "
            f"computed {manifest.manifest_hash!r}"
        )
    return manifest


def validate_snapshot_against_manifest(
    snapshot: dict[str, Any], manifest: CohortManifest
) -> list[dict[str, Any]]:
    validate_assessment_snapshot(snapshot)
    if snapshot["snapshot_hash"] != manifest.snapshot_hash:
        raise ConfigError("assessment snapshot hash does not match the cohort manifest")
    if str(snapshot["run"].get("run_id")) != manifest.run_id:
        raise ConfigError("assessment snapshot run does not match the cohort manifest")
    config = snapshot["configuration"]
    if config.get("hash_at_run_start") != manifest.config_hash:
        raise ConfigError("assessment snapshot configuration does not match the cohort manifest")
    if _digest(config["validated"]["weights.yaml"]) != manifest.weights_hash:
        raise ConfigError("assessment snapshot weights do not match the cohort manifest")
    if _digest(snapshot["feed_snapshot"]) != manifest.feed_snapshot_hash:
        raise ConfigError("assessment snapshot feeds do not match the cohort manifest")
    if snapshot.get("model_hash") != manifest.model_hash:
        raise ConfigError("assessment snapshot model does not match the cohort manifest")
    items = blinded_items(snapshot, manifest.finding_ids)
    item_hashes = {item["finding_id"]: _digest(item) for item in items}
    if item_hashes != manifest.item_hashes:
        raise ConfigError("assessment snapshot evidence does not match the cohort manifest")
    return items


def load_evidence(path: str | Path, manifest: CohortManifest) -> list[dict[str, Any]]:
    path = Path(path)
    payload = load_json_payload(path, "cohort evidence", max_bytes=MAX_COHORT_BYTES)
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise ConfigError(f"invalid cohort evidence {path}: expected a list of objects")
    try:
        item_hashes = {str(item["finding_id"]): _digest(item) for item in payload}
    except KeyError as error:
        raise ConfigError(f"invalid cohort evidence {path}: missing finding_id") from error
    if len(item_hashes) != len(payload):
        raise ConfigError(f"invalid cohort evidence {path}: duplicate finding_id")
    if item_hashes != manifest.item_hashes:
        raise ConfigError("cohort evidence content does not match the frozen manifest")
    return payload


def validate_truth_against_cohort(
    truth: dict[str, Any], manifest: CohortManifest
) -> dict[str, Any]:
    if truth.get("cohort_id") != manifest.cohort_id:
        raise ConfigError("expert truth cohort_id does not match the frozen manifest")
    if truth.get("cohort_hash") != manifest.manifest_hash:
        raise ConfigError("expert truth cohort_hash does not match the frozen manifest")
    if truth.get("evidence_status") == "VERIFIED" and manifest.evidence_status != "VERIFIED":
        raise ConfigError("VERIFIED expert truth requires a VERIFIED cohort manifest")
    expected = set(manifest.finding_ids)
    experts = truth.get("experts")
    if not isinstance(experts, list) or not experts:
        raise ConfigError("expert truth requires a non-empty experts list")
    default_critical = truth.get("expert_critical", [])
    for expert in experts:
        if not isinstance(expert, dict) or "name" not in expert or "ranking" not in expert:
            raise ConfigError("every expert truth entry requires name and ranking")
        actual = _flatten(expert.get("ranking", []))
        if len(actual) != len(set(actual)):
            raise ConfigError(f"expert {expert.get('name')!r} ranks a finding more than once")
        missing = sorted(expected - set(actual))
        extra = sorted(set(actual) - expected)
        if missing or extra:
            raise ConfigError(
                f"expert {expert.get('name')!r} does not exactly cover the cohort; "
                f"missing={missing}, extra={extra}"
            )
        critical = {str(value) for value in expert.get("critical", default_critical)}
        outside = sorted(critical - expected)
        if outside:
            raise ConfigError(
                f"expert {expert.get('name')!r} critical set contains non-cohort ID {outside[0]!r}"
            )
    return truth

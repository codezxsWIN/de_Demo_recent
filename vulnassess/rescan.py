"""Conservative post-remediation comparison for pipeline stage 8.

A missing finding is never called fixed without comparable successful coverage
and a parseable version increase on the affected service.
"""

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

from vulnassess.audit import load_json_payload
from vulnassess.errors import ConfigError
from vulnassess.schema import Finding, Host, ScoreBreakdown, Service

OUTCOMES = (
    "still_open",
    "fixed_candidate",
    "not_observable",
    "new_finding",
    "regression_candidate",
)
OBSERVATION_SCHEMA_VERSION = 1
MAX_OBSERVATION_BYTES = 64 * 1024 * 1024
EVIDENCE_STATUSES = ("VERIFIED", "TESTED WITH MOCKS", "NOT RUN", "MISSING")


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


@dataclass(frozen=True)
class CoverageRecord:
    host_ip: str
    tool: str
    status: str
    scanner_fingerprint: str
    endpoints: tuple[str, ...] = ()
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in ("success", "failed", "skipped"):
            raise ValueError("coverage status must be success, failed, or skipped")
        if not self.scanner_fingerprint.strip():
            raise ValueError("scanner_fingerprint is required")

    def to_json(self) -> dict[str, Any]:
        return {
            "host_ip": self.host_ip,
            "tool": self.tool,
            "status": self.status,
            "scanner_fingerprint": self.scanner_fingerprint,
            "endpoints": list(self.endpoints),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RunObservation:
    run_id: str
    findings: tuple[Finding, ...]
    hosts: tuple[Host, ...]
    coverage: tuple[CoverageRecord, ...]
    config_hash: str
    feed_snapshot_hash: str
    scope_hash: str


@dataclass(frozen=True)
class ObservationArtifact:
    observation: RunObservation
    scores: tuple[ScoreBreakdown, ...]
    evidence_status: str
    artifact_hash: str


@dataclass(frozen=True)
class RescanItem:
    finding_id: str
    host_ip: str
    title: str
    tool: str
    outcome: str
    evidence: str
    evidence_loss: bool = False
    risk_before: float | None = None
    risk_after: float | None = None
    band_before: str | None = None
    band_after: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "host_ip": self.host_ip,
            "title": self.title,
            "tool": self.tool,
            "outcome": self.outcome,
            "evidence": self.evidence,
            "evidence_loss": self.evidence_loss,
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
            "band_before": self.band_before,
            "band_after": self.band_after,
        }


def build_observation_artifact(
    observation: RunObservation,
    scores: Sequence[ScoreBreakdown] = (),
    *,
    evidence_status: str,
) -> dict[str, Any]:
    if evidence_status not in EVIDENCE_STATUSES:
        raise ConfigError(f"observation evidence_status must be one of {EVIDENCE_STATUSES}")
    if not observation.run_id.strip():
        raise ConfigError("observation run_id is required")
    for name, value in (
        ("config_hash", observation.config_hash),
        ("feed_snapshot_hash", observation.feed_snapshot_hash),
        ("scope_hash", observation.scope_hash),
    ):
        if not value.strip():
            raise ConfigError(f"observation {name} is required")
    finding_ids = [finding.id for finding in observation.findings]
    host_ips = [host.ip for host in observation.hosts]
    coverage_keys = [(item.host_ip, item.tool) for item in observation.coverage]
    score_ids = [score.finding_id for score in scores]
    if len(finding_ids) != len(set(finding_ids)):
        raise ConfigError("observation contains duplicate finding IDs")
    if len(host_ips) != len(set(host_ips)):
        raise ConfigError("observation contains duplicate host IPs")
    if len(coverage_keys) != len(set(coverage_keys)):
        raise ConfigError("observation contains duplicate host/tool coverage records")
    if len(score_ids) != len(set(score_ids)):
        raise ConfigError("observation contains duplicate score finding IDs")
    unknown_score = sorted(set(score_ids) - set(finding_ids))
    if unknown_score:
        raise ConfigError(f"observation score references missing finding {unknown_score[0]!r}")
    missing_hosts = sorted({finding.host_ip for finding in observation.findings} - set(host_ips))
    if missing_hosts:
        raise ConfigError(f"observation finding references missing host {missing_hosts[0]!r}")
    unknown_coverage_hosts = sorted({item.host_ip for item in observation.coverage} - set(host_ips))
    if unknown_coverage_hosts:
        raise ConfigError(
            f"observation coverage references missing host {unknown_coverage_hosts[0]!r}"
        )
    core = {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "evidence_status": evidence_status,
        "run_id": observation.run_id,
        "config_hash": observation.config_hash,
        "feed_snapshot_hash": observation.feed_snapshot_hash,
        "scope_hash": observation.scope_hash,
        "hosts": [host.to_json() for host in observation.hosts],
        "findings": [finding.to_json() for finding in observation.findings],
        "coverage": [record.to_json() for record in observation.coverage],
        "scores": [score.to_json() for score in scores],
    }
    return {**core, "observation_hash": _digest(core)}


def load_observation_artifact(path: str | Path) -> ObservationArtifact:
    path = Path(path)
    payload = load_json_payload(
        path, "re-scan observation artifact", max_bytes=MAX_OBSERVATION_BYTES
    )
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid re-scan observation artifact {path}: expected an object")
    allowed = {
        "schema_version",
        "evidence_status",
        "run_id",
        "config_hash",
        "feed_snapshot_hash",
        "scope_hash",
        "hosts",
        "findings",
        "coverage",
        "scores",
        "observation_hash",
    }
    extra = sorted(set(payload) - allowed)
    if extra:
        raise ConfigError(f"invalid re-scan observation artifact {path}: unknown key {extra[0]!r}")
    if payload.get("schema_version") != OBSERVATION_SCHEMA_VERSION:
        raise ConfigError(
            f"re-scan observation schema must be {OBSERVATION_SCHEMA_VERSION}, got "
            f"{payload.get('schema_version')!r}"
        )
    evidence_status = payload.get("evidence_status")
    if evidence_status not in EVIDENCE_STATUSES:
        raise ConfigError(f"observation evidence_status must be one of {EVIDENCE_STATUSES}")
    claimed = payload.get("observation_hash")
    core = {key: value for key, value in payload.items() if key != "observation_hash"}
    computed = _digest(core)
    if claimed != computed:
        raise ConfigError(
            f"re-scan observation hash mismatch: artifact says {claimed!r}, computed {computed!r}"
        )
    try:
        hosts = tuple(Host.from_json(item) for item in payload["hosts"])
        findings = tuple(Finding.from_json(item) for item in payload["findings"])
        coverage = tuple(
            CoverageRecord(
                host_ip=str(item["host_ip"]),
                tool=str(item["tool"]),
                status=str(item["status"]),
                scanner_fingerprint=str(item["scanner_fingerprint"]),
                endpoints=tuple(str(value) for value in item.get("endpoints", [])),
                detail=str(item.get("detail", "")),
            )
            for item in payload["coverage"]
        )
        scores = tuple(ScoreBreakdown.from_json(item) for item in payload["scores"])
        observation = RunObservation(
            run_id=str(payload["run_id"]),
            findings=findings,
            hosts=hosts,
            coverage=coverage,
            config_hash=str(payload["config_hash"]),
            feed_snapshot_hash=str(payload["feed_snapshot_hash"]),
            scope_hash=str(payload["scope_hash"]),
        )
        rebuilt = build_observation_artifact(
            observation, scores, evidence_status=str(evidence_status)
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigError(f"invalid re-scan observation artifact {path}: {error}") from error
    if rebuilt != payload:
        raise ConfigError(
            f"re-scan observation artifact {path} is not canonical or contains invalid values"
        )
    return ObservationArtifact(
        observation=observation,
        scores=scores,
        evidence_status=str(evidence_status),
        artifact_hash=str(claimed),
    )


def _origin(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.hostname:
        return None
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    default = 443 if parsed.scheme == "https" else 80
    suffix = "" if parsed.port in (None, default) else f":{parsed.port}"
    return f"{parsed.scheme}://{host}{suffix}"


def _coverage(observation: RunObservation, finding: Finding) -> CoverageRecord | None:
    return next(
        (
            record
            for record in observation.coverage
            if record.host_ip == finding.host_ip and record.tool == finding.tool
        ),
        None,
    )


def _service(hosts: Sequence[Host], finding: Finding) -> Service | None:
    host = next((item for item in hosts if item.ip == finding.host_ip), None)
    if host is None or finding.port is None:
        return None
    return next((item for item in host.services if item.port == finding.port), None)


def _comparable(
    before: RunObservation,
    after: RunObservation,
    finding: Finding,
) -> tuple[bool, str]:
    old = _coverage(before, finding)
    new = _coverage(after, finding)
    if old is None or new is None:
        return False, "matching tool coverage metadata is missing"
    if old.status != "success" or new.status != "success":
        return False, f"tool coverage was not successful ({old.status} -> {new.status})"
    if old.scanner_fingerprint != new.scanner_fingerprint:
        return False, "scanner command/version fingerprint changed"
    origin = _origin(finding.url)
    if origin is not None and (origin not in old.endpoints or origin not in new.endpoints):
        return False, f"affected endpoint {origin} was not covered successfully in both runs"
    if _service(before.hosts, finding) is None or _service(after.hosts, finding) is None:
        return False, "affected host/service was not observed in both runs"
    return True, "successful equivalent tool and affected-instance coverage"


def _newer_version(before: Service | None, after: Service | None) -> tuple[bool, str]:
    if before is None or after is None:
        return False, "service is not observed in both captures"
    if not before.product or not after.product or before.product != after.product:
        return False, "service product is missing or changed"
    if not before.version or not after.version:
        return False, "service version is missing"
    try:
        old, new = Version(before.version), Version(after.version)
    except InvalidVersion:
        return False, "service version is not parseable"
    if new > old:
        return True, f"service version increased from {before.version} to {after.version}"
    if new == old:
        return False, f"vulnerable service version is unchanged at {before.version}"
    return False, f"service version decreased from {before.version} to {after.version}"


def _scores(
    scores: Sequence[ScoreBreakdown] | None,
) -> Mapping[str, ScoreBreakdown]:
    return {item.finding_id: item for item in (scores or ())}


def compare_runs(
    before: RunObservation,
    after: RunObservation,
    before_scores: Sequence[ScoreBreakdown] | None = None,
    after_scores: Sequence[ScoreBreakdown] | None = None,
) -> dict[str, Any]:
    """Classify observations without treating absence as proof of remediation."""
    if before.run_id == after.run_id:
        raise ConfigError("re-scan comparison requires two different run IDs")
    old_findings = {finding.id: finding for finding in before.findings}
    new_findings = {finding.id: finding for finding in after.findings}
    if len(old_findings) != len(before.findings) or len(new_findings) != len(after.findings):
        raise ConfigError("re-scan observation contains duplicate finding IDs")
    old_scores = _scores(before_scores)
    new_scores = _scores(after_scores)
    outcomes: list[RescanItem] = []

    for finding_id in sorted(old_findings):
        finding = old_findings[finding_id]
        old_score = old_scores.get(finding_id)
        new_score = new_scores.get(finding_id)
        if finding_id in new_findings:
            outcomes.append(
                RescanItem(
                    finding_id=finding_id,
                    host_ip=finding.host_ip,
                    title=finding.title,
                    tool=finding.tool,
                    outcome="still_open",
                    evidence="the same finding fingerprint was observed again",
                    risk_before=None if old_score is None else old_score.risk,
                    risk_after=None if new_score is None else new_score.risk,
                    band_before=None if old_score is None else old_score.band,
                    band_after=None if new_score is None else new_score.band,
                )
            )
            continue

        comparable, coverage_evidence = _comparable(before, after, finding)
        if not comparable:
            outcomes.append(
                RescanItem(
                    finding_id=finding_id,
                    host_ip=finding.host_ip,
                    title=finding.title,
                    tool=finding.tool,
                    outcome="not_observable",
                    evidence=coverage_evidence,
                    risk_before=None if old_score is None else old_score.risk,
                    band_before=None if old_score is None else old_score.band,
                )
            )
            continue

        old_service = _service(before.hosts, finding)
        new_service = _service(after.hosts, finding)
        changed, version_evidence = _newer_version(old_service, new_service)
        outcome = "fixed_candidate" if changed else "still_open"
        outcomes.append(
            RescanItem(
                finding_id=finding_id,
                host_ip=finding.host_ip,
                title=finding.title,
                tool=finding.tool,
                outcome=outcome,
                evidence=f"{coverage_evidence}; {version_evidence}",
                evidence_loss=not changed,
                risk_before=None if old_score is None else old_score.risk,
                band_before=None if old_score is None else old_score.band,
            )
        )

    for finding_id in sorted(set(new_findings) - set(old_findings)):
        finding = new_findings[finding_id]
        comparable, coverage_evidence = _comparable(before, after, finding)
        old_service = _service(before.hosts, finding)
        outcome = (
            "regression_candidate" if comparable and old_service is not None else "new_finding"
        )
        new_score = new_scores.get(finding_id)
        outcomes.append(
            RescanItem(
                finding_id=finding_id,
                host_ip=finding.host_ip,
                title=finding.title,
                tool=finding.tool,
                outcome=outcome,
                evidence=(
                    f"{coverage_evidence}; affected instance was previously observed without this finding"
                    if outcome == "regression_candidate"
                    else "finding was not present in the baseline observation"
                ),
                risk_after=None if new_score is None else new_score.risk,
                band_after=None if new_score is None else new_score.band,
            )
        )

    counts = {outcome: 0 for outcome in OUTCOMES}
    for item in outcomes:
        counts[item.outcome] += 1
    return {
        "before": before.run_id,
        "after": after.run_id,
        "outcomes": [item.to_json() for item in outcomes],
        "counts": counts,
        "drift": {
            "config_changed": before.config_hash != after.config_hash,
            "feed_snapshot_changed": before.feed_snapshot_hash != after.feed_snapshot_hash,
            "scope_changed": before.scope_hash != after.scope_hash,
        },
        "interpretation": (
            "fixed_candidate requires human adjudication; not_observable and evidence_loss "
            "must never count as remediation"
        ),
    }

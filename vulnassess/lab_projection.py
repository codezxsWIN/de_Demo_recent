"""Publish verified full-lab evidence into the existing assessment/report flow.

No scanner, AI provider or intelligence transport is invoked here. Native policy
findings retain their recorded priority and never acquire an inferred CVE.
"""

import copy
import hashlib
import json
import sqlite3
from pathlib import Path

from vulnassess import analyst, capture_history, live_assessment
from vulnassess.errors import ConfigError
from vulnassess.lab_assessment import ACTIONS, CASE_ID, TARGETS, _local, checksum
from vulnassess.lab_live import evidence_digest
from vulnassess.run_history import encoded
from vulnassess.schema import ContextProfile, Feature, Finding, Host, ScoreBreakdown, Service
from vulnassess.store import Store


def _verified_cases(lab, suite):
    environment = suite["environment"]
    declared = {row["id"]: row for row in suite["cases"]}
    cases = []
    for check in suite["checks"]:
        identity = check.get("case_id")
        if identity is None:
            continue
        if not isinstance(identity, str) or not CASE_ID.fullmatch(identity):
            raise ConfigError("Full assessment contains an invalid investigation reference")
        case = lab.load(identity)
        expected = declared.get(identity)
        action = check["action"]
        if (
            expected is None
            or action not in ACTIONS[environment]
            or case["environment"] != environment
            or case["target"] != TARGETS[environment]
            or case["kind"] != "full_assessment"
            or case["action"] != action
            or (case["port"], case["transport"]) != ACTIONS[environment][action][:2]
            or any(
                case.get(key) != expected.get(key)
                for key in (
                    "target",
                    "action",
                    "port",
                    "transport",
                    "policy_sha256",
                    "started_at",
                    "finished_at",
                )
            )
        ):
            raise ConfigError("Investigation does not belong to the selected full assessment")
        if expected.get("evidence_sha256"):
            if (
                case.get("evidence_sha256") != expected["evidence_sha256"]
                or evidence_digest(case) != expected["evidence_sha256"]
            ):
                raise ConfigError("Collection evidence changed after the full assessment")
        elif case["sha256"] != expected.get("sha256"):
            raise ConfigError("Legacy investigation changed; a new full assessment is required")
        if case.get("policy_error") and case.get("findings"):
            raise ConfigError("Unstable owner policy cannot publish vulnerability findings")
        cases.append((case, check))
    if len({case["id"] for case, _ in cases}) != len(cases):
        raise ConfigError("A full assessment references the same investigation twice")
    return cases


def project(lab, suite):
    cases = _verified_cases(lab, suite)
    if not cases:
        raise ConfigError("No retained protocol evidence is available to publish")
    ip = TARGETS[suite["environment"]]
    services, findings, scores, endpoint_context, checks = {}, {}, {}, [], []
    for case, check in cases:
        proof = case["result"]["proof"]
        if not isinstance(proof, dict):
            raise ConfigError("Protocol evidence is not an object")
        service_name = ACTIONS[suite["environment"]][case["action"]][2]
        if proof.get("protocol_confirmed") is True:
            service = Service(
                case["port"],
                case["transport"],
                name="microsoft-ds" if service_name == "smb" else service_name,
                product="Redis"
                if proof.get("identity_established") is True and service_name == "redis"
                else None,
                version=proof.get("redis_version")
                if proof.get("identity_established") is True
                else None,
                tls=bool(proof.get("tls_version")),
                banner="Bounded live "
                + service_name
                + " protocol exchange; no OS identity inferred",
            )
            services[(service.port, service.protocol)] = service
        profile = (
            ContextProfile.from_json(case["context"])
            if case.get("context")
            else ContextProfile(
                ip,
                Feature("unknown", 0.0, "rule", "Context was not established"),
                Feature("unknown", 0.0, "rule", "Exposure was not established"),
            )
        )
        if profile.host_ip != ip:
            raise ConfigError("Endpoint context is not bound to this host")
        endpoint_context.append(
            {
                "case_id": case["id"],
                "port": case["port"],
                "transport": case["transport"],
                "context": profile.to_json(),
            }
        )
        for row in case["findings"]:
            finding = Finding.from_json(row["finding"])
            score = ScoreBreakdown.from_json(row["score"])
            if (
                finding.host_ip != ip
                or finding.port != case["port"]
                or finding.protocol != case["transport"]
                or finding.tool != "service-network"
                or finding.cve_ids
                or score.finding_id != finding.id
                or score.host_ip != ip
                or finding.id in findings
            ):
                raise ConfigError(
                    "Native finding or priority is not uniquely bound to its endpoint"
                )
            observed = json.loads(finding.evidence)
            if (
                observed.get("observed") != proof
                or observed.get("expected_policy") != case["expected_policy"]
                or observed.get("policy_sha256") != case["policy_sha256"]
            ):
                raise ConfigError("Finding evidence contradicts its retained protocol exchange")
            findings[finding.id], scores[finding.id] = finding.to_json(), score.to_json()
        checks.append(
            {
                "case_id": case["id"],
                "action": case["action"],
                "port": case["port"],
                "transport": case["transport"],
                "state": check["state"],
                "observed_at": case["finished_at"],
                "proof": copy.deepcopy(proof),
                "evidence_sha256": case.get("evidence_sha256"),
                "evidence_url": case["evidence_url"],
                "pcap": case.get("pcap"),
                "clock_alignment": case.get("packet_evidence", {}).get("clock_alignment"),
            }
        )
    aggregate = ContextProfile.from_json(endpoint_context[0]["context"])
    if len(endpoint_context) > 1:
        aggregate.role = Feature(
            "unknown",
            0.0,
            "rule",
            "This host has multiple endpoint roles; inspect the retained per-service contexts. No single business role was established.",
        )
        aggregate.controls = {
            key: Feature(
                None,
                0.0,
                "rule",
                "Endpoint controls are assessed separately; no uniform host-wide protection was established.",
            )
            for key in aggregate.controls
        }
    failures = [
        {
            "stage": row["action"],
            "detail": "Protocol coverage was "
            + row["state"]
            + "; inspect the retained endpoint proof.",
        }
        for row in suite["checks"]
        if row["state"] != "complete"
    ]
    source = {
        key: value for key, value in suite.items() if key not in {"sha256", "main_assessment"}
    }
    payload = {
        "scan_status": "partial" if failures else "complete",
        "collection_failures": failures,
        "hosts": [Host(ip=ip, services=tuple(services[key] for key in sorted(services))).to_json()],
        "findings": [findings[key] for key in sorted(findings)],
        "scores": sorted(scores.values(), key=lambda row: (-row["risk"], row["finding_id"])),
        "context": [aggregate.to_json()],
        "service_context": endpoint_context,
        "enrichments": [],
        "unscored_findings": [],
        "feeds_meta": {},
        "feed_status": [],
        "intelligence_mode": "not_applicable",
        "scanner_coverage": {
            "nmap": "not run; this assessment used the fixed authorised protocol operations, not port discovery",
            "service-network": f"{suite['coverage']['attempted_endpoints']} of {suite['coverage']['declared_endpoints']} configured endpoints attempted; {suite['coverage']['tested_conditions']} of {suite['coverage']['known_conditions']} reviewed conditions tested",
            "cve-discovery": "not tested; Redis provides identity only; no CVE applicability was inferred",
            "nikto": "not run; no web-scanner coverage claimed",
            "nessus": "not imported",
        },
        "scoring_policy": {
            "mode": "retained native priorities",
            "weights_hashes": sorted({row["weights_hash"] for row in scores.values()}),
        },
        "network_lab": {
            "assessment_id": suite["id"],
            "environment": suite["environment"],
            "source_sha256": checksum(source),
            "coverage": suite["coverage"],
            "ground_truth": suite["ground_truth"],
            "checks": checks,
            "limit": "Known configured endpoints only. Packet association is supporting evidence, not transaction causality or proof of CVE applicability. Unresolved controls remain unresolved.",
        },
    }
    return payload


def _write_once(path, raw):
    try:
        with path.open("xb") as output:
            output.write(raw)
    except FileExistsError:
        if path.is_symlink():
            raise ConfigError("Existing publication content is a link; nothing was overwritten")
        with path.open("rb") as source:
            existing = source.read(len(raw) + 1)
        if existing != raw:
            raise ConfigError("Existing publication content differs; nothing was overwritten")


def publish(lab, suite, database):
    """Publish once; partial failures are retained and may be retried explicitly."""
    if str(database).startswith(("postgres:", "postgresql:", "env:")):
        raise ConfigError(
            "Live lab database publication currently requires the local SQLite backend"
        )
    payload = project(lab, suite)
    identifier = "assessment-lab-" + suite["id"].removeprefix("full-")
    root = lab.root / "data/live/raw"
    directory = root / identifier
    _local(lab.root, directory)
    directory.mkdir(parents=True, exist_ok=True)
    binding = {
        "assessment_id": suite["id"],
        "source_sha256": payload["network_lab"]["source_sha256"],
    }
    _write_once(directory / "publication.json", encoded(binding).encode("utf-8"))
    _write_once(directory / "case.json", encoded(payload).encode("utf-8"))
    manifest = {
        "target": TARGETS[suite["environment"]],
        "resolved_ip": TARGETS[suite["environment"]],
        "captured_at": suite["finished_at"],
        "files": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ("case.json", "publication.json")
        },
    }
    _write_once(directory / "manifest.json", encoded(manifest).encode("utf-8"))
    target = manifest["target"]
    services = payload["hosts"][0]["services"]
    result = {
        "target": target,
        "resolved_ip": target,
        "scan_profile": payload["scanner_coverage"]["nmap"],
        "services": services,
        "finding_count": len(payload["findings"]),
        "scan_status": payload["scan_status"],
        "decision_frame": analyst.build_evidence_frame(payload, target),
        "assessment_summary": live_assessment.assessment_summary(target, target, services, payload),
        "analyst": None,
        "ai_status": "not_attempted",
        "ai_attempts": [],
    }
    checkpoint = directory / "review-evidence.json"
    if not checkpoint.exists():
        capture_history.save(directory, result, config_hash=checksum(binding))
    record = capture_history.load(root, identifier)
    if record["payload"] != payload:
        raise ConfigError("Saved report differs from the verified lab projection")
    run_id = "lab-" + suite["id"]
    try:
        with Store(Path(database)) as store:
            store.import_frozen_network_run(
                run_id,
                record["configuration_hash"],
                suite["finished_at"],
                payload,
                {
                    "source": "live-network-lab",
                    "assessment_id": suite["id"],
                    "capture_id": identifier,
                    "scan_status": payload["scan_status"],
                    "source_sha256": binding["source_sha256"],
                },
            )
    except sqlite3.Error as error:
        raise ConfigError(
            "Report retained, but the assessment database publication failed: "
            + type(error).__name__
        ) from error
    return {
        "status": "saved",
        "capture_id": identifier,
        "run_id": run_id,
        "report_url": f"/captures/{identifier}/report",
        "findings_url": f"/vulnerabilities?capture={identifier}",
        "evidence_url": f"/api/captures/{identifier}",
        "source_sha256": binding["source_sha256"],
        "snapshot_hash": record["snapshot_hash"],
    }

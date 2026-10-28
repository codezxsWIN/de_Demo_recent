"""Additive local review receipts; reading one never restores execution authority."""

import json
import math
import os
import re
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from vulnassess.errors import ConfigError
from vulnassess.run_history import encoded

MAX_BYTES = 8 * 1024 * 1024
_CAPTURE_TIME_DEFAULT = object()
RESULT_KEYS = frozenset(
    {
        "target",
        "resolved_ip",
        "scan_profile",
        "services",
        "finding_count",
        "decision_frame",
        "assessment_summary",
        "scan_status",
        "analyst",
        "ai_status",
        "ai_attempts",
        "selected_provider",
        "used_provider",
        "role_model",
    }
)
FIELDS = frozenset(
    {
        "schema_version",
        "capture_id",
        "captured_at",
        "intelligence_recorded_at",
        "analysis_attempted_at",
        "configuration_hash",
        "manifest_hash",
        "evidence_hash",
        "intelligence_hash",
        "parent_hash",
        "result",
    }
)
AI_SUMMARY_FIELDS = frozenset(
    {
        "validated_ai_summary",
        "ai_coverage",
        "next_actions",
        "uncertainties",
        "ai_status",
        "ai_attempts",
    }
)


def _hash(value):
    return sha256(encoded(value).encode("utf-8")).hexdigest()


def _intelligence_content(payload):
    result = {
        "enrichments": payload.get("enrichments", []),
        "feeds_meta": payload.get("feeds_meta", {}),
    }
    if "intelligence_evidence" in payload:
        result["intelligence_evidence"] = payload["intelligence_evidence"]
    return result


def _directory(root, identity):
    if not isinstance(identity, str) or not re.fullmatch(
        r"assessment-[a-zA-Z0-9_-]{1,80}", identity
    ):
        raise ConfigError("Invalid saved assessment ID")
    root = Path(root).resolve()
    path = root / identity
    if path.is_symlink() or path.resolve().parent != root or not path.is_dir():
        raise ConfigError("Saved assessment directory is unavailable")
    return path


def _bytes(directory, name):
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+", name):
        raise ConfigError("Invalid saved assessment filename")
    path = directory / name
    if path.is_symlink() or path.resolve().parent != directory.resolve():
        raise ConfigError("Saved assessment file leaves its directory")
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ConfigError("Saved assessment file exceeds the review budget")
        return raw
    except OSError as error:
        raise ConfigError("Saved assessment file is unavailable") from error


def _json(raw):
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ConfigError("Saved assessment JSON is malformed") from error


def _timestamp(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 80:
        raise ValueError("timestamp must be a bounded ISO string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp requires an explicit timezone")
    return parsed.astimezone(UTC).isoformat()


def manifest_time(manifest):
    """Absent legacy time stays unknown; malformed declared time is not replaced."""
    if "captured_at" not in manifest:
        return None
    try:
        return _timestamp(manifest["captured_at"])
    except (TypeError, ValueError, OverflowError) as error:
        raise ConfigError("Saved capture timestamp is invalid or has no timezone") from error


def capture_time(directory, manifest, manifest_raw):
    """Read recorded chronology, never filesystem dates or restored authority."""
    declared = manifest_time(manifest)
    if not any(
        (directory / name).exists() or (directory / name).is_symlink()
        for name in ("review-evidence.json", "review-final.json")
    ):
        return declared, "manifest" if declared else "unknown", None
    record = _selected(directory)
    if record["manifest_hash"] != sha256(manifest_raw).hexdigest():
        raise ConfigError("Saved assessment manifest hash mismatch")
    if any(record["result"][key] != manifest.get(key) for key in ("target", "resolved_ip")):
        raise ConfigError("Saved assessment target does not match its manifest")
    recorded = _timestamp(record["captured_at"]) if record["captured_at"] is not None else None
    if declared and recorded and declared != recorded:
        raise ConfigError("Saved capture timestamp conflicts with its review receipt")
    return (
        recorded or declared,
        "review_receipt" if recorded else "manifest" if declared else "unknown",
        record,
    )


def _record(directory, name):
    value = _json(_bytes(directory, name))
    core = {key: item for key, item in value.items() if key != "snapshot_hash"}
    try:
        if (
            set(core) != FIELDS
            or type(core["schema_version"]) is not int
            or core["schema_version"] != 1
        ):
            raise ValueError("schema")
        if value.get("snapshot_hash") != _hash(core) or core["capture_id"] != directory.name:
            raise ValueError("hash or identity")
        if not isinstance(core["result"], dict) or set(core["result"]) - RESULT_KEYS:
            raise ValueError("result")
        if core["result"].get("scan_status") not in ("complete", "partial"):
            raise ValueError("scan status")
        result = core["result"]
        if (
            not isinstance(result.get("assessment_summary"), dict)
            or result.get("ai_status")
            not in {"not_attempted", "unavailable", "needs_review", "validated"}
            or not isinstance(result.get("target"), str)
            or not isinstance(result.get("resolved_ip"), str)
            or (result.get("ai_status") != "validated" and result.get("analyst") is not None)
        ):
            raise ValueError("result fields")
        for key in ("captured_at", "intelligence_recorded_at", "analysis_attempted_at"):
            if core[key] is not None:
                _timestamp(core[key])
        _summary_ai(result)
        return value
    except (ValueError, TypeError, KeyError, OverflowError) as error:
        raise ConfigError("Saved assessment schema or hash mismatch; review refused") from error


def _selected(directory):
    baseline = _record(directory, "review-evidence.json")
    if (
        not (directory / "review-final.json").exists()
        and not (directory / "review-final.json").is_symlink()
    ):
        return baseline
    final = _record(directory, "review-final.json")
    unchanged = FIELDS - {"result", "parent_hash", "analysis_attempted_at"}
    if final["parent_hash"] != baseline["snapshot_hash"] or any(
        final[key] != baseline[key] for key in unchanged
    ):
        raise ConfigError("Saved assessment final review does not match its evidence checkpoint")
    _same_collection(baseline["result"], final["result"])
    return final


def _same_collection(baseline, final):
    fields = (
        "target",
        "resolved_ip",
        "scan_profile",
        "services",
        "finding_count",
        "scan_status",
        "decision_frame",
        "role_model",
    )
    if any(not _same_content(baseline.get(key), final.get(key)) for key in fields):
        raise ConfigError("Final AI review cannot change collection evidence or its status")
    summaries = [result.get("assessment_summary") for result in (baseline, final)]
    if any(not isinstance(summary, dict) for summary in summaries) or not _same_content(
        *[
            {key: value for key, value in summary.items() if key not in AI_SUMMARY_FIELDS}
            for summary in summaries
        ]
    ):
        raise ConfigError("Final AI review cannot change canonical assessment summary evidence")


def _same_content(left, right):
    """JSON equality preserves types and rejects non-finite numbers, including nested ones."""
    try:
        return encoded(left) == encoded(right)
    except (TypeError, ValueError, RecursionError):
        return False


def _check_facts(actual, expected):
    """Check declared facts only; absent historical fields remain absent."""
    for key, value in expected.items():
        if key in actual and not _same_content(actual[key], value):
            raise ConfigError(f"Saved assessment summary {key} contradicts retained evidence")


def _summary_ai(result):
    summary = result.get("assessment_summary")
    status = result.get("ai_status")
    if (
        not isinstance(summary, dict)
        or not _same_content(summary, summary)
        or status not in ("not_attempted", "unavailable", "needs_review", "validated")
        or (status != "validated" and result.get("analyst") is not None)
    ):
        raise ConfigError("Saved assessment summary or AI status is invalid")
    if "coverage_gaps" in summary and not isinstance(summary["coverage_gaps"], list):
        raise ConfigError("Saved assessment summary coverage gaps must be a list")
    if "context" in summary and not isinstance(summary["context"], dict):
        raise ConfigError("Saved assessment summary context is invalid")
    _check_facts(
        summary, {key: result[key] for key in ("ai_status", "ai_attempts") if key in result}
    )
    content_fields = AI_SUMMARY_FIELDS - {"ai_status", "ai_attempts"}
    if status != "validated":
        if any(summary.get(key) for key in content_fields):
            raise ConfigError("Saved assessment summary contains unvalidated AI output")
        return
    analyst = result.get("analyst")
    if not isinstance(analyst, dict):
        if any(summary.get(key) for key in content_fields):
            raise ConfigError("Saved assessment summary AI output has no retained analyst source")
        return  # Legacy status-only receipts have no retained AI projection to compare.
    analysis = analyst.get("analysis", {})
    batches = analyst.get("batches", [])
    coverage = analyst.get("batch_coverage")
    if not isinstance(analysis, dict) or not isinstance(batches, list):
        raise ConfigError("Saved assessment summary AI projection is invalid")
    if batches:
        included = coverage.get("findings_included") if isinstance(coverage, dict) else None
        if type(included) is not int or included < 0:
            raise ConfigError("Saved assessment summary AI coverage count is invalid")
        expected = {
            "validated_ai_summary": f"{included} findings included in {len(batches)} validated AI batches.",
            "ai_coverage": coverage,
            "next_actions": [],
            "uncertainties": [
                "AI claims and citations are scoped to each batch; relationships across batches were not assessed."
            ],
        }
    else:
        expected = {
            "validated_ai_summary": analysis.get("summary"),
            "ai_coverage": coverage,
            "next_actions": analysis.get("recommended_actions", []),
            "uncertainties": analysis.get("uncertainties", []),
        }
    _check_facts(summary, expected)


def _collections(payload: dict[str, Any]) -> None:
    """Reject malformed present collections without filling absent historical fields."""
    if not _same_content(payload, payload):
        raise ConfigError("Saved assessment evidence contains invalid JSON values")
    if "intelligence_evidence" in payload:
        from vulnassess.errors import IntelUnavailable
        from vulnassess.intelligence_evidence import verify

        try:
            verify(
                payload["intelligence_evidence"],
                findings=payload.get("findings", []),
                enrichments=payload.get("enrichments", []),
                feeds=payload.get("feeds_meta", {}),
            )
        except (IntelUnavailable, ValueError, TypeError, KeyError) as error:
            raise ConfigError("Saved assessment publisher evidence is invalid") from error
    for key in (
        "hosts",
        "findings",
        "context",
        "scores",
        "enrichments",
        "rationales",
        "unscored_findings",
        "collection_failures",
    ):
        if key in payload and (
            not isinstance(payload[key], list)
            or any(not isinstance(item, dict) for item in payload[key])
        ):
            raise ConfigError(f"Saved assessment {key} must be a list of objects")
    for key in ("feeds_meta", "scanner_coverage"):
        if key in payload and not isinstance(payload[key], dict):
            raise ConfigError(f"Saved assessment {key} must be an object")
    for host in payload.get("hosts", []):
        if "services" in host and (
            not isinstance(host["services"], list)
            or any(not isinstance(item, dict) for item in host["services"])
        ):
            raise ConfigError("Saved assessment services must be a list of objects")
    for finding in payload.get("findings", []):
        if not isinstance(finding.get("id"), str) or not finding["id"]:
            raise ConfigError("Saved assessment finding ID is invalid")
        if "cve_ids" in finding and (
            not isinstance(finding["cve_ids"], list)
            or any(not isinstance(cve, str) for cve in finding["cve_ids"])
        ):
            raise ConfigError("Saved assessment CVE IDs must be a list of strings")
        if "provenance" in finding and not isinstance(finding["provenance"], dict):
            raise ConfigError("Saved assessment finding provenance must be an object")


def _summary_facts(result, payload):
    """Compare recorded projections, never import an engine or recalculate a score."""
    _collections(payload)
    if "role_model" in result:
        if "role_model" not in payload or not _same_content(
            payload["role_model"], result["role_model"]
        ):
            raise ConfigError(
                "Saved assessment shadow role prediction contradicts retained evidence"
            )
    _summary_ai(result)
    summary = result["assessment_summary"]
    _check_facts(summary, {key: result[key] for key in ("target", "resolved_ip", "scan_status")})
    if "finding_count" in result:
        _check_facts(summary, {"finding_count": result["finding_count"]})
    for facts in (result, summary):
        for key in (
            "finding_count",
            "service_count",
            "scored_finding_count",
            "unscored_finding_count",
        ):
            if key in facts and (type(facts[key]) is not int or facts[key] < 0):
                raise ConfigError(f"Saved assessment summary {key} must be a non-negative integer")
    for key in ("collection_failures", "self_defence"):
        if key in payload:
            _check_facts(summary, {key: payload[key]})
    coverage = payload.get("scanner_coverage")
    _check_facts(summary, {"scanner_coverage": coverage if isinstance(coverage, dict) else {}})
    if isinstance(coverage, dict) and isinstance(coverage.get("nmap"), str):
        _check_facts(result, {"scan_profile": coverage["nmap"]})
    services = result.get("services")
    for host in payload.get("hosts", []):
        if isinstance(host, dict) and host.get("ip") == result["resolved_ip"]:
            if isinstance(host.get("services"), list):
                _check_facts(result, {"services": host["services"]})
                services = host["services"]
            break
    if isinstance(services, list):
        _check_facts(summary, {"service_count": len(services)})
    context = summary.get("context")
    if context is not None:
        if not isinstance(context, dict):
            raise ConfigError("Saved assessment summary context is invalid")
        context_facts = {key: "unknown" for key in ("role", "exposure")}
        for profile in payload.get("context", []):
            if isinstance(profile, dict) and profile.get("host_ip") == result["resolved_ip"]:
                context_facts.update(
                    {
                        key: profile[key].get("value", "unknown")
                        for key in ("role", "exposure")
                        if isinstance(profile.get(key), dict)
                    }
                )
                break
        _check_facts(context, context_facts)
    findings, scores = payload.get("findings"), payload.get("scores")
    if isinstance(findings, list):
        _check_facts(result, {"finding_count": len(findings)})
        _check_facts(summary, {"finding_count": len(findings)})
        analyst = result.get("analyst")
        coverages = [summary.get("ai_coverage")]
        if isinstance(analyst, dict):
            coverages.append(analyst.get("batch_coverage"))
        for ai_coverage in coverages:
            if isinstance(ai_coverage, dict) and "findings_included" in ai_coverage:
                included = ai_coverage["findings_included"]
                if type(included) is not int or not 0 <= included <= len(findings):
                    raise ConfigError(
                        "Saved assessment summary AI coverage exceeds retained findings"
                    )
                _check_facts(
                    ai_coverage,
                    {
                        "findings_total": len(findings),
                        "findings_omitted": len(findings) - included,
                    },
                )
                batches = analyst.get("batches", []) if isinstance(analyst, dict) else []
                if isinstance(batches, list):
                    _check_facts(ai_coverage, {"batch_count": len(batches)})
                    if batches:
                        _check_facts(ai_coverage, {"cross_batch_reasoning": False})
    if not isinstance(scores, list):
        return  # No absent list is interpreted as a recorded zero.
    if any(not isinstance(item, dict) for item in scores) or (
        isinstance(findings, list) and any(not isinstance(item, dict) for item in findings)
    ):
        raise ConfigError("Saved assessment findings or priorities are invalid")
    finding_ids = (
        {item.get("id") for item in findings if isinstance(item.get("id"), str)}
        if isinstance(findings, list)
        else None
    )
    scored_ids = set()
    for score in scores:
        identity, risk = score.get("finding_id"), score.get("risk")
        if (
            not isinstance(identity, str)
            or (finding_ids is not None and identity not in finding_ids)
            or identity in scored_ids
            or type(risk) not in (int, float)
            or not 0 <= risk <= 100
            or not math.isfinite(risk)
            or score.get("band") not in ("Critical", "High", "Medium", "Low")
        ):
            raise ConfigError("Saved assessment retained priority is invalid or unbound")
        scored_ids.add(identity)
    _check_facts(
        summary,
        {
            "priorities": scores,
            "scored_finding_count": len(scored_ids),
        },
    )
    if not isinstance(findings, list):
        return
    _check_facts(summary, {"unscored_finding_count": len(findings) - len(scored_ids)})
    reasons = {
        item["finding_id"]: item.get("reason", "No deterministic priority was recorded")
        for item in payload.get("unscored_findings", [])
        if isinstance(item, dict) and isinstance(item.get("finding_id"), str)
    }
    _check_facts(
        summary,
        {
            "unscored_findings": [
                {
                    "finding_id": item["id"],
                    "title": item.get("title", item["id"]),
                    "reason": reasons.get(item["id"], "No deterministic priority was recorded"),
                }
                for item in findings
                if isinstance(item.get("id"), str) and item["id"] not in scored_ids
            ]
        },
    )
    enrichments = payload.get("enrichments")
    if isinstance(enrichments, list) and all(isinstance(item, dict) for item in enrichments):
        _summary_intelligence(summary, payload, findings, scores, enrichments)


def _summary_intelligence(summary, payload, findings, scores, enrichments):
    cves = sorted({cve for item in findings for cve in item.get("cve_ids", [])})
    sources = payload.get("feed_status") or []
    intelligence = summary.get("intelligence")
    if intelligence is not None:
        if not isinstance(intelligence, dict):
            raise ConfigError("Saved assessment summary intelligence is invalid")
        _check_facts(
            intelligence,
            {
                "mode": "on_demand"
                if payload.get("intelligence_mode") == "on_demand"
                else "offline"
                if sources
                else "unavailable"
                if cves
                else "not_applicable",
                "checked_cves": cves if sources else [],
                "matched_findings": len({item.get("finding_id") for item in enrichments}),
                "sources": sources,
            },
        )
    if "cve_evidence" not in summary:
        return
    rows = []
    for finding in findings:
        for cve in finding.get("cve_ids", []):
            match = next(
                (
                    item
                    for item in enrichments
                    if item.get("finding_id") == finding.get("id") and item.get("cve_id") == cve
                ),
                {},
            )
            score = next(
                (
                    item
                    for item in scores
                    if item.get("finding_id") == finding.get("id") and item.get("cve_id") == cve
                ),
                {},
            )
            rows.append(
                {
                    "finding_id": finding["id"],
                    "cve_id": cve,
                    "title": finding.get("title", ""),
                    "tool": finding.get("tool", "unknown"),
                    "port": finding.get("port"),
                    "evidence": finding.get("evidence", ""),
                    "raw_path": finding.get("provenance", {}).get("raw_path"),
                    "cvss_base": match.get("cvss40_base")
                    if match.get("cvss40_base") is not None
                    else match.get("cvss31_base"),
                    "epss": match.get("epss"),
                    "kev_status": ("listed" if match.get("kev") else "not_listed")
                    if match and "kev" in sources
                    else "not_checked",
                    "feed_dates": match.get("feed_dates", {}),
                    "priority": {"risk": score["risk"], "band": score["band"]} if score else None,
                }
            )
    _check_facts(summary, {"cve_evidence": rows})


def _evidence(directory: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Parse the same bounded case bytes that were checked against the manifest."""
    files = manifest.get("files")
    if not isinstance(files, dict) or "case.json" not in files or len(files) > 20:
        raise ConfigError("Saved assessment evidence manifest is invalid")
    total = 0
    case_raw = None
    for name, expected in files.items():
        raw = _bytes(directory, name)
        total += len(raw)
        if total > 64 * 1024 * 1024 or sha256(raw).hexdigest() != expected:
            raise ConfigError("Saved assessment evidence hash mismatch or budget exceeded")
        if name == "case.json":
            case_raw = raw
    return _json(case_raw)


def load(root, identity):
    """Return a verified frozen result; no scope decisions or network operations."""
    directory = _directory(root, identity)
    record = _selected(directory)
    manifest_raw = _bytes(directory, "manifest.json")
    if sha256(manifest_raw).hexdigest() != record["manifest_hash"]:
        raise ConfigError("Saved assessment manifest hash mismatch")
    manifest = _json(manifest_raw)
    payload = _evidence(directory, manifest)
    declared = manifest_time(manifest)
    if declared and (
        record["captured_at"] is None or declared != _timestamp(record["captured_at"])
    ):
        raise ConfigError("Saved capture timestamp conflicts with its review receipt")
    if _hash(payload) != record["evidence_hash"]:
        raise ConfigError("Saved assessment case hash mismatch")
    if "scan_status" in payload and payload["scan_status"] != record["result"]["scan_status"]:
        raise ConfigError("Saved assessment collection status does not match its evidence")
    if _hash(_intelligence_content(payload)) != record["intelligence_hash"]:
        raise ConfigError("Saved assessment intelligence hash mismatch")
    if any(record["result"][key] != manifest.get(key) for key in ("target", "resolved_ip")):
        raise ConfigError("Saved assessment target does not match its manifest")
    _summary_facts(record["result"], payload)
    loaded = {**record, "payload": payload, "read_only": True}
    if "redis-lua-check.json" in manifest.get("files", {}):
        from vulnassess.finding_assurance import bounded_redis_proof

        proof_bytes = _bytes(directory, "redis-lua-check.json")
        if sha256(proof_bytes).hexdigest() != manifest["files"]["redis-lua-check.json"]:
            raise ConfigError("Bounded protocol proof changed during review")
        loaded["bounded_protocol_proofs"] = [
            bounded_redis_proof(
                _json(proof_bytes),
                record["result"]["resolved_ip"],
                payload.get("findings", []),
                manifest["files"]["redis-lua-check.json"],
            )
        ]
    if "analysis-source.json" in manifest.get("files", {}):
        reference = _json(_bytes(directory, "analysis-source.json"))
        if (
            set(reference)
            - {"source_capture", "source_snapshot_hash", "mode", "source_intelligence_recorded_at"}
            or not re.fullmatch(
                r"assessment-[a-zA-Z0-9_-]{1,80}", str(reference.get("source_capture", ""))
            )
            or not re.fullmatch(r"[a-f0-9]{64}", str(reference.get("source_snapshot_hash", "")))
            or reference.get("mode") != "retained-evidence reanalysis; no scanner or feed refresh"
        ):
            raise ConfigError("Saved reanalysis source reference is invalid")
        if reference.get("source_intelligence_recorded_at") is not None:
            try:
                _timestamp(reference["source_intelligence_recorded_at"])
            except (TypeError, ValueError, OverflowError) as error:
                raise ConfigError("Saved reanalysis intelligence timestamp is invalid") from error
        loaded["analysis_source"] = reference
    return loaded


def _has_receipt(directory: Path) -> bool:
    return any(
        (directory / name).exists() or (directory / name).is_symlink()
        for name in ("review-evidence.json", "review-final.json")
    )


def _legacy_manifest(directory: Path) -> dict[str, Any]:
    manifest = _json(_bytes(directory, "manifest.json"))
    if any(
        not isinstance(manifest.get(key), str) or not manifest[key].strip()
        for key in ("target", "resolved_ip")
    ):
        raise ConfigError("Saved assessment manifest target is invalid")
    manifest_time(manifest)  # A malformed declared date is not an unknown date.
    return manifest


def _load_for_review(root: str | Path, identity: str) -> dict[str, Any]:
    """HTML-only evidence view; a present receipt must pass the strict reader."""
    directory = _directory(root, identity)
    if _has_receipt(directory):
        return load(root, identity)
    manifest = _legacy_manifest(directory)
    payload = _evidence(directory, manifest)
    _collections(payload)
    ip = manifest["resolved_ip"]
    hosts = payload.get("hosts", [])
    if len(hosts) != 1 or hosts[0].get("ip") != ip:
        raise ConfigError("Legacy evidence host does not match its manifest")
    for key in ("findings", "context"):
        if any(item.get("host_ip") != ip for item in payload.get(key, [])):
            raise ConfigError(f"Legacy evidence {key} belong to a different host")
    findings = payload.get("findings", [])
    identities = {item["id"] for item in findings}
    if len(identities) != len(findings):
        raise ConfigError("Legacy evidence finding IDs are duplicated")
    for key in ("scores", "enrichments", "rationales", "unscored_findings"):
        for item in payload.get(key, []):
            identity = item.get("finding_id")
            if (
                not isinstance(identity, str)
                or identity not in identities
                or ("host_ip" in item and item["host_ip"] != ip)
            ):
                raise ConfigError(f"Legacy evidence {key} have a different finding owner")
    return {
        "legacy": True,
        "capture_id": directory.name,
        "target": manifest["target"],
        "captured_at": manifest_time(manifest),
        "payload": payload,
        "file_hashes": manifest["files"],
    }


def _listing_for_review(root: str | Path, page: int = 1) -> dict[str, Any]:
    """HTML-only, bounded index including legacy directories and damaged receipts."""
    if type(page) is not int or not 1 <= page <= 500:
        raise ConfigError("History page must be between 1 and 500")
    candidates = []
    for path in Path(root).glob("assessment-*"):
        if path.is_dir() or path.is_symlink():
            candidates.append(path.name)
        if len(candidates) > 10000:
            raise ConfigError("History index exceeds the local review budget")
    rows = []
    for identity in candidates:
        try:
            directory = _directory(root, identity)
            if _has_receipt(directory):
                record = _selected(directory)
                row = {
                    "target": record["result"]["target"],
                    "captured_at": record["captured_at"],
                    "ai_status": record["result"]["ai_status"],
                    "scan_status": record["result"]["scan_status"],
                    "status": "recorded",
                }
            else:
                manifest = _legacy_manifest(directory)
                row = {
                    "target": manifest["target"],
                    "captured_at": manifest_time(manifest),
                    "status": "legacy",
                }
            rows.append({"capture_id": identity, **row})
        except (ConfigError, OSError):
            rows.append({"capture_id": identity, "status": "needs_review"})
    rows.sort(key=lambda row: (row.get("captured_at") or "", row["capture_id"]), reverse=True)
    return {
        "captures": rows[(page - 1) * 20 : page * 20],
        "page": page,
        "page_size": 20,
        "total": len(candidates),
    }


def save(
    directory, result, *, config_hash=None, final=False, captured_at_override=_CAPTURE_TIME_DEFAULT
):
    """Publish one write-once checkpoint. Final review cannot change source state."""
    directory = _directory(Path(directory).parent, Path(directory).name)
    safe_result = {key: value for key, value in result.items() if key in RESULT_KEYS}
    if safe_result.get("scan_status") not in ("complete", "partial"):
        raise ConfigError("Saved assessment collection status must be complete or partial")
    now = datetime.now(UTC).isoformat()
    if final:
        if captured_at_override is not _CAPTURE_TIME_DEFAULT:
            raise ConfigError("Final AI review cannot change collection time")
        previous = load(directory.parent, directory.name)
        _same_collection(previous["result"], safe_result)
        _summary_facts(safe_result, previous["payload"])
        core = {key: previous[key] for key in FIELDS}
        core.update(
            parent_hash=previous["snapshot_hash"], analysis_attempted_at=now, result=safe_result
        )
    else:
        if not isinstance(config_hash, str) or not config_hash:
            raise ConfigError("Capture configuration hash is required")
        payload = _json(_bytes(directory, "case.json"))
        _summary_facts(safe_result, payload)
        if "scan_status" in payload and payload["scan_status"] != safe_result["scan_status"]:
            raise ConfigError("Saved assessment collection status does not match its evidence")
        manifest_raw = _bytes(directory, "manifest.json")
        declared_time = manifest_time(_json(manifest_raw))
        if captured_at_override is _CAPTURE_TIME_DEFAULT:
            captured_at = declared_time or now
        else:
            try:
                captured_at = (
                    None if captured_at_override is None else _timestamp(captured_at_override)
                )
            except (TypeError, ValueError, OverflowError) as error:
                raise ConfigError("Reanalysis capture timestamp is invalid") from error
            if declared_time and captured_at != declared_time:
                raise ConfigError("Reanalysis capture timestamp conflicts with its manifest")
        core = {
            "schema_version": 1,
            "capture_id": directory.name,
            "captured_at": captured_at,
            "intelligence_recorded_at": now,
            "analysis_attempted_at": None,
            "configuration_hash": config_hash,
            "manifest_hash": sha256(manifest_raw).hexdigest(),
            "evidence_hash": _hash(payload),
            "intelligence_hash": _hash(_intelligence_content(payload)),
            "parent_hash": None,
            "result": safe_result,
        }
    record = {**core, "snapshot_hash": _hash(core)}
    raw = encoded(record).encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ConfigError("Saved assessment result exceeds the review budget")
    destination = directory / ("review-final.json" if final else "review-evidence.json")
    temporary = directory / f"review-{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, destination)  # Atomic publication; fails if destination exists.
    except FileExistsError as error:
        raise ConfigError("Saved assessment checkpoint already exists") from error
    finally:
        temporary.unlink(missing_ok=True)
    return record


def listing(root, page=1):
    """Bounded metadata listing; raw evidence hashes are checked when opened."""
    if type(page) is not int or not 1 <= page <= 500:
        raise ConfigError("History page must be between 1 and 500")
    root = Path(root)
    candidates = []
    for path in root.glob("assessment-*"):
        if (path / "review-evidence.json").exists():
            candidates.append(path.name)
        if len(candidates) > 10000:
            raise ConfigError("History index exceeds the local review budget")
    rows = []
    for identity in candidates:
        try:
            record = _selected(_directory(root, identity))
            rows.append(
                {
                    "capture_id": identity,
                    "captured_at": record["captured_at"],
                    "target": record["result"].get("target"),
                    "ai_status": record["result"].get("ai_status"),
                    "scan_status": record["result"]["scan_status"],
                    "status": "recorded",
                    "evidence_verification": "checked when opened",
                }
            )
        except ConfigError:
            rows.append({"capture_id": identity, "status": "needs_review"})
    rows.sort(key=lambda row: (row.get("captured_at") or "", row["capture_id"]), reverse=True)
    return {
        "captures": rows[(page - 1) * 20 : page * 20],
        "page": page,
        "page_size": 20,
        "total": len(candidates),
    }

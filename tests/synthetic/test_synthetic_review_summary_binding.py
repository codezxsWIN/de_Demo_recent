"""Synthetic receipt consistency only; no scanner, provider, or scoring execution."""

import builtins
import copy
import hashlib
import json

import pytest

from vulnassess import capture_history as history
from vulnassess.errors import ConfigError


def synthetic_capture(tmp_path):
    directory = tmp_path / "assessment-synthetic-summary"
    directory.mkdir()
    services = [{"port": 443, "protocol": "tcp", "name": "https"}]
    payload = {
        "hosts": [{"ip": "127.0.0.1", "services": services}],
        "findings": [
            {"id": "synthetic-scored", "title": "SYNTHETIC scored", "cve_ids": []},
            {"id": "synthetic-unscored", "title": "SYNTHETIC unscored", "cve_ids": []},
        ],
        "scores": [{"finding_id": "synthetic-scored", "risk": 42, "band": "Medium"}],
        "unscored_findings": [
            {"finding_id": "synthetic-unscored", "reason": "SYNTHETIC missing severity"}
        ],
        "enrichments": [],
        "context": [
            {
                "host_ip": "127.0.0.1",
                "role": {"value": "web_frontend"},
                "exposure": {"value": "internal"},
            }
        ],
        "feeds_meta": {},
        "scan_status": "partial",
        "scanner_coverage": {"nmap": "top 100 TCP ports", "nikto": "failed"},
        "collection_failures": [{"stage": "nikto", "detail": "SYNTHETIC timeout"}],
        "self_defence": {"checks": [], "limitations": ["SYNTHETIC unknown controls"]},
    }
    write_payload(directory, payload)
    result = {
        "target": "synthetic.invalid",
        "resolved_ip": "127.0.0.1",
        "scan_status": "partial",
        "services": copy.deepcopy(services),
        "finding_count": 2,
        "ai_status": "not_attempted",
        "ai_attempts": [],
        "analyst": None,
        "assessment_summary": {
            "target": "synthetic.invalid",
            "resolved_ip": "127.0.0.1",
            "scan_status": "partial",
            "service_count": 1,
            "finding_count": 2,
            "scored_finding_count": 1,
            "unscored_finding_count": 1,
            "priorities": copy.deepcopy(payload["scores"]),
            "unscored_findings": [
                {
                    **payload["unscored_findings"][0],
                    "title": "SYNTHETIC unscored",
                }
            ],
            "context": {"role": "web_frontend", "exposure": "internal"},
            "scanner_coverage": copy.deepcopy(payload["scanner_coverage"]),
            "collection_failures": copy.deepcopy(payload["collection_failures"]),
            "self_defence": copy.deepcopy(payload["self_defence"]),
            "intelligence": {
                "mode": "not_applicable",
                "checked_cves": [],
                "matched_findings": 0,
                "sources": [],
            },
            "cve_evidence": [],
            "conclusion": "SYNTHETIC partial evidence, one unscored finding",
            "coverage_gaps": ["SYNTHETIC incomplete checks"],
            "validated_ai_summary": None,
            "ai_coverage": None,
            "next_actions": [],
            "uncertainties": [],
        },
    }
    return directory, result, payload


def write_payload(directory, payload):
    raw = json.dumps(payload).encode()
    (directory / "case.json").write_bytes(raw)
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "target": "synthetic.invalid",
                "resolved_ip": "127.0.0.1",
                "files": {"case.json": hashlib.sha256(raw).hexdigest()},
            }
        ),
        encoding="utf-8",
    )


def rewrite_receipt(path, result, *, parent_hash=None):
    record = json.loads(path.read_text(encoding="utf-8"))
    record["result"] = result
    if parent_hash is not None:
        record["parent_hash"] = parent_hash
    record["snapshot_hash"] = history._hash(
        {key: value for key, value in record.items() if key != "snapshot_hash"}
    )
    path.write_text(json.dumps(record), encoding="utf-8")
    return record["snapshot_hash"]


CANONICAL_CHANGES = [
    ("target", "synthetic-other.invalid"),
    ("resolved_ip", "127.0.0.2"),
    ("scan_status", "complete"),
    ("finding_count", 0),
    ("scored_finding_count", 2),
    ("unscored_finding_count", 0),
    ("service_count", 99),
    ("priorities", [{"finding_id": "synthetic-scored", "risk": 99, "band": "Critical"}]),
    ("unscored_findings", []),
    ("context", {"role": "database", "exposure": "internet_facing"}),
    ("scanner_coverage", {"nmap": "all ports complete", "nikto": "complete"}),
    ("collection_failures", []),
    ("self_defence", {"checks": [{"state": "protected"}]}),
    ("intelligence", {"matched_findings": 99}),
    ("cve_evidence", [{"finding_id": "synthetic-scored", "priority": {"risk": 99}}]),
    ("conclusion", "SYNTHETIC unsupported all clear"),
    ("coverage_gaps", []),
    ("future_canonical_fact", "SYNTHETIC injected fact"),
]


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize("field,value", CANONICAL_CHANGES)
def test_final_cannot_change_canonical_summary(tmp_path, boundary, field, value):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    changed["assessment_summary"][field] = value
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
        assert not (directory / "review-final.json").exists()
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)
        assert history.listing(tmp_path)["captures"][0]["status"] == "needs_review"


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize("field", ["conclusion", "coverage_gaps", "finding_count"])
def test_final_cannot_remove_canonical_summary_fields(tmp_path, boundary, field):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    del changed["assessment_summary"][field]
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize("field,value", CANONICAL_CHANGES[:15])
def test_even_matching_base_and_final_must_match_retained_facts(tmp_path, boundary, field, value):
    directory, result, _ = synthetic_capture(tmp_path)
    changed = copy.deepcopy(result)
    changed["assessment_summary"][field] = value
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, config_hash="SYNTHETIC config")
        assert not (directory / "review-evidence.json").exists()
    else:
        history.save(directory, result, config_hash="SYNTHETIC config")
        history.save(directory, result, final=True)
        parent = rewrite_receipt(directory / "review-evidence.json", changed)
        rewrite_receipt(directory / "review-final.json", changed, parent_hash=parent)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize("status", ["not_attempted", "unavailable", "needs_review"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("validated_ai_summary", "SYNTHETIC rejected prose"),
        ("ai_coverage", {"findings_included": 2}),
        ("next_actions", ["SYNTHETIC rejected action"]),
        ("uncertainties", ["SYNTHETIC rejected response"]),
    ],
)
def test_nonvalidated_ai_cannot_smuggle_summary_output(tmp_path, boundary, status, field, value):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    changed["ai_status"] = status
    changed["assessment_summary"][field] = value
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize(
    "field,value",
    [("ai_status", "validated"), ("ai_attempts", [{"status": "validated"}])],
)
def test_summary_ai_metadata_must_match_outer_result(tmp_path, boundary, field, value):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    changed["assessment_summary"][field] = value
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("batched", [False, True])
def test_legitimate_validated_ai_changes_preserve_evidence(tmp_path, batched, monkeypatch):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    before = (directory / "review-evidence.json").read_bytes()
    changed = copy.deepcopy(result)
    analysis = {
        "summary": "SYNTHETIC validated explanation",
        "recommended_actions": [{"action": "SYNTHETIC review evidence"}],
        "uncertainties": ["SYNTHETIC coverage limit"],
    }
    changed.update(
        ai_status="validated",
        ai_attempts=[{"provider": "synthetic", "status": "validated"}],
        analyst={"analysis": analysis},
    )
    summary = changed["assessment_summary"]
    summary.update(
        validated_ai_summary=analysis["summary"],
        next_actions=analysis["recommended_actions"],
        uncertainties=analysis["uncertainties"],
        ai_status=changed["ai_status"],
        ai_attempts=changed["ai_attempts"],
    )
    if batched:
        coverage = {
            "findings_total": 2,
            "findings_included": 2,
            "findings_omitted": 0,
            "batch_count": 2,
            "cross_batch_reasoning": False,
        }
        changed["analyst"].update(batches=[{}, {}], batch_coverage=coverage)
        summary.update(
            validated_ai_summary="2 findings included in 2 validated AI batches.",
            ai_coverage=coverage,
            next_actions=[],
            uncertainties=[
                "AI claims and citations are scoped to each batch; relationships across batches were not assessed."
            ],
        )
    original_import = builtins.__import__

    def offline_import(name, *args, **kwargs):
        assert name not in {
            "vulnassess.live_assessment",
            "vulnassess.scoring",
            "vulnassess.analyst",
        }, "receipt validation must use retained facts only"
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", offline_import)
    history.save(directory, changed, final=True)
    assert history.load(tmp_path, directory.name)["result"] == changed
    assert (directory / "review-evidence.json").read_bytes() == before


def test_legacy_minimal_summary_and_incomplete_profile_stay_unchanged(tmp_path):
    directory, result, payload = synthetic_capture(tmp_path)
    payload["context"] = [{"host_ip": "127.0.0.1"}]
    del payload["scanner_coverage"]
    del payload["scan_status"]
    write_payload(directory, payload)
    result["assessment_summary"] = {"conclusion": "SYNTHETIC legacy wording"}
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = {**result, "ai_status": "unavailable"}
    history.save(directory, changed, final=True)
    loaded = history.load(tmp_path, directory.name)
    assert loaded["result"] == changed
    assert loaded["result"]["assessment_summary"] == result["assessment_summary"]
    assert "scanner_coverage" not in loaded["payload"]
    assert "scan_status" not in loaded["payload"]


@pytest.mark.parametrize("value", [0, True, -1, "2"])
def test_minimal_summary_does_not_excuse_explicit_outer_count_lies(tmp_path, value):
    directory, result, _ = synthetic_capture(tmp_path)
    result["assessment_summary"] = {"conclusion": "SYNTHETIC legacy wording"}
    result["finding_count"] = value
    with pytest.raises(ConfigError):
        history.save(directory, result, config_hash="SYNTHETIC config")


@pytest.mark.parametrize("field,value", [("service_count", True), ("scored_finding_count", True)])
def test_boolean_is_not_a_recorded_count(tmp_path, field, value):
    directory, result, _ = synthetic_capture(tmp_path)
    result["assessment_summary"][field] = value
    with pytest.raises(ConfigError):
        history.save(directory, result, config_hash="SYNTHETIC config")


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize("value", [False, float("nan"), float("inf"), -float("inf")])
def test_canonical_priority_comparison_rejects_booleans_and_nonfinite_values(
    tmp_path, boundary, value
):
    directory, result, payload = synthetic_capture(tmp_path)
    payload["scores"][0]["risk"] = 0
    write_payload(directory, payload)
    result["assessment_summary"]["priorities"][0]["risk"] = 0
    changed = copy.deepcopy(result)
    changed["assessment_summary"]["priorities"][0]["risk"] = value
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, config_hash="SYNTHETIC config")
    else:
        history.save(directory, result, config_hash="SYNTHETIC config")
        history.save(directory, result, final=True)
        if type(value) is bool:
            parent = rewrite_receipt(directory / "review-evidence.json", changed)
            rewrite_receipt(directory / "review-final.json", changed, parent_hash=parent)
        else:
            # An attacker can hash nonstandard JSON; our strict canonical encoder refuses it.
            for name in ("review-evidence.json", "review-final.json"):
                path = directory / name
                record = json.loads(path.read_text(encoding="utf-8"))
                record["result"] = changed
                raw = json.dumps(
                    {key: item for key, item in record.items() if key != "snapshot_hash"},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                record["snapshot_hash"] = hashlib.sha256(raw.encode()).hexdigest()
                path.write_text(json.dumps(record), encoding="utf-8")
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
def test_zero_count_cannot_be_forged_as_false_in_matching_receipts(tmp_path, boundary):
    directory, result, _ = synthetic_capture(tmp_path)
    changed = copy.deepcopy(result)
    changed["assessment_summary"]["intelligence"]["matched_findings"] = False
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, config_hash="SYNTHETIC config")
    else:
        history.save(directory, result, config_hash="SYNTHETIC config")
        history.save(directory, result, final=True)
        parent = rewrite_receipt(directory / "review-evidence.json", changed)
        rewrite_receipt(directory / "review-final.json", changed, parent_hash=parent)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
def test_outer_count_lie_remains_invalid_with_a_minimal_summary(tmp_path, boundary):
    directory, result, _ = synthetic_capture(tmp_path)
    result["assessment_summary"] = {"conclusion": "SYNTHETIC legacy wording"}
    changed = {**result, "finding_count": 0}
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, config_hash="SYNTHETIC config")
    else:
        history.save(directory, result, config_hash="SYNTHETIC config")
        history.save(directory, result, final=True)
        parent = rewrite_receipt(directory / "review-evidence.json", changed)
        rewrite_receipt(directory / "review-final.json", changed, parent_hash=parent)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("field", ["findings", "scores", "hosts", "context", "scanner_coverage"])
def test_absent_legacy_payload_fields_are_not_filled_in(tmp_path, field):
    directory, result, payload = synthetic_capture(tmp_path)
    del payload[field]
    write_payload(directory, payload)
    result["assessment_summary"] = {"conclusion": "SYNTHETIC legacy wording"}
    history.save(directory, result, config_hash="SYNTHETIC config")
    loaded = history.load(tmp_path, directory.name)
    assert loaded["payload"] == payload
    assert loaded["result"] == result


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
def test_unrecorded_scanner_coverage_cannot_be_upgraded_to_complete(tmp_path, boundary):
    directory, result, payload = synthetic_capture(tmp_path)
    del payload["scanner_coverage"]
    write_payload(directory, payload)
    result["assessment_summary"].pop("scanner_coverage")
    changed = copy.deepcopy(result)
    changed["assessment_summary"]["scanner_coverage"] = {"nmap": "complete: all TCP ports"}
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, config_hash="SYNTHETIC config")
    else:
        history.save(directory, result, config_hash="SYNTHETIC config")
        history.save(directory, result, final=True)
        parent = rewrite_receipt(directory / "review-evidence.json", changed)
        rewrite_receipt(directory / "review-final.json", changed, parent_hash=parent)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
def test_validated_status_does_not_unbind_summary_from_retained_ai_output(tmp_path, boundary):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    changed.update(ai_status="validated", analyst={"analysis": {"summary": "SYNTHETIC retained"}})
    changed["assessment_summary"]["validated_ai_summary"] = "SYNTHETIC substituted output"
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("forgery", [None, "cvss_base", "epss", "priority", "feed_dates"])
def test_cve_summary_uses_only_retained_intelligence_and_priority_facts(tmp_path, forgery):
    directory, result, payload = synthetic_capture(tmp_path)
    payload["findings"][0]["cve_ids"] = ["CVE-2099-0001"]
    payload["scores"][0]["cve_id"] = "CVE-2099-0001"
    payload["feed_status"] = ["nvd", "epss", "kev"]
    payload["enrichments"] = [
        {
            "finding_id": "synthetic-scored",
            "cve_id": "CVE-2099-0001",
            "cvss40_base": 7.1,
            "cvss31_base": 9.1,
            "epss": 0.2,
            "kev": False,
            "feed_dates": {"nvd": "2099-01-01"},
        }
    ]
    write_payload(directory, payload)
    summary = result["assessment_summary"]
    summary["priorities"] = copy.deepcopy(payload["scores"])
    summary["intelligence"] = {
        "mode": "offline",
        "checked_cves": ["CVE-2099-0001"],
        "matched_findings": 1,
        "sources": payload["feed_status"],
    }
    summary["cve_evidence"] = [
        {
            "finding_id": "synthetic-scored",
            "cve_id": "CVE-2099-0001",
            "title": "SYNTHETIC scored",
            "tool": "unknown",
            "port": None,
            "evidence": "",
            "raw_path": None,
            "cvss_base": 7.1,
            "epss": 0.2,
            "kev_status": "not_listed",
            "feed_dates": {"nvd": "2099-01-01"},
            "priority": {"risk": 42, "band": "Medium"},
        }
    ]
    history.save(directory, result, config_hash="SYNTHETIC config")
    history.save(directory, result, final=True)
    if forgery is None:
        assert history.load(tmp_path, directory.name)["result"] == result
    else:
        changed = copy.deepcopy(result)
        changed["assessment_summary"]["cve_evidence"][0][forgery] = {
            "cvss_base": 0,
            "epss": 0.99,
            "priority": {"risk": False, "band": "Low"},
            "feed_dates": {},
        }[forgery]
        parent = rewrite_receipt(directory / "review-evidence.json", changed)
        rewrite_receipt(directory / "review-final.json", changed, parent_hash=parent)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


def test_reordered_json_keys_preserve_the_same_canonical_summary(tmp_path):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    changed["assessment_summary"] = dict(reversed(list(changed["assessment_summary"].items())))
    history.save(directory, changed, final=True)
    assert history.load(tmp_path, directory.name)["result"] == result


@pytest.mark.parametrize("field,value", [("finding_count", 0), ("priorities", [])])
def test_absent_findings_do_not_disable_other_available_fact_checks(tmp_path, field, value):
    directory, result, payload = synthetic_capture(tmp_path)
    del payload["findings"]
    write_payload(directory, payload)
    result["assessment_summary"][field] = value
    with pytest.raises(ConfigError):
        history.save(directory, result, config_hash="SYNTHETIC config")


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize("analyst", [None, "SYNTHETIC invalid mapping"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("validated_ai_summary", "SYNTHETIC unbound AI prose"),
        ("ai_coverage", {"findings_included": 2}),
        ("next_actions", ["SYNTHETIC unbound AI action"]),
        ("uncertainties", ["SYNTHETIC unbound AI uncertainty"]),
    ],
)
def test_validated_ai_content_requires_a_retained_analyst_mapping(
    tmp_path, boundary, analyst, field, value
):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    changed.update(ai_status="validated", analyst=analyst)
    changed["assessment_summary"][field] = value
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


def test_legacy_validated_status_only_summary_remains_readable(tmp_path):
    directory, result, _ = synthetic_capture(tmp_path)
    result.update(ai_status="validated", analyst=None)
    result["assessment_summary"] = {"conclusion": "SYNTHETIC legacy status only"}
    history.save(directory, result, config_hash="SYNTHETIC config")
    history.save(directory, result, final=True)
    assert history.load(tmp_path, directory.name)["result"] == result


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize("missing", ["profile", "feature", "value"])
@pytest.mark.parametrize("key", ["role", "exposure"])
def test_missing_context_supports_unknown_only(tmp_path, boundary, missing, key):
    directory, result, payload = synthetic_capture(tmp_path)
    if missing == "profile":
        payload.pop("context")
    elif missing == "feature":
        payload["context"][0].pop(key)
    else:
        payload["context"][0][key].pop("value")
    write_payload(directory, payload)
    changed = copy.deepcopy(result)
    if missing == "profile":
        result["assessment_summary"]["context"] = {"role": "unknown", "exposure": "unknown"}
    else:
        result["assessment_summary"]["context"][key] = "unknown"
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, config_hash="SYNTHETIC config")
    else:
        history.save(directory, result, config_hash="SYNTHETIC config")
        history.save(directory, result, final=True)
        assert history.load(tmp_path, directory.name)["result"] == result
        parent = rewrite_receipt(directory / "review-evidence.json", changed)
        rewrite_receipt(directory / "review-final.json", changed, parent_hash=parent)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
def test_omitted_summary_coverage_cannot_hide_an_impossible_batch_count(tmp_path, boundary):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    changed = copy.deepcopy(result)
    changed.update(
        ai_status="validated",
        analyst={"batches": [{}], "batch_coverage": {"findings_included": 99}},
    )
    changed["assessment_summary"] = {
        key: value
        for key, value in changed["assessment_summary"].items()
        if key not in history.AI_SUMMARY_FIELDS
    }
    changed["assessment_summary"]["validated_ai_summary"] = (
        "99 findings included in 1 validated AI batches."
    )
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)


@pytest.mark.parametrize("boundary", ["save", "rehashed_load"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("findings_total", 99),
        ("findings_total", True),
        ("findings_omitted", 1),
        ("findings_omitted", False),
        ("batch_count", 99),
        ("batch_count", True),
        ("cross_batch_reasoning", True),
    ],
)
def test_self_consistent_ai_coverage_cannot_invent_counts_or_global_reasoning(
    tmp_path, boundary, field, value
):
    directory, result, _ = synthetic_capture(tmp_path)
    history.save(directory, result, config_hash="SYNTHETIC config")
    coverage = {
        "findings_total": 2,
        "findings_included": 2,
        "findings_omitted": 0,
        "batch_count": 2,
        "cross_batch_reasoning": False,
    }
    coverage[field] = value
    changed = copy.deepcopy(result)
    changed.update(ai_status="validated", analyst={"batches": [{}, {}], "batch_coverage": coverage})
    changed["assessment_summary"].update(
        validated_ai_summary="2 findings included in 2 validated AI batches.",
        ai_coverage=coverage,
        uncertainties=[
            "AI claims and citations are scoped to each batch; relationships across batches were not assessed."
        ],
    )
    if boundary == "save":
        with pytest.raises(ConfigError):
            history.save(directory, changed, final=True)
    else:
        history.save(directory, result, final=True)
        rewrite_receipt(directory / "review-final.json", changed)
        with pytest.raises(ConfigError):
            history.load(tmp_path, directory.name)

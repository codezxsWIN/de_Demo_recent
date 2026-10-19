"""Outcome checks for stored synthetic evidence, never live assessment results."""

import copy
import re
from dataclasses import replace

import pytest

from tests.test_assessment_snapshot import SETTINGS, prepared_store
from tests.test_capture_history import capture
from vulnassess import capture_history, scoring
from vulnassess.schema import ContextProfile, Enrichment, Finding, Host
from vulnassess.ui import capture_review, presentation
from vulnassess.ui.reader import ReadOnlyStore


@pytest.fixture
def payload(tmp_path):
    with prepared_store(str(tmp_path)):
        pass
    with ReadOnlyStore(tmp_path / "assessment.db") as store:
        return store.run("snapshot")


def test_context_ledger_attributes_rewrites_to_recorded_rules_and_evidence(payload):
    score = next(row for row in payload["scores"] if row["host_ip"] == "172.28.0.10")
    rows = presentation._ledger_rows(score, SETTINGS.weights["environmental"])
    by_metric = {row["metric"]: row for row in rows}
    assert by_metric["MAV"]["rule"] == "Internal exposure narrows the attack vector"
    assert by_metric["MAV"]["driver"] == score["inputs"]["exposure"]
    assert by_metric["CR"]["rule"] == "Test environment overrides the role requirement"
    assert by_metric["CR"]["driver"] == score["inputs"]["manual"]["environment"]
    markup = presentation._context_ledger(
        {"scores": [score]}, {"weights": {"values": SETTINGS.weights}}
    )
    assert "Test environment overrides the role requirement" in markup
    assert str(score["env_score"]) in markup


def test_legacy_score_with_missing_context_is_shown_as_unattributed(payload):
    score = copy.deepcopy(next(row for row in payload["scores"] if row["base_vector"]))
    score["inputs"] = {}
    markup = presentation._context_ledger(
        {"scores": [score]}, {"weights": {"values": SETTINGS.weights}}
    )
    assert '<span class="quiet">Not recorded</span>' in markup
    assert str(score["env_score"]) in markup
    assert "confidence None" not in markup


def test_unscored_asset_has_explicit_empty_priority(payload):
    payload["hosts"].append(Host(ip="172.28.0.99").to_json())
    markup = presentation._priority_focus(payload, "172.28.0.99")
    assert markup == '<p class="state-message">No scored finding recorded for this asset.</p>'
    assert "priority-number" not in markup


def test_missing_epss_score_is_placed_below_axis_without_imputed_percentile(payload):
    original = next(row for row in payload["scores"] if row["base_vector"])
    finding = Finding.from_json(
        next(row for row in payload["findings"] if row["id"] == original["finding_id"])
    )
    profile = ContextProfile.from_json(
        next(row for row in payload["context"] if row["host_ip"] == finding.host_ip)
    )
    host = Host.from_json(next(row for row in payload["hosts"] if row["ip"] == finding.host_ip))
    enrichment = Enrichment.from_json(
        next(row for row in payload["enrichments"] if row["finding_id"] == finding.id)
    )
    score = scoring.score(
        finding,
        replace(enrichment, epss_percentile=None, kev=False),
        profile,
        host.services,
        SETTINGS.weights,
    ).to_json()
    assert score["epss_percentile"] is None and score["threat_multiplier"] is None
    markup = presentation._quadrant({"scores": [score]})
    point = re.search(r'<g class="quad-point.*?</g>', markup).group()
    assert "no EPSS row" in point
    assert 'cy="396.0"' in point
    assert f"stored risk {score['risk']}" in point
    assert "EPSS 0%" not in point and "EPSS 50%" not in point


def test_waterfall_uses_valid_nondefault_weights_in_report(payload):
    weights = copy.deepcopy(SETTINGS.weights)
    weights["threat"].update(base_multiplier=0.2, epss_weight=0.3, kev_boost=7)
    original = next(row for row in payload["scores"] if row["base_vector"])
    finding = Finding.from_json(
        next(row for row in payload["findings"] if row["id"] == original["finding_id"])
    )
    profile = ContextProfile.from_json(
        next(row for row in payload["context"] if row["host_ip"] == finding.host_ip)
    )
    host = Host.from_json(next(row for row in payload["hosts"] if row["ip"] == finding.host_ip))
    enrichment = Enrichment.from_json(
        next(row for row in payload["enrichments"] if row["finding_id"] == finding.id)
    )
    score = scoring.score(
        finding,
        replace(enrichment, epss_percentile=0.5, kev=False),
        profile,
        host.services,
        weights,
    ).to_json()
    payload["scores"] = [score]
    before = copy.deepcopy(payload)
    markup = presentation._risk_stage(payload, {"weights": {"values": weights}})
    waterfall = re.search(r'<div class="waterfall".*?</figure>', markup).group()
    assert "× exploitation multiplier 0.35" in waterfall
    assert "threat = 0.2 + 0.3 × EPSS percentile" in waterfall
    assert f"{score['env_score'] * 10 * (0.35 - 1):+.1f}" in waterfall
    assert payload == before


def test_capture_history_middle_page_preserves_navigation_and_escapes_target():
    markup = capture_review.index(
        {
            "page": 2,
            "page_size": 1,
            "total": 3,
            "captures": [
                {
                    "capture_id": "assessment-synthetic",
                    "target": "<script>bad()</script>",
                    "status": "ready",
                    "ai_status": "not_attempted",
                }
            ],
        }
    )
    assert 'href="/captures?page=1"' in markup and 'href="/captures?page=3"' in markup
    assert "No completed analysis recorded" in markup
    assert "&lt;script&gt;bad()&lt;/script&gt;" in markup
    assert "<script>" not in markup


def test_saved_review_escapes_ai_summary_and_local_protection_details(tmp_path):
    directory, result = capture(tmp_path)
    result["ai_status"] = "validated"
    result["assessment_summary"]["validated_ai_summary"] = "SYNTHETIC <script>summary</script>"
    result["analyst"] = {
        "analysis": {"summary": result["assessment_summary"]["validated_ai_summary"]}
    }
    capture_history.save(directory, result, config_hash="synthetic-config")
    record = capture_history.load(tmp_path, directory.name)
    assert (
        record["result"]["assessment_summary"]["validated_ai_summary"]
        == record["result"]["analyst"]["analysis"]["summary"]
    )
    record["payload"]["self_defence"] = {"note": "SYNTHETIC <img onerror=bad()>"}
    markup = capture_review.review(record)
    assert "Recorded AI assessment" in markup
    assert "SYNTHETIC &lt;script&gt;summary&lt;/script&gt;" in markup
    assert "Self-defence observations and precautions" in markup
    assert "&lt;img onerror=bad()&gt;" in markup
    assert "<img" not in markup and "<script>" not in markup

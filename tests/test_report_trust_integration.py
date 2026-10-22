"""Evidence packaging and display boundaries, without scans or provider calls."""

import copy
import json

import pytest

from tests.test_analyst import demo_payload
from tests.test_assessment_report import setup_report
from vulnassess import analyst, capture_history
from vulnassess.ai_boundary import verify_claims
from vulnassess.errors import LLMUnavailable
from vulnassess.ui import assessment_report


def test_evidence_reference_digits_are_not_factual_numbers_or_numeric_permission():
    case = {"services": [], "findings": []}
    evidence = [{"id": "E617", "text": "A retained observation"}]
    analyst.validate_prose_identifiers(["Review the observation in E617."], case, evidence)
    for prose in (
        "There are 617 vulnerabilities.",
        "E617 describes 617 vulnerabilities.",
        "Review E618.",
        "Review E617.52.",
    ):
        with pytest.raises(LLMUnavailable, match="unsupported numbers"):
            analyst.validate_prose_identifiers([prose], case, evidence)


def test_report_accepts_valid_inline_reference_and_still_withholds_invented_numbers(tmp_path):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    batch = record["result"]["analyst"]
    batch["evidence"][0]["id"] = "E617"
    for claim in batch["analysis"]["claims"]:
        claim["evidence_ids"] = ["E617"]
        for quote in claim["quotes"]:
            quote["evidence_id"] = "E617"
    batch["analysis"]["summary"] = "SYNTHETIC observation described in E617."
    document = assessment_report.render(record)
    assert "Current report validation: passed" in document
    assert "SYNTHETIC observation described in E617." in document
    assert "Supporting evidence for this interpretation" in document
    assert document.index('id="ai"') < document.index('id="decisions"')
    batch["analysis"]["summary"] = "SYNTHETIC observation described in E617 with 617 findings."
    document = assessment_report.render(record)
    assert "Current report validation: needs review" in document
    assert "with 617 findings" not in document


def test_network_highlights_are_scanner_records_with_escaped_product_text(tmp_path):
    _, directory = setup_report(tmp_path, ai=False)
    record = capture_history.load(directory.parent, directory.name)
    record["payload"]["hosts"][0]["services"] = [
        {
            "port": 7001,
            "protocol": "tcp",
            "name": "http",
            "product": "Oracle WebLogic admin httpd <script>unsafe</script>",
        }
    ]
    document = assessment_report.render(record)
    assert "Observed network evidence" in document
    assert "7001/tcp" in document
    assert "Endpoint role candidate: management interface" in document
    assert "&lt;script&gt;unsafe&lt;/script&gt;" in document
    assert "<script>unsafe</script>" not in document
    assert "Current report validation: passed" not in document


def test_model_case_separates_endpoint_controls_and_preserves_source():
    payload = demo_payload()
    host = payload["hosts"][0]
    ip = host["ip"]
    payload["findings"] = []
    payload["scores"] = []
    host["services"] = [
        {"port": 80, "protocol": "tcp", "name": "http", "tls": False},
        {"port": 443, "protocol": "tcp", "name": "http", "tls": True},
        {"port": 7001, "protocol": "tcp", "product": "Oracle WebLogic admin httpd", "tls": True},
    ]
    original = copy.deepcopy(payload)
    case, evidence, _ = analyst.build_case(payload, ip)
    assert payload == original
    by_port = {service["port"]: service for service in case["services"]}
    assert by_port[80]["tls"] is None
    assert by_port[443]["tls"] is True
    assert by_port[7001]["endpoint_context"]["role_candidate"] == "management_interface"
    assert all(
        service["endpoint_context"]["controls"]["auth_required"] is None
        for service in by_port.values()
    )
    evidence_by_id = {item["id"]: item["text"] for item in evidence}
    assert "tls=unknown" in evidence_by_id[by_port[80]["evidence_id"]]
    assert "tls=observed" in evidence_by_id[by_port[443]["evidence_id"]]


def test_all_citations_require_a_quote(tmp_path):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    batch = record["result"]["analyst"]
    claim = batch["analysis"]["claims"][0]
    claim["evidence_ids"].append("E2")
    evidence = [*batch["evidence"], {"id": "E2", "text": "A second observation"}]
    with pytest.raises(LLMUnavailable, match="every cited evidence ID"):
        verify_claims([claim], evidence, set(), {}, {"summary"}, {"summary": "Observed service"})


def test_report_exposes_management_candidate_and_does_not_claim_plaintext(tmp_path):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    record["payload"]["hosts"][0]["services"] = [
        {"port": 7001, "protocol": "tcp", "product": "Oracle WebLogic admin httpd", "tls": False}
    ]
    document = assessment_report.render(record)
    assert "management interface" in document
    assert "Unknown — no positive TLS observation" in document
    assert "does not prove console accessibility or unauthenticated access" in document


@pytest.mark.parametrize("mutation", ["tls", "procedural-label"])
def test_report_rechecks_retained_semantic_claims(tmp_path, mutation):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    analysis = record["result"]["analyst"]["analysis"]
    if mutation == "tls":
        analysis["summary"] = "TLS is enabled on port 443."
    else:
        analysis["uncertainties"] = ["Authentication remains unknown."]
        claim = copy.deepcopy(analysis["claims"][0])
        claim["path"] = "uncertainties.0"
        analysis["claims"].append(claim)
    document = assessment_report.render(record)
    assert "Current report validation: needs review" in document
    assert "All AI prose is withheld" in document
    assert "TLS is enabled on port 443." not in document


def test_reanalysis_preserves_original_and_marks_no_new_collection(tmp_path, monkeypatch):
    import json

    from scripts.reanalyze_saved_report import reanalyze

    _, directory = setup_report(tmp_path)
    original = {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}
    seen = []

    def unavailable(payload, ip, provider, progress, **options):
        seen.append((ip, provider, options))
        return {"ai_status": "unavailable", "analyst": None, "ai_attempts": []}

    monkeypatch.setattr(analyst, "analyze_optional", unavailable)
    record = reanalyze(directory.parent, directory.name, "ollama", lambda *_: None)
    assert seen[0][1] == "ollama"
    assert record["capture_id"] != directory.name
    assert record["result"]["ai_status"] == "unavailable"
    assert record["analysis_source"]["source_capture"] == directory.name
    assert (
        record["analysis_source"]["source_snapshot_hash"]
        == capture_history.load(directory.parent, directory.name)["snapshot_hash"]
    )
    assert original == {
        path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()
    }
    assert record["payload"] == json.loads(original["case.json"])
    assert "No new scanner or intelligence refresh" in assessment_report.render(record)


def test_reanalysis_requires_cloud_authorization_before_any_write(tmp_path):
    from scripts.reanalyze_saved_report import reanalyze
    from vulnassess.errors import ConfigError

    with pytest.raises(ConfigError, match="explicit authorization"):
        reanalyze(tmp_path, "assessment-absent", "google", lambda *_: None)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("host_value", [True, False, None])
def test_host_control_cannot_authorize_endpoint_auth_assertion(host_value):
    service = {"port": 7001, "protocol": "tcp", "product": "Oracle WebLogic admin httpd"}
    host = {"controls": {"auth_required": {"value": host_value}}}
    from vulnassess.service_context import endpoint_context

    service["endpoint_context"] = endpoint_context(service, host)
    assert service["endpoint_context"]["controls"]["auth_required"]["value"] is None
    with pytest.raises(LLMUnavailable, match="unsupported control assertion about auth_required"):
        analyst.validate_control_grounding(
            {"claims": [], "investigations": [], "uncertainties": []},
            [service],
            ["Port 7001 is unauthenticated."],
        )


def test_redis_finding_has_specific_verification_and_remediation():
    theme, meaning, verify, improve = assessment_report._finding_guidance(
        {
            "tool": "redis-check",
            "cve_ids": ["CVE-2022-0543"],
            "title": "Redis Lua package.loadlib exposed",
        }
    )
    assert theme == "Redis Lua sandbox exposure"
    assert "OS command execution were not attempted" in meaning
    assert "vendor patch status" in verify
    assert "do not replace the package fix" in improve


@pytest.mark.parametrize(
    "unsupported",
    [
        "Port 7001 is unauthenticated.",
        "Confirmed CVE-2099-99999 on this host.",
        "The replacement risk score is 99.",
        "A Redis service was observed.",
    ],
)
def test_saved_report_reuses_live_control_and_identifier_checks(tmp_path, unsupported):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    record["payload"]["hosts"][0]["services"] = [
        {"port": 7001, "protocol": "tcp", "product": "Oracle WebLogic admin httpd"}
    ]
    record["result"]["analyst"]["analysis"]["summary"] = unsupported
    document = assessment_report.render(record)
    assert "Current report validation: needs review" in document
    assert unsupported not in document


@pytest.mark.parametrize("captured_at", ["2025-01-01T00:00:00+00:00", None])
def test_reanalysis_preserves_receipt_only_capture_time_and_unknown(
    tmp_path, monkeypatch, captured_at
):
    from scripts.reanalyze_saved_report import reanalyze
    from tests.test_capture_history import capture
    from vulnassess import live_assessment

    directory, result = capture(tmp_path)
    capture_history.save(
        directory,
        result,
        config_hash="SYNTHETIC configuration",
        captured_at_override=captured_at,
    )
    source = capture_history.load(tmp_path, directory.name)
    assert source["captured_at"] == captured_at
    assert "captured_at" not in json.loads((directory / "manifest.json").read_text())

    def unavailable(*args, **kwargs):
        return {"ai_status": "unavailable", "analyst": None, "ai_attempts": []}

    def forbidden(*args, **kwargs):
        raise AssertionError("Retained-evidence reanalysis must not launch a scanner")

    monkeypatch.setattr(analyst, "analyze_optional", unavailable)
    monkeypatch.setattr(live_assessment.subprocess, "run", forbidden)
    # Reanalyzing a reanalysis must retain the same collection time as well.
    for _ in range(2):
        source_dir = tmp_path / source["capture_id"]
        original = {path.name: path.read_bytes() for path in source_dir.iterdir() if path.is_file()}
        record = reanalyze(tmp_path, source["capture_id"], "ollama", lambda *_: None)
        derived_dir = tmp_path / record["capture_id"]
        manifest = json.loads((derived_dir / "manifest.json").read_text())

        assert record["captured_at"] == captured_at
        assert record["analysis_attempted_at"] is not None
        baseline = json.loads((derived_dir / "review-evidence.json").read_text())
        final = json.loads((derived_dir / "review-final.json").read_text())
        assert baseline["captured_at"] == final["captured_at"] == captured_at
        assert final["parent_hash"] == baseline["snapshot_hash"]
        if captured_at is None:
            assert "captured_at" not in manifest
        else:
            assert manifest["captured_at"] == captured_at
        assert record["analysis_source"]["source_capture"] == source["capture_id"]
        assert record["analysis_source"]["source_snapshot_hash"] == source["snapshot_hash"]
        for key in ("payload", "evidence_hash", "intelligence_hash", "configuration_hash"):
            assert record[key] == source[key]
        assert (derived_dir / "case.json").read_bytes() == original["case.json"]
        assert original == {
            path.name: path.read_bytes() for path in source_dir.iterdir() if path.is_file()
        }
        source = record

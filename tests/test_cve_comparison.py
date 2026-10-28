"""Offline comparison contracts: frozen range replay is not remediation proof."""

import copy
import json

import pytest

from tests.test_cve_discovery import configurations, criterion, nvd_entry, page, service
from vulnassess import cve_comparison, cve_discovery
from vulnassess.schema import Host
from vulnassess.ui import cve_lab, network_labs

OLD = "CVE-2026-70101"
SHARED = "CVE-2026-70102"
NEW = "CVE-2026-70103"


def make_record(tmp_path, name, ip, version, entries):
    directory = tmp_path / name
    directory.mkdir()
    observed = service(version=version, port=6379)
    findings, _ = cve_discovery.discover(
        Host(ip, services=(observed,)),
        directory,
        None,
        fetch=lambda *_: page(*entries),
        sleep=lambda _: None,
    )
    return {
        "capture_id": name,
        "snapshot_hash": "a" * 64,
        "captured_at": "2026-10-27T00:00:00+00:00",
        "configuration_hash": "same-config",
        "read_only": True,
        "result": {"resolved_ip": ip, "scan_status": "complete", "ai_status": "validated"},
        "payload": {
            "hosts": [Host(ip, services=(observed,)).to_json()],
            "findings": [row.to_json() for row in findings],
            "scores": [
                {
                    "finding_id": row.id,
                    "host_ip": ip,
                    "cve_id": row.cve_ids[0],
                    "risk": 71.2,
                    "band": "High",
                }
                for row in findings
            ],
            "enrichments": [
                {"finding_id": row.id, "cve_id": row.cve_ids[0], "match_method": "cpe_range"}
                for row in findings
            ],
            "scanner_coverage": {"cve-discovery": "complete: one product query"},
            "feeds_meta": {
                "nvd": {
                    "path": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "file_date": "2026-10-27",
                    "loaded_at": "2026-10-27T00:00:00Z",
                }
            },
        },
    }


@pytest.fixture
def pair(tmp_path):
    left = make_record(
        tmp_path,
        "assessment-left",
        "127.0.0.4",
        "7.0.5",
        [
            nvd_entry(OLD),
            nvd_entry(SHARED, configs=configurations(criterion(versionEndExcluding="7.0.20"))),
        ],
    )
    right = make_record(
        tmp_path,
        "assessment-right",
        "127.0.0.5",
        "7.0.12",
        [
            nvd_entry(SHARED, configs=configurations(criterion(versionEndExcluding="7.0.20"))),
            nvd_entry(
                NEW,
                configs=configurations(
                    criterion(versionStartIncluding="7.0.10", versionEndExcluding="7.0.20")
                ),
            ),
        ],
    )
    return left, right


def test_comparison_derives_changes_and_replays_frozen_range_without_mutation(pair):
    left, right = pair
    original = copy.deepcopy(pair)
    result = cve_comparison.compare(left, right)
    assert result["status"] == "comparable"
    assert result["counts"] == {"left_only": 1, "shared": 1, "right_only": 1}
    by_cve = {row["cve_id"]: row for row in result["rows"]}
    assert by_cve[OLD]["reference_matches_left_retained_range"] is False
    assert by_cve[SHARED]["reference_matches_left_retained_range"] is True
    assert by_cve[NEW]["reference_matches_left_retained_range"] is None
    assert by_cve[OLD]["reference_version"] == "7.0.12"
    assert by_cve[SHARED]["right"]["priority"] == 71.2
    assert result["sources"][0]["snapshot_hash"] == "a" * 64
    assert "not proof" in " ".join(result["limits"])
    assert pair == original


@pytest.mark.parametrize("missing", ["left", "right", "both"])
def test_missing_capture_is_unavailable_not_zero_risk(pair, missing):
    left, right = pair
    result = cve_comparison.compare(
        None if missing != "right" else left, None if missing != "left" else right
    )
    assert result["status"] == "unavailable" and result["rows"] == []


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("result", "scan_status", "partial"),
        ("result", "scan_status", "failed"),
        ("coverage", "cve-discovery", "partial: finding budget reached"),
        ("coverage", "cve-discovery", "not run: offline snapshot"),
    ],
)
def test_incomplete_coverage_stays_limited(pair, section, key, value):
    left, right = pair
    destination = right["result"] if section == "result" else right["payload"]["scanner_coverage"]
    destination[key] = value
    result = cve_comparison.compare(left, right)
    assert result["status"] == "limited"
    assert any("coverage" in note for note in result["limits"])
    assert result["counts"]["shared"] == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("port", 9999),
        ("protocol", "udp"),
        ("version", "8.0.0"),
        ("cpe", "cpe:2.3:a:other:product:7.0.12:*:*:*:*:*:*:*"),
    ],
)
def test_mismatched_service_does_not_promote_an_unbound_candidate(pair, field, value):
    left, right = pair
    right["payload"]["hosts"][0]["services"][0][field] = value
    result = cve_comparison.compare(left, right)
    assert result["status"] == "limited"
    assert all(row["right"] is None for row in result["rows"])


def test_duplicate_identity_is_ambiguous_and_cannot_support_range_check(pair):
    left, right = pair
    right["payload"]["hosts"][0]["services"] *= 2
    result = cve_comparison.compare(left, right)
    assert result["status"] == "limited"
    assert any("Ambiguous" in note for note in result["limits"])
    assert all(row["reference_matches_left_retained_range"] is None for row in result["rows"])


def test_conflicting_products_on_one_endpoint_cannot_support_range_check(pair):
    left, right = pair
    conflicting = copy.deepcopy(right["payload"]["hosts"][0]["services"][0])
    conflicting["cpe"] = "cpe:2.3:a:other:product:7.0.12:*:*:*:*:*:*:*"
    right["payload"]["hosts"][0]["services"].append(conflicting)
    result = cve_comparison.compare(left, right)
    assert result["status"] == "limited"
    assert all(row["reference_matches_left_retained_range"] is None for row in result["rows"])


def test_conflicting_candidate_proofs_never_choose_by_input_order(pair, tmp_path):
    left, right = pair
    another = make_record(
        tmp_path,
        "assessment-conflicting-proof",
        "127.0.0.4",
        "7.0.5",
        [nvd_entry(OLD, configs=configurations(criterion(versionEndExcluding="7.0.20")))],
    )
    left["payload"]["findings"].append(another["payload"]["findings"][0])
    first = cve_comparison.compare(left, right)
    left["payload"]["findings"].reverse()
    second = cve_comparison.compare(left, right)
    for result in (first, second):
        row = next(row for row in result["rows"] if row["cve_id"] == OLD)
        assert row["reference_matches_left_retained_range"] is None
        assert row["left"]["ambiguous"] and row["left"]["priority"] is None
        assert row["left"]["matched_criteria"] == []
    assert first == second


@pytest.mark.parametrize("field", ["file_date", "loaded_at", "path"])
def test_intelligence_drift_is_disclosed_without_rewriting_scores(pair, field):
    left, right = pair
    right["payload"]["feeds_meta"]["nvd"][field] = "different"
    result = cve_comparison.compare(left, right)
    assert result["status"] == "limited"
    assert any("Intelligence snapshot" in note for note in result["limits"])
    assert (
        next(row for row in result["rows"] if row["cve_id"] == SHARED)["right"]["priority"] == 71.2
    )


def test_configuration_drift_and_retained_ai_provenance_are_visible(pair):
    left, right = pair
    right["configuration_hash"] = "another-policy"
    left["analysis_source"] = {"source_capture": "assessment-original"}
    result = cve_comparison.compare(left, right)
    assert any("configuration differs" in note for note in result["limits"])
    assert result["sources"][0]["analysis_mode"] == "retained-evidence reanalysis"


def test_same_endpoint_is_not_a_reference_pair_or_remediation_certificate(pair):
    left, _ = pair
    result = cve_comparison.compare(left, left)
    assert result["status"] == "limited"
    assert any("requires two separate" in note for note in result["limits"])


def test_missing_score_stays_unscored_and_foreign_cve_score_is_ignored(pair):
    left, right = pair
    right["payload"]["scores"][0]["cve_id"] = OLD
    result = cve_comparison.compare(left, right)
    row = next(row for row in result["rows"] if row["cve_id"] == SHARED)
    assert row["right"]["priority"] is None
    assert "unscored" in cve_lab._comparison_section(result)


@pytest.mark.parametrize("defect", ["cve", "host", "duplicate"])
def test_individual_cards_bind_score_to_unique_finding_cve_and_target(pair, defect):
    left, right = pair
    score = left["payload"]["scores"][0]
    score["risk"] = 99.9
    if defect == "cve":
        score["cve_id"] = "CVE-2026-79999"
    elif defect == "host":
        score["host_ip"] = "192.0.2.99"
    else:
        left["payload"]["scores"].append(copy.deepcopy(score))
    html = cve_lab.render({"127.0.0.4": left, "127.0.0.5": right})
    assert "99.9" not in html
    assert "unscored" in html


def test_changed_candidates_are_visible_and_shared_inventory_is_collapsed(pair):
    result = cve_comparison.compare(*pair)
    html = cve_lab._comparison_section(result)
    assert OLD in html and NEW in html
    assert "Still requires attention" in html
    assert "retained NVD range excludes reference version 7.0.12" in html
    assert "1 candidates recorded on both versions" in html
    assert "<details open" not in html
    assert "comparison.json" in html and "source receipts" in html


def test_read_only_route_has_no_scan_refresh_or_provider_side_effects(pair, tmp_path, monkeypatch):
    from tests.test_assessment_report import setup_report
    from vulnassess import analyst, intel_online, live_assessment

    app, directory = setup_report(tmp_path)
    records = dict(zip(("127.0.0.4", "127.0.0.5"), pair))
    monkeypatch.setattr(network_labs, "latest_records", lambda *_: records)

    def forbidden(*_, **__):
        pytest.fail("Read-only comparison attempted an active operation")

    monkeypatch.setattr(intel_online, "fetch_json", forbidden)
    monkeypatch.setattr(live_assessment, "run", forbidden)
    monkeypatch.setattr(analyst, "analyze_optional", forbidden)
    before = {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}
    response = app.get("/cve-lab/comparison.json")
    assert response.status == 200
    assert json.loads(response.body) == cve_lab.comparison(records)
    assert app.get("/cve-lab").status == 200
    assert before == {
        path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()
    }
    assert app.get("/cve-lab/comparison.json?target=192.0.2.1").status != 200

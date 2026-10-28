import copy
from types import SimpleNamespace

import pytest

from vulnassess import intelligence_evidence as evidence
from vulnassess.errors import IntelUnavailable
from vulnassess.schema import Enrichment
from vulnassess.store import Store
from vulnassess.ui.assessment_report import _intelligence_used

CVE = "CVE-2022-0543"


def case(path):
    with Store(path) as store:
        store.put_cves([{"id": CVE, "description": "Redis publisher proof", "cvss31_base": 10.0}])
        store.put_epss([(CVE, 0.9, 0.99, "2026-10-27")])
        store.put_kev([{"cveID": CVE, "requiredAction": "Apply vendor updates"}])
        feeds = {
            "nvd": {"path": "public NVD"},
            "epss": {"path": "daily EPSS"},
            "kev": {"path": "CISA catalog"},
        }
        finding = SimpleNamespace(id="finding-1", cve_ids=(CVE,))
        enrichment = Enrichment(
            "finding-1",
            CVE,
            "explicit",
            1.0,
            cvss31_base=10.0,
            epss=0.9,
            epss_percentile=0.99,
            kev=True,
        )
        return evidence.freeze(store, [finding], [enrichment], feeds), enrichment, feeds


def test_snapshot_freezes_real_point_reads_and_finding_binding(tmp_path):
    cache = tmp_path / "intel-cache.db"
    snapshot, enrichment, feeds = case(cache)
    evidence.verify(
        snapshot,
        findings=[{"id": "finding-1", "cve_ids": [CVE]}],
        enrichments=[enrichment.to_json()],
        feeds=feeds,
    )
    row = snapshot["records"][0]
    assert row["finding_ids"] == row["matched_finding_ids"] == ["finding-1"]
    assert row["records"]["epss"]["epss"] == 0.9
    with Store(cache) as store:
        store.put_epss([(CVE, 0.1, 0.2, "2026-10-28")])
        store.put_cves([{"id": CVE, "description": "changed later"}])
    assert row["records"]["epss"]["epss"] == 0.9
    assert row["records"]["nvd"]["description"] == "Redis publisher proof"
    evidence.verify(snapshot)


@pytest.mark.parametrize("mode", ["data", "record_hash", "binding", "identity", "duplicate"])
def test_snapshot_rejects_corruption_and_rebound_findings(tmp_path, mode):
    snapshot, enrichment, feeds = case(tmp_path / "intel-cache.db")
    forged = copy.deepcopy(snapshot)
    row = forged["records"][0]
    if mode == "data":
        row["records"]["epss"]["epss"] = 0.01
    elif mode == "record_hash":
        row["record_sha256"]["epss"] = "0" * 64
    elif mode == "binding":
        row["finding_ids"] = ["different-finding"]
    elif mode == "identity":
        row["records"]["nvd"]["id"] = "CVE-2021-44228"
        row["record_sha256"]["nvd"] = evidence.digest(row["records"]["nvd"])
    else:
        forged["records"].append(copy.deepcopy(row))
    forged["sha256"] = evidence.digest(
        {key: value for key, value in forged.items() if key != "sha256"}
    )
    with pytest.raises(IntelUnavailable):
        evidence.verify(
            forged,
            findings=[{"id": "finding-1", "cve_ids": [CVE]}],
            enrichments=[enrichment.to_json()],
            feeds=feeds,
        )


def test_report_uses_only_frozen_records_and_escapes_publisher_text(tmp_path):
    snapshot, enrichment, _ = case(tmp_path / "intel-cache.db")
    snapshot["records"][0]["records"]["nvd"]["description"] = "<script>unsafe</script>"
    snapshot["records"][0]["record_sha256"]["nvd"] = evidence.digest(
        snapshot["records"][0]["records"]["nvd"]
    )
    snapshot["sha256"] = evidence.digest(
        {key: value for key, value in snapshot.items() if key != "sha256"}
    )
    html = _intelligence_used(
        {
            "intelligence_evidence": snapshot,
            "findings": [{"id": "finding-1", "title": "Redis check"}],
            "enrichments": [enrichment.to_json()],
        }
    )
    assert "Intelligence used in this assessment" in html
    assert "2026-10-27" in html and "Apply vendor updates" in html and "Redis check" in html
    assert "&lt;script&gt;" in html and "<script>" not in html
    assert _intelligence_used({}) == ""


def test_snapshot_budget_is_enforced_before_large_lookups(tmp_path, monkeypatch):
    with Store(tmp_path / "intel-cache.db") as store:
        monkeypatch.setattr(evidence, "MAX_RECORDS", 0)
        with pytest.raises(IntelUnavailable, match="CVE budget"):
            evidence.freeze(store, [SimpleNamespace(id="x", cve_ids=(CVE,))], [], {})


def test_canonical_enrichment_cannot_contradict_frozen_numbers(tmp_path):
    snapshot, enrichment, feeds = case(tmp_path / "intel-cache.db")
    changed = {**enrichment.to_json(), "epss": 0.01}
    with pytest.raises(IntelUnavailable, match="contradicts"):
        evidence.verify(
            snapshot,
            findings=[{"id": "finding-1", "cve_ids": [CVE]}],
            enrichments=[changed],
            feeds=feeds,
        )
    empty = {**snapshot, "records": []}
    empty["sha256"] = evidence.digest(
        {key: value for key, value in empty.items() if key != "sha256"}
    )
    with pytest.raises(IntelUnavailable, match="incomplete CVE coverage"):
        evidence.verify(
            empty,
            findings=[{"id": "finding-1", "cve_ids": [CVE]}],
            enrichments=[enrichment.to_json()],
            feeds=feeds,
        )

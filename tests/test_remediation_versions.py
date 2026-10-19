"""Vulnerable-range boundaries are evidence, not vendor-fixed releases."""

from dataclasses import replace

import pytest

from tests.test_all import WEIGHTS, make_enrichment, make_profile
from tests.test_intel_trace import SYNTHETIC, apache, finding
from vulnassess import intel, scoring
from vulnassess.schema import Enrichment
from vulnassess.store import Store


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("boundary", ["inclusive", "exclusive", "ambiguous", "absent"])
def test_vulnerable_range_is_not_an_upgrade_target(tmp_path, explicit, boundary):
    observation = finding(cves=("CVE-1999-9001",) if explicit else ())
    services = (apache("2.4.49"),)
    with Store(tmp_path / "synthetic.db") as store:
        intel.load_feeds(SYNTHETIC / "feeds", store)
        record = store.cve("CVE-1999-9001")
        assert record is not None
        for match in record["cpe_matches"]:
            if "versionEndExcluding" in match:
                if boundary in {"inclusive", "ambiguous"}:
                    match["versionEndIncluding"] = match["versionEndExcluding"]
                if boundary in {"inclusive", "absent"}:
                    del match["versionEndExcluding"]
        store.put_cves([record])
        matches = intel.match_finding(observation, services, store, {})

    enrichment = next(item for item in matches if item.cve_id == "CVE-1999-9001")
    expected = {"inclusive": True, "exclusive": False}.get(boundary)
    assert enrichment.version_end_inclusive is expected
    assert Enrichment.from_json(enrichment.to_json()) == enrichment
    advice = scoring.fix_text(observation, enrichment, services)
    assert "to 2.4.51 or later" not in advice
    assert "httpd.apache.org" in advice
    if boundary != "absent":
        assert "Verify the vendor-fixed release" in advice
        label = "inclusion unknown" if boundary == "ambiguous" else boundary
        assert f"2.4.51 ({label})" in advice
    else:
        assert "2.4.51" not in advice
        assert "Apply the vendor fix" in advice


@pytest.mark.parametrize("bad_metadata", [None, "false", "true", 0, 1])
def test_legacy_or_invalid_boundary_metadata_is_not_guessed(bad_metadata):
    data = make_enrichment().to_json()
    data.pop("version_end_inclusive")
    if bad_metadata is not None:
        data["version_end_inclusive"] = bad_metadata
    loaded = Enrichment.from_json(data)
    assert loaded.version_end_inclusive is None
    advice = scoring.fix_text(finding(), loaded, (apache("2.4.49"),))
    assert "inclusion unknown" in advice
    assert "to 2.4.51 or later" not in advice


@pytest.mark.parametrize("inclusive", [True, False, None])
def test_boundary_metadata_changes_advice_without_changing_score(inclusive):
    observation = finding(cves=("CVE-1999-9001",))
    services = (apache("2.4.49"),)
    profile = make_profile()
    original = make_enrichment(finding_id=observation.id, patch_references=())
    updated = replace(original, version_end_inclusive=inclusive)
    before = scoring.score(observation, original, profile, services, WEIGHTS).to_json()
    after = scoring.score(observation, updated, profile, services, WEIGHTS).to_json()
    before.pop("fix")
    assert "Verify the vendor-fixed release" in after.pop("fix")
    assert before == after

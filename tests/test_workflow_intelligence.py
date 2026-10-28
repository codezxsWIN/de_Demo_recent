import json
from hashlib import sha256
from pathlib import Path

import pytest

from tests.test_assessment_report import setup_report
from tests.test_intelligence_submission import publisher
from vulnassess import intel_online
from vulnassess.store import Store


def test_workflow_reads_source_values_without_mutating_evidence_or_cache(tmp_path, monkeypatch):
    app, directory = setup_report(tmp_path)
    cache = Path(app.database).with_name("intel-cache.db")
    with Store(cache) as store:
        intel_online.sync_cves(["CVE-2022-0543"], store, fetch_json=publisher)
    before = sha256(cache.read_bytes()).hexdigest()
    case_before = (directory / "case.json").read_bytes()
    monkeypatch.setattr(
        intel_online,
        "fetch_json",
        lambda *_: pytest.fail("Read-only lookup fetched publisher data"),
    )
    index = json.loads(app.get("/api/intelligence").body)
    assert index["cve_ids"] == ["CVE-2022-0543"]
    response = app.get("/api/intelligence?cve=CVE-2022-0543")
    assert response.status == 200
    data = json.loads(response.body)
    assert data["record"]["nvd"]["cvss31_base"] == 10.0
    assert data["record"]["epss"]["epss"] == 0.99
    assert data["record"]["epss"]["score_date"] == "2026-10-23"
    assert data["record"]["kev_listed"] is True
    assert data["sources"]["nvd"]["url"] == intel_online.NVD_URL
    assert data["network_requested"] is False
    assert "not proof" in data["notice"]
    assert sha256(cache.read_bytes()).hexdigest() == before
    assert (directory / "case.json").read_bytes() == case_before
    missing = json.loads(app.get("/api/intelligence?cve=CVE-1999-9999").body)
    assert missing["state"] == "not_found"


@pytest.mark.parametrize(
    "query",
    [
        "cve=",
        "cve=invalid",
        "cve=A&cve=B",
        "url=https://other.invalid",
        "cve=../../secret",
        "cve=cve-2022-0543",
    ],
)
def test_workflow_cache_rejects_non_cve_input(tmp_path, query):
    app, _ = setup_report(tmp_path)
    assert app.get("/api/intelligence?" + query).status == 400


def test_missing_cache_is_explicit_and_never_created_by_viewer(tmp_path):
    app, _ = setup_report(tmp_path)
    assert json.loads(app.get("/api/intelligence").body)["state"] == "missing"
    assert not Path(app.database).with_name("intel-cache.db").exists()


def test_fixture_intelligence_not_presented_as_operational(tmp_path):
    app, _ = setup_report(tmp_path)
    cache = Path(app.database).with_name("intel-cache.db")
    with Store(cache) as store:
        store.put_feed_meta("nvd", "tests/synthetic/feeds/nvd.json", "synthetic", "2026-10-23", 1)
    data = json.loads(app.get("/api/intelligence?cve=CVE-2022-0543").body)
    assert data["state"] == "fixture"
    assert "record" not in data

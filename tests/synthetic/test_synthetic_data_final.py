"""Offline intelligence and persistence outcomes using bounded synthetic records."""

import gzip
import json

import pytest

from tests.test_all import make_finding
from vulnassess import intel, intel_status
from vulnassess.errors import ConfigError, IntelUnavailable
from vulnassess.repository import AssessmentRepository
from vulnassess.schema import Enrichment, Service
from vulnassess.store import Store

CVE = "CVE-2026-10001"
CPE = "cpe:2.3:a:synthetic:widget:*:*:*:*:*:*:*:*"


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "synthetic.db") as database:
        yield database


@pytest.fixture
def feeds(tmp_path):
    directory = tmp_path / "synthetic-feeds"
    (directory / "nvd").mkdir(parents=True)
    (directory / "nvd" / "page.json").write_text(
        json.dumps({"vulnerabilities": [{"cve": {"id": CVE}}]}), encoding="utf-8"
    )
    (directory / "epss.csv").write_text(
        "cve,epss,percentile\n" + CVE + ",0.2,0.7\n", encoding="utf-8"
    )
    (directory / "kev.json").write_text(
        json.dumps({"vulnerabilities": [{"cveID": CVE, "dateAdded": "2026-01-01"}]}),
        encoding="utf-8",
    )
    return directory


@pytest.mark.parametrize("feed,relative", [("nvd", "nvd/page.json"), ("kev", "kev.json")])
def test_invalid_feed_json_does_not_publish_that_feed(store, feeds, feed, relative):
    (feeds / relative).write_text('{"vulnerabilities":', encoding="utf-8")

    with pytest.raises(IntelUnavailable, match=f"not valid {feed.upper()} JSON"):
        intel.load_feeds(feeds, store)

    assert feed not in store.feeds_meta()
    assert (store.cve(CVE) if feed == "nvd" else store.kev(CVE)) is None


def test_gzip_epss_rejects_missing_scores_atomically_and_preserves_prior_provenance(store, feeds):
    intel.load_feeds(feeds, store)
    prior_metadata = store.feeds_meta()["epss"]
    (feeds / "epss.csv").unlink()
    raw = (
        "#model_version:v1,score_date:2026-01-02\n"
        "cve,epss,percentile\n,0.99,0.99\n   ,0.8,0.9\n" + CVE + ",0.2,0.7\nCVE-2026-10002,,\n"
    ).encode()
    path = feeds / "epss.csv.gz"
    path.write_bytes(gzip.compress(raw, mtime=0))

    with pytest.raises(IntelUnavailable, match="invalid EPSS score data"):
        intel.load_feeds(feeds, store)

    assert store.epss(CVE)["epss"] == 0.2
    assert store.epss("CVE-2026-10002") is None
    assert store.epss("") is None
    meta = store.feeds_meta()["epss"]
    assert meta == prior_metadata


@pytest.mark.parametrize(
    "service_cpe,criteria",
    [
        (CPE, None),
        ("cpe:2.3:a:synthetic", CPE),
        ("unrecognised:synthetic:widget", CPE),
        ("cpe:/a:synthetic", CPE),
    ],
    ids=["missing-candidate-cpe", "truncated-cpe23", "unknown-scheme", "partial-legacy-cpe"],
)
def test_incomplete_product_identity_never_creates_a_cve_match(store, service_cpe, criteria):
    finding = make_finding(port=443, cve_ids=())
    store.put_cves([{"id": CVE, "cpe_matches": [{"criteria": criteria}]}])
    service = Service(port=443, protocol="tcp", cpe=service_cpe, version="1.2")

    matches, traces = intel.match_finding_with_trace(finding, [service], store, {})

    assert matches == []
    assert any(item.decision == "not_matched" for item in traces)
    assert traces[-1].method == "native_severity"


@pytest.mark.parametrize(
    "version,bound,confidence,accepted",
    [
        ("1.2vendor", "2.0", 0.9, True),
        ("..vendor", "2.0", 0.5, True),
        ("1.2", "..vendor", None, False),
    ],
    ids=["numeric-banner-prefix", "unparseable-version-is-uncertain", "invalid-bound-rejected"],
)
def test_version_uncertainty_is_reflected_in_matching_outcome(
    store, version, bound, confidence, accepted
):
    finding = make_finding(port=443, cve_ids=())
    store.put_cves([{"id": CVE, "cpe_matches": [{"criteria": CPE, "versionEndExcluding": bound}]}])
    service = Service(port=443, protocol="tcp", cpe="cpe:/a:synthetic:widget", version=version)

    matches, traces = intel.match_finding_with_trace(finding, [service], store, {})

    assert bool(matches) is accepted
    if accepted:
        assert matches[0].match_confidence == confidence
        assert matches[0].version_end == bound
        assert matches[0].version_end_inclusive is False
    else:
        assert traces[0].decision == "rejected"
        assert traces[-1].decision == "fallback"


@pytest.mark.parametrize("version,accepted", [("1.2", True), ("1.3", False)])
def test_pinned_cpe_requires_the_exact_observed_version(store, version, accepted):
    finding = make_finding(port=443, cve_ids=())
    store.put_cves(
        [{"id": CVE, "cpe_matches": [{"criteria": CPE.replace("widget:*", "widget:1.2")}]}]
    )
    service = Service(port=443, protocol="tcp", cpe=CPE, version=version)

    matches = intel.match_finding(finding, [service], store, {})

    assert bool(matches) is accepted
    if accepted:
        assert matches[0].match_confidence == 1.0
        assert matches[0].version_end is None


def test_explicit_cve_uses_only_matching_product_for_remediation_bound(store):
    finding = make_finding(port=443, cve_ids=(CVE,))
    store.put_cves(
        [
            {
                "id": CVE,
                "cpe_matches": [
                    {"criteria": CPE.replace("widget", "other"), "versionEndExcluding": "99"},
                    {"criteria": CPE, "versionEndIncluding": "2.0"},
                ],
            }
        ]
    )
    service = Service(port=443, protocol="tcp", cpe=CPE, version="1.2")

    matches = intel.match_finding(finding, [service], store, {})

    assert len(matches) == 1
    assert matches[0].match_method == "explicit"
    assert matches[0].version_end == "2.0"
    assert matches[0].version_end_inclusive is True


@pytest.mark.parametrize("operation", [intel.enrich_run, intel.trace_run])
def test_missing_feeds_leave_run_history_and_findings_unchanged(store, operation):
    store.start_run("synthetic", "config")
    finding = make_finding()
    store.upsert_findings("synthetic", [finding])
    before = store.history_status("synthetic")

    with pytest.raises(IntelUnavailable, match="MISSING feed snapshots"):
        operation("synthetic", store)

    assert store.history_status("synthetic") == before
    assert store.findings("synthetic") == [finding]
    assert store.enrichments_for_run("synthetic") == {}
    assert not store.connection.in_transaction


def test_cache_status_distinguishes_fixtures_from_offline_snapshots(tmp_path):
    with Store(tmp_path / "intel-cache.db") as cache:
        cache.put_cves([{"id": CVE}])
        cache.put_epss([(CVE, 0.2, 0.7, "2026-01-01")])
        cache.put_feed_meta("nvd", "tests/synthetic/feeds/nvd", "nvd-hash", "2026-01-01", 1)
        cache.put_feed_meta("epss", "operator-snapshots/epss.csv", "epss-hash", "2026-01-01", 1)

    status = intel_status.read_cache_status(tmp_path / "assessment.db")

    assert status["mode"] == "partial_cache"
    assert status["feeds"] == [
        {"feed": "nvd", "status": "fixture", "rows": 1, "date": "2026-01-01"},
        {"feed": "epss", "status": "offline_snapshot", "rows": 1, "date": "2026-01-01"},
        {"feed": "kev", "status": "missing", "rows": 0, "date": None},
    ]


def test_legacy_enrichment_update_does_not_rewrite_a_run_snapshot(store):
    store.start_run("synthetic", "config")
    finding = make_finding()
    store.upsert_findings("synthetic", [finding])
    original = Enrichment(
        finding_id=finding.id, cve_id=CVE, match_method="explicit", match_confidence=1
    )
    store.upsert_enrichment(original)
    revised = Enrichment(
        finding_id=finding.id, cve_id=CVE, match_method="explicit", match_confidence=1, epss=0.8
    )
    store.upsert_enrichment(revised)

    assert store.enrichments(finding.id) == [revised]
    assert store.enrichments(finding.id, run_id="synthetic") == []
    assert store.connection.execute("SELECT count(*) FROM enrichments").fetchone()[0] == 1


def test_cannot_attach_intelligence_to_an_unknown_run(store):
    with pytest.raises(ConfigError, match="MISSING: run 'absent'"):
        store.capture_intelligence("absent", [], {}, {})

    assert store.run_info("absent") is None
    assert store.connection.execute("SELECT count(*) FROM enrichments").fetchone()[0] == 0
    assert not store.connection.in_transaction


def test_profile_lookup_is_scoped_to_run_and_host(store):
    from tests.test_all import make_profile

    profile = make_profile()
    store.start_run("synthetic", "config")
    store.upsert_profile("synthetic", profile)

    assert store.profile("synthetic", profile.host_ip) == profile
    assert store.profile("other", profile.host_ip) is None
    assert store.profile("synthetic", "192.0.2.99") is None


def test_repository_expands_a_legacy_store_without_losing_findings(tmp_path):
    path = tmp_path / "legacy.db"
    finding = make_finding()
    with Store(path) as legacy:
        legacy.start_run("synthetic", "config")
        legacy.upsert_findings("synthetic", [finding])

    with AssessmentRepository(path) as repository:
        rows = repository.findings_queue(run_id="synthetic", status="open")
        assert len(rows) == 1
        assert rows[0]["id"] == finding.id
        assert rows[0]["recurrence_count"] == 0
        assert rows[0]["lifecycle_status"] == "open"
        payload = repository.connection.execute(
            "SELECT json FROM findings WHERE id = ?", (finding.id,)
        ).fetchone()[0]
        assert json.loads(payload) == finding.to_json()

    with AssessmentRepository(path) as reopened:
        assert reopened.findings_queue(run_id="synthetic") == rows

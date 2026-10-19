"""Targeted publisher refreshes must not relabel unrelated cache rows as fresh."""

import copy
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnassess import intel, intel_online, live_assessment, saved_cve_case, scoring
from vulnassess.errors import ConfigError
from vulnassess.saved_cve_case import refresh_saved_case
from vulnassess.schema import ContextProfile, Feature, Finding, Host, Provenance, Service
from vulnassess.settings import Settings
from vulnassess.store import Store

REQUESTED = "CVE-2026-1001"
UNRELATED = "CVE-2026-1002"
CATALOG_ENTRY = "CVE-2026-1003"
NOW = datetime(2026, 10, 17, tzinfo=UTC)
OLD = "2020-01-01T00:00:00+00:00"
LOW_VECTOR = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CPE = "cpe:2.3:a:synthetic:widget:1.0:*:*:*:*:*:*:*"


def _record(cve_id, *, stale=False):
    return {
        "id": cve_id,
        "cvss31_vector": HIGH_VECTOR if stale else LOW_VECTOR,
        "cvss31_base": 9.8 if stale else 1.8,
        "cvss40_base": None,
        "cpe_matches": [{"criteria": CPE}],
        "_fetched_at": OLD if stale else NOW.isoformat(),
    }


def _payload():
    host = Host(
        ip="172.28.0.12",
        services=(Service(port=8080, protocol="tcp", name="http", version="1.0", cpe=CPE),),
    )
    profile = ContextProfile(
        host_ip=host.ip,
        role=Feature("unknown", 1.0, "rule", "SYNTHETIC role observation"),
        exposure=Feature("internal", 1.0, "rule", "SYNTHETIC exposure observation"),
    )
    finding = Finding(
        id="synthetic-targeted-finding",
        host_ip=host.ip,
        tool="nikto",
        tool_native_id="synthetic-targeted",
        title="SYNTHETIC finding naming only the requested CVE",
        description="Synthetic refresh regression",
        evidence="SYNTHETIC scanner observation; no scanner was called",
        provenance=Provenance("nikto", "synthetic/targeted.json", 0, "synthetic"),
        port=8080,
        protocol="tcp",
        cve_ids=(REQUESTED,),
        native_severity="high",
    )
    return {
        "hosts": [host.to_json()],
        "context": [profile.to_json()],
        "findings": [finding.to_json()],
        "scores": [],
        "enrichments": [],
    }


@pytest.mark.parametrize("missing_nvd", [False, True])
@pytest.mark.parametrize("missing_epss", [False, True])
def test_saved_refresh_cannot_score_old_b_when_only_a_was_refreshed(
    tmp_path, monkeypatch, missing_nvd, missing_epss
):
    payload = _payload()
    original = copy.deepcopy(payload)
    cache_path = tmp_path / "intel-cache.db"
    with Store(cache_path) as store:
        store.put_cves([_record(REQUESTED, stale=True), _record(UNRELATED, stale=True)])
        store.put_epss(
            [(REQUESTED, 0.99, 0.99, "2020-01-01"), (UNRELATED, 0.99, 0.99, "2020-01-01")]
        )
        unrelated_before = (store.cve(UNRELATED), store.epss(UNRELATED), store.kev(UNRELATED))

    calls = []

    def fetch(url, limit):
        calls.append(url)
        if url.startswith(intel_online.NVD_URL):
            assert REQUESTED in url and UNRELATED not in url
            return {
                "vulnerabilities": []
                if missing_nvd
                else [
                    {
                        "cve": {
                            "id": REQUESTED,
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 1.8, "vectorString": LOW_VECTOR}}
                                ]
                            },
                        }
                    }
                ]
            }
        if url.startswith(intel_online.EPSS_URL):
            assert REQUESTED in url and UNRELATED not in url
            return {
                "status": "OK",
                "data": []
                if missing_epss
                else [{"cve": REQUESTED, "epss": "0.1", "percentile": "0.2", "date": "2026-10-17"}],
            }
        assert url == intel_online.KEV_URL
        return {
            "count": 1,
            "dateReleased": "2026-10-17",
            "vulnerabilities": [{"cveID": CATALOG_ENTRY}],
        }

    sync_cves = intel_online.sync_cves

    def targeted_sync(ids, store, **kwargs):
        assert ids == [REQUESTED]
        assert kwargs["force_refresh"] is True
        return sync_cves(ids, store, fetch_json=fetch, now=NOW, **kwargs)

    monkeypatch.setattr(intel_online, "sync_cves", targeted_sync)
    events = []
    result = refresh_saved_case(
        payload,
        "172.28.0.12",
        Settings(Path(__file__).resolve().parents[2] / "config"),
        tmp_path / "assessment.db",
        lambda *event: events.append(event),
    )

    assert result["scores"][0]["cve_id"] == REQUESTED
    assert {item["cve_id"] for item in result["enrichments"]} == {REQUESTED}
    enrichment = result["enrichments"][0]
    assert enrichment["cvss31_vector"] == (None if missing_nvd else LOW_VECTOR)
    assert enrichment["epss"] == (None if missing_epss else 0.1)
    assert (result["scores"][0]["native_fallback"] is not None) is missing_nvd
    assert result["intelligence_mode"] == "on_demand"
    assert result["intelligence_refreshed_at"]
    assert len(calls) == 3
    assert payload == original

    # The bounded match must not delete unrelated facts or change full-catalog matching.
    with Store(cache_path) as store:
        assert (
            store.cve(UNRELATED),
            store.epss(UNRELATED),
            store.kev(UNRELATED),
        ) == unrelated_before
        assert (store.cve(REQUESTED) is None) is missing_nvd
        assert (store.epss(REQUESTED) is None) is missing_epss
        full_matches, _ = intel.match_finding_with_trace(
            Finding.from_json(payload["findings"][0]),
            Host.from_json(payload["hosts"][0]).services,
            store,
            {"nvd": "2020-01-01"},
        )
        assert scoring.best_enrichment(full_matches).cve_id == UNRELATED


def test_requested_cache_restricts_every_lookup_without_mutating_the_cache(tmp_path):
    with Store(tmp_path / "intel-cache.db") as store:
        store.put_cves([_record(REQUESTED), _record(UNRELATED, stale=True)])
        store.put_epss([(REQUESTED, 0.1, 0.2, "2026-10-17"), (UNRELATED, 0.99, 0.99, "2020-01-01")])
        store.put_kev([{"cveID": REQUESTED}, {"cveID": UNRELATED}])
        before = list(store.connection.iterdump())
        ids = [f" {REQUESTED.lower()} "]
        view = intel_online.requested_cache(store, ids)
        ids.append(UNRELATED)

        assert view.cve(REQUESTED) == store.cve(REQUESTED)
        assert view.epss(REQUESTED) == store.epss(REQUESTED)
        assert view.kev(REQUESTED) == store.kev(REQUESTED)
        assert view.cve(UNRELATED) is None
        assert view.epss(UNRELATED) is None
        assert view.kev(UNRELATED) is None
        assert view.all_cves() == [store.cve(REQUESTED)]
        assert list(store.connection.iterdump()) == before


def test_requested_cache_does_not_replace_missing_requested_rows_with_other_cves(tmp_path):
    with Store(tmp_path / "intel-cache.db") as store:
        store.put_cves([_record(UNRELATED, stale=True)])
        store.put_epss([(UNRELATED, 0.99, 0.99, "2020-01-01")])
        store.put_kev([{"cveID": UNRELATED}])
        before = list(store.connection.iterdump())
        view = intel_online.requested_cache(store, [REQUESTED])

        assert view.cve(REQUESTED) is None
        assert view.epss(REQUESTED) is None
        assert view.kev(REQUESTED) is None
        assert view.all_cves() == []
        assert list(store.connection.iterdump()) == before


def test_requested_cache_never_decodes_unrelated_malformed_cve_rows(tmp_path):
    with Store(tmp_path / "intel-cache.db") as store:
        store.put_cves([_record(REQUESTED)])
        store.connection.execute("INSERT INTO cve (id, json) VALUES (?, ?)", (UNRELATED, "{"))
        store.connection.commit()
        view = intel_online.requested_cache(store, [REQUESTED])

        assert view.all_cves() == [store.cve(REQUESTED)]
        assert view.cve(UNRELATED) is None


@pytest.fixture
def live_cache_scenario(tmp_path, monkeypatch):
    config = tmp_path / "config"
    shutil.copytree(Path(__file__).resolve().parents[2] / "config", config)
    payload = _payload()
    host = Host.from_json(payload["hosts"][0])
    finding = Finding.from_json(payload["findings"][0])
    cache_path = tmp_path / "intel-cache.db"
    with Store(cache_path) as store:
        store.put_cves([_record(REQUESTED, stale=True), _record(UNRELATED, stale=True)])
        store.put_epss([(UNRELATED, 0.99, 0.99, "2020-01-01")])

    def scanner(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text("SYNTHETIC scanner boundary")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "synthetic-nmap")
    monkeypatch.setattr(live_assessment.subprocess, "run", scanner)
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", lambda *_: ([host], [finding]))
    monkeypatch.setattr(
        live_assessment.analyst,
        "configuration_detail",
        lambda _: "SYNTHETIC provider configuration",
    )
    monkeypatch.setattr(
        live_assessment.analyst,
        "analyze_optional",
        lambda *_args, **_kwargs: {
            "analyst": None,
            "ai_status": "unavailable",
            "ai_attempts": [],
        },
    )

    def run():
        cases = []
        result = live_assessment.run(
            host.ip,
            {"status": "ready", "resolved_ips": [host.ip]},
            config,
            provider="ollama",
            database=tmp_path / "assessment.db",
            on_progress=lambda *_: None,
            on_case=cases.append,
        )
        assert len(cases) == 1
        return result, cases[0]["payload"]

    return run, cache_path


@pytest.mark.parametrize("corrupt_unrelated", [False, True])
@pytest.mark.parametrize("missing_nvd", [False, True])
def test_live_on_demand_matching_is_bounded_and_never_decodes_unrelated_rows(
    live_cache_scenario, monkeypatch, corrupt_unrelated, missing_nvd
):
    run, cache_path = live_cache_scenario
    with Store(cache_path) as store:
        if corrupt_unrelated:
            store.connection.execute("UPDATE cve SET json = ? WHERE id = ?", ("{", UNRELATED))
            store.connection.commit()
        before = tuple(
            store.connection.execute("SELECT * FROM cve WHERE id = ?", (UNRELATED,)).fetchone()
        )
        epss_before = store.epss(UNRELATED)

    calls, reads, views = [], [], []
    original_sync = intel_online.sync_cves
    original_cve = Store.cve
    original_view = intel_online.requested_cache

    def fetch(url, limit):
        calls.append(url)
        if url.startswith(intel_online.NVD_URL):
            assert REQUESTED in url and UNRELATED not in url
            return {
                "vulnerabilities": []
                if missing_nvd
                else [
                    {
                        "cve": {
                            "id": REQUESTED,
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 1.8,
                                            "vectorString": LOW_VECTOR,
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ],
            }
        if url.startswith(intel_online.EPSS_URL):
            assert REQUESTED in url and UNRELATED not in url
            return {
                "status": "OK",
                "data": [
                    {
                        "cve": REQUESTED,
                        "epss": "0.1",
                        "percentile": "0.2",
                        "date": "2026-10-17",
                    }
                ],
            }
        assert url == intel_online.KEV_URL
        return {"count": 1, "vulnerabilities": [{"cveID": CATALOG_ENTRY}]}

    def sync(ids, store, **kwargs):
        assert ids == [REQUESTED]
        return original_sync(ids, store, fetch_json=fetch, now=NOW, **kwargs)

    def cve(store, identity):
        reads.append(identity)
        assert identity == REQUESTED, "Targeted matching must never read unrelated CVE JSON"
        return original_cve(store, identity)

    def bounded(store, ids):
        assert store.feeds_meta()["nvd"]["path"] == intel_online.NVD_URL
        views.append(tuple(ids))
        return original_view(store, ids)

    def forbidden(*args):
        pytest.fail("The on-demand branch must not decode the full shared CVE catalog")

    monkeypatch.setattr(intel_online, "sync_cves", sync)
    monkeypatch.setattr(intel_online, "requested_cache", bounded)
    monkeypatch.setattr(Store, "cve", cve)
    monkeypatch.setattr(Store, "all_cves", forbidden)
    result, payload = run()

    assert views == [(REQUESTED,)]
    assert reads and set(reads) == {REQUESTED}
    assert len(calls) == 3
    assert payload["intelligence_mode"] == "on_demand"
    assert payload["feeds_meta"]["nvd"]["path"] == intel_online.NVD_URL
    assert {item["cve_id"] for item in payload["enrichments"]} == {REQUESTED}
    assert payload["enrichments"][0]["cvss31_vector"] == (None if missing_nvd else LOW_VECTOR)
    assert result["assessment_summary"]["priorities"][0]["cve_id"] == REQUESTED
    with Store(cache_path) as store:
        after = tuple(
            store.connection.execute("SELECT * FROM cve WHERE id = ?", (UNRELATED,)).fetchone()
        )
        assert after == before
        assert store.epss(UNRELATED) == epss_before


def test_live_offline_snapshot_keeps_full_catalog_matching(live_cache_scenario, monkeypatch):
    run, cache_path = live_cache_scenario
    with Store(cache_path) as store:
        store.put_cves([_record(REQUESTED)])
        for feed in ("nvd", "epss", "kev"):
            store.put_feed_meta(feed, f"/offline-publisher/{feed}", "synthetic", "2020-01-01", 2)

    def forbidden(*args, **kwargs):
        pytest.fail("The offline full-catalog branch must not sync or restrict the cache")

    monkeypatch.setattr(intel_online, "sync_cves", forbidden)
    monkeypatch.setattr(intel_online, "requested_cache", forbidden)
    result, payload = run()

    assert payload["intelligence_mode"] == "offline"
    assert {item["cve_id"] for item in payload["enrichments"]} == {REQUESTED, UNRELATED}
    assert result["assessment_summary"]["priorities"][0]["cve_id"] == UNRELATED


@pytest.mark.parametrize("section", ["hosts", "context", "findings"])
@pytest.mark.parametrize("defect", ["missing", "not_list", "empty", "non_object", "wrong_target"])
def test_refresh_rejects_missing_or_invalid_prerequisites_before_cache_access(
    tmp_path, monkeypatch, section, defect
):
    payload = _payload()
    if defect == "missing":
        payload.pop(section)
    elif defect == "not_list":
        payload[section] = {}
    elif defect == "empty":
        payload[section] = []
    elif defect == "non_object":
        payload[section] = [None]
    else:
        payload[section][0]["ip" if section == "hosts" else "host_ip"] = "192.0.2.99"
    _assert_invalid_refresh(payload, tmp_path, monkeypatch)


@pytest.mark.parametrize("section", ["hosts", "context"])
def test_refresh_rejects_ambiguous_matching_prerequisites(tmp_path, monkeypatch, section):
    payload = _payload()
    payload[section].append(copy.deepcopy(payload[section][0]))
    _assert_invalid_refresh(payload, tmp_path, monkeypatch)


@pytest.mark.parametrize(
    "defect",
    ["host_service", "profile_role", "finding_fields", "finding_cve_list", "finding_cve_value"],
)
def test_refresh_wraps_malformed_prerequisite_records_as_config_errors(
    tmp_path, monkeypatch, defect
):
    payload = _payload()
    if defect == "host_service":
        payload["hosts"][0]["services"] = [None]
    elif defect == "profile_role":
        payload["context"][0]["role"] = None
    elif defect == "finding_fields":
        payload["findings"][0].pop("provenance")
    elif defect == "finding_cve_list":
        payload["findings"][0]["cve_ids"] = REQUESTED
    else:
        payload["findings"][0]["cve_ids"] = [None]
    _assert_invalid_refresh(payload, tmp_path, monkeypatch)


def test_refresh_rejects_non_object_payload_before_cache_access(tmp_path, monkeypatch):
    _assert_invalid_refresh(None, tmp_path, monkeypatch)


def _assert_invalid_refresh(payload, tmp_path, monkeypatch):
    original = copy.deepcopy(payload)

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid synthetic prerequisites must fail before cache or publisher access")

    monkeypatch.setattr(saved_cve_case, "Store", forbidden)
    monkeypatch.setattr(intel_online, "sync_cves", forbidden)
    events = []
    with pytest.raises(ConfigError, match="Saved refresh requires"):
        refresh_saved_case(
            payload,
            "172.28.0.12",
            Settings(Path(__file__).resolve().parents[2] / "config"),
            tmp_path / "assessment.db",
            lambda *event: events.append(event),
        )
    assert events == []
    assert payload == original
    assert not (tmp_path / "intel-cache.db").exists()

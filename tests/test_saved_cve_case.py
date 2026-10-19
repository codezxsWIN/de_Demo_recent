import hashlib
import json
from types import SimpleNamespace

import pytest

from vulnassess.errors import ConfigError


def saved(tmp_path):
    directory = tmp_path / "assessment-real"
    directory.mkdir()
    payload = {
        "hosts": [{"ip": "178.79.134.182", "services": []}],
        "findings": [{"cve_ids": ["CVE-2022-0543"]}],
    }
    content = json.dumps(payload).encode()
    (directory / "case.json").write_bytes(content)
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "target": "http://pentest-ground.com:6379/",
                "resolved_ip": "178.79.134.182",
                "files": {"case.json": hashlib.sha256(content).hexdigest()},
            }
        )
    )
    return directory


def load(tmp_path, allowed=True):
    from vulnassess.saved_cve_case import load_saved_cve_case

    scope = SimpleNamespace(contains=lambda _: allowed, is_canary=lambda _: False)
    return load_saved_cve_case(tmp_path, "http://pentest-ground.com:6379/", scope)


def test_saved_cve_capture_is_explicitly_historical(tmp_path):
    saved(tmp_path)
    result = load(tmp_path)
    assert result["historical_capture"] is True
    assert result["payload"]["findings"][0]["cve_ids"] == ["CVE-2022-0543"]
    assert result["captured_at"] is None
    assert result["capture_time_source"] == "unknown"
    assert "not recorded" in result["capture_time_warning"]


def test_tampered_saved_evidence_fails_closed(tmp_path):
    directory = saved(tmp_path)
    (directory / "case.json").write_text("{}")
    with pytest.raises(ConfigError):
        load(tmp_path)


def test_saved_capture_does_not_bypass_current_scope(tmp_path):
    saved(tmp_path)
    with pytest.raises(ConfigError):
        load(tmp_path, allowed=False)


def test_refresh_uses_publishers_and_recalculates_without_overwriting_capture(
    tmp_path, monkeypatch
):
    import copy
    from pathlib import Path

    from tests.test_analyst import demo_payload
    from vulnassess import intel_online
    from vulnassess.saved_cve_case import refresh_saved_case
    from vulnassess.settings import Settings

    payload = demo_payload()
    payload["intelligence_refreshed_at"] = "2020-01-01T00:00:00+00:00"
    payload["feeds_meta"] = {"nvd": {"file_date": "2020-01-01", "sha256": "old-capture"}}
    original = copy.deepcopy(payload)
    calls = []

    def sync(ids, store, **kwargs):
        calls.append((ids, kwargs))
        assert kwargs["force_refresh"] is True
        raise intel_online.IntelUnavailable("publisher unavailable")

    monkeypatch.setattr(intel_online, "sync_cves", sync)
    events = []
    result = refresh_saved_case(
        payload,
        "172.28.0.12",
        Settings(Path(__file__).resolve().parents[1] / "config"),
        tmp_path / "database.db",
        lambda *event: events.append(event),
    )
    assert calls
    assert payload == original
    assert result["enrichments"] == []
    assert result["feed_status"] == []
    assert result["feeds_meta"] == {}
    assert result["intelligence_mode"] == "unavailable"
    assert "intelligence_refreshed_at" not in result
    assert any(event[0] == "nvd" and event[1] == "error" for event in events)


@pytest.mark.parametrize("failed_feed", [None, "nvd", "epss", "kev"])
def test_fresh_feed_values_drive_new_derivatives_not_retained_scores(
    tmp_path, monkeypatch, failed_feed
):
    import copy
    from pathlib import Path

    from tests.test_analyst import demo_payload
    from vulnassess import intel_online
    from vulnassess.saved_cve_case import refresh_saved_case
    from vulnassess.settings import Settings
    from vulnassess.store import Store

    payload = demo_payload()
    payload["feeds_meta"] = {"nvd": {"file_date": "2020-01-01", "sha256": "old-capture"}}
    calls = []
    cve = next(
        item["cve_ids"][0]
        for item in payload["findings"]
        if item["host_ip"] == "172.28.0.12" and item["cve_ids"]
    )
    payload["findings"] = [
        item
        for item in payload["findings"]
        if item["host_ip"] == "172.28.0.12" and cve in item["cve_ids"]
    ]
    original = copy.deepcopy(payload)

    def fetch(url, limit):
        calls.append(url)
        feed = "nvd" if "nvd.nist.gov" in url else "epss" if "api.first.org" in url else "kev"
        if feed == failed_feed:
            raise intel_online.IntelUnavailable("SYNTHETIC publisher outage")
        if "nvd.nist.gov" in url:
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": cve,
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.8,
                                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            }
        if "api.first.org" in url:
            return {
                "status": "OK",
                "data": [{"cve": cve, "epss": "0.5", "percentile": "0.9", "date": "2026-10-01"}],
            }
        return {
            "count": 1,
            "dateReleased": "2026-10-01",
            "vulnerabilities": [{"cveID": "CVE-2026-9999"}],
        }

    real_sync = intel_online.sync_cves
    monkeypatch.setattr(
        intel_online,
        "sync_cves",
        lambda ids, store, **kwargs: real_sync(ids, store, fetch_json=fetch, **kwargs),
    )
    events = []
    with Store(tmp_path / "intel-cache.db") as store:
        for feed in ("nvd", "epss", "kev"):
            store.put_feed_meta(feed, "SYNTHETIC old cache", "old-hash", "2020-01-01", 1)
        old_cache_meta = store.feeds_meta()
    result = refresh_saved_case(
        payload,
        "172.28.0.12",
        Settings(Path(__file__).resolve().parents[1] / "config"),
        tmp_path / "database.db",
        lambda *event: events.append(event),
    )
    assert payload == original
    if failed_feed:
        assert len(calls) == {"nvd": 1, "epss": 2, "kev": 3}[failed_feed]
        assert result["enrichments"] == []
        assert result["feeds_meta"] == {}
        assert result["feed_status"] == []
        assert result["intelligence_mode"] == "unavailable"
        assert "intelligence_refreshed_at" not in result
        assert result["scores"]  # Collection remains usable when a publisher fails.
        with Store(tmp_path / "intel-cache.db") as store:
            assert store.feeds_meta() == old_cache_meta  # No partial publisher update.
        return
    assert len(calls) == 3
    assert result["enrichments"][0]["epss"] == 0.5
    assert result["enrichments"][0]["kev"] is False
    assert result["scores"] != original["scores"]
    assert result["intelligence_refreshed_at"]
    assert {event[0] for event in events if event[1] == "complete"} >= {
        "nvd",
        "epss",
        "kev",
        "intel",
        "score",
        "queue",
        "rationale",
    }
    with Store(tmp_path / "intel-cache.db") as store:
        assert store.feeds_meta()["nvd"]["path"] == intel_online.NVD_URL
        assert result["feeds_meta"] == store.feeds_meta()
    assert result["feeds_meta"]["epss"]["file_date"] == "2026-10-01"
    assert result["feeds_meta"]["kev"]["file_date"] == "2026-10-01"


def test_matching_failure_discards_partial_refresh_derivatives(tmp_path, monkeypatch):
    import copy
    import sqlite3
    from pathlib import Path

    from tests.test_analyst import demo_payload
    from vulnassess import saved_cve_case
    from vulnassess.schema import Enrichment
    from vulnassess.settings import Settings

    payload = demo_payload()
    finding = next(item for item in payload["findings"] if item["host_ip"] == "172.28.0.12")
    second = copy.deepcopy(finding)
    second["id"] = "synthetic-second-finding"
    payload["findings"] = [finding, second]
    payload["feeds_meta"] = {"nvd": {"file_date": "2020-01-01"}}
    original = copy.deepcopy(payload)
    matches = 0

    def match(item, *args):
        nonlocal matches
        matches += 1
        if matches == 2:
            raise sqlite3.OperationalError("SYNTHETIC read failure after first match")
        enrichment = copy.deepcopy(payload["enrichments"][0])
        enrichment["finding_id"] = item.id
        return [Enrichment.from_json(enrichment)], {}

    monkeypatch.setattr(saved_cve_case.intel_online, "sync_cves", lambda *args, **kwargs: {})
    monkeypatch.setattr(saved_cve_case.intel, "match_finding_with_trace", match)
    result = saved_cve_case.refresh_saved_case(
        payload,
        "172.28.0.12",
        Settings(Path(__file__).resolve().parents[1] / "config"),
        tmp_path / "database.db",
        lambda *args: None,
    )
    assert matches == 2
    assert payload == original
    assert result["intelligence_mode"] == "unavailable"
    assert result["enrichments"] == []
    assert result["feeds_meta"] == {}
    assert result["feed_status"] == []
    assert "intelligence_refreshed_at" not in result
    assert len(result["scores"]) == 2  # Evidence still receives native-severity priorities.


def test_replay_uses_valid_stage_ids_without_launching_scanners():
    from pathlib import Path
    from unittest.mock import patch

    from vulnassess.schema import ContextProfile, Feature
    from vulnassess.ui.server import UiApplication

    app = object.__new__(UiApplication)
    app.config_dir = Path(__file__).resolve().parents[1] / "config"
    app.database = app.config_dir.parent / "data" / "vulnassess.db"
    data = {
        "hosts": [{"ip": "178.79.134.182", "services": []}],
        "findings": [],
        "scores": [],
        "enrichments": [],
        "context": [
            ContextProfile(
                host_ip="178.79.134.182",
                role=Feature("unknown", 0.1, "rule", "SYNTHETIC retained test context"),
                exposure=Feature("internet_facing", 1.0, "rule", "SYNTHETIC retained public IP"),
            ).to_json()
        ],
    }
    capture = {
        "payload": data,
        "target": "http://pentest-ground.com:6379/",
        "resolved_ip": "178.79.134.182",
        "historical_capture": True,
        "captured_at": "2026-09-29T12:00:00+00:00",
    }
    events = []
    with (
        patch("vulnassess.ui.server.load_saved_cve_case", return_value=capture),
        patch("vulnassess.ui.server.refresh_saved_case", return_value=data) as refresh,
        patch(
            "vulnassess.ui.server.analyst.analyze_optional",
            return_value={"analyst": None, "ai_status": "unavailable", "ai_attempts": []},
        ),
        patch("vulnassess.live_assessment.subprocess.run") as scanner,
    ):
        result = app.live_report(
            capture["target"], "google", lambda *event: events.append(event), replay_saved=True
        )
    scanner.assert_not_called()
    refresh.assert_called_once()
    allowed = {
        "scope",
        "scanner",
        "endpoint_scan",
        "canonical",
        "context",
        "score",
        "queue",
        "rationale",
        "nikto",
        "nvd",
        "epss",
        "kev",
        "intel",
        "report",
    }
    assert all(event[0] in allowed for event in events)
    assert result["assessment_summary"]["historical_capture"] is True

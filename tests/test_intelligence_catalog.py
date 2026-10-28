"""Offline catalog union, pagination, provenance and read-only route regressions."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.test_assessment_report import setup_report
from vulnassess import intelligence_catalog as catalog
from vulnassess.intel_status import SOURCES
from vulnassess.store import Store

BULK = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
A, B, C, D = (f"CVE-2026-{10000 + i}" for i in range(4))


def populate(path):
    with Store(path) as store:
        store.put_cves(
            [
                {
                    "id": A,
                    "description": "Synthetic publisher description",
                    "cvss31_base": 8.1,
                    "published": "2026-01-01",
                }
            ]
        )
        store.put_epss(
            [(A, 0.5, 0.9, "2026-10-27"), (B, 0.01, 0.4, "2026-10-27"), (D, 0.0, 0.0, "2026-10-27")]
        )
        store.put_kev(
            [
                {
                    "cveID": A,
                    "dateAdded": "2026-10-01",
                    "dueDate": "2026-10-22",
                    "product": "Cache Server",
                },
                {"cveID": C, "vulnerabilityName": "Synthetic KEV-only reference"},
            ]
        )
        for name, url, count in (
            ("nvd", SOURCES["nvd"], 1),
            ("epss", BULK, 3),
            ("kev", SOURCES["kev"], 2),
        ):
            store.put_feed_meta(name, url, "a" * 64, "2026-10-27", count)


@pytest.fixture
def database(tmp_path):
    populate(tmp_path / "intel-cache.db")
    return tmp_path / "assessment.db"


def test_union_includes_unmatched_publisher_records_and_joins_page_summaries(database):
    result = catalog.read_catalog(database)
    assert result["state"] == "cached"
    assert result["counts"] == {"nvd": 1, "epss": 3, "kev": 2, "total": 4}
    records = {row["cve"]: row for row in result["records"]}
    assert list(records) == [A, B, C, D]
    assert records[A]["sources"] == ["nvd", "epss", "kev"]
    assert records[A]["cvss31_base"] == 8.1
    assert records[A]["description"] == "Synthetic publisher description"
    assert records[A]["published"] == "2026-01-01"
    assert records[A]["epss"] == 0.5 and records[A]["epss_date"] == "2026-10-27"
    assert records[A]["kev_date_added"] == "2026-10-01"
    assert records[A]["kev_due_date"] == "2026-10-22"
    assert records[B]["sources"] == ["epss"] and records[B]["cvss31_base"] is None
    assert records[B]["kev_listed"] is False
    assert records[C]["sources"] == ["kev"] and records[C]["kev_listed"] is True
    assert records[D]["epss"] == records[D]["epss_percentile"] == 0
    assert result["read_only"] and result["network_requested"] is False
    assert "not evidence" in result["notice"] and "absent" in result["notice"]


@pytest.mark.parametrize(
    "source,expected", [("all", [A, B, C, D]), ("nvd", [A]), ("epss", [A, B, D]), ("kev", [A, C])]
)
def test_source_filter_membership_and_exact_actual_counts(database, source, expected):
    result = catalog.read_catalog(database, source=source)
    assert [row["cve"] for row in result["records"]] == expected
    assert result["pagination"]["total_records"] == len(expected)
    assert result["counts"]["total"] == 4


def test_pagination_search_normalization_and_literal_sql_input(database):
    first = catalog.read_catalog(database, page_size=2)
    second = catalog.read_catalog(database, page=2, page_size=2)
    assert [row["cve"] for row in first["records"]] == [A, B]
    assert [row["cve"] for row in second["records"]] == [C, D]
    assert first["pagination"]["has_next"] and not first["pagination"]["has_previous"]
    assert second["pagination"]["has_previous"] and not second["pagination"]["has_next"]
    assert catalog.read_catalog(database, page=3, page_size=2)["records"] == []
    assert (
        catalog.read_catalog(database, search=" cve-2026-1000 ")["pagination"]["total_records"] == 4
    )
    assert catalog.read_catalog(database, search=B)["records"][0]["cve"] == B
    for query in ("%' OR 1=1 --", "CVE-2026-%", "CVE-2026-_"):
        assert catalog.read_catalog(database, search=query)["records"] == []


@pytest.mark.parametrize(
    "parameters",
    [
        {"page": 0},
        {"page": True},
        {"page": "1"},
        {"page_size": 0},
        {"page_size": 101},
        {"page_size": True},
        {"page": 1_000_001, "page_size": 100},
        {"source": "epss; DROP TABLE cve"},
        {"source": []},
        {"search": "x" * 65},
        {"search": "a\n"},
    ],
)
def test_invalid_bounds_and_filters_fail_before_opening_database(tmp_path, parameters):
    from vulnassess.errors import ConfigError

    with pytest.raises(ConfigError):
        catalog.read_catalog(tmp_path / "absent.db", **parameters)
    assert list(tmp_path.iterdir()) == []


def test_missing_remote_empty_and_corrupt_cache_states_never_create_cache(tmp_path):
    database = tmp_path / "assessment.db"
    assert catalog.read_catalog(database)["state"] == "missing"
    assert not (tmp_path / "intel-cache.db").exists()
    assert catalog.read_catalog("postgresql://unused")["state"] == "not_cached"
    with Store(tmp_path / "intel-cache.db"):
        pass
    assert catalog.read_catalog(database)["state"] == "empty"
    (tmp_path / "intel-cache.db").write_bytes(b"not sqlite")
    broken = catalog.read_catalog(database)
    assert broken["state"] == "unavailable" and broken["records"] == []
    assert broken["counts"]["total"] == 0


def test_fixture_metadata_hides_all_reference_rows(database):
    with Store(database.with_name("intel-cache.db")) as store:
        store.put_feed_meta("epss", "C:/repo/tests/synthetic/epss.csv", "x", "2026-10-27", 3)
    result = catalog.read_catalog(database)
    assert result["state"] == "fixture" and result["records"] == []
    assert A not in json.dumps(result)


def test_bulk_counts_freshness_and_nvd_date_labels(database):
    result = catalog.read_catalog(database)
    epss = result["sources"]["epss"]
    assert epss["url"] == BULK and epss["source_kind"] == "online"
    assert epss["coverage"] == "full daily snapshot" and epss["status"] == "fresh"
    assert epss["stored_rows"] == 3
    assert result["sources"]["nvd"]["date_label"] == "Cache reference date"
    assert result["sources"]["nvd"]["publisher_date"] is None
    assert result["sources"]["nvd"]["reference_date"] == "2026-10-27"
    with Store(database.with_name("intel-cache.db")) as store:
        with store.connection:
            store.connection.execute(
                "UPDATE feeds_meta SET rows = ?, loaded_at = ? WHERE feed = ?",
                (999, (datetime.now(UTC) - timedelta(days=2)).isoformat(), "epss"),
            )
    epss = catalog.read_catalog(database)["sources"]["epss"]
    assert epss["stored_rows"] == 3 and epss["declared_rows"] == 999
    assert "incomplete" in epss["coverage"] and epss["status"] == "incomplete"
    with Store(database.with_name("intel-cache.db")) as store:
        with store.connection:
            store.connection.execute("UPDATE feeds_meta SET rows = 3 WHERE feed = 'epss'")
    assert catalog.read_catalog(database)["sources"]["epss"]["status"] == "stale"


@pytest.mark.parametrize("mode", ["missing", "zero", "mismatch"])
def test_kev_absence_is_not_a_negative_without_usable_snapshot(database, mode):
    with Store(database.with_name("intel-cache.db")) as store:
        with store.connection:
            if mode == "missing":
                store.connection.execute("DELETE FROM feeds_meta WHERE feed = 'kev'")
            else:
                store.connection.execute(
                    "UPDATE feeds_meta SET rows = ? WHERE feed = 'kev'",
                    (0 if mode == "zero" else 99,),
                )
    result = catalog.read_catalog(database)
    assert all(row["kev_listed"] is None for row in result["records"])


def test_bad_or_oversized_summary_does_not_hide_valid_scalar_reference_rows(database):
    with Store(database.with_name("intel-cache.db")) as store:
        with store.connection:
            store.connection.execute(
                "UPDATE cve SET json = ?", ('{"description": "' + "x" * 100_000 + '"}',)
            )
            store.connection.execute("UPDATE kev SET json = ? WHERE cve = ?", ("not json", A))
    result = catalog.read_catalog(database)
    assert result["state"] == "cached"
    row = result["records"][0]
    assert row["summary_unavailable"] == ["nvd", "kev"]
    assert row["description"] is None and row["cvss31_base"] == 8.1 and row["epss"] == 0.5


def test_large_catalog_decodes_only_selected_page_and_uses_primary_keys(database, monkeypatch):
    with Store(database.with_name("intel-cache.db")) as store:
        with store.connection:
            store.connection.executemany(
                "INSERT INTO epss VALUES (?, ?, ?, ?)",
                ((f"CVE-2025-{20000 + i}", 0.1, 0.5, "2026-10-27") for i in range(12000)),
            )
    loads = catalog.json.loads
    decoded = []

    def count_loads(raw):
        decoded.append(raw)
        return loads(raw)

    monkeypatch.setattr(catalog.json, "loads", count_loads)
    result = catalog.read_catalog(database, page_size=10, search="CVE-2025-")
    assert result["pagination"]["total_records"] == 12000
    assert len(result["records"]) == 10 and decoded == []  # EPSS rows need no JSON decoding.
    query, values = catalog._identifiers("epss", "CVE-2025-")
    with sqlite3.connect(database.with_name("intel-cache.db")) as db:
        plan = db.execute("EXPLAIN QUERY PLAN " + query, values).fetchall()
    assert any("SEARCH" in row[3] and "INDEX" in row[3] for row in plan)


def test_catalog_routes_and_static_assets_are_offline_and_do_not_mutate_cache(
    tmp_path, monkeypatch
):
    from vulnassess import intel_online, live_assessment

    app, directory = setup_report(tmp_path)
    cache = Path(app.database).with_name("intel-cache.db")
    populate(cache)
    before = cache.read_bytes()
    evidence_before = (directory / "case.json").read_bytes()

    def forbidden(*_, **__):
        pytest.fail("Catalog GET attempted a publisher request or scan")

    monkeypatch.setattr(intel_online, "fetch_json", forbidden)
    monkeypatch.setattr(live_assessment, "run", forbidden)
    response = app.get("/api/intelligence/catalog?page_size=2&source=epss")
    assert response.status == 200
    assert json.loads(response.body)["pagination"]["total_records"] == 3
    for path in (
        "/intelligence",
        "/static/intelligence.html",
        "/static/intelligence.js",
        "/static/intelligence.css",
    ):
        assert app.get(path).status == 200
    assert app.get("/api/intelligence?cve=" + B).status == 200
    for query in (
        "page=0",
        "page_size=101",
        "page=no",
        "q=a&q=b",
        "source=nvd&source=epss",
        "unknown=x",
        "q=" + "x" * 513,
    ):
        assert app.get("/api/intelligence/catalog?" + query).status == 400
    assert cache.read_bytes() == before
    assert (directory / "case.json").read_bytes() == evidence_before
    script = app.get("/static/intelligence.js").body.decode()
    assert "innerHTML" not in script and "textContent" in script and "Not checked" in script

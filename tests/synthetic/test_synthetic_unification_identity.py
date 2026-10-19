"""Synthetic grouping-identity regressions, not measured scanner corroboration."""

import copy
from dataclasses import replace
from itertools import permutations

import pytest

from tests.test_all import make_enrichment
from tests.test_assessment_snapshot import SETTINGS, prepared_store
from vulnassess import pipeline, report, unify
from vulnassess.errors import ConfigError
from vulnassess.schema import Finding, Provenance
from vulnassess.unify import unify_findings, unify_run

A, B, C = "CVE-1999-9001", "CVE-1999-9002", "CVE-1999-9003"


def synthetic_finding(native_id, tool="nmap", cves=(A,), **changes):
    fields = {
        "host_ip": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "url": "http://192.0.2.10/synthetic-instance",
        "tool": tool,
        "tool_native_id": native_id,
        "title": native_id,
        "description": "SYNTHETIC identity input, not a real scanner result",
        "evidence": f"SYNTHETIC record {native_id}",
        "cve_ids": cves,
        "cwe_ids": (),
        "first_seen": "2026-10-18T00:00:00Z",
        "last_seen": "2026-10-18T00:00:00Z",
        "provenance": Provenance(tool, "tests/synthetic/synthetic_identity.json", 1, "synthetic"),
    }
    fields.update(changes)
    return Finding.make(**fields)


def assert_preserved(result, records):
    sources = [source for group in result.groups for source in group.source_finding_ids]
    assert sorted(sources) == sorted(record.id for record in records)
    assert len(sources) == len(set(sources))
    for group in result.groups:
        expected = {record.evidence for record in records if record.id in group.source_finding_ids}
        assert set(group.evidence) == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("url", None),
        ("url", ""),
        ("url", " "),
        ("url", "\n"),
        ("url", "http://192.0.2.10/a b"),
        ("port", None),
        ("port", 0),
        ("port", True),
        ("port", -1),
        ("port", 65536),
        ("port", "80"),
        ("protocol", None),
        ("protocol", ""),
        ("protocol", "unknown"),
        ("host_ip", ""),
        ("host_ip", " "),
    ],
)
def test_equal_unknown_or_malformed_identity_is_not_duplicate_confirmation(field, value):
    records = [
        synthetic_finding("alpha", **{field: value}),
        synthetic_finding("omega", "nikto", **{field: value}),
    ]
    before = [copy.deepcopy(record.to_json()) for record in records]
    result = unify_findings(records)
    assert result.unified_count == 2
    assert all(group.method == "singleton" for group in result.groups)
    assert_preserved(result, records)
    assert [record.to_json() for record in records] == before


@pytest.mark.parametrize("url_pair", [(None, None), (None, "/synthetic"), ("", "")])
def test_unresolved_instance_retains_visible_cve_review_link(url_pair):
    records = [
        synthetic_finding("alpha", url=url_pair[0]),
        synthetic_finding("omega", "nikto", url=url_pair[1]),
    ]
    result = unify_findings(records)
    assert result.unified_count == 2
    assert len(result.candidates) == 1
    assert "unresolved" in result.candidates[0].method
    assert "review" in result.candidates[0].justification.lower()
    assert_preserved(result, records)


@pytest.mark.parametrize("url", ["/synthetic-instance", "http://192.0.2.10/synthetic-instance"])
def test_positive_duplicate_requires_complete_matching_identity_and_cve_set(url):
    records = [
        synthetic_finding("alpha", cves=(A, B), url=url),
        synthetic_finding("omega", "nikto", cves=(B, A), url=url),
    ]
    result = unify_findings(records)
    assert result.raw_count == 2 and result.unified_count == 1
    assert result.groups[0].method == "shared_cve_same_instance"
    assert result.groups[0].confidence == 0.95
    assert result.groups[0].cve_ids == (A, B)
    assert result.candidates == ()
    assert_preserved(result, records)


@pytest.mark.parametrize("order", list(permutations(range(3))))
@pytest.mark.parametrize("case", ["chain", "pairwise_clique"])
def test_overlapping_cve_sets_cannot_bridge_distinct_weaknesses(order, case):
    sets = [(A,), (A, B), (B,)] if case == "chain" else [(A, B), (B, C), (A, C)]
    records = [
        synthetic_finding(name, tool, cves=cves)
        for name, tool, cves in zip(
            ("alpha", "middle", "omega"), ("nmap", "nikto", "nessus"), sets, strict=True
        )
    ]
    ordered = [records[index] for index in order]
    result = unify_findings(ordered)
    assert result.unified_count == 3
    assert len(result.candidates) == (2 if case == "chain" else 3)
    assert all("overlap" in candidate.method for candidate in result.candidates)
    assert result.to_json() == unify_findings(records).to_json()
    assert_preserved(result, records)


@pytest.mark.parametrize("order", list(permutations(range(3))))
def test_real_duplicate_pair_is_not_absorbed_by_a_compound_alert(order):
    records = [
        synthetic_finding("alpha"),
        synthetic_finding("middle", "nikto"),
        synthetic_finding("omega", "nessus", cves=(A, B)),
    ]
    result = unify_findings([records[index] for index in order])
    assert result.unified_count == 2
    duplicate = next(group for group in result.groups if len(group.source_finding_ids) == 2)
    assert set(duplicate.source_finding_ids) == {records[0].id, records[1].id}
    assert duplicate.cve_ids == (A,)
    assert len(result.candidates) == 2
    assert_preserved(result, records)
    assert result.to_json() == unify_findings(records).to_json()


def test_matching_publisher_association_can_support_a_group_without_raw_cve_ids():
    records = [synthetic_finding("alpha", cves=()), synthetic_finding("omega", "nikto", cves=())]
    enrichments = {
        record.id: [make_enrichment(finding_id=record.id, cve_id=A)] for record in records
    }
    before = {key: [entry.to_json() for entry in values] for key, values in enrichments.items()}
    result = unify_findings(records, enrichments)
    assert result.unified_count == 1
    assert result.groups[0].cve_ids == (A,)
    assert {
        key: [entry.to_json() for entry in values] for key, values in enrichments.items()
    } == before
    assert_preserved(result, records)


def test_an_enrichment_for_another_finding_cannot_create_corroboration():
    records = [synthetic_finding("alpha", cves=()), synthetic_finding("omega", "nikto", cves=())]
    foreign = make_enrichment(finding_id="SYNTHETIC unrelated identity", cve_id=A)
    with pytest.raises(ConfigError, match="unification.*enrichment.*finding"):
        unify_findings(records, {record.id: [foreign] for record in records})


@pytest.mark.parametrize(
    "identifier", ["", "unknown", "CVE-2024-1", "cve-2024-1234", None, False, 123, []]
)
@pytest.mark.parametrize("origin", ["raw", "enrichment"])
def test_malformed_cve_identifiers_cannot_become_group_identity(identifier, origin):
    records = [
        synthetic_finding("alpha", cves=(identifier,) if origin == "raw" else ()),
        synthetic_finding("omega", "nikto", cves=(identifier,) if origin == "raw" else ()),
    ]
    enrichment = (
        {}
        if origin == "raw"
        else {
            record.id: [make_enrichment(finding_id=record.id, cve_id=identifier)]
            for record in records
        }
    )
    with pytest.raises(ConfigError, match="unification.*CVE.*finding"):
        unify_findings(records, enrichment)


def test_known_different_instances_stay_review_only_without_losing_their_urls():
    records = [
        synthetic_finding("alpha", url="/one"),
        synthetic_finding("omega", "nikto", url="/two"),
    ]
    result = unify_findings(records)
    assert result.unified_count == 2
    assert result.candidates[0].method == "shared_cve_different_instance"
    assert "URLs differ" in result.candidates[0].justification
    assert {group.url for group in result.groups} == {"/one", "/two"}
    assert_preserved(result, records)


@pytest.mark.parametrize("kind", ["unresolved", "overlap"])
def test_actual_report_html_shows_why_ambiguous_records_are_not_merged(kind):
    records = [
        synthetic_finding("alpha"),
        synthetic_finding(
            "omega",
            "nikto",
            cves=(A, B) if kind == "overlap" else (A,),
            url="http://192.0.2.10/synthetic-instance" if kind == "overlap" else None,
        ),
    ]
    result = unify_findings(records)
    rendered = report._audit({"unification": result.to_json()})
    assert "Correlation candidates requiring review" in rendered
    assert "Why not merged" in rendered
    assert (
        f"shared_cve_{'overlap_candidate' if kind == 'overlap' else 'unresolved_instance'}"
        in rendered
    )
    assert "preview only" in rendered
    assert all(record.id in rendered for record in records)


@pytest.mark.parametrize("url", [None, "http://172.28.0.10/synthetic-instance"])
def test_grouping_preview_never_replaces_canonical_findings_or_score_queue(tmp_path, url):
    with prepared_store(str(tmp_path)) as store:
        records = [
            synthetic_finding(
                native_id,
                tool,
                host_ip="172.28.0.10",
                url=url,
                provenance=Provenance(
                    tool, "tests/synthetic/synthetic_identity.json", 1, "snapshot"
                ),
            )
            for native_id, tool in (("alpha", "nmap"), ("omega", "nikto"))
        ]
        store.upsert_findings("snapshot", records)
        pipeline.do_rank(SETTINGS, store, "snapshot")
        before = tuple(store.connection.iterdump())
        scores = [entry.to_json() for entry in store.scores("snapshot")]
        result = unify_run(store, "snapshot")
        assert tuple(store.connection.iterdump()) == before
        assert [entry.to_json() for entry in store.scores("snapshot")] == scores
        assert {record.id for record in records} <= {entry["finding_id"] for entry in scores}
        pair = [
            group
            for group in result.groups
            if set(group.source_finding_ids) & {record.id for record in records}
        ]
        assert len(pair) == (2 if url is None else 1)


@pytest.mark.parametrize("identifier", ["", " ", None, False, 1, [], {}])
def test_malformed_raw_source_identity_is_a_controlled_error(identifier):
    record = replace(synthetic_finding("alpha"), id=identifier)
    with pytest.raises(ConfigError, match="unification.*finding.*ID"):
        unify_findings([record])


def test_unrelated_service_blocks_do_not_require_all_pairs_comparison(monkeypatch):
    records = [synthetic_finding(f"synthetic-{index}", port=index + 1000) for index in range(200)]
    calls = 0
    original = unify._same_service

    def counted(left, right):
        nonlocal calls
        calls += 1
        return original(left, right)

    monkeypatch.setattr(unify, "_same_service", counted)
    result = unify_findings(records)
    assert result.unified_count == 200
    assert result.candidates == ()
    assert calls <= len(records)
    assert calls == 0
    assert_preserved(result, records)


@pytest.mark.parametrize("value", [float("nan"), object()])
def test_non_json_service_identity_has_a_controlled_error(value):
    record = replace(synthetic_finding("alpha"), port=value)
    with pytest.raises(ConfigError, match="unification.*service identity.*finding"):
        unify_findings([record])

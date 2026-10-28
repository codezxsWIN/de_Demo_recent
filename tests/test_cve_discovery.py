"""Offline regression contracts for conditional product/version CVE discovery."""

import copy
import json
from dataclasses import replace
from hashlib import sha256
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from vulnassess import cve_discovery, intel, intel_online
from vulnassess.errors import IntelUnavailable
from vulnassess.schema import Finding, Host, Provenance, Service
from vulnassess.store import Store

CVE = "CVE-2026-12345"
OTHER_CVE = "CVE-2026-12346"
TARGET = "192.0.2.41"
PRODUCT = "cpe:2.3:a:independentvendor:cache_server:*:*:*:*:*:*:*:*"
VERSIONED = PRODUCT.replace("cache_server:*", "cache_server:7.0.5")


def service(**changes):
    values = dict(
        port=16379,
        protocol="tcp",
        name="redis",
        product="Independent Cache Server",
        version="7.0.5",
        cpe=PRODUCT,
        banner="private scanner banner must never be sent to NVD",
    )
    return Service(**(values | changes))


def criterion(**changes):
    return (
        dict(
            vulnerable=True,
            criteria=PRODUCT,
            versionStartIncluding="7.0.0",
            versionEndExcluding="7.0.9",
        )
        | changes
    )


def configurations(match=None):
    return [{"nodes": [{"operator": "OR", "cpeMatch": [criterion() if match is None else match]}]}]


def nvd_entry(cve=CVE, *, configs=None):
    return {
        "cve": {
            "id": cve,
            "descriptions": [{"lang": "en", "value": "Synthetic cache product vulnerability"}],
            "configurations": configurations() if configs is None else configs,
            "references": [{"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]}],
        }
    }


def page(*entries, total=None, start=0):
    return {
        "startIndex": start,
        "totalResults": len(entries) if total is None else total,
        "vulnerabilities": list(entries),
    }


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "intel-cache.db") as cache:
        yield cache


def discover(tmp_path, store, *, services=None, payload=None, fetch=None):
    fetch = (
        fetch
        if fetch is not None
        else Mock(return_value=page(nvd_entry()) if payload is None else payload)
    )
    sleep, progress = Mock(), Mock()
    findings, receipt = cve_discovery.discover(
        Host(
            TARGET,
            hostname="private-host.example",
            services=(service(),) if services is None else services,
        ),
        tmp_path,
        store,
        fetch=fetch,
        sleep=sleep,
        progress=progress,
    )
    saved = json.loads((tmp_path / "cve-discovery.json").read_text(encoding="utf-8"))
    assert saved == receipt
    assert receipt["findings_created"] == len(findings)
    return findings, receipt, fetch, sleep, progress


@pytest.fixture
def candidate(tmp_path, store):
    findings, *_ = discover(tmp_path, store)
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize(
    "cpe",
    [
        PRODUCT,
        VERSIONED,
        "cpe:/a:independentvendor:cache_server:7.0.5",
        "cpe:/a:independentvendor:cache_server",
    ],
)
def test_identity_normalizes_only_observed_application_product_and_version(cpe):
    assert cve_discovery.identity(service(cpe=cpe)) == VERSIONED


@pytest.mark.parametrize(
    "changes",
    [
        {"cpe": None},
        {"cpe": "redis"},
        {"cpe": PRODUCT.replace(":a:", ":o:")},
        {"cpe": PRODUCT.replace(":a:", ":h:")},
        {"cpe": PRODUCT.replace("independentvendor", "*")},
        {"cpe": PRODUCT.replace("cache_server", "cache server")},
        {"cpe": PRODUCT.replace("cache_server:*", "cache_server:7.0.4")},
        {"cpe": PRODUCT.replace("cache_server:*", "cache_server:-")},
        {"version": None},
        {"version": ""},
        {"version": "*"},
        {"version": "7.x"},
        {"version": "7.0.5 or 7.2.0"},
        {"version": "7.0.5 (vendor patched)"},
        {"version": "7.0.5-1ubuntu1"},
        {"version": " 7.0.5"},
    ],
)
def test_identity_rejects_missing_conflicting_or_ambiguous_identity(changes):
    assert cve_discovery.identity(service(**changes)) is None


@pytest.mark.parametrize("field", range(6, 13))
def test_identity_rejects_unobserved_cpe_platform_or_edition_constraints(field):
    fields = PRODUCT.split(":")
    fields[field] = "restricted"
    assert cve_discovery.identity(service(cpe=":".join(fields))) is None


@pytest.mark.parametrize(
    "cpe",
    [
        "cpe:2.3:a:independentvendor:cache_server:7.0.5",
        VERSIONED + ":*",
        "cpe:/a:independentvendor:cache_server:7.0.5:vendor_patch",
    ],
)
def test_identity_does_not_erase_malformed_or_legacy_update_constraints(cpe):
    assert cve_discovery.identity(service(cpe=cpe)) is None


def test_independent_or_branch_survives_unrelated_environment_branch():
    matched = criterion()
    configs = [
        {
            "operator": "OR",
            "nodes": [
                {"operator": "AND", "nodes": [{"cpeMatch": [criterion()]}]},
                {"operator": "OR", "cpeMatch": [matched]},
            ],
        }
    ]
    before = copy.deepcopy(configs)
    assert cve_discovery.matching_criteria(configs, service()) == [matched]
    assert configs == before


@pytest.mark.parametrize(
    "restriction",
    [
        {"operator": "AND"},
        {"operator": "and"},
        {"operator": "XOR"},
        {"negate": True},
        {"negate": "false"},
    ],
)
@pytest.mark.parametrize("at_parent", [False, True])
def test_and_and_negated_applicability_are_never_flattened(restriction, at_parent):
    node = {"operator": "OR", "cpeMatch": [criterion()]}
    configs = [dict(restriction, nodes=[node])] if at_parent else [node | restriction]
    assert cve_discovery.matching_criteria(configs, service()) == []


def test_application_and_required_operating_system_is_unresolved():
    configs = [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [criterion()]},
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:independentvendor:required_os:*:*:*:*:*:*:*:*",
                        }
                    ],
                },
            ],
        }
    ]
    assert cve_discovery.matching_criteria(configs, service()) == []


@pytest.mark.parametrize("field", range(6, 13))
def test_matching_rejects_platform_language_update_and_edition_restrictions(field):
    fields = PRODUCT.split(":")
    fields[field] = "specific_platform"
    assert (
        cve_discovery.matching_criteria(
            configurations(criterion(criteria=":".join(fields))), service()
        )
        == []
    )


@pytest.mark.parametrize(
    "match",
    [
        criterion(vulnerable=False),
        criterion(vulnerable="true"),
        criterion(vulnerable=1),
        criterion(criteria=None),
        criterion(criteria="cpe:/a:independentvendor:cache_server:*"),
        criterion(criteria=PRODUCT + ":*"),
        criterion(criteria=PRODUCT.replace("cache_server", "other_product")),
        criterion(criteria=PRODUCT.replace("independentvendor", "other_vendor")),
        criterion(criteria=PRODUCT.replace(":a:", ":o:")),
        criterion(criteria=PRODUCT.replace("cache_server:*", "cache_server:-")),
        criterion(versionEndExcluding="7.0.9 vendor-patched"),
        criterion(versionEndExcluding=True),
        criterion(versionEndExcluding={"version": "7.0.9"}),
    ],
)
def test_non_vulnerable_other_product_and_malformed_criteria_do_not_match(match):
    assert cve_discovery.matching_criteria(configurations(match), service()) == []


@pytest.mark.parametrize(
    "configs",
    [None, {}, "OR", [None], [{"nodes": None}], [{"cpeMatch": {}}], [{"cpeMatch": [None]}]],
)
def test_malformed_configuration_shapes_fail_closed(configs):
    assert cve_discovery.matching_criteria(configs, service()) == []


@pytest.mark.parametrize(
    "version,bounds,expected",
    [
        ("7.0.0", {"versionStartIncluding": "7.0.0"}, True),
        ("7.0.0", {"versionStartExcluding": "7.0.0"}, False),
        ("6.9.9", {"versionStartIncluding": "7.0.0"}, False),
        ("7.0.9", {"versionEndExcluding": "7.0.9"}, False),
        ("7.0.9", {"versionEndIncluding": "7.0.9"}, True),
        ("7.0.10", {"versionEndIncluding": "7.0.9"}, False),
        ("7.0.5", {"versionStartIncluding": "7.0.0", "versionEndExcluding": "7.0.9"}, True),
        ("7.0.5", {"versionStartIncluding": "7.1.0", "versionEndExcluding": "7.0.9"}, False),
    ],
)
def test_range_boundaries_use_full_versions_including_patched_release(version, bounds, expected):
    match = {"vulnerable": True, "criteria": PRODUCT} | bounds
    assert cve_discovery.matching_criteria(configurations(match), service(version=version)) == (
        [match] if expected else []
    )


@pytest.mark.parametrize("version,expected", [("7.0.5", True), ("7.0.6", False)])
def test_pinned_nvd_version_requires_exact_observed_version(version, expected):
    match = {"vulnerable": True, "criteria": VERSIONED}
    assert (
        bool(cve_discovery.matching_criteria(configurations(match), service(version=version)))
        is expected
    )


def test_pinned_criteria_cannot_override_an_excluding_version_bound():
    match = criterion(criteria=VERSIONED, versionEndExcluding="7.0.5")
    assert cve_discovery.matching_criteria(configurations(match), service()) == []


def test_discovery_archives_candidate_evidence_and_queries_only_public_product(tmp_path, store):
    findings, receipt, fetch, sleep, progress = discover(tmp_path, store)
    fetch.assert_called_once()
    url, limit = fetch.call_args.args
    assert urlsplit(url)._replace(query="").geturl() == intel_online.NVD_URL
    assert parse_qs(urlsplit(url).query, keep_blank_values=True) == {
        "cpeName": [VERSIONED],
        "isVulnerable": [""],
        "resultsPerPage": [str(cve_discovery.MAX_RESULTS)],
        "startIndex": ["0"],
    }
    assert limit == 2 * 1024 * 1024
    assert TARGET not in url
    assert "private-host" not in url and "private scanner banner" not in url
    sleep.assert_not_called()
    assert progress.call_args.args[:2] == ("nvd", "running")
    assert receipt["queries"][0]["status"] == "complete"
    assert receipt["queries"][0]["decisions"][0]["matched"] is True
    assert receipt["services_skipped"] == []
    finding = findings[0]
    facts = cve_discovery.candidate_facts(finding, service())
    assert facts is not None
    assert facts["cve"] == CVE
    assert (facts["target_ip"], facts["port"], facts["transport"]) == (TARGET, 16379, "tcp")
    assert "banner" not in facts["service"]
    assert facts["notice"] == cve_discovery.NOTICE
    assert facts["nvd_record_sha256"] == intel.publisher_record_digest(store.cve(CVE))
    assert finding.cve_ids == (CVE,)
    assert finding.native_confidence == "medium"
    assert finding.provenance.raw_path == str((tmp_path / "cve-discovery.json").resolve())
    assert finding.reference_urls == ("https://vendor.example/advisory",)
    assert store.feeds_meta()["nvd"]["rows"] == 1
    assert store.connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 0


@pytest.mark.parametrize("version", [None, "", "7.x", "7.0.5 or 7.2.0"])
def test_no_port_name_or_banner_cve_guess_without_version(tmp_path, store, version):
    fetch = Mock(side_effect=AssertionError("ambiguous service must not query NVD"))
    findings, receipt, _, sleep, progress = discover(
        tmp_path, store, services=(service(version=version),), fetch=fetch
    )
    assert findings == [] and receipt["queries"] == []
    assert receipt["services_skipped"][0]["port"] == 16379
    assert receipt["services_skipped"][0]["reason"]
    assert cve_discovery.coverage(receipt).startswith("partial: 0 observed product/version queries; skipped services: 1")
    assert store.all_cves() == []
    fetch.assert_not_called()
    sleep.assert_not_called()
    progress.assert_not_called()


def test_discovery_coverage_distinguishes_complete_and_unidentified_services(tmp_path, store):
    complete_dir = tmp_path / "complete"
    complete_dir.mkdir()
    _, complete, *_ = discover(complete_dir, store, services=(service(),), payload=page())
    assert cve_discovery.coverage(complete).startswith("complete: 1 observed product/version queries; skipped services: 0")
    mixed_dir = tmp_path / "mixed"
    mixed_dir.mkdir()
    _, mixed, *_ = discover(mixed_dir, store, services=(service(), service(port=1234, cpe=None)), payload=page())
    assert cve_discovery.coverage(mixed).startswith("partial: 1 observed product/version queries; skipped services: 1")


@pytest.mark.parametrize("version", ["6.9.9", "7.0.9", "7.0.10"])
def test_discovery_rechecks_nvd_returned_versions_and_retains_rejection(tmp_path, store, version):
    findings, receipt, *_ = discover(tmp_path, store, services=(service(version=version),))
    assert findings == []
    assert receipt["queries"][0]["status"] == "complete"
    decision = receipt["queries"][0]["decisions"][0]
    assert decision["cve"] == CVE and decision["matched"] is False
    assert decision["reason"]


@pytest.mark.parametrize("restriction", [{"operator": "AND"}, {"negate": True}])
def test_discovery_never_uses_flattened_environment_or_negated_cpe_matches(
    tmp_path, store, restriction
):
    configs = [{"nodes": [{"operator": "OR", "cpeMatch": [criterion()]}]} | restriction]
    findings, receipt, *_ = discover(tmp_path, store, payload=page(nvd_entry(configs=configs)))
    assert findings == []
    assert receipt["queries"][0]["status"] == "complete"
    assert receipt["queries"][0]["decisions"][0]["matched"] is False


def test_same_product_reuses_lookup_but_binds_findings_to_each_endpoint(tmp_path, store):
    observed = (service(), service(port=26379), service(protocol="udp"))
    findings, receipt, fetch, sleep, _ = discover(tmp_path, store, services=observed)
    fetch.assert_called_once()
    sleep.assert_not_called()
    assert len(receipt["queries"]) == 1
    assert len({item.id for item in findings}) == 3
    assert {(item.port, item.protocol) for item in findings} == {
        (16379, "tcp"),
        (26379, "tcp"),
        (16379, "udp"),
    }
    for finding, endpoint in zip(findings, observed, strict=True):
        assert cve_discovery.candidate_facts(finding, endpoint) is not None


def test_different_products_are_throttled_and_product_budget_is_explicit(tmp_path, store):
    observed = tuple(
        service(port=16000 + index, cpe=PRODUCT.replace("cache_server", f"cache_{index}"))
        for index in range(cve_discovery.MAX_PRODUCTS + 1)
    )
    fetch = Mock(return_value=page())
    findings, receipt, _, sleep, _ = discover(tmp_path, store, services=observed, fetch=fetch)
    assert findings == []
    assert fetch.call_count == cve_discovery.MAX_PRODUCTS
    assert [call.args for call in sleep.call_args_list] == [(7,)] * (fetch.call_count - 1)
    assert len(receipt["queries"]) == fetch.call_count
    assert all(query["status"] == "complete" for query in receipt["queries"])
    assert receipt["services_skipped"][0]["port"] == observed[-1].port
    assert "partial" in receipt["services_skipped"][0]["reason"].lower()


@pytest.mark.parametrize("total,coverage", [(1, "complete"), (2, "partial"), (1000, "partial")])
def test_bounded_first_page_never_claims_complete_unseen_coverage(tmp_path, store, total, coverage):
    findings, receipt, fetch, *_ = discover(tmp_path, store, payload=page(nvd_entry(), total=total))
    assert len(findings) == 1
    query = receipt["queries"][0]
    assert (query["status"], query["returned"], query["total_results"]) == (coverage, 1, total)
    assert len(query["response_sha256"]) == 64
    fetch.assert_called_once()


def test_empty_complete_response_is_not_an_error_or_a_finding(tmp_path, store):
    findings, receipt, *_ = discover(tmp_path, store, payload=page())
    assert findings == []
    assert receipt["queries"][0]["status"] == "complete"
    assert receipt["queries"][0]["returned"] == receipt["queries"][0]["total_results"] == 0
    assert store.all_cves() == []


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"startIndex": 0, "totalResults": 1, "vulnerabilities": None},
        page(nvd_entry(), start=1),
        page(nvd_entry(), start=False),
        page(nvd_entry(), total=True),
        page(nvd_entry(), total="1"),
        page(nvd_entry(), total=0),
        page(total=1),
        page(total=-1),
        page(*[nvd_entry(f"CVE-2026-{20000 + i}") for i in range(cve_discovery.MAX_RESULTS + 1)]),
        page(nvd_entry(), nvd_entry()),
        page(nvd_entry(), nvd_entry("not-a-cve")),
        page(nvd_entry(), {"cve": {"id": None}}),
        page(nvd_entry(), None),
        page(nvd_entry(), {"cve": {"id": OTHER_CVE, "configurations": "broken"}}),
    ],
    ids=[
        "list-root",
        "missing-fields",
        "non-list-entries",
        "wrong-page",
        "boolean-page",
        "boolean-total",
        "string-total",
        "understated-total",
        "empty-incomplete",
        "negative-total",
        "oversized-page",
        "duplicate-cve",
        "invalid-cve",
        "null-cve",
        "null-entry",
        "bad-configurations",
    ],
)
def test_invalid_or_duplicate_response_publishes_no_partial_records(tmp_path, store, payload):
    store.put_cves([{"id": OTHER_CVE, "description": "existing cache row"}])
    before = (store.all_cves(), store.feeds_meta())
    findings, receipt, *_ = discover(tmp_path, store, payload=payload)
    assert findings == []
    assert receipt["queries"][0]["status"] == "error"
    assert receipt["queries"][0]["error"]
    assert receipt["queries"][0]["decisions"] == []
    assert (store.all_cves(), store.feeds_meta()) == before


def test_lookup_failure_is_receipted_without_exposing_transport_details(tmp_path, store):
    fetch = Mock(side_effect=IntelUnavailable("private transport diagnostics"))
    findings, receipt, *_ = discover(tmp_path, store, fetch=fetch)
    assert findings == [] and store.all_cves() == []
    assert receipt["queries"][0]["status"] == "error"
    assert "private transport diagnostics" not in json.dumps(receipt)


def test_finding_budget_reports_omitted_candidates(tmp_path, store):
    count = cve_discovery.MAX_FINDINGS + 1
    findings, receipt, *_ = discover(
        tmp_path,
        store,
        payload=page(*[nvd_entry(f"CVE-2026-{20000 + index}") for index in range(count)]),
    )
    assert len(findings) == cve_discovery.MAX_FINDINGS
    assert receipt["finding_budget_reached"] is True
    assert len(receipt["queries"][0]["decisions"]) == count
    assert all(decision["matched"] for decision in receipt["queries"][0]["decisions"])


def test_candidate_facts_accepts_finding_and_json_with_optional_observation(candidate):
    proof = json.loads(candidate.evidence)
    assert cve_discovery.candidate_facts(candidate) == proof
    assert cve_discovery.candidate_facts(candidate.to_json()) == proof
    assert cve_discovery.candidate_facts(candidate, service()) == proof


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_ip", "192.0.2.42"),
        ("port", 26379),
        ("protocol", "udp"),
        ("tool", "service-network"),
        ("tool", "nmap"),
        ("tool_native_id", "policy:redis:anonymous"),
        ("tool_native_id", "cpe-version:" + OTHER_CVE),
        ("cve_ids", []),
        ("cve_ids", [OTHER_CVE]),
        ("cve_ids", [CVE, OTHER_CVE]),
    ],
)
def test_candidate_facts_binds_endpoint_tool_policy_and_single_cve(candidate, field, value):
    record = candidate.to_json()
    record[field] = value
    assert cve_discovery.candidate_facts(record) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_ip", "192.0.2.42"),
        ("port", 26379),
        ("transport", "udp"),
        ("status", "observed policy violation"),
        ("cve", OTHER_CVE),
        ("nvd_record_sha256", "not-a-digest"),
        ("nvd_record_sha256", "A" * 64),
        ("matched_criteria", []),
        ("matched_criteria", [criterion(versionEndExcluding="7.0.5")]),
        ("matched_criteria", [criterion(criteria=PRODUCT.replace("cache_server", "other"))]),
    ],
)
def test_candidate_facts_rejects_rebound_or_unsupported_proof(candidate, field, value):
    proof = json.loads(candidate.evidence)
    proof[field] = value
    record = candidate.to_json() | {"evidence": json.dumps(proof)}
    assert cve_discovery.candidate_facts(record) is None


@pytest.mark.parametrize(
    "field",
    ["target_ip", "port", "transport", "cve", "service", "matched_criteria", "nvd_record_sha256"],
)
def test_candidate_facts_requires_binding_fields(candidate, field):
    proof = json.loads(candidate.evidence)
    del proof[field]
    assert (
        cve_discovery.candidate_facts(candidate.to_json() | {"evidence": json.dumps(proof)}) is None
    )


@pytest.mark.parametrize("evidence", ["not-json", "{}", "[]", "null", "true"])
def test_candidate_facts_malformed_evidence_fails_closed(candidate, evidence):
    assert cve_discovery.candidate_facts(candidate.to_json() | {"evidence": evidence}) is None


@pytest.mark.parametrize("duplicate_first", [False, True])
def test_candidate_facts_rejects_duplicate_json_binding_keys(candidate, duplicate_first):
    duplicate = '"target_ip": "192.0.2.42"'
    evidence = (
        "{" + duplicate + "," + candidate.evidence[1:]
        if duplicate_first
        else candidate.evidence[:-1] + "," + duplicate + "}"
    )
    assert cve_discovery.candidate_facts(candidate.to_json() | {"evidence": evidence}) is None


def test_discovered_finding_retains_parseable_binding_when_service_description_is_long(
    tmp_path, store
):
    observed = service(
        product="Independent Cache Server with optional compatibility modules; " * 30
    )
    findings, _, *_ = discover(tmp_path, store, services=(observed,))
    assert len(findings) == 1
    assert cve_discovery.candidate_facts(findings[0], observed) is not None


@pytest.mark.parametrize(
    "changes",
    [
        {"port": 26379},
        {"protocol": "udp"},
        {"version": "7.0.6"},
        {"cpe": PRODUCT.replace("cache_server", "other")},
    ],
)
def test_candidate_facts_rejects_different_live_service(candidate, changes):
    assert cve_discovery.candidate_facts(candidate, service(**changes)) is None


@pytest.mark.parametrize(
    "changes", [{"port": 26379}, {"protocol": "udp"}, {"version": None}, {"tls": "false"}]
)
def test_candidate_facts_checks_embedded_service_without_external_service(candidate, changes):
    proof = json.loads(candidate.evidence)
    proof["service"].update(changes)
    assert (
        cve_discovery.candidate_facts(candidate.to_json() | {"evidence": json.dumps(proof)}) is None
    )


def test_candidate_enrichment_is_conditional_and_never_cross_enriches_cached_cves(candidate, store):
    unrelated = intel._compact_cve(nvd_entry(OTHER_CVE))
    unrelated["_configurations"] = configurations()
    store.put_cves([unrelated])
    enrichments, traces = intel.match_finding_with_trace(candidate, (service(),), store, {})
    assert len(enrichments) == 1
    result = enrichments[0]
    assert (result.finding_id, result.cve_id, result.match_method) == (
        candidate.id,
        CVE,
        "cpe_range",
    )
    assert 0 < result.match_confidence < 1.0
    assert result.version_end == "7.0.9"
    assert result.version_end_inclusive is False
    assert all(trace.method != "explicit" for trace in traces)
    assert {trace.cve_id for trace in traces} == {CVE}
    assert store.enrichments(candidate.id) == []


@pytest.mark.parametrize(
    "mode",
    [
        "no-service",
        "different-port",
        "different-protocol",
        "patched",
        "no-version",
        "extra-cve",
        "no-cve",
        "missing-cache",
        "legacy-flat-cache",
        "environment-cache",
    ],
)
def test_candidate_enrichment_revalidates_identity_and_cache_instead_of_explicit_fallback(
    candidate, store, mode
):
    observed = (service(),)
    if mode == "no-service":
        observed = ()
    elif mode == "different-port":
        observed = (service(port=26379),)
    elif mode == "different-protocol":
        observed = (service(protocol="udp"),)
    elif mode == "patched":
        observed = (service(version="7.0.9"),)
    elif mode == "no-version":
        observed = (service(version=None),)
    elif mode == "extra-cve":
        candidate = replace(candidate, cve_ids=(CVE, OTHER_CVE))
        other = intel._compact_cve(nvd_entry(OTHER_CVE))
        other["_configurations"] = configurations()
        store.put_cves([other])
    elif mode == "no-cve":
        candidate = replace(candidate, cve_ids=())
    elif mode == "missing-cache":
        with store.connection:
            store.connection.execute("DELETE FROM cve WHERE id = ?", (CVE,))
    elif mode == "legacy-flat-cache":
        record = store.cve(CVE)
        del record["_configurations"]
        store.put_cves([record])
    elif mode == "environment-cache":
        record = store.cve(CVE)
        record["_configurations"] = [{"operator": "AND", "nodes": configurations()}]
        store.put_cves([record])
    enrichments, traces = intel.match_finding_with_trace(candidate, observed, store, {})
    assert enrichments == []
    assert all(trace.decision != "accepted" for trace in traces)
    assert all(trace.method != "explicit" for trace in traces)


def test_candidate_matching_selects_exact_transport_when_ports_collide(candidate, store):
    enrichments, _ = intel.match_finding_with_trace(
        candidate, (service(protocol="udp"), service()), store, {}
    )
    assert [(item.cve_id, item.match_method) for item in enrichments] == [(CVE, "cpe_range")]
    assert enrichments[0].match_confidence < 1.0


def ordinary_finding(observed, *, cves=()):
    return Finding.make(
        host_ip=TARGET,
        port=observed.port,
        protocol=observed.protocol,
        tool="service-network",
        tool_native_id="policy:synthetic-endpoint",
        title="Synthetic endpoint policy observation",
        description="Observed policy condition; applicability remains to be established",
        evidence="Synthetic policy observation on this endpoint",
        cve_ids=cves,
        provenance=Provenance("service-network", "synthetic-policy-capture.json", 0, "live"),
    )


def test_publisher_digest_excludes_only_top_level_retrieval_timestamp():
    record = {
        "id": CVE,
        "description": "Synthetic publisher content",
        "_configurations": configurations(),
    }
    before = copy.deepcopy(record)
    expected = sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert intel.publisher_record_digest(record) == expected
    assert (
        intel.publisher_record_digest(record | {"_fetched_at": "2026-10-27T00:00:00Z"}) == expected
    )
    assert (
        intel.publisher_record_digest(record | {"_fetched_at": "2026-10-28T00:00:00Z"}) == expected
    )
    assert intel.publisher_record_digest(dict(reversed(list(record.items())))) == expected
    assert record == before
    assert intel.publisher_record_digest(record | {"_other_metadata": "changed"}) != expected
    nested = copy.deepcopy(record)
    nested["_configurations"][0]["_fetched_at"] = "nested publisher field is not retrieval metadata"
    assert intel.publisher_record_digest(nested) != expected


@pytest.mark.parametrize("timestamp", [None, "2026-10-28T00:00:00+00:00"])
def test_candidate_survives_retrieval_only_cache_refresh(candidate, store, timestamp):
    before = intel.match_finding(candidate, (service(),), store, {})
    assert len(before) == 1
    record = store.cve(CVE)
    if timestamp is None:
        del record["_fetched_at"]
    else:
        record["_fetched_at"] = timestamp
    store.put_cves([record])
    restored = Finding.from_json(candidate.to_json())
    after = intel.match_finding(
        restored, (service(),), intel_online.requested_cache(store, [CVE]), {}
    )
    assert after == before
    assert after[0].match_method == "cpe_range" and after[0].match_confidence < 1.0


@pytest.mark.parametrize("change", [None, "timestamp", "publisher-content"])
def test_legacy_timestamp_bearing_proof_requires_exact_cached_record(candidate, store, change):
    record = store.cve(CVE)
    proof = json.loads(candidate.evidence)
    proof["nvd_record_sha256"] = intel_online._digest(record)
    legacy = replace(candidate, evidence=json.dumps(proof))
    assert len(intel.match_finding(legacy, (service(),), store, {})) == 1
    if change == "timestamp":
        record["_fetched_at"] = "2026-10-28T00:00:00+00:00"
    elif change == "publisher-content":
        record["description"] = "Changed publisher content"
    store.put_cves([record])
    results = intel.match_finding(legacy, (service(),), store, {})
    assert len(results) == (1 if change is None else 0)
    if results:
        assert results[0].match_method == "cpe_range" and results[0].match_confidence < 1.0


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", OTHER_CVE),
        ("description", "Changed publisher description"),
        ("cvss31_base", 10),
        ("patch_references", ["https://vendor.example/changed-advisory"]),
        ("published", "2026-10-28T00:00:00Z"),
        ("_configurations", configurations(criterion(versionEndExcluding="7.0.8"))),
        ("cpe_matches", []),
    ],
)
def test_candidate_rejects_meaningful_cache_changes_even_when_version_still_matches(
    candidate, store, field, value
):
    record = store.cve(CVE)
    original_digest = intel.publisher_record_digest(record)
    record[field] = value
    assert intel.publisher_record_digest(record) != original_digest
    if field == "id":
        # Preserve the lookup key to exercise a contradictory stored row, rather than a cache miss.
        with store.connection:
            store.connection.execute(
                "UPDATE cve SET json = ? WHERE id = ?", (json.dumps(record), CVE)
            )
    else:
        store.put_cves([record])
    enrichments, traces = intel.match_finding_with_trace(candidate, (service(),), store, {})
    assert enrichments == []
    assert any(trace.decision == "rejected" and trace.cve_id == CVE for trace in traces)


@pytest.mark.parametrize("version", [None, "7.0.5"])
@pytest.mark.parametrize("scoped", [False, True])
def test_discovery_cannot_lend_and_platform_applicability_to_other_endpoint(
    tmp_path, store, version, scoped
):
    other_product = PRODUCT.replace("cache_server", "other_cache")
    configs = configurations() + [
        {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [criterion(criteria=other_product)]},
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:independentvendor:required_os:*:*:*:*:*:*:*:*",
                        }
                    ],
                },
            ],
        }
    ]
    candidates, *_ = discover(tmp_path, store, payload=page(nvd_entry(configs=configs)))
    assert len(candidates) == 1
    assert any(match["criteria"] == other_product for match in store.cve(CVE)["cpe_matches"])
    observed = service(port=26379, cpe=other_product, version=version)
    matching_store = intel_online.requested_cache(store, [CVE]) if scoped else store
    enrichments, traces = intel.match_finding_with_trace(
        ordinary_finding(observed), (service(), observed), matching_store, {}
    )
    assert enrichments == []
    assert any(trace.decision == "rejected" and trace.cve_id == CVE for trace in traces)


@pytest.mark.parametrize(
    "configs",
    [
        None,
        [],
        {},
        [{"operator": "AND", "nodes": configurations()}],
        [{"negate": True, "nodes": configurations()}],
        configurations(
            criterion(criteria=PRODUCT.replace(":*:*:*:*:*:*:*:*", ":*:vendor_update:*:*:*:*:*:*"))
        ),
    ],
    ids=["null", "empty", "object", "and", "negated", "required-update"],
)
def test_inferred_enrichment_cannot_fall_back_to_flat_matches_for_configured_records(
    candidate, store, configs
):
    record = store.cve(CVE)
    assert record["cpe_matches"]
    record["_configurations"] = configs
    store.put_cves([record])
    enrichments = intel.match_finding(ordinary_finding(service()), (service(),), store, {})
    assert enrichments == []


@pytest.mark.parametrize("version", [None, "", "7.x", "7.0.5 vendor-patched", "7.0.9"])
def test_inferred_configured_enrichment_requires_unambiguous_in_range_version(
    candidate, store, version
):
    observed = service(version=version)
    assert intel.match_finding(ordinary_finding(observed), (observed,), store, {}) == []


@pytest.mark.parametrize("pinned", [False, True])
def test_independent_configured_branch_enriches_ordinary_finding_conditionally(
    candidate, store, pinned
):
    if pinned:
        record = store.cve(CVE)
        record["_configurations"] = configurations(criterion(criteria=VERSIONED))
        store.put_cves([record])
    finding = ordinary_finding(service())
    enrichments, traces = intel.match_finding_with_trace(finding, (service(),), store, {})
    assert len(enrichments) == 1
    result = enrichments[0]
    assert (result.finding_id, result.cve_id, result.match_method) == (finding.id, CVE, "cpe_range")
    assert 0 < result.match_confidence < 1.0
    assert result.version_end == "7.0.9" and result.version_end_inclusive is False
    assert any(trace.decision == "accepted" and trace.method == "cpe_range" for trace in traces)


def test_configured_inference_uses_exact_transport_when_ports_collide(candidate, store):
    tcp = service()
    udp = service(protocol="udp", cpe=PRODUCT.replace("cache_server", "other_product"))
    finding = ordinary_finding(tcp)
    result = intel.match_finding(finding, (udp, tcp), store, {})
    assert len(result) == 1 and result[0].cve_id == CVE
    assert intel.match_finding(finding, (udp,), store, {}) == []


@pytest.mark.parametrize("version", [None, "7.0.5"])
@pytest.mark.parametrize("independent", [False, True])
def test_explicit_scanner_cve_never_borrows_unverified_remediation_bounds(
    candidate, store, version, independent
):
    if not independent:
        record = store.cve(CVE)
        record["_configurations"] = [{"operator": "AND", "nodes": configurations()}]
        store.put_cves([record])
    observed = service(version=version)
    result = intel.match_finding(ordinary_finding(observed, cves=(CVE,)), (observed,), store, {})
    assert len(result) == 1
    assert result[0].match_method == "explicit" and result[0].match_confidence == 1.0
    assert result[0].version_end == ("7.0.9" if independent and version else None)
    assert result[0].version_end_inclusive is (False if independent and version else None)

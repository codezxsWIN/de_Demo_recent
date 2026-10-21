"""Focused evidence-boundary and consumer-contract tests for pure decision cards."""

import copy
import json

import pytest

from vulnassess.assessment_derivations import derive
from vulnassess.finding_assurance import bounded_redis_proof
from vulnassess.redis_probe import POSITIVE, REQUEST


def finding(identity="redis-1", **changes):
    return {
        "id": identity,
        "host_ip": "192.0.2.10",
        "port": 6379,
        "protocol": "tcp",
        "tool": "redis-check",
        "tool_native_id": "lua-package-type-v1",
        "title": "Redis Lua package.loadlib exposed (CVE-2022-0543)",
        "evidence": "Scanner says type inspection returned table:function.",
        "cve_ids": ["CVE-2022-0543"],
        "provenance": {},
        **changes,
    }


def record(findings=None, *, proof=False):
    findings = [finding()] if findings is None else findings
    value = {
        "capture_id": "assessment-synthetic",
        "result": {
            "resolved_ip": "192.0.2.10",
            "target": "synthetic.example",
            "scan_status": "complete",
            "analyst": None,
            "services": [{"port": 6379, "protocol": "tcp", "name": "redis"}],
        },
        "payload": {"findings": findings, "hosts": [], "context": []},
    }
    if proof:
        value["bounded_protocol_proofs"] = [
            bounded_redis_proof(
                {
                    "target_ip": "192.0.2.10",
                    "port": 6379,
                    "check": "lua-package-type-v1",
                    "request": REQUEST.decode(),
                    "response": POSITIVE.decode(),
                },
                "192.0.2.10",
                findings,
                "a" * 64,
            )
        ]
    return value


def verified_observations(card):
    return [o for o in card["observations"] if o["source"].startswith("/bounded_protocol_proofs/")]


def test_matching_proof_establishes_only_the_bounded_exchange():
    card = derive(record(proof=True))[0]
    proof = verified_observations(card)
    assert len(proof) == 1
    assert "without an AUTH exchange" in proof[0]["text"]
    assert "table:function" in proof[0]["text"]
    assert proof[0]["id"] in card["conclusion"]["premise_ids"]
    assert "Scripting command execution" in card["conclusion"]["text"]
    assert "OS command execution remains untested" in card["conclusion"]["text"]
    assert "candidate pending" in " ".join(card["limits"])
    assert {a["id"].rsplit(":", 1)[-1] for a in card["actions"]} == {
        "containment",
        "package",
        "retest",
    }
    assert "AUTH/ACL" in card["actions"][0]["task"]
    assert "approved-client" in card["actions"][0]["task"]
    assert "vendor" in card["significance"]
    assert "isolated test service" in " ".join(card["alternatives"])


@pytest.mark.parametrize(
    "change",
    [
        {"target_ip": "192.0.2.99"},
        {"protocol": "udp"},
        {"port": 6380},
        {"port": True},
        {"finding_ids": ["different-finding"]},
        {"finding_ids": "redis-1"},
        {"status": "unavailable"},
        {"request": "arbitrary EVAL"},
        {"response": "unexpected"},
    ],
)
def test_wrong_or_unverified_proof_cannot_be_borrowed(change):
    value = record(proof=True)
    value["bounded_protocol_proofs"][0].update(change)
    card = derive(value)[0]
    assert not verified_observations(card)
    assert "scanner-reported" in card["conclusion"]["text"]
    assert "not independently established" in card["conclusion"]["text"]


@pytest.mark.parametrize(
    "change",
    [
        {"host_ip": "192.0.2.99"},
        {"protocol": "udp"},
        {"port": 6380},
        {"id": "other"},
    ],
)
def test_proof_must_match_the_specific_finding(change):
    value = record(proof=True)
    value["payload"]["findings"][0].update(change)
    assert not verified_observations(derive(value)[0])


def test_proof_must_also_match_the_verified_capture_target():
    value = record(proof=True)
    value["result"]["resolved_ip"] = "192.0.2.99"
    assert not verified_observations(derive(value)[0])


def test_missing_proof_does_not_promote_scanner_or_analyst_text():
    value = record()
    baseline = derive(value)
    value["result"]["analyst"] = {"analysis": {"summary": "STALE: RCE confirmed, no AUTH required"}}
    value["payload"]["rationales"] = [{"text": "STALE: public reachability confirmed"}]
    value["result"]["assessment_summary"] = {"conclusion": "STALE: exploit succeeded"}
    assert derive(value) == baseline
    assert not verified_observations(baseline[0])
    assert "RCE untested" in " ".join(baseline[0]["limits"])


def test_mixed_services_do_not_share_redis_proof_or_invent_correlations():
    value = record(
        [
            finding(),
            finding("redis-other-port", port=6380),
            finding("web", tool="nikto", port=443, title="Header reported missing", cve_ids=[]),
            finding("redis-named-only", tool="other", title="Redis Lua", cve_ids=[]),
        ],
        proof=True,
    )
    cards = {c["finding_ids"][0]: c for c in derive(value)}
    assert verified_observations(cards["redis-1"])
    assert not verified_observations(cards["redis-other-port"])
    for identity in ("web", "redis-named-only"):
        card = cards[identity]
        assert card["kind"] == "scanner-lead"
        assert "scanner lead" in card["conclusion"]["text"]
        assert not verified_observations(card)
        assert "AUTH/ACL" not in json.dumps(card)


def test_recorded_risk_orders_mixed_services_with_id_ties_and_unscored_last():
    value = record(
        [
            finding(),
            finding("web-high", tool="nikto", port=443, cve_ids=[]),
            finding("web-tie", tool="nikto", port=443, cve_ids=[]),
            finding("zero", tool="scanner", cve_ids=[]),
            finding("a-unscored"),
            finding("b-unscored", tool="scanner", cve_ids=[]),
        ],
        proof=True,
    )
    value["payload"]["scores"] = [
        {"finding_id": "zero", "risk": 0, "band": "Low"},
        {"finding_id": "redis-1", "risk": 40, "band": "Medium"},
        {"finding_id": "web-tie", "risk": 90, "band": "Critical"},
        {"finding_id": "web-high", "risk": 90, "band": "Critical"},
    ]
    expected = ["web-high", "web-tie", "redis-1", "zero", "a-unscored", "b-unscored"]
    before = copy.deepcopy(value)
    assert [c["finding_ids"][0] for c in derive(value)] == expected
    assert value == before
    value["payload"]["findings"].reverse()
    value["payload"]["scores"].reverse()
    assert [c["finding_ids"][0] for c in derive(value)] == expected


def test_card_limit_preserves_higher_scored_nonredis_findings():
    value = record(
        [finding()] + [finding(f"web-{i}", tool="nikto", port=443, cve_ids=[]) for i in range(8)],
        proof=True,
    )
    value["payload"]["scores"] = [
        {"finding_id": f"web-{i}", "risk": 90 - i, "band": "Critical"} for i in range(8)
    ] + [{"finding_id": "redis-1", "risk": 20, "band": "Low"}]
    cards = derive(value)
    assert [c["finding_ids"] for c in cards[:-1]] == [[f"web-{i}"] for i in range(7)]
    assert cards[-1]["kind"] == "coverage"
    assert cards[-1]["finding_ids"] == ["web-7", "redis-1"]


@pytest.mark.parametrize("proof", [False, True])
def test_vantage_tag_cannot_establish_public_reachability(proof):
    value = record(proof=proof)
    baseline = derive(value)
    value["payload"]["context"] = [{"host_ip": "192.0.2.10", "vantage": "internet"}]
    value["result"]["vantage"] = "public internet"
    assert derive(value) == baseline
    assert "vantage tag alone" in " ".join(baseline[0]["limits"])


@pytest.mark.parametrize("status", ["complete", "partial"])
def test_zero_findings_returns_one_service_management_verification_card(status):
    value = record([])
    value["result"]["scan_status"] = status
    cards = derive(value)
    assert len(cards) == 1
    card = cards[0]
    assert card["kind"] == "service-verification"
    assert card["finding_ids"] == []
    assert "not a secure verdict" in card["conclusion"]["text"]
    assert "management" in card["actions"][0]["task"]
    assert "0 of 0" in " ".join(card["limits"])


@pytest.mark.parametrize("projected", [False, True])
def test_zero_findings_services_use_matching_payload_host_and_resolvable_source(projected):
    value = record([])
    services = value["result"]["services"]
    value["payload"]["hosts"] = [
        {"ip": "192.0.2.99", "services": []},
        {"ip": "192.0.2.10", "services": copy.deepcopy(services)},
    ]
    if not projected:
        del value["result"]["services"]
    card = derive(value)[0]
    observation = card["observations"][1]
    assert observation["text"] == "Retained service count: 1."
    assert observation["source"] == "/payload/hosts/1/services"
    assert resolve_pointer(value, observation["source"]) == services


def test_zero_findings_services_fall_back_to_retained_result_projection():
    value = record([])
    observation = derive(value)[0]["observations"][1]
    assert observation["source"] == "/result/services"
    assert resolve_pointer(value, observation["source"]) == value["result"]["services"]
    del value["result"]["services"]
    assert len(derive(value)[0]["observations"]) == 1


@pytest.mark.parametrize("count", [1, 8, 9, 20])
def test_card_limit_explicitly_accounts_for_every_retained_finding(count):
    value = record([finding(f"f-{i:02}", tool="scanner", cve_ids=[]) for i in range(count)])
    cards = derive(value)
    assert len(cards) == min(count, 8)
    assert {identity for c in cards for identity in c["finding_ids"]} == {
        f["id"] for f in value["payload"]["findings"]
    }
    individual = min(count, 7) if count > 8 else count
    for card in cards:
        assert f"{individual} of {count}" in " ".join(card["limits"])
    if count > 8:
        assert cards[-1]["kind"] == "coverage"
        assert len(cards[-1]["finding_ids"]) == count - 7


def resolve_pointer(value, source):
    for part in source.split("/")[1:]:
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


@pytest.mark.parametrize(
    "value",
    [
        record(proof=True),
        record(),
        record([]),
        record([finding(str(i), tool="generic") for i in range(10)]),
    ],
)
def test_complete_contract_global_ids_local_premises_sources_and_immutability(value):
    before = copy.deepcopy(value)
    cards = derive(value)
    assert value == before
    assert derive(value) == cards
    all_ids = []
    for card in cards:
        assert set(card) == {
            "id",
            "finding_ids",
            "title",
            "observations",
            "conclusion",
            "significance",
            "limits",
            "alternatives",
            "actions",
            "changes_conclusion",
            "kind",
        }
        all_ids.append(card["id"])
        for key in ("id", "title", "significance", "kind"):
            assert isinstance(card[key], str) and card[key]
        for key in ("finding_ids", "limits", "alternatives", "changes_conclusion"):
            assert isinstance(card[key], list)
            assert all(isinstance(item, str) for item in card[key])
        observation_ids = {o["id"] for o in card["observations"]}
        assert set(card["conclusion"]) == {"text", "premise_ids", "label"}
        assert card["conclusion"]["label"] == "inferred"
        assert isinstance(card["conclusion"]["text"], str)
        assert card["conclusion"]["premise_ids"]
        assert set(card["conclusion"]["premise_ids"]) <= observation_ids
        for observation in card["observations"]:
            assert set(observation) == {"id", "text", "source"}
            assert all(isinstance(item, str) for item in observation.values())
            resolve_pointer(value, observation["source"])
        assert 2 <= len(card["actions"]) <= 3
        for action in card["actions"]:
            assert set(action) == {
                "id",
                "task",
                "expected",
                "if_fail",
                "if_pass",
                "reason",
                "premise_ids",
            }
            assert all(isinstance(v, str) and v for k, v in action.items() if k != "premise_ids")
            assert action["premise_ids"]
            assert set(action["premise_ids"]) <= observation_ids
        for child in card["observations"] + card["actions"]:
            assert child["id"].startswith(card["id"] + ":")
            all_ids.append(child["id"])
    assert len(set(all_ids)) == len(all_ids)
    cards[0]["finding_ids"].append("mutated-output")
    assert value == before


def test_ids_stable_across_order_and_distinct_across_captures():
    value = record([finding(), finding("web", tool="nikto", cve_ids=[])], proof=True)
    cards = derive(value)
    value["payload"]["findings"].reverse()
    reordered = derive(value)
    assert [c["id"] for c in reordered] == [c["id"] for c in cards]
    assert [a["id"] for a in reordered[0]["actions"]] == [a["id"] for a in cards[0]["actions"]]
    value["capture_id"] = "assessment-other"
    assert {c["id"] for c in derive(value)}.isdisjoint(c["id"] for c in cards)


@pytest.mark.parametrize("proof", [False, True])
def test_first_redis_model_catalog_fits_consumer_budget(proof):
    card = derive(record(proof=proof))[0]
    catalog = {key: card[key] for key in ("id", "observations", "conclusion", "limits", "actions")}
    assert len(json.dumps(catalog).encode("utf-8")) < 5000

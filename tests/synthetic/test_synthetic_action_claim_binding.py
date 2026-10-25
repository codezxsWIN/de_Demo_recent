"""Pure synthetic regressions keep reordered action prose and claims inseparable."""

import copy

import pytest

from vulnassess import analyst
from vulnassess.ai_boundary import INJECTION_SENTINEL
from vulnassess.errors import LLMUnavailable, NeedsReview


def claim(text, evidence_id, finding_id=None, *, score=None, label="inferred", confidence=0.8):
    return {
        "text": text,
        "label": label,
        "confidence": confidence,
        "evidence_ids": [evidence_id],
        "finding_ids": [] if finding_id is None else [finding_id],
        "verification_action": None,
        "score": score,
    }


@pytest.fixture
def action_payload():
    host = "192.0.2.10"
    payload = {
        "hosts": [{"ip": host, "services": []}],
        "context": [
            {
                "host_ip": host,
                "role": {
                    "value": "database",
                    "confidence": 1.0,
                    "source": "manual",
                    "evidence": "Synthetic database role.",
                },
                "exposure": {
                    "value": "internal",
                    "confidence": 1.0,
                    "source": "manual",
                    "evidence": "Synthetic internal exposure.",
                },
                "controls": {},
            }
        ],
        "findings": [
            {
                "id": f"synthetic-{name}",
                "host_ip": host,
                "tool": "nmap",
                "title": f"Synthetic {name} observation",
                "evidence": f"Synthetic {name} observation requires review.",
                "cve_ids": [],
            }
            for name in ("alpha", "beta")
        ],
        "scores": [
            {"finding_id": "synthetic-alpha", "risk": 20, "band": "Low"},
            {"finding_id": "synthetic-beta", "risk": 80, "band": "High"},
        ],
        "enrichments": [],
    }
    return payload


@pytest.fixture
def action_case(action_payload):
    case, evidence, _ = analyst.build_case(action_payload, action_payload["hosts"][0]["ip"])
    return case, evidence


def wire_response(case, *, numeric=False):
    actions = []
    for rank, finding in reversed(list(enumerate(case["findings"], 1))):
        score = finding["deterministic_score"]["risk"] if numeric else None
        actions.append(
            {
                "order": rank,
                "action": claim(
                    f"Review risk score {score}." if numeric else f"Review {finding['title']}.",
                    finding["evidence_id"],
                    finding["id"],
                    score=score,
                    label="inferred",
                    confidence=0.4 if rank == 2 else 0.9,
                ),
                "reason": claim(
                    f"The evidence records {finding['title']}.",
                    finding["evidence_id"],
                    finding["id"],
                    confidence=0.5 if rank == 2 else 0.8,
                ),
                "finding_ids": [finding["id"]],
                "evidence_ids": [finding["evidence_id"]],
            }
        )
    first = case["findings"][0]
    exposure = case["context"]["exposure"]["evidence_id"]
    return {
        "schema_version": analyst.SCHEMA_VERSION,
        "summary": claim("Recorded observations require review.", first["evidence_id"]),
        "confidence": "medium",
        "context_effect": {
            "explanation": claim("Recorded exposure guides review urgency.", exposure),
            "evidence_ids": [exposure],
        },
        "recommended_actions": actions,
        "correlations": [
            {
                "observation": claim(
                    "The recorded finding has supporting evidence.",
                    first["evidence_id"],
                    first["id"],
                ),
                "finding_ids": [first["id"]],
                "evidence_ids": [first["evidence_id"]],
            }
        ],
        "investigations": [],
        "uncertainties": [claim("Independent verification remains necessary.", exposure)],
    }


def validate(raw, case, evidence):
    return analyst.validate_analysis(
        raw, {finding["id"] for finding in case["findings"]}, {item["id"] for item in evidence}
    )


def test_action_order_is_preserved_until_grounding_succeeds(action_case):
    case, evidence = action_case
    result = validate(wire_response(case), case, evidence)
    assert [row["order"] for row in result["recommended_actions"]] == [2, 1]


@pytest.mark.parametrize("numeric", [False, True], ids=["scoreless", "deterministic-scores"])
def test_sorted_actions_keep_all_claim_metadata_and_prose_paired(action_case, numeric):
    case, evidence = action_case
    raw = wire_response(case, numeric=numeric)
    original = copy.deepcopy((raw, case, evidence))
    result = validate(raw, case, evidence)
    analyst.validate_grounding(result, case, evidence)

    expected_actions = sorted(raw["recommended_actions"], key=lambda row: row["order"])
    assert [row["order"] for row in result["recommended_actions"]] == [1, 2]
    by_path = {item["path"]: item for item in result["claims"]}
    evidence_text = {item["id"]: item["text"] for item in evidence}
    for index, expected in enumerate(expected_actions):
        action = result["recommended_actions"][index]
        assert action["finding_ids"] == expected["finding_ids"]
        assert action["evidence_ids"] == expected["evidence_ids"]
        for field in ("action", "reason"):
            path = f"recommended_actions.{index}.{field}"
            metadata = expected[field]
            assert action[field] == metadata["text"]
            assert by_path[path] == {
                "path": path,
                **{key: value for key, value in metadata.items() if key != "text"},
                "quotes": [
                    {"evidence_id": identity, "text": evidence_text[identity]}
                    for identity in metadata["evidence_ids"]
                ],
            }
    assert [item["path"] for item in result["claims"]] == [
        "summary",
        "context_effect.explanation",
        "recommended_actions.0.action",
        "recommended_actions.0.reason",
        "recommended_actions.1.action",
        "recommended_actions.1.reason",
        "correlations.0.observation",
        "uncertainties.0",
    ]
    assert by_path["summary"]["evidence_ids"] == raw["summary"]["evidence_ids"]
    assert (
        by_path["context_effect.explanation"]["evidence_ids"]
        == raw["context_effect"]["explanation"]["evidence_ids"]
    )
    assert (
        by_path["correlations.0.observation"]["finding_ids"]
        == raw["correlations"][0]["observation"]["finding_ids"]
    )
    assert by_path["uncertainties.0"]["evidence_ids"] == raw["uncertainties"][0]["evidence_ids"]
    assert (raw, case, evidence) == original


def test_sorting_cannot_supply_missing_finding_support_from_another_action(action_case):
    case, evidence = action_case
    raw = wire_response(case)
    for row, unrelated in zip(raw["recommended_actions"], case["findings"], strict=True):
        row["evidence_ids"] = [unrelated["evidence_id"]]
        for field in ("action", "reason"):
            row[field]["evidence_ids"] = [unrelated["evidence_id"]]
    result = validate(raw, case, evidence)
    original_actions = copy.deepcopy(result["recommended_actions"])
    original_paths = [item["path"] for item in result["claims"]]
    with pytest.raises(LLMUnavailable, match="without its supporting evidence"):
        analyst.validate_grounding(result, case, evidence)
    assert result["recommended_actions"] == original_actions
    assert [item["path"] for item in result["claims"]] == original_paths


@pytest.mark.parametrize("order", [True, False, 1.0, "1", None, [], {}, 0, -1, 3])
def test_invalid_action_order_is_rejected_before_normalization(action_case, order):
    case, evidence = action_case
    raw = wire_response(case)
    raw["recommended_actions"][0]["order"] = order
    with pytest.raises(LLMUnavailable, match="invalid order"):
        validate(raw, case, evidence)


@pytest.mark.parametrize("mutation", ["unknown-field", "unknown-finding", "unknown-evidence"])
def test_action_normalization_preserves_strict_schema_and_citations(action_case, mutation):
    case, evidence = action_case
    raw = wire_response(case)
    row = raw["recommended_actions"][0]
    if mutation == "unknown-field":
        row["extra"] = True
        message = "unknown fields"
    elif mutation == "unknown-finding":
        row["finding_ids"] = ["F999"]
        message = "unknown finding"
    else:
        row["evidence_ids"] = ["E999"]
        message = "unknown evidence"
    with pytest.raises(LLMUnavailable, match=message):
        validate(raw, case, evidence)


def test_action_normalization_still_rejects_changed_deterministic_scores(action_case):
    case, evidence = action_case
    raw = wire_response(case, numeric=True)
    raw["recommended_actions"][0]["action"].update(text="Review risk score 80.", score=80)
    with pytest.raises(LLMUnavailable, match="claim score differs from deterministic value"):
        analyst.validate_grounding(validate(raw, case, evidence), case, evidence)


def test_action_normalization_still_rejects_canary_output(action_case):
    case, evidence = action_case
    raw = wire_response(case)
    raw["recommended_actions"][0]["reason"]["text"] = INJECTION_SENTINEL
    original = copy.deepcopy(raw)
    with pytest.raises(LLMUnavailable, match="untrusted instruction canary triggered"):
        validate(raw, case, evidence)
    assert raw == original


@pytest.mark.parametrize("canary", [False, True], ids=["validated-publication", "raw-canary"])
def test_published_action_claims_keep_canonical_ids_and_raw_canary_guard(
    action_payload, action_case, monkeypatch, canary
):
    case, _ = action_case
    raw = wire_response(case, numeric=True)
    original = copy.deepcopy(action_payload)
    monkeypatch.setattr(analyst, "append_audit", lambda *_: None)

    class InertClient:
        model = "synthetic"
        source = "synthetic_offline"

        def available(self):
            return True

        def generate_structured(self, prompt, schema, **options):
            if canary:
                options["on_raw"](INJECTION_SENTINEL.encode("ascii"))
            return copy.deepcopy(raw)

    host = action_payload["hosts"][0]["ip"]
    if canary:
        with pytest.raises(NeedsReview, match="untrusted instruction canary triggered"):
            analyst.analyze_target(action_payload, host, InertClient())
    else:
        published = analyst.analyze_target(action_payload, host, InertClient())
        actions = published["analysis"]["recommended_actions"]
        assert [row["order"] for row in actions] == [1, 2]
        assert [row["finding_ids"] for row in actions] == [
            ["synthetic-beta"],
            ["synthetic-alpha"],
        ]
        claims = {item["path"]: item for item in published["analysis"]["claims"]}
        for index, action in enumerate(actions):
            for field in ("action", "reason"):
                metadata = claims[f"recommended_actions.{index}.{field}"]
                assert metadata["finding_ids"] == action["finding_ids"]
                assert metadata["evidence_ids"] == action["evidence_ids"]
        assert published["canonical_scores_changed"] is False
    assert action_payload == original

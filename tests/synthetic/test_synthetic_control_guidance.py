"""Synthetic request guidance must not weaken unknown-control rejection."""

import copy
import json

import pytest

from tests.test_analyst import FakeClient, demo_payload, valid_result
from vulnassess import analyst
from vulnassess.errors import NeedsReview


@pytest.mark.parametrize("bind_scores", [True, False])
@pytest.mark.parametrize("compact", [True, False])
def test_control_guidance_reaches_every_claim_without_mutating_contract(bind_scores, compact):
    original = copy.deepcopy(analyst.ANALYSIS_SCHEMA)
    schema = analyst.analysis_schema(
        {"F1"},
        {"E1", "E2"},
        {"F1": 30},
        bind_scores=bind_scores,
        finding_support={"F1": ["E1"]},
    )
    if compact:
        schema = analyst.compact_analysis_schema(schema)
    found = []

    def walk(node):
        if isinstance(node, dict):
            if "$ref" in node:
                assert node["$ref"].startswith("#/$defs/")
                return walk(schema["$defs"][node["$ref"].removeprefix("#/$defs/")])
            if "text" in node.get("properties", {}):
                fields = node["properties"]
                found.append(fields)
                text = fields["text"]
                citations = fields["evidence_ids"]
                if "$ref" in text:
                    text = schema["$defs"][text["$ref"].removeprefix("#/$defs/")]
                if "$ref" in citations:
                    citations = schema["$defs"][citations["$ref"].removeprefix("#/$defs/")]
                assert "null control value means unknown" in text["description"]
                assert "explicit negative test" in text["description"]
                assert "not established by this scan" in text["description"]
                assert citations["items"]["enum"] == ["E1", "E2"]
                assert "score" in fields and "label" in fields
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(schema)
    assert found
    assert schema["required"] == analyst.ANALYSIS_SCHEMA["required"]
    assert analyst.ANALYSIS_SCHEMA == original


@pytest.mark.parametrize(
    ("control", "assertion"),
    [
        ("auth_required", "The service is unauthenticated."),
        ("waf", "The service has no WAF."),
        ("rate_limiting", "The service has no rate limiting."),
        ("tls", "The service lacks TLS."),
    ],
)
def test_guidance_rejects_repeated_unsupported_control_claim_after_one_fresh_correction(
    tmp_path, monkeypatch, control, assertion
):
    payload = demo_payload()
    profile = next(row for row in payload["context"] if row["host_ip"] == "172.28.0.12")
    profile["controls"][control] = {
        "value": None,
        "confidence": 0.0,
        "source": "rule",
        "evidence": "none observed",
    }
    case, _, _ = analyst.build_case(payload, "172.28.0.12")
    response = valid_result(case["findings"][0]["id"], case["findings"][0]["evidence_id"])
    response["summary"] = assertion
    original = copy.deepcopy(payload)
    audit = tmp_path / "synthetic_control_audit.jsonl"
    monkeypatch.setattr(analyst, "AUDIT_PATH", audit)

    class RefusingClient(FakeClient):
        calls = 0

        def generate_structured(self, prompt, schema, **kwargs):
            self.calls += 1
            return super().generate_structured(prompt, schema, **kwargs)

    client = RefusingClient(response)
    with pytest.raises(NeedsReview, match="unsupported control assertion about " + control):
        analyst.analyze_target(payload, "172.28.0.12", client)
    # A fresh correction is permitted, but repeating the same rejected claim
    # must stop immediately; neither answer may be accepted or published.
    assert client.calls == 2
    assert payload == original
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert records[-1]["outcome"] == "needs_review"
    assert all(row.get("outcome") not in {"validated", "accepted"} for row in records)

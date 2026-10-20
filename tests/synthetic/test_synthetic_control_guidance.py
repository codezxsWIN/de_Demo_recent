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
            if "text" in node.get("properties", {}):
                fields = node["properties"]
                found.append(fields)
                assert "null control value means unknown" in fields["text"]["description"]
                assert "explicit negative test" in fields["text"]["description"]
                assert "not established by this scan" in fields["text"]["description"]
                assert fields["evidence_ids"]["items"]["enum"] == ["E1", "E2"]
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
def test_guidance_cannot_accept_or_retry_an_unsupported_control_claim(
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
    assert client.calls == 1
    assert payload == original
    assert json.loads(audit.read_text())["outcome"] == "needs_review"

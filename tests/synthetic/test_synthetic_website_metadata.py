"""Synthetic metadata/privacy and model-wiring checks; never contact a website."""

import copy
import hashlib
import json
from unittest.mock import MagicMock

import pytest

from tests.adversarial.test_evidence_requests import context, proposal
from tests.test_analyst import FakeClient, demo_payload
from vulnassess import analyst, evidence_requests, website_metadata
from vulnassess.errors import LLMUnavailable, NeedsReview


def response(*headers, status="200 OK", body=b""):
    return ("HTTP/1.1 " + status + "\r\n" + "\r\n".join(headers) + "\r\n\r\n").encode() + body


def projection(*headers, **kwargs):
    output = website_metadata.minimise(response(*headers, **kwargs))
    return output, json.loads(bytes.fromhex(output["raw_hex"]))


def test_metadata_keeps_security_attributes_without_private_values():
    output, metadata = projection(
        "Content-Type: text/html; charset=UTF-8",
        "Set-Cookie: SYNTHETIC_SESSION=DO_NOT_RETAIN_COOKIE; Secure; HttpOnly; SameSite=Lax",
        "Location: https://user:DO_NOT_RETAIN_PASSWORD@synthetic.invalid/private/identity?token=DO_NOT_RETAIN_TOKEN#private",
        "Server: DO_NOT_RETAIN_SERVER",
        "X-Arbitrary: DO_NOT_RETAIN_HEADER",
        "Content-Security-Policy: script-src 'nonce-DO_NOT_RETAIN_NONCE'",
        body=b"DO_NOT_RETAIN_BODY",
    )
    retained = bytes.fromhex(output["raw_hex"]).decode() + output["observation"]
    for secret in (
        "DO_NOT_RETAIN",
        "synthetic.invalid",
        "SYNTHETIC_SESSION",
        "/private/identity",
        "user:",
    ):
        assert secret not in retained
    assert metadata["format"] == website_metadata.FORMAT
    assert metadata["status"] == 200
    assert metadata["declared_media"] == "html"
    assert metadata["redirect"] == "absolute HTTPS destination"
    assert metadata["headers"]["content-security-policy"] == "observed"
    assert metadata["cookies"] == {
        "issued": 1,
        "without_secure": 0,
        "without_httponly": 0,
        "without_recognised_samesite": 0,
        "attributes_unverified": 0,
    }
    assert "not a site-wide finding" in output["observation"]
    assert "authentication" in output["observation"]
    assert all(
        len(part) <= 200 for part in website_metadata.observation_parts(output["observation"])
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("sid=secret", (1, 1, 1, 0)),
        ("sid=secret; secure; HTTPONLY; SameSite=Strict", (0, 0, 0, 0)),
        ("sid=secret; Secure=true; HttpOnly=true; SameSite=bad", (1, 1, 1, 0)),
        ('sid="secret; Secure"; HttpOnly', (0, 0, 0, 1)),
        ('sid=secret; Path="/x;Secure;"; HttpOnly', (0, 0, 0, 1)),
        ("missing-pair", (0, 0, 0, 1)),
        ("sid=secret; SameSite=Lax; SameSite=None", (1, 1, 1, 0)),
    ],
)
def test_cookie_counts_do_not_invent_session_purpose(value, expected):
    _, metadata = projection("Set-Cookie: " + value)
    cookies = metadata["cookies"]
    assert (
        tuple(
            cookies[key]
            for key in (
                "without_secure",
                "without_httponly",
                "without_recognised_samesite",
                "attributes_unverified",
            )
        )
        == expected
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("/login?secret=omit", "relative destination"),
        ("//synthetic.invalid/", "network-relative destination"),
        ("http://synthetic.invalid/", "absolute HTTP destination"),
        ("https://synthetic.invalid/", "absolute HTTPS destination"),
        ("javascript:omit", "destination requires review"),
    ],
)
def test_redirect_classification_never_retains_or_follows_destination(value, expected):
    output, metadata = projection("Location: " + value, status="302 Found")
    assert metadata["redirect"] == expected
    assert value not in bytes.fromhex(output["raw_hex"]).decode()
    assert value not in output["observation"]
    assert "never followed" in output["observation"]


@pytest.mark.parametrize(
    "headers,key,state",
    [
        (("X-Frame-Options: DENY",), "x-frame-options", "recognised value observed"),
        (
            ("X-Frame-Options: ALLOW-FROM https://secret.invalid",),
            "x-frame-options",
            "value or multiplicity needs review",
        ),
        (
            ("X-Frame-Options: DENY", "X-Frame-Options: SAMEORIGIN"),
            "x-frame-options",
            "value or multiplicity needs review",
        ),
        (
            ("X-Content-Type-Options: nosniff",),
            "x-content-type-options",
            "recognised value observed",
        ),
        (
            ("X-Content-Type-Options: wrong",),
            "x-content-type-options",
            "value or multiplicity needs review",
        ),
    ],
)
def test_header_values_are_interpreted_without_retaining_them(headers, key, state):
    _, metadata = projection(*headers)
    assert metadata["headers"][key] == state


@pytest.mark.parametrize(
    "raw",
    [
        b"not HTTP\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n folded: ambiguous\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nMissing colon\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Test: bad\x00value\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Test: " + b"x" * 8192 + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n" + b"X: v\r\n" * 129 + b"\r\n",
    ],
)
def test_malformed_or_ambiguous_headers_fail_closed(raw):
    with pytest.raises(NeedsReview):
        website_metadata.minimise(raw)


def test_wire_probe_discards_body_and_values_before_durable_capture(tmp_path, monkeypatch):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.recv.return_value = response(
        "Set-Cookie: sid=DO_NOT_RETAIN; HttpOnly",
        "Content-Type: application/json",
        body=b"DO_NOT_RETAIN_BODY" * 600,
    )
    monkeypatch.setattr(evidence_requests.socket, "socket", lambda *_: connection)
    manager = evidence_requests.EvidenceRequests(tmp_path)
    record = manager.create(proposal(), context())
    completed = manager.execute(
        record["request_id"], record["request_hash"], lambda _: context()["scope_hash"]
    )
    captured = completed["evidence"]
    retained = bytes.fromhex(captured["raw_hex"])
    assert captured["raw_sha256"] == hashlib.sha256(retained).hexdigest()
    assert json.loads(retained)["declared_media"] == "json"
    assert "DO_NOT_RETAIN" not in captured["observation"]
    assert b"DO_NOT_RETAIN" not in retained
    assert "DO_NOT_RETAIN" not in next(tmp_path.glob("*.json")).read_text()
    assert manager.evidence("demo", "172.28.0.10") == [captured]
    connection.connect.assert_called_once_with(("172.28.0.10", 80))
    assert connection.sendall.call_count == 1
    with pytest.raises(NeedsReview, match="already consumed"):
        manager.execute(
            record["request_id"], record["request_hash"], lambda _: context()["scope_hash"]
        )


def case_with_metadata():
    payload = demo_payload()
    payload.update(findings=[], scores=[], enrichments=[])
    output, _ = projection("Set-Cookie: sid=secret", "Content-Type: text/html")
    payload["supplemental_evidence"] = [
        {
            "id": "synthetic-approved-http",
            "target_ip": "172.28.0.12",
            "origin": "ai_request",
            "kind": "http_head",
            "port": 80,
            "captured_at": "2026-10-19T00:00:00Z",
            "raw_sha256": hashlib.sha256(bytes.fromhex(output["raw_hex"])).hexdigest(),
            "observation": output["observation"],
        }
    ]
    return payload


def test_every_metadata_assertion_reaches_model_without_truncation_or_score_changes():
    payload = case_with_metadata()
    original = copy.deepcopy(payload)
    case, evidence, _ = analyst.build_case(payload, "172.28.0.12")
    parts = website_metadata.observation_parts(payload["supplemental_evidence"][0]["observation"])
    selected = {
        identity
        for item in case["supplemental_observations"]
        for identity in item.get("evidence_ids", [item["evidence_id"]])
    }
    supplied = [item["text"] for item in evidence if item["id"] in selected]
    assert supplied == parts
    assert len(selected) == len(parts)
    assert case["coverage"]["supplemental_included"] == 1
    assert case["coverage"]["supplemental_omitted"] == 0
    prompt = analyst.build_prompt(case, evidence, 0)
    assert len(prompt) <= analyst.MAX_PROMPT_CHARS
    assert "Cookie precaution" in prompt
    assert "HEAD / only" in prompt
    assert "secret" not in prompt
    assert payload == original


@pytest.mark.parametrize("budget", ["evidence", "prompt"])
def test_insufficient_model_budget_omits_whole_metadata_request(monkeypatch, budget):
    payload = case_with_metadata()
    baseline = copy.deepcopy(payload)
    del baseline["supplemental_evidence"]
    case, evidence, _ = analyst.build_case(baseline, "172.28.0.12")
    if budget == "evidence":
        monkeypatch.setattr(analyst, "MAX_EVIDENCE", len(evidence) + 1)
    else:
        monkeypatch.setattr(
            analyst, "MAX_PROMPT_CHARS", len(analyst.build_prompt(case, evidence, 0)) + 100
        )
    actual, actual_evidence, _ = analyst.build_case(payload, "172.28.0.12")
    assert actual["coverage"]["supplemental_included"] == 0
    assert actual["coverage"]["supplemental_omitted"] == 1
    assert actual.get("supplemental_observations", []) == []
    assert actual_evidence == evidence


def test_model_can_cite_approved_metadata_for_a_precaution_not_a_new_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic-audit.jsonl")
    payload = case_with_metadata()
    original = copy.deepcopy(payload)
    case, evidence, _ = analyst.build_case(payload, "172.28.0.12")
    identity = next(item["id"] for item in evidence if item["text"].startswith("Response cookies:"))
    answer = {
        "summary": "The response cookie protection attributes need review.",
        "confidence": "low",
        "context_effect": {
            "explanation": "Exposure does not establish the cookie purpose.",
            "evidence_ids": [case["context"]["exposure"]["evidence_id"]],
        },
        "recommended_actions": [
            {
                "order": 1,
                "action": "Review protections for sensitive cookies.",
                "reason": "The response lacks observed cookie protection attributes; its purpose needs verification.",
                "finding_ids": [],
                "evidence_ids": [identity],
            }
        ],
        "correlations": [],
        "uncertainties": ["Other pages and authenticated behaviour were not tested."],
    }
    result = analyst.analyze_target(payload, "172.28.0.12", FakeClient(answer))
    assert result["canonical_scores_changed"] is False
    assert result["analysis"]["recommended_actions"][0]["evidence_ids"] == [identity]
    assert payload == original
    answer["recommended_actions"][0]["evidence_ids"] = [case["context"]["exposure"]["evidence_id"]]
    with pytest.raises(LLMUnavailable, match="action lacks observed"):
        analyst.analyze_target(payload, "172.28.0.12", FakeClient(answer))


@pytest.mark.parametrize(
    "text",
    [website_metadata.PREFIX + "\n" + "x" * 201, website_metadata.PREFIX + "\n" + "x\n" * 21],
)
def test_oversized_projection_text_is_not_silently_truncated(text):
    with pytest.raises(NeedsReview, match="citation budget"):
        website_metadata.observation_parts(text)

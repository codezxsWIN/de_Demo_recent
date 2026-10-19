"""Synthetic proposals and wire failures retain fail-closed approval outcomes."""

import json
from unittest.mock import MagicMock, Mock

import pytest

from tests.adversarial.test_evidence_requests import context as request_context
from tests.adversarial.test_evidence_requests import proposal
from tests.adversarial.test_scan_plans import answer
from tests.adversarial.test_scan_plans import context as plan_context
from vulnassess import evidence_requests, scan_plans
from vulnassess.errors import NeedsReview


@pytest.mark.parametrize("text", [None, "", "  ", "x" * 501])
def test_evidence_justification_must_be_nonempty_bounded_text(tmp_path, text):
    requests = evidence_requests.EvidenceRequests(tmp_path)
    with pytest.raises(NeedsReview, match="justification is invalid"):
        requests.create(proposal() | {"reason": text}, request_context())
    assert list(tmp_path.iterdir()) == []


def test_probe_citation_must_support_the_selected_service(tmp_path):
    source = request_context()
    source["evidence"].append({"id": "E2", "text": "Baseline policy allows reviewed probes"})
    candidate = proposal()
    candidate["claims"][0].update(
        evidence_ids=["E2"],
        quotes=[{"evidence_id": "E2", "text": source["evidence"][1]["text"]}],
    )
    with pytest.raises(NeedsReview, match="citations to its observed service"):
        evidence_requests.EvidenceRequests(tmp_path).create(candidate, source)
    assert not list(tmp_path.iterdir())


def test_evidence_request_capacity_recovers_after_expiry(tmp_path):
    now = [0.0]
    requests = evidence_requests.EvidenceRequests(tmp_path, clock=lambda: now[0])
    records = [requests.create(proposal(), request_context()) for _ in range(64)]
    with pytest.raises(NeedsReview, match="queue is full"):
        requests.create(proposal(), request_context())
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 64
    now[0] = 601.0
    fresh = requests.create(proposal(), request_context())
    assert fresh["state"] == "proposed"
    scope = Mock(side_effect=AssertionError("Expired authority must not reach scope or transport"))
    transport = Mock(side_effect=AssertionError("Expired authority must not execute"))
    for record in records:
        with pytest.raises(NeedsReview, match="expired, changed or already consumed"):
            requests.execute(record["request_id"], record["request_hash"], scope, transport)
    assert (
        requests.reject(fresh["request_id"], fresh["request_hash"], "Window closed")["state"]
        == "rejected"
    )
    scope.assert_not_called()
    transport.assert_not_called()


@pytest.mark.parametrize("reason", [None, "", "  ", "x" * 501])
def test_invalid_rejection_does_not_consume_request(tmp_path, reason):
    requests = evidence_requests.EvidenceRequests(tmp_path)
    record = requests.create(proposal(), request_context())
    with pytest.raises(NeedsReview, match="rejection needs a reason"):
        requests.reject(record["request_id"], record["request_hash"], reason)
    result = requests.reject(record["request_id"], record["request_hash"], "Review postponed")
    assert result["state"] == "rejected"
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [row["decision"] for row in rows] == ["proposed", "rejected"]
    assert rows[-1]["reason"] == "Review postponed"


@pytest.mark.parametrize(
    "output", [{"observation": "missing raw bytes"}, {"raw_hex": 1, "observation": "x"}]
)
def test_invalid_transport_schema_consumes_approval_and_never_publishes_evidence(tmp_path, output):
    requests = evidence_requests.EvidenceRequests(tmp_path)
    record = requests.create(proposal(), request_context())
    transport = Mock(return_value=output)
    with pytest.raises(NeedsReview, match="no finding or score was changed") as error:
        requests.execute(
            record["request_id"],
            record["request_hash"],
            lambda _: request_context()["scope_hash"],
            transport,
        )
    assert "unknown transport evidence schema" in str(error.value.__cause__)
    assert not list(tmp_path.glob("*.json"))
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [row["decision"] for row in rows] == ["proposed", "human_approved", "needs_review"]
    with pytest.raises(NeedsReview, match="already consumed"):
        requests.execute(record["request_id"], record["request_hash"], Mock(), transport)
    assert transport.call_count == 1


@pytest.fixture
def wire(monkeypatch):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    monkeypatch.setattr(evidence_requests.socket, "socket", lambda *_: connection)
    return connection


def test_oversized_certificate_is_not_published_as_verified_evidence(wire, monkeypatch):
    secured = MagicMock()
    secured.getpeercert.return_value = b"x" * (evidence_requests.MAX_BYTES + 1)
    tls = MagicMock()
    tls.wrap_socket.return_value.__enter__.return_value = secured
    monkeypatch.setattr(evidence_requests.ssl, "create_default_context", lambda: tls)
    with pytest.raises(NeedsReview, match="certificate exceeds evidence budget"):
        evidence_requests.probe(proposal() | {"kind": "tls_inspect", "port": 443})
    assert secured.getpeercert.call_args.kwargs == {"binary_form": True}
    assert tls.wrap_socket.call_args.kwargs == {"server_hostname": "172.28.0.10"}
    wire.__exit__.assert_called_once()


def test_http_read_stops_at_shared_deadline_before_receiving(wire, monkeypatch):
    ticks = iter([0.0, 1.0, 3.0])
    monkeypatch.setattr(evidence_requests.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="deadline exceeded"):
        evidence_requests.probe(proposal())
    wire.recv.assert_not_called()
    wire.__exit__.assert_called_once()


def test_late_tcp_completion_cannot_be_returned_as_success(wire, monkeypatch):
    ticks = iter([0.0, 1.0, 3.1])
    monkeypatch.setattr(evidence_requests.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="deadline exceeded"):
        evidence_requests.probe(proposal() | {"kind": "tcp_connect"})
    wire.sendall.assert_not_called()
    wire.__exit__.assert_called_once()


def test_unknown_transport_is_rejected_before_socket_creation(monkeypatch):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    socket_factory = Mock(return_value=connection)
    monkeypatch.setattr(evidence_requests.socket, "socket", socket_factory)
    with pytest.raises(NeedsReview, match="unsupported transport"):
        evidence_requests.probe(proposal() | {"kind": "arbitrary_transport"})
    socket_factory.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        "extra-field",
        "empty",
        "too-many",
        "unknown-endpoint",
        "reason",
        "confidence",
        "claim-confidence",
        "web-citation",
    ],
)
def test_invalid_scan_plan_never_enters_approval_registry(tmp_path, case):
    source, candidate = plan_context(web=True), answer(web=True)
    if case == "extra-field":
        candidate["approved"] = True
        message = "unknown scan plan schema"
    elif case == "empty":
        candidate["steps"] = []
        message = "baseline and at most one web step"
    elif case == "too-many":
        candidate["steps"].append(candidate["steps"][1].copy())
        message = "baseline and at most one web step"
    elif case == "unknown-endpoint":
        candidate["steps"][1]["endpoint_evidence_id"] = "E999"
        message = "requires an observed endpoint"
    elif case == "reason":
        candidate["steps"][0]["reason"] = " "
        message = "reason or confidence is invalid"
    elif case == "confidence":
        candidate["steps"][0]["confidence"] = True
        message = "reason or confidence is invalid"
    elif case == "claim-confidence":
        candidate["claims"][0]["confidence"] = 0.5
        message = "confidence disagrees"
    else:
        candidate["claims"][1].update(
            evidence_ids=["E1"],
            quotes=[{"evidence_id": "E1", "text": source["evidence"][0]["text"]}],
        )
        message = "must cite its observed endpoint"
    registry = scan_plans.PlanRegistry(tmp_path / "synthetic_audit.jsonl")
    with pytest.raises(NeedsReview, match=message):
        registry.create(candidate, source)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("failure", ["prompt-budget", "unavailable"])
def test_planner_preflight_failure_is_audited_without_generation(tmp_path, failure):
    source = plan_context()
    if failure == "prompt-budget":
        source["evidence"].extend(
            {"id": f"E{index}", "text": "SYNTHETIC observed service " * 65}
            for index in range(2, 14)
        )
    client = Mock(model="synthetic-planner", available=Mock(return_value=False))
    audit_path = tmp_path / "synthetic_audit.jsonl"
    with pytest.raises(NeedsReview, match="prompt budget|Planner model unavailable"):
        scan_plans.propose(source, client, audit_path)
    client.generate_structured.assert_not_called()
    if failure == "prompt-budget":
        client.available.assert_not_called()
    row = json.loads(audit_path.read_text())
    assert row["decision"] == "reject" and row["outcome"] == "needs_review"
    assert row["output_hash"] is None
    assert row["reason"] == ("NeedsReview" if failure == "prompt-budget" else "LLMUnavailable")

"""Evidence-request boundaries: all network I/O is replaced with explicit fakes."""

import copy
import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from vulnassess import evidence_requests as requests
from vulnassess.ai_boundary import INJECTION_SENTINEL, digest
from vulnassess.errors import NeedsReview
from vulnassess.settings import Settings


def context():
    settings = Settings(Path(__file__).parents[2] / "config")
    return {
        "target_ip": "172.28.0.10",
        "scope_hash": digest(settings.raw["scope.yaml"]),
        "run_id": "demo",
        "evidence": [{"id": "E1", "text": "Observed 80/tcp http"}],
        "probe_options": [{"kind": "http_head", "port": 80, "evidence_id": "E1"}],
    }


def proposal():
    return {
        "schema_version": "evidence_request.v1",
        "target_ip": "172.28.0.10",
        "kind": "http_head",
        "port": 80,
        "timeout_seconds": 3,
        "reason": "Inspect the observed HTTP service",
        "expected_information_gain": "Establish the root response status and headers",
        "claims": [
            {
                "path": path,
                "label": "inferred",
                "confidence": 0.7,
                "evidence_ids": ["E1"],
                "quotes": [{"evidence_id": "E1", "text": "Observed 80/tcp http"}],
                "finding_ids": [],
                "verification_action": None,
                "score": None,
            }
            for path in ("reason", "expected_information_gain")
        ],
    }


def model_output():
    value = proposal()
    for claim in value["claims"]:
        del claim["quotes"]
    return value


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_ip", "example.com"),
        ("target_ip", "8.8.8.8"),
        ("port", 443),
        ("port", True),
        ("timeout_seconds", 11),
        ("timeout_seconds", 0),
        ("kind", "shell"),
        ("flags", "-sV"),
    ],
)
def test_invalid_requests_cannot_reach_transport(tmp_path, field, value):
    candidate = proposal()
    candidate[field] = value
    registry = requests.EvidenceRequests(tmp_path)
    with pytest.raises(NeedsReview):
        registry.create(candidate, context())
    assert not list(tmp_path.glob("*.json"))


def test_fabricated_quote_is_rejected():
    candidate = proposal()
    candidate["claims"][0]["quotes"][0]["text"] = "Authentication disabled"
    with pytest.raises(NeedsReview):
        requests.validate(candidate, context())


@pytest.mark.parametrize(
    "text", ["CVE-2026-12345 affects this service", "Evidence E999 confirms it", "Inspect 8.8.8.8"]
)
def test_prose_cannot_introduce_identifiers(text):
    with pytest.raises(NeedsReview):
        requests.validate(proposal() | {"reason": text}, context())


def test_rejection_reason_is_persisted_and_cannot_execute(tmp_path):
    registry = requests.EvidenceRequests(tmp_path)
    record = registry.create(proposal(), context())
    result = registry.reject(
        record["request_id"], record["request_hash"], "Maintenance window closed"
    )
    assert result["state"] == "rejected"
    log = (tmp_path / "audit.jsonl").read_text()
    assert "Maintenance window closed" in log
    transport = Mock()
    with pytest.raises(NeedsReview):
        registry.execute(
            record["request_id"],
            record["request_hash"],
            lambda ip: context()["scope_hash"],
            transport,
        )
    transport.assert_not_called()


def test_execution_is_one_use_and_provenance_survives_restart(tmp_path):
    registry = requests.EvidenceRequests(tmp_path)
    record = registry.create(proposal(), context())
    original = copy.deepcopy(record)
    transport = Mock(return_value={"raw_hex": "48545450", "observation": "HTTP/1.1 302 Found"})
    result = registry.execute(
        record["request_id"], record["request_hash"], lambda ip: context()["scope_hash"], transport
    )
    assert result["state"] == "complete"
    assert result["evidence"]["origin"] == "ai_request"
    assert result["evidence"]["request_hash"] == original["request_hash"]
    with pytest.raises(NeedsReview):
        registry.execute(
            record["request_id"],
            record["request_hash"],
            lambda ip: context()["scope_hash"],
            transport,
        )
    assert transport.call_count == 1
    saved = requests.EvidenceRequests(tmp_path).evidence("demo", "172.28.0.10")
    assert saved == [result["evidence"]]
    assert requests.EvidenceRequests(tmp_path).evidence("another-run", "172.28.0.10") == []


def test_scope_change_prevents_io(tmp_path):
    registry = requests.EvidenceRequests(tmp_path)
    record = registry.create(proposal(), context())
    transport = Mock()
    with pytest.raises(NeedsReview):
        registry.execute(
            record["request_id"], record["request_hash"], lambda ip: "changed", transport
        )
    transport.assert_not_called()


def test_tampered_saved_evidence_fails_closed(tmp_path):
    registry = requests.EvidenceRequests(tmp_path)
    record = registry.create(proposal(), context())
    registry.execute(
        record["request_id"],
        record["request_hash"],
        lambda ip: context()["scope_hash"],
        Mock(return_value={"raw_hex": "", "observation": "connected"}),
    )
    file = next(tmp_path.glob("*.json"))
    saved = json.loads(file.read_text())
    saved["evidence"]["observation"] = "injected"
    file.write_text(json.dumps(saved))
    with pytest.raises(NeedsReview):
        registry.evidence("demo", "172.28.0.10")


@pytest.mark.parametrize("mode", ["valid", "canary", "malformed", "unavailable", "no_observations"])
def test_model_boundary_is_audited_and_never_executes(tmp_path, mode):
    source = context()
    model = Mock(model="test-model")
    model.available.return_value = mode != "unavailable"
    if mode == "no_observations":
        source["probe_options"] = []

    def generate(prompt, schema, **options):
        assert 'trust="untrusted"' in prompt
        assert schema["additionalProperties"] is False
        claim_schema = schema["properties"]["claims"]["items"]["properties"]
        assert claim_schema["path"]["enum"] == ["reason", "expected_information_gain"]
        assert "quotes" not in claim_schema
        variant = schema["oneOf"][0]["properties"]
        assert variant["kind"]["enum"] == ["http_head"]
        assert variant["port"]["enum"] == [80]
        assert variant["claims"]["items"]["properties"]["evidence_ids"]["items"]["enum"] == ["E1"]
        if mode == "malformed":
            raise ValueError("bad JSON")
        if mode == "canary":
            options["on_raw"](INJECTION_SENTINEL.encode())
        options["on_raw"](json.dumps(model_output()).encode())
        return model_output()

    model.generate_structured.side_effect = generate
    with patch.object(requests, "probe", side_effect=AssertionError("proposal must not probe")):
        if mode == "valid":
            assert requests.propose(source, model, tmp_path / "audit.jsonl") == proposal()
        else:
            with pytest.raises(NeedsReview):
                requests.propose(source, model, tmp_path / "audit.jsonl")
    audit = json.loads((tmp_path / "audit.jsonl").read_text())
    assert audit["outcome"] == ("validated" if mode == "valid" else "needs_review")
    assert audit["model"] == "test-model"
    assert len(audit["prompt_hash"]) == 64


def test_expiry_and_restart_revoke_authority(tmp_path):
    clock = Mock(return_value=0)
    registry = requests.EvidenceRequests(tmp_path, clock)
    record = registry.create(proposal(), context())
    clock.return_value = 601
    for active in (registry, requests.EvidenceRequests(tmp_path)):
        with pytest.raises(NeedsReview):
            active.execute(record["request_id"], record["request_hash"], Mock(), Mock())


def test_model_citation_choices_exclude_baseline_policy(tmp_path):
    source = context()
    source["evidence"].append({"id": "E2", "text": "Baseline policy; not a service observation"})
    model = Mock(model="schema-check", available=Mock(return_value=True))

    def generate(prompt, schema, **options):
        properties = schema["properties"]["claims"]["items"]["properties"]
        assert properties["evidence_ids"]["items"]["enum"] == ["E1"]
        assert "quotes" not in properties
        return model_output()

    model.generate_structured.side_effect = generate
    assert requests.propose(source, model, tmp_path / "audit.jsonl") == proposal()


@pytest.mark.parametrize(
    "bad_output",
    [
        proposal(),
        {"claims": "invalid"},
        model_output()
        | {
            "claims": [
                model_output()["claims"][0] | {"evidence_ids": ["E999"]},
                model_output()["claims"][1],
            ]
        },
    ],
)
def test_model_cannot_inject_quotes_or_unknown_references(tmp_path, bad_output):
    model = Mock(model="boundary-test", available=Mock(return_value=True))
    model.generate_structured.return_value = bad_output
    with pytest.raises(NeedsReview):
        requests.propose(context(), model, tmp_path / "audit.jsonl")


@pytest.mark.parametrize(
    "output",
    [
        TimeoutError(),
        {"raw_hex": "00" * 8193, "observation": "too big"},
        {"raw_hex": "", "observation": "connected", "origin": "scanner"},
    ],
)
def test_failed_transport_cannot_publish_partial_evidence(tmp_path, output):
    registry = requests.EvidenceRequests(tmp_path)
    record = registry.create(proposal(), context())
    transport = (
        Mock(side_effect=output) if isinstance(output, Exception) else Mock(return_value=output)
    )
    with pytest.raises(NeedsReview):
        registry.execute(
            record["request_id"],
            record["request_hash"],
            lambda ip: context()["scope_hash"],
            transport,
        )
    assert not list(tmp_path.glob("*.json"))
    assert '"decision": "needs_review"' in (tmp_path / "audit.jsonl").read_text()


def test_redirect_is_observed_without_following_it():
    connection = MagicMock()
    connection.__enter__.return_value = connection
    wire = b"HTTP/1.1 302 Found\r\nLocation: http://outside.invalid/\r\nSet-Cookie: private\r\n\r\n"
    connection.recv.return_value = wire
    with patch.object(requests.socket, "socket", return_value=connection):
        result = requests.probe(proposal())
    connection.connect.assert_called_once_with(("172.28.0.10", 80))
    assert connection.sendall.call_count == 1
    assert connection.sendall.call_args.args[0].startswith(b"HEAD / HTTP/1.0\r\n")
    retained = json.loads(bytes.fromhex(result["raw_hex"]))
    assert retained["format"] == "website_metadata.v1"
    assert retained["status"] == 302
    assert retained["redirect"] == "absolute HTTP destination"
    assert retained["cookies"]["issued"] == 1
    assert "outside.invalid" not in result["observation"]
    assert "outside.invalid" not in bytes.fromhex(result["raw_hex"]).decode()
    assert "private" not in bytes.fromhex(result["raw_hex"]).decode()
    assert "never followed" in result["observation"]
    assert "private" not in result["observation"]


@pytest.mark.parametrize("wire", [b"not HTTP\r\n\r\n", b"HTTP/1.1 200 OK\r\n", b"X" * 8193])
def test_incomplete_or_oversized_response_fails_closed(wire):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.recv.side_effect = [wire, b""]
    with (
        patch.object(requests.socket, "socket", return_value=connection),
        pytest.raises(NeedsReview),
    ):
        requests.probe(proposal())


def test_tls_uses_verified_context_and_pinned_ip():
    connection, tls_context, secured = MagicMock(), MagicMock(), MagicMock()
    connection.__enter__.return_value = connection
    tls_context.wrap_socket.return_value.__enter__.return_value = secured
    secured.getpeercert.side_effect = [b"certificate", {"subject": "test"}]
    secured.version.return_value = "TLSv1.3"
    with (
        patch.object(requests.socket, "socket", return_value=connection),
        patch.object(requests.ssl, "create_default_context", return_value=tls_context),
    ):
        result = requests.probe(proposal() | {"kind": "tls_inspect", "port": 443})
    connection.connect.assert_called_once_with(("172.28.0.10", 443))
    tls_context.wrap_socket.assert_called_once_with(connection, server_hostname="172.28.0.10")
    assert "TLSv1.3" in result["observation"]
    assert bytes.fromhex(result["raw_hex"]) == b"certificate"


def test_tcp_ipv6_probe_only_connects():
    connection = MagicMock()
    connection.__enter__.return_value = connection
    with patch.object(requests.socket, "socket", return_value=connection) as factory:
        result = requests.probe(proposal() | {"kind": "tcp_connect", "target_ip": "::1"})
    factory.assert_called_once_with(requests.socket.AF_INET6, requests.socket.SOCK_STREAM)
    connection.sendall.assert_not_called()
    assert "identity" in result["observation"]

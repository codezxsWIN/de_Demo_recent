import copy
import hashlib
import json

import pytest

from tests.test_capture_history import capture
from vulnassess import capture_history
from vulnassess.claim_semantics import verify_semantic_claims
from vulnassess.errors import LLMUnavailable
from vulnassess.finding_assurance import assurance, bounded_redis_proof
from vulnassess.redis_probe import POSITIVE, REQUEST
from vulnassess.schema import Finding, Provenance
from vulnassess.ui import assessment_report


def finding():
    return Finding.make(
        host_ip="127.0.0.1",
        port=6379,
        protocol="tcp",
        tool="redis-check",
        tool_native_id="lua-package-type-v1",
        description="SYNTHETIC bounded configuration observation",
        provenance=Provenance(
            tool="redis-check", raw_path="SYNTHETIC", record_index=1, run_id="test"
        ),
        title="Redis Lua package.loadlib exposed (CVE-2022-0543)",
        cve_ids=["CVE-2022-0543"],
        evidence="Fixed type inspection returned table:function.",
    ).to_json()


def proof():
    return {
        "target_ip": "127.0.0.1",
        "port": 6379,
        "check": "lua-package-type-v1",
        "request": REQUEST.decode(),
        "response": POSITIVE.decode(),
    }


def test_condition_does_not_confirm_package_or_exploitability():
    status = assurance(finding())
    assert "unconfirmed" in status["cve"]
    assert "Not tested" in status["exploitability"]
    assert "Conditional" in status["priority"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("request", "AUTH PRIVATE-CREDENTIAL"),
        ("response", "PRIVATE-TARGET-CONTENT"),
        ("port", True),
        ("port", 7001),
        ("target_ip", "192.0.2.5"),
        ("check", "other-check"),
    ],
)
def test_unrecognized_raw_values_are_not_disclosed(key, value):
    raw = proof()
    raw[key] = value
    bounded = bounded_redis_proof(raw, "127.0.0.1", [finding()], "a" * 64)
    assert bounded["status"] == "unavailable"
    assert "PRIVATE-" not in json.dumps(bounded)
    assert "request" not in bounded and "response" not in bounded


def test_exact_bound_proof_exposes_only_fixed_wire_exchange():
    bounded = bounded_redis_proof(proof(), "127.0.0.1", [finding()], "a" * 64)
    assert bounded["status"] == "verified"
    assert bounded["request"] == REQUEST.decode()
    assert bounded["response"] == POSITIVE.decode()
    assert "not global authentication" in bounded["limitations"]


@pytest.mark.parametrize(
    "change",
    [{"host_ip": "192.0.2.5"}, {"protocol": "udp"}, {"port": 7001}, {"id": "another-finding"}],
)
def test_verified_proof_cannot_be_borrowed_by_another_endpoint(change):
    f = finding()
    bounded = bounded_redis_proof(proof(), "127.0.0.1", [f], "a" * 64)
    assert assessment_report._proof_supports(bounded, f)
    assert not assessment_report._proof_supports(bounded, {**f, **change})


def test_saved_report_reads_manifest_bound_proof_without_modifying_payload(tmp_path):
    directory, result = capture(tmp_path)
    payload = json.loads((directory / "case.json").read_text())
    payload["findings"] = [finding()]
    raw_case = json.dumps(payload).encode()
    raw_proof = json.dumps(proof()).encode()
    (directory / "case.json").write_bytes(raw_case)
    (directory / "redis-lua-check.json").write_bytes(raw_proof)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"].update(
        {
            "case.json": hashlib.sha256(raw_case).hexdigest(),
            "redis-lua-check.json": hashlib.sha256(raw_proof).hexdigest(),
        }
    )
    (directory / "manifest.json").write_text(json.dumps(manifest))
    capture_history.save(directory, result, config_hash="SYNTHETIC")
    record = capture_history.load(tmp_path, directory.name)
    original = copy.deepcopy(record["payload"])
    html = assessment_report.render(record)
    assert "Candidate association" in html and "table:function" in html
    assert "without an AUTH exchange" in html
    assert "OS command execution" in html and "Exact bounded probe" in html
    assert record["payload"] == original


@pytest.mark.parametrize(
    "text", ["This host exposes CVE-2022-0543.", "CVE-2022-0543 is confirmed."]
)
def test_definitive_package_cve_claim_rejected(text):
    with pytest.raises(LLMUnavailable, match="package-dependent CVE"):
        verify_semantic_claims(
            [{"path": "summary", "label": "observed", "evidence_ids": ["E1"]}],
            [{"id": "E1", "text": "Redis version 5.0.7"}],
            {"summary": text},
        )

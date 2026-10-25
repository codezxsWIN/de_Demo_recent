"""Synthetic verifier receipts only: no scanner or network activity in these tests."""

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest
import yaml

from labs.harbordesk import verify as verifier
from labs.harbordesk.app import LAB_ID
from vulnassess import harbordesk_probe as probe
from vulnassess import live_assessment
from vulnassess.errors import ConfigError, ScopeError
from vulnassess.scan_plans import PlanExecution
from vulnassess.schema import Finding, Host, Service
from vulnassess.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = {"host": "127.0.0.1", "scheme": "http", "port": 8787, "path": "/"}
SCOPE = SimpleNamespace(contains=lambda ip: ip == "127.0.0.1", is_canary=lambda ip: False)


@pytest.fixture
def receipt():
    return {
        "lab_id": LAB_ID,
        "target": probe.BASE.rstrip("/"),
        "checks": [
            {
                "id": "HD-02",
                "observed_intentional_weakness": True,
                "evidence": {"baseline_customers": 1, "injected_customers": 3},
            },
            {
                "id": "HD-07",
                "observed_intentional_weakness": False,
                "evidence": {"unauthenticated_status": 403},
            },
            {
                "id": "HD-09",
                "observed_intentional_weakness": True,
                "evidence": {"returned_owner": "other-demo", "status": 200},
            },
        ],
        "passed": 2,
        "total": 3,
        "secure_controls": [{"id": "HC-01", "passed": True}],
        "network_status": "not started",
    }


def test_verified_receipt_findings_are_canonical_and_stable(tmp_path, monkeypatch, receipt):
    fake = Mock(return_value=receipt)
    monkeypatch.setattr(verifier, "verify", fake)
    first, raw = probe.run(SCOPE, "127.0.0.1", ENDPOINT, tmp_path)
    fake.assert_called_once_with(probe.BASE, extended=True, include_network=True)
    assert raw == receipt
    capture = tmp_path / "harbordesk-checks.json"
    assert json.loads(capture.read_text()) == receipt
    other = tmp_path / "second"
    other.mkdir()
    second, _ = probe.run(SCOPE, "127.0.0.1", ENDPOINT, other)
    assert [item.id for item in first] == [item.id for item in second]
    assert [item.tool_native_id for item in first] == ["HD-02", "HD-09"]
    for item, index in zip(first, (1, 3)):
        assert Finding.from_json(item.to_json()) == item
        assert item.tool == item.provenance.tool == "harbordesk"
        assert item.port == 8787 and item.protocol == "tcp"
        assert item.cve_ids == () and item.reference_urls == ()
        assert item.native_confidence == "high"
        assert item.native_severity == "High"
        assert item.provenance.run_id == "live"
        assert item.provenance.raw_path == str(capture.resolve())
        assert item.provenance.record_index == index
        assert json.loads(item.evidence)["evidence"] == receipt["checks"][index - 1]["evidence"]
    assert "2/3" in probe.coverage(raw)
    assert "secure_controls=" in probe.coverage(raw)
    assert "network checks not configured" in probe.coverage(raw)
    saved = capture.read_bytes()
    fake.reset_mock()
    with pytest.raises(FileExistsError):
        probe.run(SCOPE, "127.0.0.1", ENDPOINT, tmp_path)
    assert capture.read_bytes() == saved
    fake.assert_not_called()


@pytest.mark.parametrize(
    "target,change",
    [
        ("192.0.2.1", {}),
        ("127.0.0.2", {}),
        ("::1", {}),
        ("127.0.0.1", {"host": "localhost"}),
        ("127.0.0.1", {"host": "remote.invalid"}),
        ("127.0.0.1", {"scheme": "https"}),
        ("127.0.0.1", {"port": 8788}),
        ("127.0.0.1", {"port": "8787"}),
        ("127.0.0.1", {"path": "/secure/"}),
    ],
)
def test_wrong_target_rejected_before_any_verifier_post(tmp_path, monkeypatch, target, change):
    fake = Mock(side_effect=AssertionError("no active request allowed"))
    monkeypatch.setattr(verifier, "verify", fake)
    endpoint = {**ENDPOINT, **change}
    assert not probe.eligible(target, endpoint)
    with pytest.raises(ScopeError):
        probe.run(SCOPE, target, endpoint, tmp_path)
    fake.assert_not_called()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "scope",
    [
        SimpleNamespace(contains=lambda ip: False, is_canary=lambda ip: False),
        SimpleNamespace(contains=lambda ip: True, is_canary=lambda ip: True),
    ],
)
def test_scope_gate_precedes_verifier(tmp_path, monkeypatch, scope):
    fake = Mock()
    monkeypatch.setattr(verifier, "verify", fake)
    with pytest.raises(ScopeError):
        probe.run(scope, "127.0.0.1", ENDPOINT, tmp_path)
    fake.assert_not_called()


@pytest.mark.parametrize("unknown_id", ["HD-99", "HD-12"])
@pytest.mark.parametrize("observed", [False, True])
def test_unknown_negative_and_large_evidence(tmp_path, monkeypatch, receipt, unknown_id, observed):
    receipt["checks"][0]["evidence"] = {"actual_response": "x" * 10000}
    receipt["checks"].append(
        {
            "id": unknown_id,
            "observed_intentional_weakness": observed,
            "evidence": {"untrusted": "unknown check"},
        }
    )
    monkeypatch.setattr(verifier, "verify", lambda *a, **kw: receipt)
    findings, _ = probe.run(SCOPE, "127.0.0.1", ENDPOINT, tmp_path)
    assert [item.tool_native_id for item in findings] == ["HD-02", "HD-09"]
    assert len(findings[0].evidence) <= 2048
    assert json.loads(findings[0].evidence)["truncated"] is True
    assert json.loads((tmp_path / "harbordesk-checks.json").read_text()) == receipt
    detail = probe.coverage(receipt)
    assert detail.startswith("partial:")
    assert f"unsupported check IDs={unknown_id}" in detail
    assert "2/3 verified" in detail  # Unknown positives never inflate observed weaknesses.


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(lab_id="spoof"),
        lambda r: r.update(target="http://remote.invalid"),
        lambda r: r["checks"][0].update(observed_intentional_weakness="true"),
        lambda r: r["checks"][0].update(port=2121),
        lambda r: r["checks"].append(copy.deepcopy(r["checks"][0])),
    ],
)
def test_invalid_receipt_is_preserved_without_findings(tmp_path, monkeypatch, receipt, mutation):
    mutation(receipt)
    monkeypatch.setattr(verifier, "verify", lambda *a, **kw: receipt)
    with pytest.raises(ValueError):
        probe.run(SCOPE, "127.0.0.1", ENDPOINT, tmp_path)
    assert json.loads((tmp_path / "harbordesk-checks.json").read_text()) == receipt


def test_network_ports_urls_severities_and_services(tmp_path, monkeypatch, receipt):
    receipt["checks"] = [
        {
            "id": identity,
            "port": port,
            "observed_intentional_weakness": True,
            "evidence": {"verified_port": port},
        }
        for identity, port in (("HD-13", 2121), ("HD-14", 2121), ("HD-15", 8443), ("HD-16", 8443))
    ]
    receipt["network_status"] = "enabled"
    receipt["checks"][0]["evidence"]["banner"] = "220 HarborDesk FTP fixture"
    receipt["checks"][2]["evidence"]["tls_version"] = "TLSv1.3"
    monkeypatch.setattr(verifier, "verify", lambda *a, **kw: receipt)
    findings, raw = probe.run(SCOPE, "127.0.0.1", ENDPOINT, tmp_path)
    assert [item.port for item in findings] == [2121, 2121, 8443, 8443]
    assert [item.native_severity for item in findings] == ["Medium", "Medium", "Medium", "High"]
    assert [item.cwe_ids for item in findings] == [
        ("CWE-306",),
        ("CWE-319",),
        ("CWE-295",),
        ("CWE-306",),
    ]
    assert [item.url for item in findings] == ["ftp://127.0.0.1:2121/"] * 2 + [
        "https://127.0.0.1:8443/",
        "https://127.0.0.1:8443/admin",
    ]
    assert all(item.tool == "harbordesk" and not item.cve_ids for item in findings)
    assert probe.confirmed_services(raw) == (
        Service(2121, "tcp", name="ftp", banner="220 HarborDesk FTP fixture"),
        Service(8443, "tcp", name="https", tls=True),
    )
    assert "4/4" in probe.coverage(raw)


def test_service_context_requires_actual_protocol_observations(receipt):
    receipt["checks"] = [
        {
            "id": "HD-13",
            "port": 2121,
            "observed_intentional_weakness": True,
            "evidence": {"fixture_file_read": True},
        },
        {
            "id": "HD-15",
            "port": 8443,
            "observed_intentional_weakness": True,
            "evidence": {"certificate_expired": True},
        },
    ]
    assert probe.confirmed_services(receipt) == ()
    receipt["checks"][0]["evidence"]["banner"] = "220 FTP fixture"
    receipt["checks"][1].update(observed_intentional_weakness=False)
    receipt["checks"][1]["evidence"]["tls_version"] = "TLSv1.3"
    receipt["secure_controls"] = [
        {"id": "HC-11", "passed": True},
        {"id": "HC-12", "passed": True},
    ]
    assert [s.port for s in probe.confirmed_services(receipt)] == [2121, 2122, 8443, 8444]
    assert all(s.product is None for s in probe.confirmed_services(receipt))
    receipt["checks"][1]["evidence"]["check_error"] = "TimeoutError"
    receipt["secure_controls"] = [{"id": "HC-11", "passed": False}]
    assert [s.port for s in probe.confirmed_services(receipt)] == [2121]


@pytest.mark.parametrize(
    "mapping", [None, {"High": 60, "Medium": 40, "Low": 20, "Informational": 5}]
)
def test_settings_accept_optional_mapping(tmp_path, mapping):
    for name in ("scope.yaml", "weights.yaml", "roles.yaml", "controls.yaml"):
        shutil.copyfile(ROOT / "config" / name, tmp_path / name)
    path = tmp_path / "weights.yaml"
    weights = yaml.safe_load(path.read_text())
    weights["native_fallback"].pop("harbordesk", None)
    if mapping is not None:
        weights["native_fallback"]["harbordesk"] = mapping
    path.write_text(yaml.safe_dump(weights))
    settings = Settings(tmp_path)
    assert settings.weights["native_fallback"].get("harbordesk") == mapping


@pytest.mark.parametrize("mapping", [60, {}, {"High": True}, {"High": 101}, {"Critical": 80}])
def test_settings_validate_harbordesk_mapping(tmp_path, mapping):
    for name in ("scope.yaml", "weights.yaml", "roles.yaml", "controls.yaml"):
        shutil.copyfile(ROOT / "config" / name, tmp_path / name)
    path = tmp_path / "weights.yaml"
    weights = yaml.safe_load(path.read_text())
    weights["native_fallback"]["harbordesk"] = mapping
    path.write_text(yaml.safe_dump(weights))
    with pytest.raises(ConfigError, match="native_fallback.harbordesk"):
        Settings(tmp_path)


@pytest.mark.parametrize(
    "failure", [False, True, "check_error", "network", "missing", "unknown", "plan"]
)
def test_live_collection_integrates_before_scoring_and_preserves_manifest(
    tmp_path, monkeypatch, receipt, failure
):
    events, cases = [], []
    if failure == "missing":
        receipt["requested_checks"] = [row["id"] for row in receipt["checks"]] + ["HD-03"]
        receipt["requested_controls"] = ["HC-01"]
    if failure == "unknown":
        receipt["checks"].append(
            {"id": "HD-99", "observed_intentional_weakness": True, "evidence": {}}
        )
    if failure == "check_error":
        receipt["checks"].append(
            {
                "id": "HD-15",
                "port": 8443,
                "observed_intentional_weakness": False,
                "evidence": {"check_error": "TimeoutError"},
            }
        )
    if failure == "network":
        receipt["checks"].extend(
            [
                {
                    "id": "HD-13",
                    "port": 2121,
                    "observed_intentional_weakness": True,
                    "evidence": {"banner": "220 FTP fixture", "fixture_file_read": True},
                },
                {
                    "id": "HD-15",
                    "port": 8443,
                    "observed_intentional_weakness": True,
                    "evidence": {"tls_version": "TLSv1.3", "certificate_expired": True},
                },
            ]
        )
        receipt["secure_controls"] = [
            {"id": "HC-11", "passed": True},
            {"id": "HC-12", "passed": True},
        ]
        receipt["network_status"] = "enabled"

    def fake_verify(*args, **kwargs):
        if failure is True:
            raise ValueError("Not the identified HarborDesk fixture lab")
        return receipt

    verify_mock = Mock(side_effect=fake_verify)
    monkeypatch.setattr(verifier, "verify", verify_mock)
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "synthetic-nmap")
    monkeypatch.setattr(live_assessment, "mkdtemp", lambda **kw: str(tmp_path))

    def fake_process(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text("<synthetic/>")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(live_assessment.subprocess, "run", fake_process)
    monkeypatch.setattr(
        live_assessment,
        "parse_nmap_xml",
        lambda *a: ([Host("127.0.0.1", services=(Service(135, "tcp", name="msrpc"),))], []),
    )
    monkeypatch.setattr(
        live_assessment,
        "_scan_requested_endpoint",
        lambda *a: (a[5], a[6], "complete", "not configured"),
    )
    monkeypatch.setattr(
        live_assessment.analyst,
        "analyze_optional",
        lambda *a, **kw: {
            "analyst": None,
            "ai_status": "not_attempted",
            "ai_attempts": [],
        },
    )
    plan = (
        SimpleNamespace(
            before=Mock(return_value=180),
            remaining=Mock(return_value=90),
            includes=Mock(return_value=False),
            finish=Mock(return_value={"state": "completed"}),
        )
        if failure == "plan"
        else None
    )
    result = live_assessment.run(
        probe.BASE,
        {"status": "ready", "resolved_ips": ["127.0.0.1"], "endpoint": ENDPOINT},
        ROOT / "config",
        provider="ollama",
        on_progress=lambda *e: events.append(e),
        on_case=cases.append,
        plan_execution=cast(PlanExecution | None, plan),
    )
    payload = cases[0]["payload"]
    partial = failure is True or failure in ("check_error", "network", "missing", "unknown")
    assert result["scan_status"] == ("partial" if partial else "complete")
    coverage = payload["scanner_coverage"]["harbordesk-check"]
    if failure == "plan":
        verify_mock.assert_not_called()
        assert plan is not None
        plan.before.assert_called_once()
        assert payload["findings"] == payload["scores"] == []
        assert coverage.startswith("not requested:")
        assert "approved scan plan" in coverage
        assert not (tmp_path / "harbordesk-checks.json").exists()
    elif failure is True:
        assert payload["findings"] == []
        assert "failed:" in coverage
    else:
        assert (
            len(payload["findings"]) == len(payload["scores"]) == (4 if failure == "network" else 2)
        )
        assert payload["enrichments"] == []
        assert all(
            item["tool"] == "harbordesk" and not item["cve_ids"] for item in payload["findings"]
        )
        assert {score["risk"] for score in payload["scores"]} == (
            {60, 40} if failure == "network" else {60}
        )
        assert json.loads((tmp_path / "harbordesk-checks.json").read_text()) == receipt
    if partial:
        assert any(stage == "canonical" and state == "error" for stage, state, _ in events)
        assert payload["collection_failures"][0]["stage"] == "canonical"
    ports = {s["port"]: s for s in payload["hosts"][0]["services"]}
    assert ports[135]["name"] == "msrpc"
    if failure == "network":
        assert set(ports) == {135, 2121, 2122, 8443, 8444}
        assert ports[8443]["tls"] is ports[8444]["tls"] is True
        assert ports[2121]["name"] == "ftp"
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    capture = tmp_path / "harbordesk-checks.json"
    if failure == "plan":
        assert capture.name not in manifest["files"]
    else:
        assert manifest["files"][capture.name] == hashlib.sha256(capture.read_bytes()).hexdigest()


def test_requested_completeness_preserves_successes_and_completed_negatives(receipt):
    receipt["requested_checks"] = [row["id"] for row in receipt["checks"]]
    receipt["requested_controls"] = ["HC-01"]
    assert probe.coverage(receipt).startswith("complete: 2/3")
    receipt["requested_checks"].append("HD-03")
    assert "missing requested checks=HD-03" in probe.coverage(receipt)
    assert probe.coverage(receipt).startswith("partial: 2/3")
    receipt["checks"].append(
        {"id": "HD-03", "observed_intentional_weakness": False, "evidence": {"status": 401}}
    )
    # A completed negative result satisfies coverage without asserting a weakness.
    assert probe.coverage(receipt).startswith("complete: 2/4")
    receipt["secure_controls"] = []
    assert "missing requested controls=HC-01" in probe.coverage(receipt)
    assert probe.coverage(receipt).startswith("partial:")


@pytest.mark.parametrize(
    "control",
    [
        {"id": "HC-01", "passed": False},
        {"id": "HC-01", "passed": False, "check_error": "TimeoutError"},
        {"id": "HC-99", "passed": True},
    ],
)
def test_control_failure_error_and_unsupported_identity_are_partial(receipt, control):
    receipt["secure_controls"] = [control]
    detail = probe.coverage(receipt)
    assert detail.startswith("partial: 2/3")
    assert control["id"] in detail


@pytest.mark.parametrize("requests", [None, "HD-02", [True], ["HD-02", "HD-02"], ["HD-99"]])
def test_invalid_requested_check_manifest_is_partial(receipt, requests):
    receipt["requested_checks"] = requests
    receipt["requested_controls"] = ["HC-01"]
    assert probe.coverage(receipt).startswith("partial:")


def test_empty_and_historical_receipts_do_not_invent_coverage(receipt):
    assert probe.coverage(receipt).startswith("complete:")
    assert "historical receipt" in probe.coverage(receipt)
    assert "coverage limited to returned rows" in probe.coverage(receipt)
    receipt["checks"] = []
    assert probe.coverage(receipt).startswith("partial: 0/0")
    receipt["network_status"] = "enabled"
    assert "missing enabled network checks=HD-13,HD-14,HD-15,HD-16" in probe.coverage(receipt)


def test_split_historical_network_receipts_keep_provenance_and_deduplicate(receipt):
    row = {
        "id": "HD-15",
        "port": 8443,
        "observed_intentional_weakness": True,
        "evidence": {"tls_version": "TLSv1.3"},
    }
    receipt["network_checks"] = [row]
    assert probe._rows(receipt)[-1] == row
    receipt["checks"].append(copy.deepcopy(row))
    assert len(probe._rows(receipt)) == 4
    assert probe.coverage(receipt).startswith("complete: 3/4")

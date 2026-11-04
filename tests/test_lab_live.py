"""Live investigation proof boundaries; protocol transport itself is tested separately."""

import ftplib
import json
import shutil
import struct
from pathlib import Path

import pytest

from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.lab_live import LiveLab
from vulnassess.network_service_policy import load
from vulnassess.settings import Settings

ROOT = Path(__file__).resolve().parents[1]


class Traffic:
    def collect(self, *arguments):
        return self.correlate(*arguments), self.pcap(*arguments)

    def correlate(self, *_):
        return {
            "packet_ids": ["session:1"],
            "packets": [{"packet_id": "session:1"}],
            "method": "endpoint_and_time_window",
            "causal_validation": False,
        }

    def pcap(self, *_):
        return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def topology(self):
        return {"available": True, "nodes": []}

    def snapshot(self, *_):
        return {"available": True, "packets": []}


class Console:
    def __init__(self, root):
        self.root = root
        self.accepted = True
        self.calls = []

    def endpoint(self, environment, port):
        ip = "127.0.0.2" if environment == "office" else "127.0.0.3"
        settings = Settings(self.root / "config")
        policy = load(settings.config_dir, settings.scope, ip)
        return ip, next(e for e in policy["endpoints"] if e["port"] == port)

    def action(self, name):
        self.calls.append(name)
        return {
            "proof": {
                "protocol_confirmed": True,
                "anonymous_accepted": self.accepted,
                "response": "230 Login successful" if self.accepted else "530 Login incorrect",
            },
            "decision": {
                "violations": ["Authentication policy violation"] if self.accepted else [],
                "inconclusive": False,
            },
        }


class Control:
    def __init__(self, console):
        self.console = console

    def set_profile(self, environment, profile):
        self.console.accepted = profile == "baseline"
        return {"status": "verified", "profile": profile, "environment": environment}


@pytest.fixture
def live(tmp_path):
    shutil.copytree(ROOT / "config", tmp_path / "config")
    console = Console(tmp_path)
    return LiveLab(tmp_path, traffic=Traffic(), control=Control(console), console=console)


def test_check_retains_packet_correlation_separately_and_uses_real_score_engine(live):
    case = live.check("office", "ftp-anonymous")
    assert case["result"]["proof"]["response"].startswith("230")
    assert len(case["findings"]) == 1
    assert case["findings"][0]["score"]["risk"] == 30
    assert case["packet_evidence"]["causal_validation"] is False
    assert case["findings"][0]["finding"]["cve_ids"] == []
    assert live.load(case["id"]) == case
    assert live.pcap(case["id"]) == Traffic().pcap("office")


def test_file_read_explanation_uses_the_actual_retrieval_proof(live):
    original = live.console.action

    def file_read(action):
        result = original(action)
        result["proof"]["bytes_received"] = 32
        return result

    live.console.action = file_read
    case = live.check("office", "ftp-file")
    meaning = live._facts(case)["impact0"]["text"]
    assert "retrieved (32 bytes)" in meaning
    assert "did not" not in meaning


@pytest.mark.parametrize(
    "environment,action",
    [
        ("external", "ftp-file"),
        ("office", "mqtt-exchange"),
        ("iot", "ftp-file"),
        ("office", "execute-command"),
        ([], "ftp-file"),
        ("office", []),
    ],
)
def test_expanded_scope_never_dispatches_a_connection(live, environment, action):
    with pytest.raises(ConfigError):
        live.check(environment, action)
    assert live.console.calls == []


def test_missing_capture_does_not_hide_the_policy_finding_or_fabricate_packet_proof(live):
    def absent(*_):
        raise ValueError("No observer running")

    live.traffic.correlate = absent
    case = live.check("office", "ftp-anonymous")
    assert case["findings"] and case["packet_evidence"]["packet_ids"] == []
    assert "pcap" not in case
    with pytest.raises(ConfigError, match="No independent"):
        live.pcap(case["id"])


def test_configuration_comparison_keeps_same_target_and_policy(live):
    case = live.change("office", "restricted")
    comparison = case["comparison"]
    assert comparison["same_target"] and comparison["same_policy"]
    assert comparison["before_violations"] and not comparison["after_violations"]
    before = live.load(comparison["before_id"])
    assert before["expected_policy"] == case["expected_policy"]
    assert before["result"]["proof"]["anonymous_accepted"] is True
    assert case["result"]["proof"]["anonymous_accepted"] is False


def test_failed_configuration_change_is_not_reported_as_a_successful_retest(live):
    live.control.set_profile = lambda *_: {"status": "failed", "error": "verified rollback"}
    with pytest.raises(ConfigError, match="not verified"):
        live.change("office", "restricted")
    assert len(live.console.calls) == 1
    assert live.history("office")[0]["control_failure"]["status"] == "failed"


def test_tampered_case_and_pcap_are_refused(live):
    case = live.check("office", "ftp-anonymous")
    pcap = live.directory / (case["id"] + ".pcap")
    pcap.write_bytes(b"modified")
    with pytest.raises(ConfigError, match="integrity"):
        live.pcap(case["id"])
    path = live.directory / (case["id"] + ".json")
    raw = json.loads(path.read_text())
    raw["findings"][0]["score"]["risk"] = 100
    path.write_text(json.dumps(raw))
    with pytest.raises(ConfigError, match="changed"):
        live.load(case["id"])


@pytest.mark.parametrize("identifier", ["../config", "live-abc", "", "x/y", None, []])
def test_evidence_identifier_is_not_a_path(live, identifier):
    with pytest.raises(ConfigError):
        live.load(identifier)


def test_ai_requires_cloud_permission_before_calling_the_provider(live):
    case = live.check("office", "ftp-anonymous")
    with pytest.raises(ConfigError, match="consent"):
        live.explain(case["id"], "google", False)


class AI:
    model = "SYNTHETIC-OFFLINE-PROVIDER"

    def __init__(self, output):
        self.output = output
        self.calls = []

    def generate_structured(self, prompt, schema, **_):
        self.calls.append((prompt, schema))
        return self.output


def test_ai_selects_existing_facts_without_rewriting_score_or_observation(live):
    case = live.change("office", "restricted")
    client = AI(
        {
            "observations": ["change", "observation"],
            "why_it_matters": ["context", "earlier_priority"],
            "next_steps": ["retest"],
            "limits": ["scope"],
        }
    )
    answer = live.explain(case["id"], "ollama", False, client=client)
    assert answer["ai"]["status"] == "validated_selection"
    assert answer["ai"]["sections"]["observations"][0]["reference"] == "change"
    assert answer["result"] == case["result"] and answer["findings"] == case["findings"]
    prompt, _ = client.calls[0]
    assert "Raw PCAP" not in prompt and "payload_hex" not in prompt


@pytest.mark.parametrize("environment", ["office", "iot"])
@pytest.mark.parametrize("protocol,identity", [(True, True), (True, False), (False, False)])
def test_redis_ai_facts_preserve_identity_only_and_failed_protocol_boundaries(
    live, environment, protocol, identity
):
    live.console.action = lambda _: {
        "proof": {
            "protocol_confirmed": protocol,
            "identity_established": identity,
            "redis_version": "7.0.11" if identity else None,
        },
        "decision": {"violations": [], "inconclusive": not identity},
    }
    case = live.check(environment, "redis-" + environment)
    facts = live._facts(case)
    observation = facts["observation"]["text"]
    assert "did not test CVE applicability or exploitability" in observation
    assert "upstream Redis version alone does not confirm" in facts["retest"]["text"]
    assert not case["findings"] and case["ai"]["status"] == "not_requested"
    if identity:
        assert "INFO server reported Redis 7.0.11" in observation
    elif protocol:
        assert "protocol responded, but service identity was not established" in observation
    else:
        assert "did not establish a Redis protocol response" in observation
        assert "protocol responded" not in observation


@pytest.mark.parametrize(
    "override",
    [
        {"observations": ["nonexistent"]},
        {"observations": [{"fake": "fact"}]},
        {"observations": ["scope"]},
        {"limits": []},
        {"next_steps": []},
        {"observations": ["capture"]},
        {"why_it_matters": []},
    ],
)
def test_unknown_misclassified_or_missing_ai_evidence_is_withheld(live, override):
    case = live.check("office", "ftp-anonymous")
    output = {
        "observations": ["observation"],
        "why_it_matters": ["context"],
        "next_steps": ["retest"],
        "limits": ["scope"],
        **override,
    }
    with pytest.raises(LLMUnavailable):
        live.explain(case["id"], "ollama", False, client=AI(output))
    assert live.load(case["id"])["ai"]["status"] == "not_requested"


def test_policy_changed_during_exchange_is_not_scored_under_a_new_hash(live):
    original = live.console.action

    def drift(action):
        result = original(action)
        path = live.root / "config/network-services.json"
        policy = json.loads(path.read_text())
        endpoint = next(e for e in policy["targets"]["127.0.0.2"] if e["port"] == 2121)
        endpoint["require_auth"] = False
        path.write_text(json.dumps(policy))
        return result

    live.console.action = drift
    with pytest.raises(ConfigError, match="policy changed"):
        live.check("office", "ftp-anonymous")
    case = live.history("office")[0]
    assert not case["findings"] and case["policy_error"]
    with pytest.raises(ConfigError, match="stable"):
        live.explain(case["id"], "ollama", False)


def test_retest_failure_retains_verified_change_and_explicit_failure(live):
    original = live.console.action

    def fail_after_change(action):
        if not live.console.accepted:
            raise ConnectionRefusedError("Retest connection refused")
        return original(action)

    live.console.action = fail_after_change
    with pytest.raises(ConfigError, match="retest failed"):
        live.change("office", "restricted")
    case = live.history("office")[0]
    assert case["control"]["status"] == "verified"
    assert case["retest"]["status"] == "failed"
    assert not live.console.accepted


def test_ftp_protocol_error_does_not_leave_retest_pending(live):
    original = live.console.action

    def fail_after_change(action):
        if not live.console.accepted:
            raise ftplib.error_temp("421 Service unavailable")
        return original(action)

    live.console.action = fail_after_change
    with pytest.raises(ConfigError, match="421"):
        live.change("office", "restricted")
    assert live.history("office")[0]["retest"]["status"] == "failed"


def test_invalid_policy_after_exchange_retains_observation_without_findings(live):
    original = live.console.action

    def invalidate_policy(action):
        result = original(action)
        (live.root / "config/network-services.json").write_text("invalid JSON")
        return result

    live.console.action = invalidate_policy
    with pytest.raises(ConfigError, match="Owner policy changed"):
        live.check("office", "ftp-anonymous")
    retained = live.history("office")[0]
    assert retained["result"]["proof"]["anonymous_accepted"]
    assert retained["policy_error"] and retained["findings"] == []


def test_ai_must_include_recorded_retest_and_prior_change_priority(live):
    case = live.change("office", "restricted")
    output = {
        "observations": ["observation", "capture"],
        "why_it_matters": ["context"],
        "next_steps": ["retest"],
        "limits": ["scope"],
    }
    with pytest.raises(LLMUnavailable):
        live.explain(case["id"], "ollama", False, client=AI(output))

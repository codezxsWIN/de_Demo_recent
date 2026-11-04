"""Proof boundaries, runtime/source binding and bounded full-suite persistence."""

import copy
import hashlib
import json
import shutil
import threading
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from vulnassess import lab_assessment as assessment
from vulnassess.errors import ConfigError
from vulnassess.schema import Finding, Provenance

ROOT = Path(__file__).resolve().parents[1]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def inventory():
    result = json.loads((ROOT / "labs/service_networks/expectations.json").read_bytes())
    # Unit fixtures review the mock image, independently of the deployed image
    # that main owns in the real manifest. Do not infer this from runtime state.
    for spec in result["environments"].values():
        spec["reviewed_image_id"] = "sha256:" + "b" * 64
    return result


def finding(environment, condition, *, risk=30, native=None):
    item = Finding.make(
        host_ip=assessment.TARGETS[environment],
        port=condition["port"],
        protocol=condition["transport"],
        tool="service-network",
        tool_native_id=native
        or f"policy:{condition['service']}:{condition['port']}:{condition['rule']}",
        title="Observed endpoint policy condition",
        description="Actual protocol proof contradicts the owner endpoint policy.",
        evidence="Bounded protocol proof",
        provenance=Provenance("service-network", "case.json", 0, "case"),
    )
    return {
        "finding": item.to_json(),
        "score": {"risk": risk, "band": "Medium"},
        "guidance": {"meaning": "Owner policy condition observed"},
    }


def case(inventory, environment, action, profile="baseline"):
    port, transport, _ = assessment.ACTIONS[environment][action]
    proof = {"protocol_confirmed": True}
    findings = []
    for row in inventory["environments"][environment]["conditions"]:
        if row["action"] != action:
            continue
        expected = row["expected"][profile]
        proof[row["proof_field"]] = (
            row["violation_value"] if expected else not row["violation_value"]
        )
        if expected:
            findings.append(finding(environment, row))
    if action.startswith("redis-"):
        proof.update(identity_established=True, redis_version="7.0.11")
    return {
        "id": "live-" + uuid4().hex,
        "environment": environment,
        "target": assessment.TARGETS[environment],
        "action": action,
        "port": port,
        "transport": transport,
        "started_at": assessment._now(),
        "finished_at": assessment._now(),
        "policy_sha256": inventory["sources"]["config/network-services.json"],
        "result": {"proof": proof, "decision": {"inconclusive": False}},
        "findings": findings,
        "packet_evidence": {"packets": [{"payload": "DO_NOT_DUPLICATE_PCAP"}]},
        "pcap": {"bytes": 42},
        "ai": {"status": "not_requested"},
    }


def all_cases(inventory, environment, profile="baseline"):
    return [
        case(inventory, environment, action, profile) for action in assessment.ACTIONS[environment]
    ]


def truth(profile="baseline"):
    return {
        "status": "verified",
        "issues": [],
        "profile": profile,
        "reviewed_image_id": "sha256:" + "b" * 64,
    }


@pytest.mark.parametrize("environment,tp,tn", [("office", 5, 3), ("iot", 4, 3)])
def test_reviewed_baseline_all_conditions_are_independently_proven(inventory, environment, tp, tn):
    result = assessment.evaluate(inventory, environment, all_cases(inventory, environment), truth())
    assert result["metrics"]["true_positive"] == tp
    assert result["metrics"]["true_negative"] == tn
    assert result["metrics"]["false_positive"] == result["metrics"]["false_negative"] == 0
    assert result["metrics"]["precision"] == result["metrics"]["recall"] == 1
    assert result["coverage"]["declared_endpoints"] == (7 if environment == "office" else 6)
    assert result["coverage"]["identity_only_endpoints"] == 1
    assert result["coverage"]["cve_detection"] == "not_tested"
    assert result["coverage"]["complete_security_assessment"] is False
    assert result["metrics"]["untested"] == 0
    redis = next(row for row in result["endpoints"] if row["service"] == "redis")
    assert redis["state"] == "identity_only" and redis["cve_detection"] == "not_tested"


@pytest.mark.parametrize("environment,tp,tn", [("office", 4, 4), ("iot", 3, 4)])
def test_restricted_profile_changes_only_reviewed_access_condition(inventory, environment, tp, tn):
    result = assessment.evaluate(
        inventory, environment, all_cases(inventory, environment, "restricted"), truth("restricted")
    )
    assert result["metrics"]["true_positive"] == tp
    assert result["metrics"]["true_negative"] == tn


def test_smb_authentication_comparison_still_has_positive_signing_condition(inventory):
    result = assessment.evaluate(inventory, "office", all_cases(inventory, "office"), truth())
    rows = {row["id"]: row for row in result["conditions"]}
    assert rows["smb-1446-authentication"]["state"] == "true_negative"
    assert rows["smb-1446-signing"]["state"] == "true_positive"


def test_tls_hostname_negative_and_expiry_chain_positive_are_separate(inventory):
    result = assessment.evaluate(inventory, "iot", all_cases(inventory, "iot"), truth())
    rows = {row["id"]: row for row in result["conditions"]}
    assert rows["tls-8883-hostname"]["observed"] is False
    assert rows["tls-8883-hostname"]["state"] == "true_negative"
    assert (
        rows["tls-8883-chain"]["state"] == rows["tls-8883-certificate"]["state"] == "true_positive"
    )


@pytest.mark.parametrize("unknown", [None, 0, 1, "false", {}, []])
def test_missing_or_nonboolean_proof_never_becomes_tn_or_fn(inventory, unknown):
    cases = all_cases(inventory, "office")
    for row in cases:
        if row["action"] in {"ftp-anonymous", "ftp-protected"}:
            row["result"]["proof"]["anonymous_accepted"] = unknown
            row["findings"] = []
    result = assessment.evaluate(inventory, "office", cases, truth())
    assert result["metrics"]["true_negative"] == 2
    assert result["metrics"]["false_negative"] == 0
    assert result["metrics"]["missed_untested"] == 1
    assert result["coverage"]["untested_conditions"] == 2


def test_proven_negative_against_expected_positive_is_fn_and_extra_prediction_is_fp(inventory):
    cases = all_cases(inventory, "office")
    cases[0]["result"]["proof"]["anonymous_accepted"] = False
    cases[0]["findings"] = []
    definition = inventory["environments"]["office"]["conditions"][1]
    cases[1]["findings"] = [finding("office", definition)]
    result = assessment.evaluate(inventory, "office", cases, truth())
    assert result["metrics"]["false_negative"] == result["metrics"]["false_positive"] == 1
    assert result["metrics"]["missed_untested"] == 0


def test_case_failure_with_known_smb_signing_retains_only_that_completed_field(inventory):
    cases = all_cases(inventory, "office")
    smb = next(row for row in cases if row["action"] == "smb-read")
    del smb["result"]["proof"]["anonymous_accepted"]
    smb["result"]["decision"]["inconclusive"] = True
    smb["state"] = "failed"
    smb["findings"] = [
        row for row in smb["findings"] if row["finding"]["tool_native_id"].endswith(":signing")
    ]
    result = assessment.evaluate(inventory, "office", cases, truth())
    rows = {row["id"]: row for row in result["conditions"]}
    assert rows["smb-1445-signing"]["state"] == "true_positive"
    assert rows["smb-1445-authentication"]["state"] == "untested"
    assert result["metrics"]["missed_untested"] == 1


@pytest.mark.parametrize("failure", ["policy", "protocol"])
def test_invalid_policy_or_unconfirmed_protocol_never_credits_known_looking_fields(
    inventory, failure
):
    cases = all_cases(inventory, "office")
    if failure == "policy":
        cases[0]["policy_error"] = "Owner revoked permission"
    else:
        cases[0]["result"]["proof"]["protocol_confirmed"] = False
    result = assessment.evaluate(inventory, "office", cases, truth())
    assert result["conditions"][0]["state"] == "untested"
    assert result["metrics"]["missed_untested"] == 1
    assert result["findings"]  # Real findings remain visible even without comparison credit.


def test_unverified_truth_nulls_metrics_but_keeps_findings_and_actual_proof(inventory):
    result = assessment.evaluate(
        inventory,
        "office",
        all_cases(inventory, "office"),
        {"status": "unverified", "profile": "baseline"},
    )
    assert result["metrics"] is None
    assert len(result["findings"]) == 5
    assert all(row["state"] == "untested" for row in result["conditions"])
    assert result["conditions"][0]["observed"] is True


def test_unknown_prediction_is_retained_as_unexpected_with_original_score(inventory):
    cases = all_cases(inventory, "iot")
    definition = inventory["environments"]["iot"]["conditions"][0]
    cases[0]["findings"].append(
        finding("iot", definition, risk=74, native="policy:mqtt:1883:unknown-rule")
    )
    result = assessment.evaluate(inventory, "iot", cases, truth())
    unexpected = result["unexpected_findings"][0]
    row = next(row for row in result["findings"] if row["uid"] == unexpected["uid"])
    assert row["score"]["risk"] == 74
    assert unexpected["rule"] == "unknown-rule"


def test_deduplication_uses_canonical_uid_and_preserves_distinct_score_observations(inventory):
    cases = all_cases(inventory, "office")
    duplicate = copy.deepcopy(cases[0])
    duplicate["id"] = "live-" + uuid4().hex
    duplicate["findings"][0]["finding"]["id"] = "arbitrary-source-id"
    duplicate["findings"][0]["score"]["risk"] = 51
    original = copy.deepcopy(cases + [duplicate])
    result = assessment.evaluate(inventory, "office", cases + [duplicate], truth())
    assert cases + [duplicate] == original  # Evaluator is pure.
    assert len(result["findings"]) == 5
    row = next(row for row in result["findings"] if len(row["case_ids"]) == 2)
    assert row["score"]["risk"] == 30
    assert [item["score"]["risk"] for item in row["score_observations"]] == [30, 51]
    assert "duplicate_finding_scores_differ" in result["warnings"]


class Lab:
    def __init__(self, root, inventory):
        self.root, self.inventory = root, inventory
        self.lock = threading.Lock()
        self.actions = {
            action: None for actions in assessment.ACTIONS.values() for action in actions
        }
        self.calls, self.saved = [], []
        self.profile = "baseline"
        self.after_hook = lambda: None
        self.fail = set()
        self.save_then_fail = set()
        self.control = SimpleNamespace(profile=self.runtime)
        self.traffic = SimpleNamespace(source_receipt=self.source)
        self.snapshots = 0

    def runtime(self, environment):
        self.snapshots += 1
        if self.snapshots == 2:
            self.after_hook()
        return {
            "status": "verified",
            "profile": self.profile,
            "policy_sha256": self.inventory["sources"]["config/network-services.json"],
            "after": {
                "project": assessment.PROJECT,
                "id": "a" * 64,
                "image_id": "sha256:" + "b" * 64,
                "access_profile": self.profile,
                "network_id": "c" * 64,
                "network_namespace": 123,
                "private_ip": "172.30.41.2" if environment == "office" else "172.30.42.2",
            },
        }

    def source(self, environment):
        return {
            "available": True,
            "container_id": "a" * 64,
            "source_sha256": self.inventory["sources"][f"labs/service_networks/{environment}.py"],
        }

    def _operation(self, environment, action, *, kind):
        assert self.lock.locked() and kind == "full_assessment"
        self.calls.append((environment, action))
        if action in self.fail:
            raise RuntimeError("DO_NOT_RETAIN_SECRET")
        row = case(self.inventory, environment, action, self.profile)
        self.saved.insert(0, row)
        if action in self.save_then_fail:
            row["policy_error"] = "owner policy changed"
            raise ConfigError("Saved partial case")
        return row

    def history(self, environment):
        return [row for row in self.saved if row["environment"] == environment]


@pytest.fixture
def lab(tmp_path, inventory):
    shutil.copytree(ROOT / "config", tmp_path / "config")
    for source in assessment.SOURCES:
        destination = tmp_path / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source, destination)
    path = tmp_path / "labs/service_networks/expectations.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")
    return Lab(tmp_path, inventory)


@pytest.mark.parametrize("environment,count", [("office", 7), ("iot", 6)])
def test_run_persists_agreed_ui_contract_and_fixed_full_endpoint_scope(lab, environment, count):
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, environment)
    assert suite["ground_truth"]["status"] == "verified", suite["ground_truth"]
    assert suite["status"] == "recorded"
    assert len(suite["checks"]) == len(suite["cases"]) == count
    assert lab.calls == [(environment, action) for action in assessment.ACTIONS[environment]]
    assert suite["coverage"]["declared_endpoints"] == count
    assert suite["coverage"]["attempted_endpoints"] == count
    assert suite["metrics"]["missed_untested"] == 0
    assert suite["evidence_url"] == f"/api/network-live/assessment/{suite['id']}.json"
    assert runner.load(suite["id"]) == suite
    assert runner.history(environment) == [suite]
    assert not lab.lock.locked()
    raw = (runner.directory / (suite["id"] + ".json")).read_bytes()
    assert len(raw) < assessment.LIMIT
    assert b"DO_NOT_DUPLICATE_PCAP" not in raw and b'"packets"' not in raw
    assert not list(runner.directory.glob("*.tmp"))
    assert all(row["case_id"] for row in suite["checks"])


@pytest.mark.parametrize(
    "issue",
    [
        "unavailable",
        "source_tamper",
        "wrong_container",
        "host_source",
        "policy",
        "profile",
        "image",
    ],
)
def test_source_runtime_or_policy_drift_is_a_normal_saved_unverified_suite(lab, issue):
    if issue == "unavailable":
        lab.traffic.source_receipt = lambda _: {"available": False}
    elif issue in {"source_tamper", "wrong_container"}:
        original = lab.source

        def changed(environment):
            result = original(environment)
            result["source_sha256" if issue == "source_tamper" else "container_id"] = "d" * 64
            return result

        lab.traffic.source_receipt = changed
    elif issue in {"host_source", "policy"}:
        path = lab.root / (
            "labs/service_networks/office.py"
            if issue == "host_source"
            else "config/network-services.json"
        )
        lab.after_hook = lambda: path.write_bytes(path.read_bytes() + b"\n")
    elif issue == "profile":
        lab.after_hook = lambda: setattr(lab, "profile", "restricted")
    else:
        original = lab.runtime

        def runtime(environment):
            result = original(environment)
            if lab.snapshots == 2:
                result["after"]["image_id"] = "sha256:" + "e" * 64
            return result

        lab.control.profile = runtime
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, "office")
    assert suite["ground_truth"]["status"] == "unverified"
    assert suite["ground_truth"]["issues"]
    assert suite["metrics"] is None
    assert len(suite["findings"]) == 5
    assert runner.load(suite["id"]) == suite


def test_operation_exceptions_continue_and_saved_failed_case_ids_are_recovered(lab):
    lab.fail = {"ftp-anonymous"}
    lab.save_then_fail = {"ssh-credential"}
    suite = assessment.LabAssessment(lab.root).run(lab, "office")
    assert len(lab.calls) == 7
    assert suite["status"] == "partial"
    checks = {row["action"]: row for row in suite["checks"]}
    assert checks["ftp-anonymous"]["state"] == "failed"
    assert checks["ftp-anonymous"]["case_id"] is None
    assert checks["ssh-credential"]["state"] == "failed"
    assert checks["ssh-credential"]["case_id"] is not None
    assert suite["metrics"]["missed_untested"] == 2
    assert suite["metrics"]["false_negative"] == 0
    assert "DO_NOT_RETAIN_SECRET" not in json.dumps(suite)


def test_unsupported_declared_actions_and_policy_endpoints_remain_skipped(lab):
    del lab.actions["ftp-protected"]
    path = lab.root / "config/network-services.json"
    policy = json.loads(path.read_bytes())
    policy["targets"]["127.0.0.2"].append(
        {"port": 2999, "transport": "tcp", "service": "ftp", "require_auth": True}
    )
    path.write_text(json.dumps(policy), encoding="utf-8")
    suite = assessment.LabAssessment(lab.root).run(lab, "office")
    check = next(row for row in suite["checks"] if row["action"] == "ftp-protected")
    assert check["state"] == "skipped" and check["error"] == "operation_unsupported"
    endpoint = next(row for row in suite["endpoints"] if row["port"] == 2999)
    assert endpoint["state"] == "skipped" and endpoint["action"] is None
    assert suite["coverage"]["declared_endpoints"] == 8
    check = next(row for row in suite["checks"] if row["port"] == 2999)
    assert check["state"] == "skipped" and check["case_id"] is None
    assert check["error"] == "operation_unsupported"
    assert suite["coverage"]["attempted_endpoints"] == 6


def test_busy_lock_rejects_immediately_and_never_dispatches(lab):
    lab.lock.acquire()
    try:
        with pytest.raises(ConfigError, match="already running"):
            assessment.LabAssessment(lab.root).run(lab, "office")
    finally:
        lab.lock.release()
    assert not lab.calls


@pytest.mark.parametrize("environment", ["elsewhere", "../office", "OFFICE", None, [], {}])
def test_invalid_environment_cannot_dispatch_or_list(lab, environment):
    runner = assessment.LabAssessment(lab.root)
    with pytest.raises(ConfigError):
        runner.run(lab, environment)
    with pytest.raises(ConfigError):
        runner.history(environment)
    assert not lab.calls


def test_scope_revocation_cannot_dispatch(lab):
    path = lab.root / "config/scope.yaml"
    path.write_text("allowed_hosts: [127.0.0.1]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="not authorised"):
        assessment.LabAssessment(lab.root).run(lab, "office")
    assert not lab.calls


@pytest.mark.parametrize(
    "identifier",
    ["../full-" + "a" * 32, "full-" + "A" * 32, "live-" + "a" * 32, "full-" + "a" * 33, None, []],
)
def test_load_accepts_only_exact_suite_id(lab, identifier):
    with pytest.raises(ConfigError):
        assessment.LabAssessment(lab.root).load(identifier)


def test_tampered_checksum_and_duplicate_keys_are_refused(lab):
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, "office")
    path = runner.directory / (suite["id"] + ".json")
    changed = copy.deepcopy(suite)
    changed["metrics"]["true_positive"] = 99
    path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ConfigError, match="changed"):
        runner.load(suite["id"])
    path.write_text('{"id":"x","id":"y"}', encoding="utf-8")
    with pytest.raises(ConfigError):
        runner.load(suite["id"])
    assert runner.history("office") == []


def test_one_mib_load_and_save_budget_and_failure_release_lock(lab, monkeypatch):
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, "office")
    path = runner.directory / (suite["id"] + ".json")
    path.write_bytes(b" " * (assessment.LIMIT + 1))
    with pytest.raises(ConfigError, match="budget"):
        runner.load(suite["id"])
    original = lab._operation

    def huge(*args, **kwargs):
        result = original(*args, **kwargs)
        if result["findings"]:
            result["findings"][0]["guidance"]["meaning"] = "x" * assessment.LIMIT
        return result

    monkeypatch.setattr(lab, "_operation", huge)
    with pytest.raises(ConfigError, match="budget"):
        runner.run(lab, "office")
    assert not lab.lock.locked()


def test_atomic_publication_has_a_checksum_before_destination_exists(lab, monkeypatch):
    runner = assessment.LabAssessment(lab.root)
    original = assessment.os.replace
    saved = []

    def replace(source, destination):
        assert not Path(destination).exists()
        data = json.loads(Path(source).read_bytes())
        assert data["sha256"] == assessment.checksum(data)
        saved.append(destination)
        original(source, destination)

    monkeypatch.setattr(assessment.os, "replace", replace)
    suite = runner.run(lab, "office")
    assert len(saved) == 1 and runner.load(suite["id"]) == suite


def test_symlink_evidence_and_parent_directory_are_rejected(lab):
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, "office")
    path = runner.directory / (suite["id"] + ".json")
    other = lab.root / "outside.json"
    other.write_bytes(path.read_bytes())
    path.unlink()
    try:
        path.symlink_to(other)
    except OSError:
        pytest.skip("Symlink creation needs Windows developer mode")
    with pytest.raises(ConfigError, match="local"):
        runner.load(suite["id"])


def test_invalid_inventory_is_unverified_and_never_discards_real_findings(lab):
    path = lab.root / "labs/service_networks/expectations.json"
    path.write_text('{"schema_version":999}', encoding="utf-8")
    suite = assessment.LabAssessment(lab.root).run(lab, "office")
    assert suite["metrics"] is None
    assert suite["ground_truth"]["status"] == "unverified"
    assert len(suite["findings"]) == 5
    assert len(suite["unexpected_findings"]) == 5


def test_aggregate_priority_sort_preserves_scores_and_has_canonical_tie_order(inventory):
    cases = all_cases(inventory, "office")
    for row in cases:
        for item in row["findings"]:
            item["score"]["risk"] = 42 if row["action"].startswith("smb-") else 20
    result = assessment.evaluate(inventory, "office", cases, truth())
    findings = result["findings"]
    assert [row["score"]["risk"] for row in findings] == [42, 42, 42, 20, 20]
    assert [row["uid"] for row in findings[:3]] == sorted(row["uid"] for row in findings[:3])
    assert [row["uid"] for row in findings[3:]] == sorted(row["uid"] for row in findings[3:])


def test_progress_publishes_per_action_snapshots_and_resets_after_run(lab):
    runner = assessment.LabAssessment(lab.root)
    original = lab._operation
    snapshots = []

    def observe(environment, action, **kwargs):
        snapshots.append(runner.progress)
        assert runner.progress["running"] is True
        assert runner.progress["environment"] == environment
        assert runner.progress["action"] == action
        return original(environment, action, **kwargs)

    lab._operation = observe
    assert runner.progress["running"] is False
    runner.run(lab, "office")
    assert [row["completed"] for row in snapshots] == list(range(7))
    assert all(row["total"] == 7 and row["running"] for row in snapshots)
    assert runner.progress == {
        "running": False,
        "environment": "office",
        "completed": 7,
        "total": 7,
        "action": None,
    }


def test_progress_is_reset_and_lock_released_when_persistence_fails(lab, monkeypatch):
    runner = assessment.LabAssessment(lab.root)

    def failure(_suite):
        raise ConfigError("Assessment evidence directory unavailable")

    monkeypatch.setattr(runner, "_save", failure)
    with pytest.raises(ConfigError):
        runner.run(lab, "iot")
    assert runner.progress["running"] is False
    assert not lab.lock.locked()


def test_redis_exchange_without_identity_is_inconclusive_not_complete(lab):
    original = lab._operation

    def denied(environment, action, **kwargs):
        row = original(environment, action, **kwargs)
        if action.startswith("redis-"):
            row["result"]["proof"]["identity_established"] = False
        return row

    lab._operation = denied
    suite = assessment.LabAssessment(lab.root).run(lab, "office")
    assert suite["checks"][-1]["state"] == "inconclusive"
    assert (
        suite["endpoints"][-1]["state"] == "untested"
        or next(row for row in suite["endpoints"] if row["service"] == "redis")["state"]
        == "untested"
    )
    assert suite["metrics"]["true_positive"] == 5
    assert suite["status"] == "partial"


def test_malformed_protocol_proof_is_retained_as_untested_and_next_checks_continue(lab):
    original = lab._operation

    def malformed(environment, action, **kwargs):
        row = original(environment, action, **kwargs)
        if action == "ftp-anonymous":
            row["result"]["proof"] = None
        return row

    lab._operation = malformed
    suite = assessment.LabAssessment(lab.root).run(lab, "office")
    assert len(lab.calls) == 7
    assert suite["metrics"]["missed_untested"] == 1
    assert suite["metrics"]["false_negative"] == 0
    assert suite["checks"][0]["state"] == "inconclusive"


def test_unverified_control_receipt_never_credits_ground_truth(lab):
    lab.control.profile = lambda _: {"status": "failed", "error": "docker_unavailable"}
    suite = assessment.LabAssessment(lab.root).run(lab, "office")
    assert suite["metrics"] is None
    assert "runtime_profile_unverified:before" in suite["ground_truth"]["issues"]
    assert len(suite["findings"]) == 5


def test_checksum_valid_but_incomplete_record_cannot_break_history(lab):
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, "office")
    del suite["finished_at"]
    suite["sha256"] = assessment.checksum(suite)
    path = runner.directory / (suite["id"] + ".json")
    path.write_text(json.dumps(suite), encoding="utf-8")
    with pytest.raises(ConfigError):
        runner.load(suite["id"])
    assert runner.history("office") == []


def test_symlink_guard_is_exercised_without_windows_symlink_privileges(lab, monkeypatch):
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, "office")
    path = runner.directory / (suite["id"] + ".json")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == path or original(self))
    with pytest.raises(ConfigError, match="local"):
        runner.load(suite["id"])


def test_history_selects_newest_by_mtime_before_the_200_read_budget(lab, monkeypatch):
    runner = assessment.LabAssessment(lab.root)
    newest = runner.run(lab, "office")
    latest_path = runner.directory / (newest["id"] + ".json")
    older_paths = []
    for index in range(200):
        older = {**newest, "id": f"full-{index:032x}", "finished_at": "2020-01-01T00:00:00+00:00"}
        older["sha256"] = assessment.checksum(older)
        path = runner.directory / (older["id"] + ".json")
        path.write_text(json.dumps(older), encoding="utf-8")
        assessment.os.utime(path, ns=(2_000_000_000_000 + index, 2_000_000_000_000 + index))
        older_paths.append(path)
    assessment.os.utime(latest_path, ns=(3_000_000_000_000, 3_000_000_000_000))
    original_glob = Path.glob

    def glob(path, pattern):
        if path == runner.directory and pattern == "full-*.json":
            return iter([*older_paths, latest_path])
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", glob)
    original_load = runner.load
    loaded = []

    def load(identifier):
        loaded.append(identifier)
        return original_load(identifier)

    monkeypatch.setattr(runner, "load", load)
    history = runner.history("office")
    assert history[0]["id"] == newest["id"]
    assert loaded[0] == newest["id"]
    assert len(loaded) == 200
    assert len(history) == 12


@pytest.mark.parametrize("environment", ["office", "iot"])
def test_stable_unreviewed_image_with_matching_source_withholds_metrics(lab, environment):
    original = lab.runtime

    def different_image(name):
        result = original(name)
        # Launcher or dependency changed, while env.py, profile, IDs, policy,
        # network namespace and image identity across the run all stay stable.
        result["after"]["image_id"] = "sha256:" + "d" * 64
        return result

    lab.control.profile = different_image
    runner = assessment.LabAssessment(lab.root)
    suite = runner.run(lab, environment)
    assert suite["ground_truth"]["status"] == "unverified"
    assert suite["ground_truth"]["reviewed_image_id"] == "sha256:" + "b" * 64
    assert suite["metrics"] is None
    assert "runtime_image_not_reviewed:before" in suite["ground_truth"]["issues"]
    assert "runtime_image_not_reviewed:after" in suite["ground_truth"]["issues"]
    assert not any(issue.startswith("runtime_drift:") for issue in suite["ground_truth"]["issues"])
    runtime = suite["runtime"]
    assert runtime["before"]["after"]["image_id"] == runtime["after"]["after"]["image_id"]
    assert runtime["source_before"]["source_sha256"] == runtime["source_after"]["source_sha256"]
    assert runtime["source_before"]["available"] is True
    assert len(suite["findings"]) == (5 if environment == "office" else 4)
    assert runner.load(suite["id"]) == suite


@pytest.mark.parametrize(
    "pin",
    [
        None,
        "",
        12,
        "b" * 64,
        "vulnassess-service-networks:local",
        "sha256:" + "B" * 64,
        "sha256:" + "b" * 63,
        "sha256:" + "b" * 64 + "\n",
    ],
)
def test_invalid_reviewed_image_pin_rejects_inventory_but_retains_suite_findings(lab, pin):
    invalid = copy.deepcopy(lab.inventory)
    spec = invalid["environments"]["office"]
    if pin is None:
        del spec["reviewed_image_id"]
    else:
        spec["reviewed_image_id"] = pin
    with pytest.raises(ValueError, match="immutable image"):
        assessment._validate_inventory(invalid)
    (lab.root / "labs/service_networks/expectations.json").write_text(
        json.dumps(invalid), encoding="utf-8"
    )
    suite = assessment.LabAssessment(lab.root).run(lab, "office")
    assert suite["ground_truth"]["status"] == "unverified"
    assert "reviewed_image_unavailable" in suite["ground_truth"]["issues"]
    assert suite["metrics"] is None
    assert len(suite["findings"]) == 5
    assert len(lab.calls) == 7


def test_pure_evaluation_cannot_credit_unbound_reviewed_image_truth(inventory):
    checked = truth()
    checked["reviewed_image_id"] = "sha256:" + "d" * 64
    result = assessment.evaluate(inventory, "office", all_cases(inventory, "office"), checked)
    assert result["metrics"] is None
    assert len(result["findings"]) == 5

"""Pure planning/approval tests; no scanner or model service is contacted."""

import copy
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnassess import live_assessment, scan_plans
from vulnassess.ai_boundary import INJECTION_SENTINEL, digest
from vulnassess.errors import ConfigError, NeedsReview
from vulnassess.schema import Host, Service
from vulnassess.settings import Settings


def context(web=False):
    return {
        "target_ip": "172.28.0.12",
        "submitted": "http://172.28.0.12:80/" if web else "172.28.0.12",
        "scope_hash": "scope-v1",
        "evidence": [{"id": "E1", "text": "Approved baseline: light service discovery"}],
        "endpoints": {"E2": {"host": "172.28.0.12", "scheme": "http", "port": 80, "path": "/"}}
        if web
        else {},
    } | (
        {
            "evidence": [
                {"id": "E1", "text": "Approved baseline: light service discovery"},
                {"id": "E2", "text": "Prior run observed 80/tcp http"},
            ]
        }
        if web
        else {}
    )


def answer(web=False):
    steps = [
        {
            "tool": "nmap",
            "profile": "nmap_light",
            "timeout_seconds": 180,
            "endpoint_evidence_id": None,
            "reason": "Refresh service discovery",
            "confidence": 0.8,
        }
    ]
    if web:
        steps.append(
            {
                "tool": "nikto",
                "profile": "nikto_web_bounded",
                "timeout_seconds": 150,
                "endpoint_evidence_id": "E2",
                "reason": "Inspect the previously observed web tier",
                "confidence": 0.8,
            }
        )
    evidence = context(web)["evidence"]
    claims = [
        {
            "path": f"steps[{index}].reason",
            "label": "inferred",
            "evidence_ids": [evidence[index]["id"]],
            "quotes": [{"evidence_id": evidence[index]["id"], "text": evidence[index]["text"]}],
            "finding_ids": [],
            "confidence": 0.8,
            "verification_action": None,
            "score": None,
        }
        for index in range(len(steps))
    ]
    return {
        "schema_version": "scan_plan.v1",
        "target_ip": "172.28.0.12",
        "steps": steps,
        "claims": claims,
    }


class Model:
    model = "synthetic-planner"
    source = "synthetic-provider"

    def __init__(self, reply, canary=False):
        self.reply, self.canary = reply, canary

    def available(self):
        return True

    def generate_structured(self, prompt, schema, **options):
        assert "untrusted data follows" in prompt
        assert "scan_plan.v1" in json.dumps(schema)
        if self.canary:
            options["on_raw"](INJECTION_SENTINEL.encode())
        options["on_raw"](json.dumps(self.reply).encode())
        return copy.deepcopy(self.reply)


@pytest.mark.parametrize("web", [False, True])
def test_planner_proposes_baseline_or_observed_web_tier_and_audits(tmp_path, web):
    source = context(web)
    original = copy.deepcopy(source)
    plan = scan_plans.propose(source, Model(answer(web)), tmp_path / "audit.jsonl")
    assert [step["tool"] for step in plan["steps"]] == (["nmap", "nikto"] if web else ["nmap"])
    assert source == original
    audit = json.loads((tmp_path / "audit.jsonl").read_text())
    assert audit["outcome"] == "validated"
    assert all(audit[key] for key in ("model", "prompt_hash", "input_hash", "output_hash"))


@pytest.mark.parametrize(
    "change", ["target", "flags", "cve", "quote", "schema", "score", "timeout", "evidence"]
)
def test_invalid_proposals_never_become_drafts(tmp_path, change):
    reply = answer()
    if change == "target":
        reply["target_ip"] = "172.28.0.250"
    if change == "flags":
        reply["steps"][0]["flags"] = "--script all"
    if change == "cve":
        reply["steps"][0]["reason"] = "Confirm CVE-2099-99999"
    if change == "quote":
        reply["claims"][0]["quotes"][0]["text"] = "invented observation"
    if change == "schema":
        reply["schema_version"] = "invented.v1"
    if change == "score":
        reply["claims"][0]["score"] = 100
    if change == "timeout":
        reply["steps"][0]["timeout_seconds"] = True
    if change == "evidence":
        reply["claims"][0]["evidence_ids"] = ["E999"]
    with pytest.raises(NeedsReview):
        scan_plans.propose(context(), Model(reply), tmp_path / "audit.jsonl")
    audit = json.loads((tmp_path / "audit.jsonl").read_text())
    assert audit["decision"] == "reject" and audit["outcome"] == "needs_review"


def test_canary_cannot_be_hidden_by_clean_planner_capture(tmp_path):
    with pytest.raises(NeedsReview, match="canary"):
        scan_plans.propose(context(), Model(answer(), True), tmp_path / "audit.jsonl")


def registry(tmp_path, clock=None):
    return scan_plans.PlanRegistry(tmp_path / "audit.jsonl", clock=clock or (lambda: 10.0))


def test_plan_requires_approval_and_hash_before_execution(tmp_path):
    plans = registry(tmp_path)
    draft = plans.create(answer(), context())
    with pytest.raises(ConfigError, match="approval"):
        plans.claim(draft["plan_id"], draft["plan_hash"], context())
    approved = plans.approve(draft["plan_id"], draft["plan_hash"])
    assert approved["state"] == "approved"
    execution = plans.claim(draft["plan_id"], draft["plan_hash"], context())
    assert execution.before("nmap", "172.28.0.12", "scope-v1") == 180
    assert execution.finish()["state"] == "completed"


def test_edit_invalidates_old_approval_and_cannot_mutate_target(tmp_path):
    plans = registry(tmp_path)
    draft = plans.create(answer(), context())
    plans.approve(draft["plan_id"], draft["plan_hash"])
    edited = answer()
    edited["steps"][0]["timeout_seconds"] = 90
    changed = plans.edit(draft["plan_id"], draft["plan_hash"], edited)
    assert changed["plan_hash"] != draft["plan_hash"] and changed["state"] == "draft"
    with pytest.raises(ConfigError):
        plans.claim(draft["plan_id"], draft["plan_hash"], context())
    with pytest.raises(ConfigError, match="approval"):
        plans.claim(changed["plan_id"], changed["plan_hash"], context())
    edited["target_ip"] = "172.28.0.250"
    with pytest.raises(NeedsReview):
        plans.edit(changed["plan_id"], changed["plan_hash"], edited)


@pytest.mark.parametrize("field", ["scope_hash", "submitted", "evidence"])
def test_stale_context_refuses_execution(tmp_path, field):
    plans = registry(tmp_path)
    draft = plans.create(answer(), context())
    plans.approve(draft["plan_id"], draft["plan_hash"])
    changed = context()
    changed[field] = [] if field == "evidence" else "changed"
    with pytest.raises(ConfigError, match="changed"):
        plans.claim(draft["plan_id"], draft["plan_hash"], changed)
    with pytest.raises(ConfigError, match="approval"):
        plans.claim(draft["plan_id"], draft["plan_hash"], context())


def test_expiry_restart_replay_and_duplicate_claims_cannot_launch(tmp_path):
    now = [10.0]
    plans = registry(tmp_path, lambda: now[0])
    draft = plans.create(answer(), context())
    plans.approve(draft["plan_id"], draft["plan_hash"])

    def claim():
        try:
            return plans.claim(draft["plan_id"], draft["plan_hash"], context())
        except ConfigError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _: claim(), range(2)))
    assert sum(item is not None for item in claims) == 1
    with pytest.raises(ConfigError):
        registry(tmp_path).claim(draft["plan_id"], draft["plan_hash"], context())
    other = plans.create(answer(), context())
    now[0] += 1801
    with pytest.raises(ConfigError, match="expired"):
        plans.approve(other["plan_id"], other["plan_hash"])


def test_every_tool_rechecks_pin_scope_and_approved_order(tmp_path):
    for args in [
        ("nikto", "172.28.0.12", "scope-v1"),
        ("nmap", "172.28.0.250", "scope-v1"),
        ("nmap", "172.28.0.12", "changed"),
    ]:
        plans = registry(tmp_path)
        draft = plans.create(answer(True), context(True))
        plans.approve(draft["plan_id"], draft["plan_hash"])
        execution = plans.claim(draft["plan_id"], draft["plan_hash"], context(True))
        with pytest.raises(ConfigError):
            execution.before(*args)
        with pytest.raises(ConfigError, match="approval"):
            execution.before("nmap", "172.28.0.12", "scope-v1")
    plans = registry(tmp_path)
    draft = plans.create(answer(True), context(True))
    plans.approve(draft["plan_id"], draft["plan_hash"])
    execution = plans.claim(draft["plan_id"], draft["plan_hash"], context(True))
    execution.before("nmap", "172.28.0.12", "scope-v1")
    assert execution.finish()["state"] == "needs_reapproval"
    with pytest.raises(ConfigError, match="approval"):
        execution.before("nikto", "172.28.0.12", "scope-v1")


def test_requested_port_recheck_uses_remaining_budget_and_fresh_scope(tmp_path):
    now = [10.0]
    plans = registry(tmp_path, lambda: now[0])
    draft = plans.create(answer(True), context(True))
    plans.approve(draft["plan_id"], draft["plan_hash"])
    execution = plans.claim(draft["plan_id"], draft["plan_hash"], context(True))
    execution.before("nmap", "172.28.0.12", "scope-v1")
    now[0] += 120
    execution.recheck("nmap", "172.28.0.12", "scope-v1")
    assert execution.remaining("nmap", 90) == 60
    with pytest.raises(ConfigError, match="re-approval"):
        execution.recheck("nmap", "172.28.0.12", "changed")
    with pytest.raises(ConfigError, match="approval"):
        execution.recheck("nmap", "172.28.0.12", "scope-v1")


def test_exhausted_tool_budget_invalidates_execution(tmp_path):
    now = [10.0]
    plans = registry(tmp_path, lambda: now[0])
    draft = plans.create(answer(), context())
    plans.approve(draft["plan_id"], draft["plan_hash"])
    execution = plans.claim(draft["plan_id"], draft["plan_hash"], context())
    execution.before("nmap", "172.28.0.12", "scope-v1")
    now[0] += 180
    with pytest.raises(ConfigError, match="budget"):
        execution.remaining("nmap", 90)
    with pytest.raises(ConfigError, match="approval"):
        execution.recheck("nmap", "172.28.0.12", "scope-v1")


@pytest.mark.parametrize(
    "change", ["quotes", "quote_length", "citation_count", "verification_length"]
)
def test_plan_claims_enforce_schema_size_bounds(tmp_path, change):
    reply = answer()
    source = context()
    claim = reply["claims"][0]
    if change == "quotes":
        claim["quotes"] *= 5
    elif change == "citation_count":
        claim["evidence_ids"] *= 5
    elif change == "quote_length":
        source["evidence"][0]["text"] = "x" * 1001
        claim["quotes"][0]["text"] = "x" * 1001
    else:
        claim["verification_action"] = "x" * 1001
    with pytest.raises(NeedsReview):
        scan_plans.propose(source, Model(reply), tmp_path / "audit.jsonl")


def test_unexpected_model_failure_is_audited_and_never_returns_partial_plan(tmp_path):
    class BrokenModel(Model):
        def generate_structured(self, *args, **kwargs):
            raise ValueError("malformed JSON")

    with pytest.raises(NeedsReview, match="invalid planner response"):
        scan_plans.propose(context(), BrokenModel(answer()), tmp_path / "audit.jsonl")
    audit = json.loads((tmp_path / "audit.jsonl").read_text())
    assert audit["reason"] == "ValueError" and audit["outcome"] == "needs_review"


def test_planned_web_recheck_cannot_silently_add_a_redis_probe(tmp_path):
    # Synthetic canonical objects, mocked parser/process; no real scan or capture.
    settings = Settings(Path(__file__).resolve().parents[2] / "config")
    source = context(True)
    source.update(target_ip="127.0.0.1", scope_hash=digest(settings.raw["scope.yaml"]))
    source["endpoints"]["E2"] = {"host": "127.0.0.1", "scheme": "http", "port": 6379, "path": "/"}
    source["evidence"][1]["text"] = "Prior synthetic observation: 6379/tcp http"
    reply = answer(True)
    reply["target_ip"] = "127.0.0.1"
    reply["claims"][1]["quotes"][0]["text"] = source["evidence"][1]["text"]
    plans = registry(tmp_path)
    draft = plans.create(reply, source)
    plans.approve(draft["plan_id"], draft["plan_hash"])
    execution = plans.claim(draft["plan_id"], draft["plan_hash"], source)
    execution.before("nmap", source["target_ip"], source["scope_hash"])
    observed = Host("127.0.0.1", services=(Service(6379, "tcp", "redis"),))

    def fake_process(command, **options):
        assert options["timeout"] <= 90
        Path(command[command.index("-oX") + 1]).touch()
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(live_assessment.subprocess, "run", side_effect=fake_process),
        patch.object(live_assessment, "parse_nmap_xml", return_value=([observed], [])),
        patch.object(live_assessment.redis_probe, "run") as redis,
    ):
        _, _, status, nikto = live_assessment._scan_requested_endpoint(
            "synthetic-nmap",
            "127.0.0.1",
            source["endpoints"]["E2"],
            settings,
            tmp_path,
            Host("127.0.0.1"),
            [],
            lambda *args: None,
            execution,
        )
    assert not redis.called and status == "redis not inspected" and nikto == "not HTTP"
    assert execution.finish()["state"] == "needs_reapproval"

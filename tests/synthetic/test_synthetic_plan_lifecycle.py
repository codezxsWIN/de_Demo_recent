"""Approval lifecycle tests use synthetic proposals, no models or scanners."""

import pytest

from tests.adversarial.test_scan_plans import answer, context, registry
from vulnassess.errors import ConfigError


def approved_execution(tmp_path):
    plans = registry(tmp_path)
    draft = plans.create(answer(), context())
    plans.approve(draft["plan_id"], draft["plan_hash"])
    return plans, draft, plans.claim(draft["plan_id"], draft["plan_hash"], context())


@pytest.mark.parametrize("identity,plan_hash", [(None, "hash"), ("id", []), (1, 2)])
def test_malformed_plan_identity_is_rejected_before_lookup(tmp_path, identity, plan_hash):
    with pytest.raises(ConfigError, match="Invalid plan identity"):
        registry(tmp_path).context(identity, plan_hash)


def test_capacity_limit_recovers_only_after_drafts_expire(tmp_path):
    now = [10.0]
    plans = registry(tmp_path, clock=lambda: now[0])
    drafts = [plans.create(answer(), context()) for _ in range(32)]
    with pytest.raises(ConfigError, match="draft limit"):
        plans.create(answer(), context())
    now[0] += 1801
    fresh = plans.create(answer(), context())
    assert fresh["state"] == "draft"
    for draft in drafts:
        with pytest.raises(ConfigError, match="unavailable"):
            plans.approve(draft["plan_id"], draft["plan_hash"])


@pytest.mark.parametrize("finish", [False, True])
def test_claimed_plan_cannot_be_edited_or_reapproved(tmp_path, finish):
    plans, draft, execution = approved_execution(tmp_path)
    if finish:
        execution.before("nmap", context()["target_ip"], context()["scope_hash"])
        assert execution.finish()["state"] == "completed"
    with pytest.raises(ConfigError, match="cannot be edited"):
        plans.edit(draft["plan_id"], draft["plan_hash"], answer())
    with pytest.raises(ConfigError, match="not awaiting approval"):
        plans.approve(draft["plan_id"], draft["plan_hash"])


def test_unstarted_tool_cannot_use_requested_port_recheck(tmp_path):
    _, _, execution = approved_execution(tmp_path)
    with pytest.raises(ConfigError, match="has not started"):
        execution.recheck("nmap", context()["target_ip"], context()["scope_hash"])
    assert execution.finish()["state"] == "needs_reapproval"


def test_completed_plan_cannot_reuse_remaining_budget(tmp_path):
    _, _, execution = approved_execution(tmp_path)
    execution.before("nmap", context()["target_ip"], context()["scope_hash"])
    execution.finish()
    with pytest.raises(ConfigError, match="no longer executable"):
        execution.remaining("nmap", 90)
    with pytest.raises(ConfigError, match="no longer executable"):
        execution.recheck("nmap", context()["target_ip"], context()["scope_hash"])

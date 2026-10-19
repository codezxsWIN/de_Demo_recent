"""Read-only local evidence, failed probes, and history-hash corruption are synthetic."""

import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.test_all import WEIGHTS, make_finding, make_profile
from tests.test_capture_history import capture
from tests.test_saved_cve_case import load, saved
from vulnassess import capture_history, scoring, self_defence, visual_simulation
from vulnassess.errors import ConfigError
from vulnassess.ui import presentation


def rewrite_record(path, **changes):
    record = json.loads(path.read_text())
    core = {key: value for key, value in record.items() if key != "snapshot_hash"}
    core.update(changes)
    path.write_text(json.dumps({**core, "snapshot_hash": capture_history._hash(core)}))


@pytest.mark.parametrize(
    "field,message",
    [
        ("parent_hash", "final review"),
        ("evidence_hash", "case hash"),
        ("intelligence_hash", "intelligence hash"),
        ("result", "target does not match"),
    ],
)
def test_recomputed_receipt_hash_cannot_hide_contradictory_capture(tmp_path, field, message):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="synthetic-config")
    if field == "parent_hash":
        capture_history.save(directory, result, final=True)
        path = directory / "review-final.json"
        rewrite_record(path, parent_hash="a" * 64)
    elif field == "result":
        rewrite_record(
            directory / "review-evidence.json", result={**result, "target": "synthetic-other"}
        )
    else:
        rewrite_record(directory / "review-evidence.json", **{field: "a" * 64})
    with pytest.raises(ConfigError, match=message):
        capture_history.load(tmp_path, directory.name)


def test_invalid_manifest_shape_is_rejected_after_receipt_verification(tmp_path):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="synthetic-config")
    raw = json.dumps({"target": "self", "resolved_ip": "127.0.0.1", "files": []}).encode()
    (directory / "manifest.json").write_bytes(raw)
    rewrite_record(
        directory / "review-evidence.json", manifest_hash=hashlib.sha256(raw).hexdigest()
    )
    with pytest.raises(ConfigError, match="evidence manifest is invalid"):
        capture_history.load(tmp_path, directory.name)


def test_history_index_enforces_record_budget_without_opening_records(tmp_path, monkeypatch):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="synthetic-config")
    monkeypatch.setattr(Path, "glob", Mock(return_value=[directory] * 10001))
    with pytest.raises(ConfigError, match="index exceeds"):
        capture_history.listing(tmp_path)


@pytest.mark.parametrize(
    "failure", [OSError("synthetic missing executable"), ValueError("synthetic launch failure")]
)
def test_failed_local_protection_probe_remains_unknown(monkeypatch, failure):
    monkeypatch.setattr(self_defence.platform, "system", lambda: "Windows")
    monkeypatch.setattr(self_defence.shutil, "which", lambda _: "synthetic-powershell")
    monkeypatch.setattr(self_defence.subprocess, "run", Mock(side_effect=failure))
    result = self_defence.collect("Defender")
    assert result["checks"][0]["state"] == "unknown"
    assert result["checks"][0]["attention"] == "verify"


def test_invalid_listener_address_is_not_published(monkeypatch):
    monkeypatch.setattr(self_defence.platform, "system", lambda: "Windows")
    monkeypatch.setattr(self_defence.shutil, "which", lambda _: "synthetic-powershell")
    payload = {"Listeners": [{"port": 80, "address": "bad-address", "app": "synthetic"}]}
    monkeypatch.setattr(
        self_defence.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")),
    )
    assert self_defence.collect()["listeners"] == []


def test_remote_listener_correlation_and_unknown_control_have_explicit_actions():
    remote = {
        "id": "RemoteDesktop",
        "title": "Remote desktop",
        "state": "enabled",
        "attention": "observed",
        "observation": "Synthetic enabled",
        "precaution": "Review remote access",
    }
    unknown = {
        "id": "Defender",
        "title": "Defender",
        "state": "unknown",
        "attention": "verify",
        "precaution": "Review Defender",
    }
    actions = self_defence.prioritize(
        {
            "checks": [remote, unknown],
            "active_profiles": ["Public"],
            "listeners": [{"port": 3389, "binding": "network interface; reachability unverified"}],
        }
    )
    assert any(row["basis"] == ["RemoteDesktop", "listeners"] for row in actions)
    assert any(row["basis"] == ["Defender"] and row["kind"] == "not verified" for row in actions)


@pytest.mark.parametrize("mode", ["large", "bad_json", "wrong_check", "naive_time"])
def test_local_recheck_ignores_invalid_history_and_orders_valid_observations(tmp_path, mode):
    observation = {
        "checked_at": "2026-10-11T10:00:00",
        "checks": [{"id": "Defender", "state": "enabled"}],
    }
    raw = json.dumps(observation, sort_keys=True, ensure_ascii=True).encode()
    previous = {
        "target": "127.0.0.1",
        "observation": observation,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    path = tmp_path / "synthetic_prior.json"
    if mode == "large":
        path.write_bytes(b"x" * 65537)
    elif mode == "bad_json":
        path.write_text("{")
    else:
        if mode == "wrong_check":
            observation["checks"][0]["id"] = "Public"
            previous["sha256"] = hashlib.sha256(
                json.dumps(observation, sort_keys=True, ensure_ascii=True).encode()
            ).hexdigest()
        path.write_text(json.dumps(previous))
    result = self_defence.save_recheck(
        tmp_path,
        {
            "checked_at": "2026-10-11T11:00:00+00:00",
            "checks": [{"id": "Defender", "state": "unknown"}],
        },
    )
    assert len(result["history"]) == (2 if mode == "naive_time" else 1)
    assert result["history"][0]["state"] == "unknown"


@pytest.mark.parametrize("mode", ["large", "malformed_manifest"])
def test_previous_device_capture_does_not_trust_unreadable_evidence(tmp_path, mode):
    directory = tmp_path / "assessment-synthetic"
    directory.mkdir()
    device = directory / "device-check.json"
    device.write_bytes(b"x" * (65537 if mode == "large" else 1))
    (directory / "manifest.json").write_text("{")
    assert self_defence.previous_capture(tmp_path) is None


@pytest.mark.parametrize("mode", ["not_directory", "symlink_file"])
def test_saved_case_rejects_invalid_capture_locations(tmp_path, monkeypatch, mode):
    directory = saved(tmp_path)
    if mode == "not_directory":
        monkeypatch.setattr(Path, "is_dir", lambda self: self != directory)
        message = "No verified saved CVE"
    else:
        monkeypatch.setattr(Path, "is_symlink", lambda self: self == directory / "case.json")
        message = "stay in its capture directory"
    with pytest.raises(ConfigError, match=message):
        load(tmp_path)


def test_legacy_simulation_keeps_target_data_as_escaped_content():
    document = visual_simulation._render_legacy({"run_id": "<SYNTHETIC>", "note": "</script>"})
    assert "&lt;SYNTHETIC&gt;" in document
    assert "\\u003c/script\\u003e" in document
    assert "https://" not in document


def test_presentation_discloses_uncomparable_and_native_fallback_scores():
    assert presentation._delta({"base_score": None, "env_score": 0}) == "Not comparable"
    title = presentation._finding_title({"title": "<SYNTHETIC>", "tool": "nmap"})
    assert "&lt;SYNTHETIC&gt;" in title
    score = scoring.score(make_finding(cve_ids=[]), None, make_profile(), (), WEIGHTS).to_json()
    waterfall = presentation._waterfall({"scores": [score]}, WEIGHTS)
    assert "Native fallback (no CVE match)" in waterfall
    assert "no CVSS or EPSS contribution was calculated" in waterfall
    assert str(score["risk"]) in waterfall

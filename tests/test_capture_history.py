"""Restart-safe review never restores execution authority or fetches evidence."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vulnassess import capture_history, live_assessment
from vulnassess.errors import ConfigError
from vulnassess.store import Store
from vulnassess.ui.server import UiApplication


def capture(tmp_path):
    directory = tmp_path / "assessment-synthetic"
    directory.mkdir()
    payload = {
        "hosts": [{"ip": "127.0.0.1", "services": []}],
        "findings": [],
        "scores": [],
        "enrichments": [],
        "context": [],
        "feeds_meta": {},
    }
    raw = json.dumps(payload).encode()
    (directory / "case.json").write_bytes(raw)
    manifest = {
        "target": "self",
        "resolved_ip": "127.0.0.1",
        "files": {"case.json": hashlib.sha256(raw).hexdigest()},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = {
        "target": "self",
        "resolved_ip": "127.0.0.1",
        "scan_status": "complete",
        "ai_status": "not_attempted",
        "analyst": None,
        "ai_attempts": [],
        "assessment_summary": {"conclusion": "SYNTHETIC evidence-only result"},
    }
    return directory, result


def test_evidence_checkpoint_survives_restart_and_final_is_additive(tmp_path):
    directory, result = capture(tmp_path)
    first = capture_history.save(directory, result, config_hash="config-at-scan")
    before = (directory / "review-evidence.json").read_bytes()
    reopened = capture_history.load(tmp_path, directory.name)
    assert reopened["snapshot_hash"] == first["snapshot_hash"]
    assert reopened["read_only"] is True
    assert reopened["configuration_hash"] == "config-at-scan"
    assert reopened["analysis_attempted_at"] is None
    final = capture_history.save(directory, {**result, "ai_status": "unavailable"}, final=True)
    assert (directory / "review-evidence.json").read_bytes() == before
    assert final["parent_hash"] == first["snapshot_hash"]
    assert final["evidence_hash"] == first["evidence_hash"]
    assert final["intelligence_hash"] == first["intelligence_hash"]
    assert capture_history.load(tmp_path, directory.name)["result"]["ai_status"] == "unavailable"
    with pytest.raises(ConfigError, match="already exists"):
        capture_history.save(directory, result, final=True)


@pytest.mark.parametrize(
    "filename", ["case.json", "manifest.json", "review-evidence.json", "review-final.json"]
)
def test_tampered_capture_refuses_review(tmp_path, filename):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="config")
    capture_history.save(directory, {**result, "ai_status": "unavailable"}, final=True)
    (directory / filename).write_text("{}", encoding="utf-8")
    with pytest.raises(ConfigError):
        capture_history.load(tmp_path, directory.name)


@pytest.mark.parametrize(
    "identity", ["../assessment-other", "C:/private", "assessment-../x", "", ".."]
)
def test_history_rejects_arbitrary_paths(tmp_path, identity):
    with pytest.raises(ConfigError):
        capture_history.load(tmp_path, identity)


def test_review_never_serializes_execution_approvals(tmp_path):
    directory, result = capture(tmp_path)
    result.update(scan_plan={"approved": True}, approval_token="SYNTHETIC_DO_NOT_SAVE")
    saved = capture_history.save(directory, result, config_hash="config")
    assert "SYNTHETIC_DO_NOT_SAVE" not in json.dumps(saved)
    assert "scan_plan" not in saved["result"]


@pytest.mark.parametrize(
    "ai_status", ["unavailable", "needs_review", "interrupted", "save_failure"]
)
def test_live_capture_reopens_after_application_restart_without_provider_or_scanner(
    tmp_path, monkeypatch, ai_status
):
    config = tmp_path / "config"
    shutil.copytree(Path(__file__).resolve().parents[1] / "config", config)
    database = tmp_path / "store.db"
    with Store(database):
        pass

    def nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun start="1"><host><status state="up"/>'
            '<address addr="45.33.32.156" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh" product="SYNTHETIC"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "nmap")
    monkeypatch.setattr(live_assessment.subprocess, "run", nmap)

    def analyze(*args, **kwargs):
        if ai_status == "interrupted":
            raise RuntimeError("SYNTHETIC interrupted analysis")
        return {"analyst": None, "ai_status": ai_status, "ai_attempts": []}

    monkeypatch.setattr(live_assessment.analyst, "analyze_optional", analyze)
    if ai_status == "save_failure":

        def fail_save(*args, **kwargs):
            raise OSError("SYNTHETIC disk failure")

        monkeypatch.setattr(capture_history, "save", fail_save)
        monkeypatch.setattr(
            live_assessment.analyst,
            "analyze_optional",
            lambda *args, **kwargs: {
                "analyst": None,
                "ai_status": "unavailable",
                "ai_attempts": [],
            },
        )

    def run():
        return live_assessment.run(
            "scanme.nmap.org",
            {"status": "ready", "resolved_ips": ["45.33.32.156"]},
            config,
            provider="ollama",
            on_progress=lambda *args: None,
            database=database,
        )

    if ai_status == "save_failure":
        result = run()
        assert result["scan_status"] == "complete"
        assert result["saved_assessment"]["status"] == "unavailable"
        assert "could not be saved" in result["assessment_summary"]["persistence_warning"]
        assert "saved_capture_id" not in result["assessment_summary"]
        return
    if ai_status == "interrupted":
        with pytest.raises(RuntimeError, match="interrupted"):
            run()
        identity = next((tmp_path / "data/live/raw").glob("assessment-*")).name
    else:
        identity = run()["saved_assessment"]["capture_id"]
    app = UiApplication(database, config)
    before = app.get(f"/api/captures/{identity}")
    html = app.get(f"/captures/{identity}")
    assert before.status == html.status == 200
    assert b"Evidence-only" in html.body
    if ai_status == "interrupted":
        assert b"No completed analysis recorded" in html.body
    assert json.loads(before.body)["result"]["ai_status"] == (
        "not_attempted" if ai_status == "interrupted" else ai_status
    )
    assert b"Collection completed" in html.body
    assert b"AI analysis attempted" in html.body
    assert json.loads(before.body)["payload"]["hosts"][0]["services"][0]["port"] == 22

    def forbidden(*args, **kwargs):
        raise AssertionError("Reading history must not launch a tool or provider")

    monkeypatch.setattr(live_assessment.subprocess, "run", forbidden)
    monkeypatch.setattr(live_assessment.analyst, "analyze_optional", forbidden)
    restarted = UiApplication(database, config)
    assert restarted.get(f"/api/captures/{identity}").body == before.body
    assert restarted.get(f"/captures/{identity}").body == html.body
    assert restarted._recent_live_cases == restarted._last_live_scan == {}
    assert restarted.scan_plans._plans == {}
    assert restarted.evidence_requests._records == {}
    assert json.loads(restarted.get("/api/captures").body)["total"] == 1
    assert b"Saved assessments" in restarted.get("/captures").body


def test_listing_paginates_and_discloses_corrupt_metadata(tmp_path):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="config")
    assert capture_history.listing(tmp_path)["total"] == 1
    assert capture_history.listing(tmp_path, 2)["captures"] == []
    (directory / "review-evidence.json").write_text("{}", encoding="utf-8")
    assert capture_history.listing(tmp_path)["captures"][0]["status"] == "needs_review"
    with pytest.raises(ConfigError):
        capture_history.listing(tmp_path, -1)


def test_failed_atomic_publication_leaves_evidence_checkpoint_usable(tmp_path, monkeypatch):
    directory, result = capture(tmp_path)
    baseline = capture_history.save(directory, result, config_hash="config")

    def failure(*args):
        raise OSError("SYNTHETIC disk failure")

    monkeypatch.setattr(capture_history.os, "link", failure)
    with pytest.raises(OSError):
        capture_history.save(directory, result, final=True)
    assert not (directory / "review-final.json").exists()
    assert not list(directory.glob("*.tmp"))
    assert (
        capture_history.load(tmp_path, directory.name)["snapshot_hash"] == baseline["snapshot_hash"]
    )


def test_review_escapes_scanner_and_ai_text(tmp_path):
    from vulnassess.ui import capture_review

    directory, result = capture(tmp_path)
    result["assessment_summary"]["conclusion"] = '<script>alert("SYNTHETIC")</script>'
    capture_history.save(directory, result, config_hash="config")
    document = capture_review.review(capture_history.load(tmp_path, directory.name))
    assert "<script>" not in document
    assert "&lt;script&gt;" in document
    assert 'tabindex="-1"' in document


def test_unknown_schema_is_rejected_even_with_recomputed_hash(tmp_path):
    directory, result = capture(tmp_path)
    saved = capture_history.save(directory, result, config_hash="config")
    core = {key: value for key, value in saved.items() if key != "snapshot_hash"}
    core["schema_version"] = 999
    (directory / "review-evidence.json").write_text(
        json.dumps({**core, "snapshot_hash": capture_history._hash(core)}), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="schema"):
        capture_history.load(tmp_path, directory.name)


def test_manifest_cannot_redirect_reads_outside_capture(tmp_path):
    directory, result = capture(tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"]["../private.json"] = "SYNTHETIC"
    (directory / "manifest.json").write_text(json.dumps(manifest))
    capture_history.save(directory, result, config_hash="config")
    with pytest.raises(ConfigError, match="filename"):
        capture_history.load(tmp_path, directory.name)


def test_later_capture_cannot_change_recorded_scores_intelligence_or_report(tmp_path):
    from vulnassess.ui import capture_review

    directory, result = capture(tmp_path)
    payload = json.loads((directory / "case.json").read_text())
    payload.update(
        findings=[{"id": "synthetic-f1", "title": "SYNTHETIC finding"}],
        scores=[{"finding_id": "synthetic-f1", "risk": 42, "band": "Medium"}],
        enrichments=[{"finding_id": "synthetic-f1", "epss": 0.2}],
        feeds_meta={"epss": {"file_date": "2026-10-01"}},
    )
    raw = json.dumps(payload).encode()
    (directory / "case.json").write_bytes(raw)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"]["case.json"] = hashlib.sha256(raw).hexdigest()
    (directory / "manifest.json").write_text(json.dumps(manifest))
    capture_history.save(directory, result, config_hash="original-config")
    before = capture_history.load(tmp_path, directory.name)
    document = capture_review.review(before)
    later_root = tmp_path / "later"
    later_root.mkdir()
    later, _ = capture(later_root)
    later.rename(tmp_path / "assessment-later")
    capture_history.save(tmp_path / "assessment-later", result, config_hash="changed-config")
    after = capture_history.load(tmp_path, directory.name)
    assert after == before
    assert capture_review.review(after) == document
    assert after["payload"]["scores"][0]["risk"] == 42
    assert after["payload"]["enrichments"][0]["epss"] == 0.2


def test_review_rejects_symlink_files_and_oversized_records(tmp_path, monkeypatch):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="config")
    original = Path.is_symlink
    with monkeypatch.context() as changed:
        changed.setattr(
            Path, "is_symlink", lambda path: path.name == "review-evidence.json" or original(path)
        )
        with pytest.raises(ConfigError, match="leaves"):
            capture_history.load(tmp_path, directory.name)
    monkeypatch.setattr(capture_history, "MAX_BYTES", 4)
    with pytest.raises(ConfigError, match="budget"):
        capture_history.load(tmp_path, directory.name)


def test_inconsistent_intelligence_hash_is_rejected(tmp_path):
    directory, result = capture(tmp_path)
    saved = capture_history.save(directory, result, config_hash="config")
    core = {key: value for key, value in saved.items() if key != "snapshot_hash"}
    core["intelligence_hash"] = "different-intelligence"
    (directory / "review-evidence.json").write_text(
        json.dumps({**core, "snapshot_hash": capture_history._hash(core)}), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="intelligence"):
        capture_history.load(tmp_path, directory.name)

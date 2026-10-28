import json
import subprocess
from pathlib import Path

import pytest

from vulnassess import capture_history, cve_discovery, live_assessment, role_model
from vulnassess.errors import ConfigError

ROOT = Path(__file__).resolve().parents[1]


def test_live_shadow_prediction_is_retained_and_does_not_change_canonical_results(tmp_path, monkeypatch):
    original_mkdtemp = live_assessment.mkdtemp
    monkeypatch.setattr(live_assessment, "mkdtemp", lambda *, prefix, dir: original_mkdtemp(prefix=prefix, dir=tmp_path))
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "nmap")

    def scan(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/><address addr="45.33.32.156" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="3306"><state state="open"/>'
            '<service name="mysql" product="MySQL Server"/></port></ports></host></nmaprun>', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(live_assessment.subprocess, "run", scan)
    monkeypatch.setattr(cve_discovery, "discover", lambda *args, **kwargs: ([], {"queries": [], "services_skipped": []}))
    monkeypatch.setattr(live_assessment.analyst, "analyze_optional", lambda *args, **kwargs: {"analyst": None, "ai_status": "unavailable", "ai_attempts": []})
    events, captures, cases = [], [], []

    def run():
        return live_assessment.run("scanme.nmap.org", {"status": "needs-pinning", "resolved_ips": ["45.33.32.156"]}, ROOT / "config", provider="ollama", on_progress=lambda *event: events.append(event), on_capture=captures.append, on_case=cases.append)

    result = run()
    shadow = result["role_model"]
    assert shadow["mode"] == "synthetic_shadow" and shadow["status"] == "complete"
    assert shadow["prediction"]["model_hash"] == role_model.load_model(ROOT / "models/synthetic-role-model.json").model_hash
    assert shadow["prediction"]["contributors"]
    assert captures[0]["role_model"] == captures[-1]["role_model"] == shadow
    assert [(s, state) for s, state, _ in events if s == "role_model"] == [("role_model", "running"), ("role_model", "complete")]
    directory = Path(result["evidence_directory"])
    saved = capture_history.load(directory.parent, directory.name)
    assert saved["result"]["role_model"] == saved["payload"]["role_model"] == shadow
    assert [item["state"] for item in saved["payload"]["role_model_events"]] == ["running", "complete"]
    assert any(stage == "role_model" for stage, _, _ in cases[0]["stage_events"])

    monkeypatch.setattr(role_model, "load_model", lambda _: (_ for _ in ()).throw(ConfigError("bad model")))
    failed = run()
    assert failed["role_model"] == {"mode": "synthetic_shadow", "status": "unavailable", "prediction": None}
    failed_case = json.loads((Path(failed["evidence_directory"]) / "case.json").read_text())
    for key in ("context", "scores", "findings"):
        assert failed_case[key] == saved["payload"][key]
    assert events[-1][0] == "report"
    assert any(s == "role_model" and state == "error" for s, state, _ in events)


def test_shadow_result_must_match_retained_evidence():
    with pytest.raises(ConfigError, match="shadow role prediction"):
        capture_history._summary_facts({"role_model": {"mode": "fake"}}, {"role_model": {"mode": "synthetic_shadow"}})

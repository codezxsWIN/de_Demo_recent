"""AI report formatting can select validated prose but cannot add or change facts."""

import copy
import json

import pytest

from tests.test_assessment_report import setup_report
from vulnassess import analyst, capture_history, report_composer
from vulnassess.ai_boundary import digest
from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.ui import assessment_report


class LayoutClient:
    model = "SYNTHETIC layout model"

    def generate_structured(self, prompt, schema, **kwargs):
        assert "do not write new claims" in prompt
        assert kwargs["num_predict"] == 1200
        return {
            "layout": "brief",
            "section_order": list(report_composer.SECTIONS),
            "executive": ["B1:executive"],
            "context": ["B1:context"],
            "actions": [],
            "investigations": [],
            "uncertainties": [],
        }


def record_and_document(tmp_path):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    document = report_composer.compose(
        record["result"]["analyst"], record["payload"], LayoutClient()
    )
    return directory, record, document


def test_ai_layout_reuses_validated_prose_and_hides_validation_appendix(tmp_path):
    _, record, document = record_and_document(tmp_path)
    before = copy.deepcopy(record)
    html = assessment_report.render(record, composition=document)
    assert "Report composed by SYNTHETIC layout model" in html
    assert '<p class="ai-executive">SYNTHETIC observed loopback service.</p>' in html
    assert (
        '<details id="ai-audit" class="report-audit"><summary>Evidence and validation appendix'
        in html
    )
    assert 'class="report-audit" open' not in html
    assert record == before


@pytest.mark.parametrize(
    "mutation", ["unknown_ref", "wrong_kind", "duplicate", "missing_executive", "section_order"]
)
def test_composition_rejects_fabricated_or_wrongly_typed_source_references(tmp_path, mutation):
    _, record, document = record_and_document(tmp_path)
    plan = document["plan"]
    if mutation == "unknown_ref":
        plan["executive"] = ["B99:executive"]
    elif mutation == "wrong_kind":
        plan["executive"] = ["B1:context"]
    elif mutation == "duplicate":
        plan["executive"] *= 2
    elif mutation == "missing_executive":
        plan["executive"] = []
    else:
        plan["section_order"] = ["actions"] * 4
    document["document_hash"] = digest(
        {key: value for key, value in document.items() if key != "document_hash"}
    )
    batches = assessment_report._validated_batches(record["result"]["analyst"], record["payload"])
    with pytest.raises(LLMUnavailable):
        report_composer.validate_document(document, batches)


def test_saved_composition_is_bound_to_source_snapshot_and_write_once(tmp_path):
    directory, record, document = record_and_document(tmp_path)
    original = (directory / "review-evidence.json").read_bytes()
    report_composer.save_saved(directory, record, document)
    assert report_composer.load_saved(directory, record) == document
    assert (directory / "review-evidence.json").read_bytes() == original
    with pytest.raises(FileExistsError):
        report_composer.save_saved(directory, record, document)
    value = json.loads((directory / "report-composition.json").read_text())
    value["source_snapshot_hash"] = "0" * 64
    (directory / "report-composition.json").write_text(json.dumps(value))
    with pytest.raises(ConfigError, match="source"):
        report_composer.load_saved(directory, record)


def test_modified_source_prose_invalidates_old_ai_layout(tmp_path):
    _, record, document = record_and_document(tmp_path)
    batches = assessment_report._validated_batches(record["result"]["analyst"], record["payload"])
    batches[0][0]["analysis"]["summary"] = "SYNTHETIC changed assessment"
    with pytest.raises(LLMUnavailable, match="source"):
        report_composer.validate_document(document, batches)


def test_composition_cannot_reverse_recorded_action_sequence():
    plan = LayoutClient().generate_structured("do not write new claims", {}, num_predict=1200)
    plan["context"] = []
    plan["actions"] = ["B1:actions:1", "B1:actions:0"]
    index = {
        "B1:executive": {"kind": "executive", "batch": 1},
        "B1:actions:0": {"kind": "actions", "batch": 1, "offset": 0},
        "B1:actions:1": {"kind": "actions", "batch": 1, "offset": 1},
    }
    with pytest.raises(LLMUnavailable, match="action order"):
        report_composer.validate_plan(plan, index)


@pytest.mark.parametrize("damage", ["json", "stale", "oversized"])
@pytest.mark.parametrize("suffix", ["report", "report/download"])
def test_optional_composition_failure_does_not_block_verified_report(tmp_path, damage, suffix):
    app, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    document = report_composer.compose(
        record["result"]["analyst"], record["payload"], LayoutClient()
    )
    report_composer.save_saved(directory, record, document)
    path = directory / "report-composition.json"
    if damage == "json":
        path.write_text("{invalid")
    elif damage == "oversized":
        path.write_bytes(b"X" * 32769)
    else:
        value = json.loads(path.read_text())
        value["source_snapshot_hash"] = "0" * 64
        path.write_text(json.dumps(value))
    response = app.get(f"/captures/{directory.name}/{suffix}")
    assert response.status == 200
    assert b"AI report composition could not be verified" in response.body
    assert b"SYNTHETIC observed loopback service." in response.body


@pytest.mark.parametrize("composition_fails", [False, True])
def test_live_analysis_composes_report_and_keeps_assessment_if_layout_provider_fails(
    tmp_path, monkeypatch, composition_fails
):
    _, record, _ = record_and_document(tmp_path)
    source = copy.deepcopy(record["result"]["analyst"])
    monkeypatch.setattr(analyst, "analyze_findings", lambda *_args, **_kwargs: source)
    monkeypatch.setattr(analyst, "provider_client", lambda _provider: LayoutClient())
    monkeypatch.setattr(analyst, "append_audit", lambda *_args: None)
    if composition_fails:

        def unavailable(*_args):
            raise LLMUnavailable("SYNTHETIC provider unavailable")

        monkeypatch.setattr(report_composer, "compose", unavailable)
    outcome = analyst.analyze_optional(record["payload"], "127.0.0.1", "google", lambda *_: None)
    assert outcome["ai_status"] == "validated"
    assert outcome["analyst"]["analysis"] == source["analysis"]
    if composition_fails:
        assert outcome["analyst"]["report_document_status"] == "unavailable"
    else:
        assert outcome["analyst"]["report_document"]["model"] == LayoutClient.model

import copy

import pytest

from vulnassess import decision_focus
from vulnassess.ai_boundary import digest
from vulnassess.assessment_derivations import derive
from vulnassess.decision_focus import VERSION, validate_document, validate_plan
from vulnassess.errors import ConfigError, LLMUnavailable


def cards():
    return [
        {
            "id": f"D{i}",
            "observations": [
                {"id": f"D{i}:O1", "text": "Scanner observation", "source": "scanner"}
            ],
            "actions": [{"id": f"D{i}:A1", "premise_ids": [f"D{i}:O1"]}],
        }
        for i in (1, 2)
    ]


def plan():
    return {
        "next_decisions": [{"derivation_id": "D1", "action_id": "D1:A1", "premise_ids": ["D1:O1"]}]
    }


def test_focus_validates_without_changing_inputs():
    c, p = cards(), plan()
    before = copy.deepcopy((c, p))
    assert validate_plan(p, c) == p
    assert (c, p) == before


@pytest.mark.parametrize(
    "mutation", ["fact", "action", "premise", "borrowed", "extra", "duplicate", "order", "empty"]
)
def test_focus_rejects_invented_facts_cross_finding_borrowing_and_priority_changes(mutation):
    c, p = cards(), plan()
    row = p["next_decisions"][0]
    if mutation == "fact":
        row["derivation_id"] = "unknown"
    elif mutation == "action":
        row["action_id"] = "D2:A1"
    elif mutation == "premise":
        row["premise_ids"] = []
    elif mutation == "borrowed":
        row["premise_ids"] = ["D2:O1"]
    elif mutation == "extra":
        row["new_risk"] = 100
    elif mutation == "duplicate":
        p["next_decisions"].append(copy.deepcopy(row))
    elif mutation == "order":
        p["next_decisions"].insert(
            0, {"derivation_id": "D2", "action_id": "D2:A1", "premise_ids": ["D2:O1"]}
        )
    else:
        p["next_decisions"] = []
    with pytest.raises(LLMUnavailable):
        validate_plan(p, c)


@pytest.mark.parametrize("changed", ["source", "input", "model", "hash", "schema"])
def test_focus_document_is_bound_to_capture_and_derivation_input(changed):
    c = cards()
    record = {"snapshot_hash": "a" * 64}
    document = {
        "schema_version": VERSION,
        "source_snapshot_hash": record["snapshot_hash"],
        "input_hash": digest(c),
        "model": "synthetic-test",
        "plan": plan(),
    }
    document["document_hash"] = digest(document)
    assert validate_document(document, record, c) == plan()
    key = {
        "source": "source_snapshot_hash",
        "input": "input_hash",
        "model": "model",
        "hash": "document_hash",
        "schema": "schema_version",
    }[changed]
    document[key] = "" if changed == "model" else "changed"
    with pytest.raises(LLMUnavailable):
        validate_document(document, record, c)


def source_record():
    from tests.test_assessment_derivations import record

    return {**record(proof=True), "snapshot_hash": "a" * 64}


class Selector:
    model = "synthetic-selection-only"

    def available(self):
        return True

    def generate_structured(self, prompt, schema, **kwargs):
        assert len(prompt.encode()) <= decision_focus.MAX_INPUT
        assert "untrusted evidence" in prompt
        assert "do not repeat an already completed probe" in prompt
        assert kwargs["num_predict"] <= 800
        fields = schema["properties"]["next_decisions"]["items"]["properties"]
        card = derive(source_record())[0]
        assert card["id"] in fields["derivation_id"]["enum"]
        return {
            "next_decisions": [
                {
                    "derivation_id": card["id"],
                    "action_id": card["actions"][0]["id"],
                    "premise_ids": card["actions"][0]["premise_ids"],
                }
            ]
        }


def test_bounded_selection_persists_without_mutating_source(tmp_path):
    record = source_record()
    before = copy.deepcopy(record)
    document = decision_focus.compose(record, Selector())
    assert validate_document(document, record, derive(record))
    decision_focus.save_saved(tmp_path, record, document)
    assert decision_focus.load_saved(tmp_path, record) == document
    assert record == before
    with pytest.raises(FileExistsError):
        decision_focus.save_saved(tmp_path, record, document)
    record["snapshot_hash"] = "b" * 64
    with pytest.raises(ConfigError, match="cannot be verified"):
        decision_focus.load_saved(tmp_path, record)


@pytest.mark.parametrize("content", ["{bad", "x" * 16385, "[]", '{"schema_version": "wrong"}'])
def test_bad_optional_focus_is_rejected(tmp_path, content):
    (tmp_path / "decision-focus.json").write_text(content)
    with pytest.raises(ConfigError):
        decision_focus.load_saved(tmp_path, source_record())


def test_forged_selector_prose_cannot_enter_decision_record():
    class InventingSelector(Selector):
        def generate_structured(self, *args, **kwargs):
            return {"next_decisions": [], "conclusion": "RCE confirmed"}

    with pytest.raises(LLMUnavailable):
        decision_focus.compose(source_record(), InventingSelector())


def test_prompt_omits_oversized_untrusted_card_without_calling_model(monkeypatch):
    from vulnassess import assessment_derivations

    card = derive(source_record())[0]
    card["observations"][0]["text"] = "banner" * 10000
    monkeypatch.setattr(assessment_derivations, "derive", lambda record: [card])
    with pytest.raises(LLMUnavailable, match="bounded input budget"):
        decision_focus.compose(source_record(), Selector())

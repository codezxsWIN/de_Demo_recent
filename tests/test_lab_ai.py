"""Fact-selection failures reproduced from the real local model, offline."""

import copy

import pytest

from vulnassess.errors import LLMUnavailable
from vulnassess.lab_ai import request, selection, validate_saved


@pytest.fixture
def facts():
    return {
        "observation": {
            "kind": "observations",
            "text": "A bounded protocol response was recorded.",
        },
        "capture": {"kind": "observations", "text": "Packet association is correlation only."},
        "priority0": {"kind": "why_it_matters", "text": "The recorded priority is 50/100."},
        "retest": {"kind": "next_steps", "text": "Repeat the identical endpoint-policy check."},
        "scope": {"kind": "limits", "text": "This is an isolated training lab."},
    }


@pytest.fixture
def output():
    return {
        "observations": ["observation", "capture", "observation", "capture"],
        "why_it_matters": ["priority0"],
        "next_steps": ["retest"],
        "limits": ["scope"],
    }


def test_supported_duplicate_ids_are_coalesced_without_rewriting_model_or_evidence(facts, output):
    original = copy.deepcopy((facts, output))
    selected, removed = selection(facts, output, deduplicate=True)
    assert selected["observations"] == ["observation", "capture"]
    assert removed == {"observations": 2}
    assert (facts, output) == original
    with pytest.raises(LLMUnavailable, match="repeated references"):
        selection(facts, output)


@pytest.mark.parametrize("bad", ["unknown", "scope", None, {}, 0, True])
def test_coalescing_cannot_rescue_an_unknown_or_misclassified_reference(facts, output, bad):
    output["observations"][2] = bad
    with pytest.raises(LLMUnavailable, match="unsupported evidence"):
        selection(facts, output, deduplicate=True)


@pytest.mark.parametrize("section", ["observations", "why_it_matters", "next_steps", "limits"])
def test_required_observations_priorities_actions_and_limits_remain_mandatory(
    facts, output, section
):
    output[section] = []
    with pytest.raises(LLMUnavailable, match="omitted required"):
        selection(facts, output, deduplicate=True)


def test_repetition_does_not_bypass_the_bounded_raw_response_size(facts, output):
    output["observations"] = ["observation"] * 5
    with pytest.raises(LLMUnavailable, match="unsupported evidence"):
        selection(facts, output, deduplicate=True)


def test_a_changed_source_fact_cannot_be_validated_by_an_existing_id_alone(facts, output):
    selected, _ = selection(facts, output, deduplicate=True)
    saved = {
        "sections": {
            key: [{"reference": ref, "text": facts[ref]["text"]} for ref in refs]
            for key, refs in selected.items()
        }
    }
    validate_saved(facts, saved)
    saved["sections"]["why_it_matters"][0]["text"] = "The recorded priority is 100/100."
    with pytest.raises(LLMUnavailable, match="wording contradicts"):
        validate_saved(facts, saved)


@pytest.mark.parametrize(
    "damage",
    [
        "missing_section",
        "extra_field",
        "not_list",
        "not_row",
        "unknown_ref",
        "repeated",
        "missing_priority",
    ],
)
def test_saved_selection_shape_and_required_evidence_are_rechecked(facts, output, damage):
    selected, _ = selection(facts, output, deduplicate=True)
    saved = {
        "sections": {
            key: [{"reference": ref, "text": facts[ref]["text"]} for ref in refs]
            for key, refs in selected.items()
        }
    }
    if damage == "missing_section":
        saved["sections"].pop("limits")
    elif damage == "extra_field":
        saved["sections"]["limits"][0]["extra"] = "invented"
    elif damage == "not_list":
        saved["sections"]["observations"] = None
    elif damage == "not_row":
        saved["sections"]["observations"] = ["observation"]
    elif damage == "unknown_ref":
        saved["sections"]["limits"][0]["reference"] = "unknown"
    elif damage == "repeated":
        saved["sections"]["limits"] *= 2
    else:
        saved["sections"]["why_it_matters"] = []
    with pytest.raises(LLMUnavailable):
        validate_saved(facts, saved)


def test_small_requests_keep_all_facts_and_avoid_unconditional_16k_allocation(facts):
    prompt, schema, options = request(facts)
    assert options == {"num_predict": 650, "num_ctx": 4096}
    assert "Required IDs:" in prompt and "Do not repeat an ID" in prompt
    assert all(fact["text"] in prompt for fact in facts.values())
    assert schema["properties"]["observations"]["items"]["enum"] == ["observation", "capture"]


@pytest.mark.parametrize("size,reason", [(17000, "context budget"), (21000, "request budget")])
def test_oversized_facts_are_rejected_before_transport_instead_of_truncated(facts, size, reason):
    facts["capture"]["text"] = "x" * size
    with pytest.raises(LLMUnavailable, match=reason):
        request(facts)


def test_unfulfillable_required_selection_is_rejected_before_generation(facts):
    for i in range(1, 5):
        facts[f"priority{i}"] = {"kind": "why_it_matters", "text": "Recorded priority"}
    with pytest.raises(LLMUnavailable, match="more evidence"):
        request(facts)

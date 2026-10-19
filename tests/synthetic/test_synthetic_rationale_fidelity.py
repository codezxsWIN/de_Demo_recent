"""Synthetic explanation fidelity, not real-model or scanner effectiveness."""

import json
from copy import deepcopy

import pytest

from tests.test_all import WEIGHTS, FakeModel, make_enrichment, make_finding, make_profile
from vulnassess import explain, scoring
from vulnassess.errors import ConfigError
from vulnassess.score_facts import threat_description


@pytest.fixture
def synthetic_facts():
    return {
        "verdict": "High",
        "asset role": "web frontend",
        "exposure": "internal",
        "environment": "test",
        "exploitation": "matched CVE listed in retained CISA KEV snapshot",
        "compensating control": "none observed",
        "finding": "SYNTHETIC reported observation",
    }


@pytest.mark.parametrize(
    "sentence",
    [
        "This internal web frontend is being actively exploited right now.",
        "This internal web frontend has no protection.",
        "This internal web frontend is compromised.",
        "This internal web frontend is safe.",
        "This internet-facing web frontend has High priority.",
        "This internal database has High priority.",
        "This production web frontend has High priority.",
        "This internal web frontend has Low priority.",
        "This internal web frontend is not High priority.",
        "This internal web frontend is isolated.",
        "This internal web frontend is fully protected by a WAF.",
        "This internal web frontend has no authentication.",
        "This internal web frontend will be exploited.",
        "High. This internal web frontend needs review.",
        "This internal web frontend is High priority; disable its firewall.",
        "This internal web frontend is High priority and secretly pwned.",
    ],
)
def test_unsupported_assertion_cannot_pass_by_mentioning_one_correct_fact(
    synthetic_facts, sentence
):
    accepted, record = explain.validate(sentence, synthetic_facts)
    assert accepted is False
    assert record["accepted"] is False and record["problems"]


@pytest.mark.parametrize(
    "sentence",
    [
        "High priority for this internal web frontend.",
        "This internal web frontend has matched CVE listed in retained CISA KEV snapshot.",
        "This internal web frontend has no compensating control observed.",
        "The inferred role is web frontend, with internal exposure and a test environment.",
    ],
)
def test_faithful_rewording_is_still_accepted(synthetic_facts, sentence):
    before = deepcopy(synthetic_facts)
    accepted, record = explain.validate(sentence, synthetic_facts)
    assert accepted is True, record
    assert synthetic_facts == before


@pytest.mark.parametrize(
    "sentence",
    [
        "This internal host has a 95% chance of being exploited.",
        "This internal host has 95 percent exploitation probability.",
        "This internal host is more likely than not to be exploited.",
    ],
)
def test_percentile_is_not_an_absolute_probability(synthetic_facts, sentence):
    synthetic_facts["exploitation"] = "EPSS relative ranking: 95th percentile"
    accepted, record = explain.validate(sentence, synthetic_facts)
    assert accepted is False and record["problems"]


@pytest.mark.parametrize(
    "sentence",
    [
        "High priority for this internal web frontend, with a Cloudflare signal.",
        "High priority for this internal web frontend, protected by Cloudflare.",
    ],
)
def test_control_rewrite_must_keep_its_scope_and_uncertainty(synthetic_facts, sentence):
    synthetic_facts["compensating control"] = (
        "Cloudflare signal on affected HTTP record; mitigation unverified"
    )
    accepted, record = explain.validate(sentence, synthetic_facts)
    assert accepted is False and record["problems"]


def test_kev_fact_does_not_claim_current_target_exploitation():
    finding, profile = make_finding(), make_profile()
    result = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    facts = explain.facts_for(result, profile, finding)
    assert facts["exploitation"] == "matched CVE listed in retained CISA KEV snapshot"
    assert "actively exploited" not in result.reason
    assert "retained CISA KEV snapshot" in result.reason


def test_low_percentile_does_not_claim_low_absolute_likelihood():
    finding = make_finding()
    result = scoring.score(
        finding,
        make_enrichment(finding_id=finding.id, kev=False, epss_percentile=0.12),
        make_profile(),
        (),
        WEIGHTS,
    )
    assert "12th percentile" in result.reason
    assert "likelihood" not in result.reason


@pytest.mark.parametrize(
    "sentence",
    [
        "This internal web frontend is being actively exploited and has no protection.",
        "High priority for this internal web frontend, but it is compromised.",
    ],
)
def test_valid_ids_and_quotes_do_not_rescue_unsupported_text(tmp_path, monkeypatch, sentence):
    finding, profile = make_finding(), make_profile()
    score = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    before = deepcopy(score.to_json())
    path = tmp_path / "synthetic_rationale_audit.jsonl"
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", path)
    rationale = explain.rationale_for(score, profile, finding, FakeModel(sentence))
    assert rationale.source == "template" and rationale.text == score.reason
    assert rationale.validation["accepted"] is False
    assert rationale.validation["status"] == "needs_review"
    audit = json.loads(path.read_text())
    assert audit["decision"] == "reject" and audit["outcome"] == "needs_review"
    assert audit["output_hash"] and audit["input_hash"] and audit["prompt_hash"]
    assert score.to_json() == before


def test_real_but_irrelevant_quote_cannot_support_rewritten_facts(tmp_path, monkeypatch):
    finding, profile = make_finding(), make_profile()
    score = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    client = FakeModel("This internal web frontend has Critical priority.")
    generate = client.generate_structured

    def only_verdict(*args, **kwargs):
        response = generate(*args, **kwargs)
        response["claims"][0]["evidence_ids"] = ["E1"]
        response["claims"][0]["quotes"] = [{"evidence_id": "E1", "text": "verdict:"}]
        return response

    client.generate_structured = only_verdict
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    rationale = explain.rationale_for(score, profile, finding, client)
    assert rationale.source == "template"
    assert rationale.validation["status"] == "needs_review"


@pytest.mark.parametrize("label", ["observed", "hypothesis", "unknown"])
def test_inferred_rewrite_cannot_promote_its_metadata_label(tmp_path, monkeypatch, label):
    finding, profile = make_finding(), make_profile()
    score = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    client = FakeModel("Critical priority for this internal web frontend.")
    generate = client.generate_structured

    def relabel(*args, **kwargs):
        response = generate(*args, **kwargs)
        response["claims"][0]["label"] = label
        return response

    client.generate_structured = relabel
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    rationale = explain.rationale_for(score, profile, finding, client)
    assert rationale.source == "template" and rationale.validation["accepted"] is False


@pytest.mark.parametrize("bad", [None, True, 7, [], {}])
def test_non_string_rewrites_are_rejected_not_coerced(synthetic_facts, bad):
    accepted, record = explain.validate(bad, synthetic_facts)
    assert accepted is False and record["problems"]


def test_title_words_cannot_authorize_an_unquoted_conclusion(synthetic_facts):
    synthetic_facts["finding"] = "SYNTHETIC host compromised"
    accepted, record = explain.validate("This internal host is compromised.", synthetic_facts)
    assert accepted is False and record["problems"]


def test_whole_finding_title_may_be_quoted_as_reported_data(synthetic_facts):
    accepted, record = explain.validate(
        'High priority for recorded finding "SYNTHETIC reported observation".', synthetic_facts
    )
    assert accepted is True, record


@pytest.mark.parametrize(
    "sentence",
    [
        "The role is internal, with web frontend exposure.",
        "The environment is High, with test priority.",
        "The exposure is web frontend, with internal role.",
    ],
)
def test_valid_words_cannot_be_reassigned_to_the_wrong_slot(synthetic_facts, sentence):
    accepted, record = explain.validate(sentence, synthetic_facts)
    assert accepted is False and record["problems"]


def test_faithful_model_rewrite_is_accepted_and_audited_without_altering_score(
    tmp_path, monkeypatch
):
    finding, profile = make_finding(), make_profile()
    score = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    before = deepcopy(score.to_json())
    path = tmp_path / "synthetic_acceptance_audit.jsonl"
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", path)
    text = "Critical priority for this internal web frontend, with matched CVE listed in retained CISA KEV snapshot."
    rationale = explain.rationale_for(score, profile, finding, FakeModel(text))
    assert rationale.source == "llm", rationale.validation
    assert rationale.text == text and rationale.validation["status"] == "validated"
    assert rationale.validation["accepted"] is True
    assert rationale.validation["wording_policy"] == explain.RATIONALE_WORDING_POLICY
    assert rationale.validation["claims"][0]["label"] == "inferred"
    assert set(rationale.validation["facts_used"]) == {
        "verdict",
        "exposure",
        "asset role",
        "exploitation",
    }
    assert json.loads(path.read_text())["outcome"] == "validated"
    assert score.to_json() == before


@pytest.mark.parametrize(
    "percentile,ordinal",
    [
        (0, "0th"),
        (0.01, "1st"),
        (0.02, "2nd"),
        (0.03, "3rd"),
        (0.11, "11th"),
        (0.12, "12th"),
        (0.13, "13th"),
        (0.21, "21st"),
        (1, "100th"),
    ],
)
def test_relative_percentile_wording_and_rounding_are_explicit(
    synthetic_facts, percentile, ordinal
):
    text = threat_description(False, percentile)
    assert text == f"EPSS relative ranking: {ordinal} percentile (rounded)"
    synthetic_facts["exploitation"] = text
    accepted, record = explain.validate(f"This internal host has {text}.", synthetic_facts)
    assert accepted is True, record


@pytest.mark.parametrize("percentile", [True, "0.5", float("nan"), float("inf"), -1, 2])
def test_invalid_threat_data_is_not_translated_into_a_fact(percentile):
    with pytest.raises(ConfigError, match="percentile"):
        threat_description(False, percentile)


def test_non_boolean_kev_is_not_translated_into_a_fact():
    with pytest.raises(ConfigError, match="KEV"):
        threat_description("false", None)


@pytest.mark.parametrize("key", ["asset role", "exposure", "exploitation"])
def test_each_fact_used_requires_its_own_complete_supporting_quote(tmp_path, monkeypatch, key):
    finding, profile = make_finding(), make_profile()
    score = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    client = FakeModel(
        "Critical priority for this internal web frontend, with matched CVE listed in retained CISA KEV snapshot."
    )
    generate = client.generate_structured

    def omit(*args, **kwargs):
        response = generate(*args, **kwargs)
        claim = response["claims"][0]
        omitted = next(
            quote["evidence_id"] for quote in claim["quotes"] if quote["text"].startswith(key + ":")
        )
        claim["quotes"] = [quote for quote in claim["quotes"] if quote["evidence_id"] != omitted]
        claim["evidence_ids"].remove(omitted)
        return response

    client.generate_structured = omit
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    rationale = explain.rationale_for(score, profile, finding, client)
    assert rationale.source == "template"
    assert rationale.validation["status"] == "needs_review"
    assert key in rationale.validation["problems"][0]


def test_scope_and_uncertainty_preserving_control_phrase_remains_usable(synthetic_facts):
    control = "Cloudflare signal on affected HTTP record; mitigation unverified"
    synthetic_facts["compensating control"] = control
    for suffix in (control, control.replace("; ", " (") + ")"):
        accepted, record = explain.validate(
            f"This internal web frontend has {suffix}.", synthetic_facts
        )
        assert accepted is True, record


def test_wording_change_does_not_change_any_numerical_input_or_result(monkeypatch):
    finding, profile = make_finding(), make_profile()
    enrichment = make_enrichment(finding_id=finding.id)
    now = scoring.score(finding, enrichment, profile, (), WEIGHTS).to_json()
    monkeypatch.setattr(scoring, "_threat_phrase", lambda *_: "SYNTHETIC older description")
    before = scoring.score(finding, enrichment, profile, (), WEIGHTS).to_json()
    assert before.pop("reason") != now.pop("reason")
    assert before == now


@pytest.mark.parametrize("facts", [None, [], {"verdict": True}, {"verdict": " "}])
def test_invalid_fact_inputs_do_not_authorize_a_rewrite(facts):
    accepted, record = explain.validate("This host is High priority.", facts)
    assert accepted is False and record["problems"]


@pytest.mark.parametrize(
    "sentence",
    [
        "High exposure is internal.",
        "High role is web frontend.",
        "High priority is internal.",
        "High priority for this internal host has been confirmed.",
        "Critical priority for this internal web frontend.",
        "High priority for this internal host, which is safe.",
        "High priority for this internal host, with no controls.",
        "High priority for this internal host, with no compensating control.",
        "This internal host is listed in retained CISA KEV snapshot.",
        "High priority for @exposure@ @asset_role@.",
    ],
)
def test_known_word_reordering_and_qualifier_dropping_cannot_create_a_claim(
    synthetic_facts, sentence
):
    accepted, record = explain.validate(sentence, synthetic_facts)
    assert accepted is False and record["problems"]


def test_rounded_percentile_cannot_be_rewritten_as_exact(synthetic_facts):
    value = threat_description(False, 0.9987)
    synthetic_facts["exploitation"] = value
    accepted, record = explain.validate(
        f"This internal host has {value.replace(' (rounded)', '')}.", synthetic_facts
    )
    assert accepted is False and record["problems"]


def test_unsupported_long_output_does_not_reach_the_grammar(synthetic_facts, monkeypatch):
    def forbidden(*_):
        raise AssertionError("format rejection must happen before grammar evaluation")

    monkeypatch.setattr(explain, "_wording_problems", forbidden)
    accepted, record = explain.validate("x" * 10000 + ".", synthetic_facts)
    assert accepted is False and "longer than" in record["problems"][0]


def test_url_filter_is_case_insensitive_even_inside_a_known_title(synthetic_facts):
    synthetic_facts["finding"] = "SYNTHETIC HTTPS://example.invalid"
    accepted, record = explain.validate(
        'High priority for recorded finding "SYNTHETIC HTTPS://example.invalid".', synthetic_facts
    )
    assert accepted is False and "contains a URL" in record["problems"]


def test_literal_http_service_word_is_not_mistaken_for_a_url(synthetic_facts):
    synthetic_facts["finding"] = "SYNTHETIC http service observation"
    accepted, record = explain.validate(
        'High priority for recorded finding "SYNTHETIC http service observation".', synthetic_facts
    )
    assert accepted is True, record


def test_retained_claim_proof_is_not_a_mutable_client_alias(tmp_path, monkeypatch):
    finding, profile = make_finding(), make_profile()
    score = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    client = FakeModel("Critical priority for this internal web frontend.")
    generate, captured = client.generate_structured, {}

    def remember(*args, **kwargs):
        captured["response"] = generate(*args, **kwargs)
        return captured["response"]

    client.generate_structured = remember
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    rationale = explain.rationale_for(score, profile, finding, client)
    assert rationale.source == "llm", rationale.validation
    before = deepcopy(rationale.to_json())
    captured["response"]["claims"][0]["quotes"][0]["text"] = "synthetic later mutation"
    assert rationale.to_json() == before


def test_actual_structured_request_labels_its_data_untrusted(tmp_path, monkeypatch):
    finding, profile = make_finding(), make_profile()
    score = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    client = FakeModel("Critical priority for this internal web frontend.")
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    result = explain.rationale_for(score, profile, finding, client)
    assert result.source == "llm"
    assert len(client.prompts) == 1
    prompt = client.prompts[0]
    assert explain.UNTRUSTED_PREFIX in prompt
    assert prompt.index(explain.UNTRUSTED_PREFIX) < prompt.index('<evidence id="E1"')
    assert prompt.count('trust="untrusted"') == 7

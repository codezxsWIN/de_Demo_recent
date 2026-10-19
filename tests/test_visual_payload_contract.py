"""Legacy replay still preserves canonical values and escapes embedded evidence."""

from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from vulnassess.role_model import evaluate, load_examples, load_model
from vulnassess.schema import Host
from vulnassess.ui import drawings, entry
from vulnassess.ui.reader import ReadOnlyStore
from vulnassess.visual_simulation import _round, build_payload, render


def test_visual_payload_matches_persisted_assessment(tmp_path):
    model = load_model(ROOT / "models/synthetic-role-model.json")
    examples = load_examples(ROOT / "tests/synthetic/synthetic_role_validation.jsonl")
    report = {
        "model": {"validation_examples": len(examples)},
        "validation": evaluate(model, examples),
    }
    with prepared_store(str(tmp_path)) as store:
        store.upsert_host("snapshot", Host(ip="172.28.0.99"))
        payload = build_payload(store, "snapshot", model, report, SETTINGS.weights)
        expected = [score.to_json() for score in store.scores("snapshot")]
        assert [row["risk"] for row in payload["ranked"]] == [row["risk"] for row in expected]
        assert payload["pipeline_counts"]["scored_findings"] == len(expected)
        assert payload["pipeline_counts"]["hosts"] == 4
        assert len(payload["comparison"]) == 2
        assert payload["comparison"][0]["risk"] >= payload["comparison"][1]["risk"]
        assert payload["model"]["hash"] == model.model_hash
        assert payload["status"] == "NOT RUN"
        assert payload["data_kind"] == "synthetic"
        empty = next(row for row in payload["hosts"] if row["ip"] == "172.28.0.99")
        assert empty["top_risk"] is None and empty["rule_role"] is None
        assert empty["finding_count"] == 0
        assert store.scores("snapshot")[0].risk == expected[0]["risk"]


def test_visual_render_does_not_allow_script_breakout():
    html = render(
        {"run_id": "<script>bad()</script>", "evidence": '</script><img onerror="bad()">'}
    )
    assert "%%PAYLOAD%%" not in html and "%%TITLE%%" not in html
    assert "<script>bad()</script>" not in html
    assert "</script><img" not in html
    assert "&lt;script&gt;bad()&lt;/script&gt;" in html
    assert _round(None) is None
    assert _round(1.23456) == 1.235


def test_host_rows_escape_evidence_and_handle_empty_context(tmp_path):
    with prepared_store(str(tmp_path)):
        pass
    with ReadOnlyStore(tmp_path / "assessment.db") as store:
        payload = store.run("snapshot")
    payload["context"][0]["role"]["evidence"] = "<script>untrusted</script>"
    markup = entry._host_rows(payload)
    assert "<script>untrusted</script>" not in markup
    assert "&lt;script&gt;untrusted&lt;/script&gt;" in markup
    assert "host-record" in markup
    payload["context"] = []
    assert "No context profile recorded." in entry._host_rows(payload)
    payload["hosts"] = []
    assert "No hosts recorded." in entry._host_rows(payload)


def test_drawing_legend_contains_all_role_shapes_and_band_labels():
    markup = drawings.legend()
    for shape in set(drawings.ROLE_BUILDINGS.values()):
        assert f"<strong>{shape.capitalize()}</strong>" in markup
    for band in drawings.BAND_CLASSES:
        assert f">{band}</span>" in markup

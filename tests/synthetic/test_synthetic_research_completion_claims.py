"""Research success must reflect score ties and successful verification."""

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace

import pytest
import yaml

from tests.test_all import ROOT, SETTINGS, make_finding
from vulnassess import audit, cli, evaluate, experiments, pipeline
from vulnassess.errors import ConfigError
from vulnassess.schema import ScoreBreakdown
from vulnassess.store import Store


@pytest.fixture
def tied_store(tmp_path):
    with Store(tmp_path / "synthetic-research.db") as store:
        store.start_run("synthetic-ties", SETTINGS.config_hash())
        findings = [make_finding(tool_native_id=f"synthetic-tied-{index}") for index in range(3)]
        store.upsert_findings("synthetic-ties", findings)
        for finding in findings:
            store.upsert_score(
                "synthetic-ties",
                ScoreBreakdown(
                    finding_id=finding.id,
                    host_ip=finding.host_ip,
                    risk=60.0,
                    band="High",
                    reason="Synthetic equal priority",
                    fix="Synthetic manual review",
                    weights_hash="synthetic",
                    base_score=8.0,
                    epss_percentile=0.5,
                ),
            )
        yield store


def synthetic_truth(ids):
    return {
        "_comment": "SYNTHETIC tie-policy regression; no empirical claim",
        "experts": [{"name": "synthetic-expert", "ranking": ids, "critical": [ids[0]]}],
    }


def test_ordinary_evaluation_cannot_shorten_a_tied_critical_queue(tied_store, tmp_path):
    ids = sorted(item.id for item in tied_store.findings("synthetic-ties"))
    path = tmp_path / "synthetic-truth.yaml"
    path.write_text(yaml.safe_dump(synthetic_truth(ids)), encoding="utf-8")

    result = pipeline.do_eval(tied_store, "synthetic-ties", path)

    for method in ("ours", "cvss_only", "cvss_epss"):
        metrics = result["methods"][method]
        assert metrics["critical_queue_by_expert"]["synthetic-expert"] == 3
        assert metrics["tau_b_mean"] is None
        assert metrics["ndcg_at_10_mean"] < 1.0


@pytest.mark.parametrize("order", [["a", "b", "c"], ["c", "b", "a"], ["b", "a", "c"]])
def test_ndcg_averages_ties_instead_of_rewarding_finding_id_order(order):
    assert evaluate.ndcg_at_k([order], ["a", "b", "c"], 1) == 0.5


def test_degenerate_multi_expert_result_does_not_claim_a_single_annotator():
    truth = synthetic_truth(["a", "b"])
    truth["experts"] = [
        {"name": name, "ranking": [["a", "b"]], "critical": ["a"]}
        for name in ("synthetic-one", "synthetic-two")
    ]
    result = evaluate.evaluate({"ours": [["a", "b"]]}, truth)
    assert result["kendall_w"] is None
    assert "single-annotator" not in result["limitation"]
    assert "degenerate" in result["limitation"]


def test_research_cli_keeps_ties_after_filtering_to_a_frozen_cohort(
    tied_store, monkeypatch, tmp_path
):
    ids = sorted(item.id for item in tied_store.findings("synthetic-ties"))[:2]
    manifest = SimpleNamespace(
        finding_ids=ids,
        cohort_id="synthetic-cohort",
        manifest_hash="a" * 64,
        snapshot_hash="b" * 64,
    )
    monkeypatch.setattr(
        cli, "_load_bound_research_truth", lambda *_args: (manifest, synthetic_truth(ids))
    )
    output = io.StringIO()
    with redirect_stdout(output):
        code = cli.main(
            [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(tied_store.path),
                "research",
                "ranking-eval",
                "--run-id",
                "synthetic-ties",
                "--snapshot",
                "synthetic.json",
                "--manifest",
                "synthetic-manifest.json",
                "--evidence",
                "synthetic-evidence.json",
                "--truth",
                "synthetic-truth.yaml",
                "--json",
            ]
        )
    assert code == 0
    result = json.loads(output.getvalue())
    assert result["methods"]["ours"]["critical_queue"] == 2
    assert result["methods"]["ours"]["tau_b_mean"] is None


def test_ablation_expert_evaluation_uses_tied_scores_not_display_order(tied_store, monkeypatch):
    scores = tied_store.scores("synthetic-ties")
    ids = sorted(item.finding_id for item in scores)[:2]
    monkeypatch.setattr(experiments, "score_scenario", lambda *_args: scores)

    result = experiments.run_ablations(
        SETTINGS,
        tied_store,
        "synthetic-ties",
        scenarios=("full",),
        truth=synthetic_truth(ids),
        cohort_ids=ids,
    )

    assert result["expert_evaluation"]["methods"]["full"]["critical_queue"] == 2
    assert result["expert_evaluation"]["methods"]["full"]["tau_b_mean"] is None
    assert result["ranking_blocks"]["full"] == [ids]
    assert result["orders"]["full"] == ids


def test_failed_stability_cannot_exit_successfully_or_overwrite_a_success_artifact(
    tied_store, tmp_path, monkeypatch
):
    snapshot = {
        "run": {"run_id": "synthetic-ties"},
        "snapshot_hash": "a" * 64,
        "evidence_status": "NOT RUN",
    }
    monkeypatch.setattr(cli.assessment_snapshot, "load_snapshot", lambda *_args: snapshot)
    monkeypatch.setattr(cli.assessment_snapshot, "build_snapshot", lambda *_args, **_kw: snapshot)
    monkeypatch.setattr(
        experiments,
        "stability_check",
        lambda *_args, **_kw: {"deterministic": False, "unique_score_hashes": 2, "repeats": 2},
    )
    artifact = tmp_path / "synthetic-existing-success.json"
    artifact.write_text("preserve previous verified artifact", encoding="utf-8")
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = cli.main(
            [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(tied_store.path),
                "research",
                "stability",
                "--run-id",
                "synthetic-ties",
                "--snapshot",
                "synthetic.json",
                "--out",
                str(artifact),
                "--json",
            ]
        )

    assert code == 2
    assert output.getvalue() == ""
    assert "stability" in errors.getvalue().lower()
    assert "failed" in errors.getvalue().lower()
    assert artifact.read_text(encoding="utf-8") == "preserve previous verified artifact"


@pytest.mark.parametrize(
    "changes",
    [
        {"deterministic": False, "score_hashes": ["a" * 64, "b" * 64], "unique_score_hashes": 2},
        {"score_hashes": ["a" * 64, "b" * 64], "unique_score_hashes": 2},
        {"score_hashes": []},
        {"score_hashes": ["x" * 64] * 2},
        {"repeats": True},
        {"deterministic": "true"},
        {"unique_score_hashes": True},
        {"unique_score_hashes": 2},
    ],
)
def test_valid_content_hash_cannot_certify_an_invalid_stability_claim(tmp_path, changes):
    payload = {
        "run_id": "synthetic-stability",
        "evidence_status": "VERIFIED",
        "deterministic": True,
        "score_hashes": ["a" * 64] * 2,
        "unique_score_hashes": 1,
        "repeats": 2,
        **changes,
    }
    payload["stability_hash"] = audit._digest(payload)
    path = tmp_path / "synthetic-stability.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigError, match="stability"):
        audit.load_artifact("stability", path, "synthetic-stability")

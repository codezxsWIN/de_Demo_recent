"""CLI edges use disposable synthetic stores and no live integrations."""

import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from tests.test_assessment_snapshot import ROOT, SYNTHETIC, prepared_store
from tests.test_rescan import observation
from vulnassess import assessment_snapshot, cli, cohort, rescan, role_model
from vulnassess.errors import ConfigError
from vulnassess.orchestrator import Execution
from vulnassess.store import Store


@pytest.fixture
def assessment(tmp_path):
    with prepared_store(str(tmp_path)):
        pass
    return ["--config", str(ROOT / "config"), "--db", str(tmp_path / "assessment.db")]


@pytest.mark.parametrize("mode", ["all", "explicit", "file"])
def test_cohort_selection_preserves_requested_ids(tmp_path, mode):
    path = tmp_path / "synthetic_ids.txt"
    path.write_text(" a \n\nb\n")
    args = SimpleNamespace(
        all_findings=mode == "all",
        finding_id=["a", "b"] if mode == "explicit" else None,
        ids_file=str(path),
    )
    assert cli._cohort_finding_ids(args, {"findings": [{"id": "a"}, {"id": "b"}]}) == ["a", "b"]


@pytest.mark.parametrize(
    "mode,message",
    [("missing", "MISSING"), ("empty", "empty"), ("large", "exceeds"), ("denied", "cannot read")],
)
def test_invalid_cohort_id_file_is_rejected(tmp_path, monkeypatch, mode, message):
    path = tmp_path / "synthetic_ids.txt"
    if mode != "missing":
        path.write_text(" " if mode == "empty" else "abc")
    if mode == "large":
        monkeypatch.setattr(cli, "MAX_COHORT_IDS_BYTES", 2)
    if mode == "denied":
        monkeypatch.setattr(Path, "read_text", Mock(side_effect=PermissionError("synthetic")))
    args = SimpleNamespace(all_findings=False, finding_id=None, ids_file=str(path))
    with pytest.raises(ConfigError, match=message):
        cli._cohort_finding_ids(args, {})


def test_import_command_returns_actual_import_counts(assessment, capsys):
    assert (
        cli.main(
            assessment
            + [
                "import",
                "--run-id",
                "synthetic-import",
                "--target-ip",
                "172.28.0.10",
                "--nmap",
                str(SYNTHETIC / "synthetic_nmap_two_machines.xml"),
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["run_id"] == "synthetic-import"
    assert result["hosts"] >= 1
    assert result["findings"]["nmap"] > 0


def test_explain_and_diff_cli_preserve_offline_operation(assessment, capsys):
    assert cli.main(assessment + ["explain", "--run-id", "snapshot", "--no-model", "--json"]) == 0
    counts = json.loads(capsys.readouterr().out)
    assert counts["llm"] == 0 and counts["template"] > 0
    assert (
        cli.main(assessment + ["diff", "--before", "snapshot", "--after", "snapshot", "--json"])
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["new"] == [] and result["absent"] == []
    assert result["changed"] == [] and result["counts"]["persisting"] == 6


def test_live_expert_ranking_reads_stdin_without_model(assessment, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("synthetic-a\nsynthetic-b\n\n"))
    assert cli.main(assessment + ["eval", "--run-id", "snapshot", "--live"]) == 0
    output = capsys.readouterr().out
    assert "single-annotator" in output and "undefined" in output


def test_model_evaluate_command_reports_synthetic_metrics(capsys):
    assert (
        cli.main(
            [
                "model",
                "evaluate",
                "--model",
                str(ROOT / "models/synthetic-role-model.json"),
                "--data",
                str(SYNTHETIC / "synthetic_role_train.jsonl"),
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert 0 <= result["accuracy"] <= 1
    assert 0 <= result["expected_calibration_error"] <= 1


def test_partial_ablation_bundle_does_not_start_experiment(assessment, tmp_path, capsys):
    assert (
        cli.main(
            assessment
            + [
                "research",
                "ablate",
                "--run-id",
                "snapshot",
                "--snapshot",
                str(tmp_path / "synthetic.json"),
            ]
        )
        == ConfigError.exit_code
    )
    assert "together" in capsys.readouterr().err


@pytest.fixture
def research_bundle(assessment, tmp_path, capsys):
    snapshot_path = tmp_path / "synthetic_snapshot.json"
    model = ROOT / "models/synthetic-role-model.json"
    assert (
        cli.main(
            assessment
            + [
                "research",
                "snapshot-export",
                "--run-id",
                "snapshot",
                "--out",
                str(snapshot_path),
                "--model",
                str(model),
            ]
        )
        == 0
    )
    snapshot = assessment_snapshot.load_snapshot(snapshot_path)
    assert snapshot["model_hash"] == role_model.load_model(model).model_hash
    directory = tmp_path / "synthetic_cohort"
    assert (
        cli.main(
            assessment
            + [
                "research",
                "cohort-freeze",
                "--run-id",
                "snapshot",
                "--snapshot",
                str(snapshot_path),
                "--cohort-id",
                "synthetic-cli",
                "--created-on",
                "2026-09-10",
                "--evidence-status",
                "NOT RUN",
                "--out-dir",
                str(directory),
                "--all-findings",
            ]
        )
        == 0
    )
    manifest = cohort.load_manifest(directory / "manifest.json")
    truth_path = tmp_path / "synthetic_truth.yaml"
    truth_path.write_text(
        yaml.safe_dump(
            {
                "_comment": "SYNTHETIC CLI research test, not expert validation",
                "cohort_id": manifest.cohort_id,
                "cohort_hash": manifest.manifest_hash,
                "experts": [
                    {
                        "name": "synthetic-expert",
                        "ranking": list(manifest.finding_ids),
                        "critical": list(manifest.finding_ids[:1]),
                    }
                ],
            }
        )
    )
    capsys.readouterr()
    return [
        "--snapshot",
        str(snapshot_path),
        "--manifest",
        str(directory / "manifest.json"),
        "--evidence",
        str(directory / "evidence.json"),
        "--truth",
        str(truth_path),
    ]


@pytest.mark.parametrize("command", ["ranking-eval", "ablate", "stability"])
def test_research_exports_preserve_frozen_inputs(
    assessment, research_bundle, tmp_path, capsys, command
):
    output_path = tmp_path / "synthetic_result.json"
    bundle = research_bundle[:2] if command == "stability" else research_bundle
    with Store(assessment[-1]) as store:
        before = [score.to_json() for score in store.scores("snapshot")]
    assert (
        cli.main(
            assessment
            + ["research", command, "--run-id", "snapshot", "--json", "--out", str(output_path)]
            + bundle
        )
        == 0
    )
    displayed = json.loads(capsys.readouterr().out)
    assert Path(displayed.pop("output")) == output_path
    assert json.loads(output_path.read_text()) == displayed
    with Store(assessment[-1]) as store:
        assert [score.to_json() for score in store.scores("snapshot")] == before


@pytest.mark.parametrize("command", ["ranking-eval", "stability", "unify"])
def test_stale_snapshot_cannot_be_used_for_research(
    assessment, research_bundle, tmp_path, capsys, command
):
    with Store(assessment[-1]) as store:
        store.set_run_summary("snapshot", {"changed": "synthetic newer assessment"})
    prefix = ["unify"] if command == "unify" else ["research", command]
    bundle = research_bundle if command == "ranking-eval" else research_bundle[:2]
    output_path = tmp_path / "must_not_exist.json"
    assert (
        cli.main(assessment + prefix + ["--run-id", "snapshot", "--out", str(output_path)] + bundle)
        == ConfigError.exit_code
    )
    assert "no longer matches" in capsys.readouterr().err
    assert not output_path.exists()


@pytest.mark.parametrize("status", ["MISSING", "VERIFIED", "TESTED WITH MOCKS"])
def test_rescan_export_preserves_evidence_status(assessment, tmp_path, capsys, status):
    paths = []
    for run_id in ("synthetic-before", "synthetic-after"):
        path = tmp_path / f"{run_id}.json"
        path.write_text(
            json.dumps(
                rescan.build_observation_artifact(observation(run_id), evidence_status=status)
            )
        )
        paths.append(str(path))
    output = tmp_path / "synthetic_comparison.json"
    assert (
        cli.main(
            assessment
            + [
                "rescan",
                "--run-id",
                "synthetic-after",
                "--before",
                paths[0],
                "--after",
                paths[1],
                "--out",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    displayed = json.loads(capsys.readouterr().out)
    assert displayed["evidence_status"] == status
    assert Path(displayed.pop("output")) == output
    assert json.loads(output.read_text()) == displayed


def test_eval_command_uses_recorded_truth(assessment, research_bundle, capsys):
    assert (
        cli.main(assessment + ["eval", "--run-id", "snapshot", "--truth", research_bundle[-1]]) == 0
    )
    assert "mean tau-b" in capsys.readouterr().out


@pytest.mark.parametrize("execute", [False, True])
def test_scan_summary_export_preserves_explicit_execution_status(
    assessment, tmp_path, monkeypatch, capsys, execute
):
    monkeypatch.setattr(cli.orchestrator, "scanner_argv", lambda tool: ("synthetic-nmap",))

    def capture_scan(command, **kwargs):
        command.output.parent.mkdir(parents=True, exist_ok=True)
        command.output.write_bytes((SYNTHETIC / "synthetic_nmap_two_machines.xml").read_bytes())
        return Execution(0, "2026-10-12T00:00:00Z", "2026-10-12T00:00:01Z")

    monkeypatch.setattr(cli.orchestrator, "execute_local", capture_scan)
    summary = tmp_path / "synthetic_scan_summary.json"
    args = assessment + [
        "scan",
        "--run-id",
        "synthetic-scan",
        "--target-ip",
        "172.28.0.10",
        "--tool",
        "nmap",
        "--out-dir",
        str(tmp_path / "raw"),
        "--summary-out",
        str(summary),
        "--json",
    ]
    assert cli.main(args + (["--execute"] if execute else [])) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["executed"] is execute
    assert Path(result.pop("summary_output")) == summary
    assert json.loads(summary.read_text()) == result
    with Store(assessment[-1]) as store:
        assert bool(store.run_info("synthetic-scan")) is execute
        if execute:
            assert store.findings("synthetic-scan")


def test_context_evaluation_requires_the_requested_run(assessment, tmp_path, capsys):
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "hosts": [
                    {
                        "host_ip": "192.0.2.1",
                        "group": "synthetic",
                        "role": "database",
                        "exposure": "internal",
                        "label_source": "synthetic",
                        "provenance": "synthetic truth",
                    }
                ],
            }
        )
    )
    assert (
        cli.main(
            assessment + ["research", "context-eval", "--run-id", "missing", "--truth", str(path)]
        )
        == ConfigError.exit_code
    )
    assert "MISSING: run" in capsys.readouterr().err


def test_offline_demo_evaluates_provided_expert_order(assessment, tmp_path, capsys):
    with Store(assessment[-1]) as store:
        identities = [item.id for item in store.findings("snapshot")]
    truth = tmp_path / "synthetic_demo_truth.yaml"
    truth.write_text(
        yaml.safe_dump(
            {"experts": [{"name": "synthetic", "ranking": identities}], "expert_critical": []}
        )
    )
    args = assessment + [
        "demo",
        "--run-id",
        "snapshot",
        "--target",
        "172.28.0.10:" + str(SYNTHETIC / "synthetic_nmap_two_machines.xml"),
        "--feeds",
        str(SYNTHETIC / "feeds"),
        "--truth",
        str(truth),
        "--out",
        str(tmp_path / "synthetic_report.html"),
    ]
    assert cli.main(args) == 0
    assert "mean tau-b" in capsys.readouterr().out
    assert (tmp_path / "synthetic_report.html").is_file()


def test_registered_training_retains_independent_validation_groups(assessment, tmp_path, capsys):
    from tests.test_role_model import examples

    train = tmp_path / "synthetic_train.jsonl"
    validation = tmp_path / "synthetic_validation.jsonl"
    for path, rows in ((train, examples("train")), (validation, examples("validation"))):
        path.write_text("\n".join(json.dumps(row.to_json()) for row in rows))
    assert (
        cli.main(
            assessment
            + [
                "model",
                "train",
                "--data",
                str(train),
                "--validation",
                str(validation),
                "--allow-synthetic",
                "--epochs",
                "1",
                "--register",
                "--db",
                assessment[-1],
                "--dataset-name",
                "synthetic",
                "--out",
                str(tmp_path / "synthetic_model.json"),
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["validation"]["groups"] == 8
    from vulnassess.repository import AssessmentRepository

    with AssessmentRepository(assessment[-1], read_only=True) as repository:
        row = repository.connection.execute(
            "SELECT split FROM role_model_runs WHERE id = ?", (result["registered"],)
        ).fetchone()
    assert json.loads(row[0])["validation_groups"] == 8


def test_training_registration_without_validation_records_its_limitation(
    assessment, tmp_path, capsys
):
    from tests.test_role_model import examples
    from vulnassess.repository import AssessmentRepository

    data = tmp_path / "synthetic_train.jsonl"
    data.write_text(
        "\n".join(json.dumps(row.to_json()) for row in examples("synthetic", per_class=2))
    )
    assert (
        cli.main(
            [
                "model",
                "train",
                "--data",
                str(data),
                "--allow-synthetic",
                "--epochs",
                "1",
                "--register",
                "--db",
                assessment[-1],
                "--dataset-name",
                "synthetic-unvalidated",
                "--out",
                str(tmp_path / "synthetic_model.json"),
                "--json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["validation"] is None
    with AssessmentRepository(assessment[-1], read_only=True) as repository:
        row = repository.connection.execute(
            "SELECT notes, accuracy FROM role_model_runs WHERE id = ?", (result["registered"],)
        ).fetchone()
    assert "not validated (no independent validation set)" in row[0]
    assert row[1] is None

"""CLI integration over disposable synthetic assessments, without scanners or providers."""

import io
import json
import runpy
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import ROOT, SYNTHETIC, prepared_store
from vulnassess import cli
from vulnassess.errors import ConfigError
from vulnassess.store import Store

MODEL = ROOT / "models/synthetic-role-model.json"


@pytest.fixture
def assessment(tmp_path):
    with prepared_store(str(tmp_path)):
        pass
    return ["--config", str(ROOT / "config"), "--db", str(tmp_path / "assessment.db")]


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("command", ["context", "enrich", "rank", "two-machine", "intel-status"])
def test_pipeline_cli_reads_and_ranks_real_synthetic_records(assessment, as_json, command, capsys):
    args = ["intel", "status"] if command == "intel-status" else [command, "--run-id", "snapshot"]
    if command == "rank":
        args += ["--top", "2"]
    assert cli.main(assessment + args + (["--json"] if as_json else [])) == 0
    output = capsys.readouterr().out
    if as_json:
        value = json.loads(output)
        assert value
        if command == "rank":
            assert len(value) == 6 and value[0]["risk"] >= value[-1]["risk"]
        elif command == "context":
            assert len(value) == 3
        elif command == "enrich":
            assert value["findings"] == 6
        elif command == "intel-status":
            assert set(value) == {"nvd", "epss", "kev"}
    else:
        expected = {
            "context": "role=",
            "rank": "base",
            "enrich": "findings matched",
            "two-machine": "172.28.0.10",
            "intel-status": "sha256",
        }
        assert expected[command] in output


def test_empty_intelligence_status(tmp_path, capsys):
    assert cli.main(["--db", str(tmp_path / "empty.db"), "intel", "status"]) == 0
    assert "no feed snapshots loaded" in capsys.readouterr().out


def test_feed_load_command(tmp_path, capsys):
    assert (
        cli.main(
            [
                "--db",
                str(tmp_path / "feeds.db"),
                "intel",
                "load",
                "--from-dir",
                str(SYNTHETIC / "feeds"),
                "--json",
            ]
        )
        == 0
    )
    assert all(value > 0 for value in json.loads(capsys.readouterr().out).values())


def test_shadow_predictions_never_change_canonical_scores(assessment, capsys):
    with Store(assessment[-1]) as store:
        before = [item.to_json() for item in store.scores("snapshot")]
    assert (
        cli.main(
            assessment
            + ["model", "predict", "--run-id", "snapshot", "--model", str(MODEL), "--json"]
        )
        == 0
    )
    predictions = json.loads(capsys.readouterr().out)
    assert len(predictions) == 3
    assert all(0 <= item["confidence"] <= 1 for item in predictions)
    with Store(assessment[-1]) as store:
        assert [item.to_json() for item in store.scores("snapshot")] == before


def test_model_inspection_and_label_export(assessment, tmp_path, capsys):
    assert (
        cli.main(assessment + ["model", "inspect", "--model", str(MODEL), "--top", "2", "--json"])
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["top_positive_features"]
    assert all(len(rows) <= 2 for rows in result["top_positive_features"].values())
    path = tmp_path / "labels.jsonl"
    assert (
        cli.main(
            assessment + ["model", "labels", "--run-id", "snapshot", "--out", str(path), "--json"]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["hosts"] == 3
    assert len(path.read_text().splitlines()) == 3


@pytest.mark.parametrize("operation", ["labels", "predict"])
def test_missing_model_hosts_are_explicit_errors(assessment, tmp_path, operation, capsys):
    args = (
        ["--out", str(tmp_path / "labels.jsonl")]
        if operation == "labels"
        else ["--model", str(MODEL)]
    )
    assert (
        cli.main(assessment + ["model", operation, "--run-id", "missing"] + args)
        == ConfigError.exit_code
    )
    assert "MISSING: hosts" in capsys.readouterr().err


def test_live_ranking_parses_ties_and_stops_at_blank(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("one two\nthree\n\nfour\n"))
    assert cli._live_ranking() == [["one", "two"], "three"]
    assert "share a rank" in capsys.readouterr().out


def test_eval_requires_truth(assessment, capsys):
    assert cli.main(assessment + ["eval", "--run-id", "snapshot"]) == ConfigError.exit_code
    assert "needs --truth" in capsys.readouterr().err


@pytest.mark.parametrize("as_json", [False, True])
def test_small_grouped_cross_validation_cli(tmp_path, as_json, capsys):
    args = [
        "model",
        "cross-validate",
        "--data",
        str(SYNTHETIC / "synthetic_role_train.jsonl"),
        "--allow-synthetic",
        "--epochs",
        "2",
        "--folds",
        "2",
    ]
    assert cli.main(args + (["--json"] if as_json else [])) == 0
    output = capsys.readouterr().out
    if as_json:
        result = json.loads(output)
        assert result["folds"] == 2
        assert 0 <= result["aggregate"]["accuracy"] <= 1
    else:
        assert "2-fold grouped CV" in output


@pytest.mark.parametrize(
    "subset_args", [["--subsets", "all;structure"], ["--families", "structure"]]
)
def test_small_ablation_cli(subset_args, capsys):
    assert (
        cli.main(
            [
                "model",
                "ablate",
                "--data",
                str(SYNTHETIC / "synthetic_role_train.jsonl"),
                "--allow-synthetic",
                "--epochs",
                "2",
                "--folds",
                "2",
                "--json",
            ]
            + subset_args
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert len(result["results"]) == (2 if "--subsets" in subset_args else 1)
    assert all(0 <= item["aggregate"]["coverage"] <= 1 for item in result["results"])


def test_ablation_rejects_conflicting_selection(capsys):
    assert (
        cli.main(
            [
                "model",
                "ablate",
                "--data",
                str(SYNTHETIC / "synthetic_role_train.jsonl"),
                "--allow-synthetic",
                "--families",
                "structure",
                "--subsets",
                "all",
            ]
        )
        == ConfigError.exit_code
    )
    assert "not both" in capsys.readouterr().err


def test_ui_server_interrupt_shuts_down_cleanly(assessment, monkeypatch, capsys):
    server = Mock()
    server.server_port = 9999
    server.serve_forever.side_effect = KeyboardInterrupt()
    factory = Mock()
    factory.return_value.__enter__ = Mock(return_value=server)
    factory.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("vulnassess.ui.server.UiServer", factory)
    assert cli.main(assessment + ["ui", "--run", "snapshot"]) == 0
    assert "127.0.0.1:9999" in capsys.readouterr().out
    server.serve_forever.assert_called_once()
    factory.return_value.__exit__.assert_called_once()


def test_module_entry_point_passes_main_exit_code(monkeypatch):
    main = Mock(return_value=7)
    monkeypatch.setattr(cli, "main", main)
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("vulnassess", run_name="__main__")
    assert caught.value.code == 7
    main.assert_called_once_with()


def test_iso_date_and_target_errors_are_config_errors():
    with pytest.raises(ConfigError, match="ISO date"):
        cli._iso_date("tomorrow", "expiry")
    with pytest.raises(ConfigError, match="must look like"):
        cli._parse_target("no-colon")
    assert cli._parse_target(r"172.28.0.10:C:\scan.xml:D:\scan.json") == (
        "172.28.0.10",
        r"C:\scan.xml",
        r"D:\scan.json",
    )


def test_artifact_write_failure_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "replace", Mock(side_effect=PermissionError("locked")))
    with pytest.raises(ConfigError, match="cannot write JSON artifact"):
        cli._write_json_payload({"verified": False}, str(tmp_path / "out.json"))
    assert not (tmp_path / "out.json").exists()

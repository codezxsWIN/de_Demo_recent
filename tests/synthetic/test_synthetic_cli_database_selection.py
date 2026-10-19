"""Database selection regressions with synthetic inputs and mocked persistence."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, sentinel

import pytest

from vulnassess import cli, repository

TRAIN_COMMAND = [
    "model",
    "train",
    "--data",
    "synthetic-labels.jsonl",
    "--out",
    "synthetic-model.json",
]
DATABASE_SELECTION_CASES = [
    pytest.param(["--db", "synthetic-global.db"], [], "synthetic-global.db", id="global-only"),
    pytest.param(
        ["--db", "synthetic-global.db"],
        ["--db", "synthetic-local.db"],
        "synthetic-local.db",
        id="subcommand-overrides-global",
    ),
    pytest.param([], ["--db", "synthetic-local.db"], "synthetic-local.db", id="subcommand-only"),
    pytest.param([], [], cli.DEFAULT_DB, id="default-without-selection"),
]


@pytest.mark.parametrize("global_options,training_options,expected_db", DATABASE_SELECTION_CASES)
def test_model_train_parser_preserves_database_selection(
    global_options, training_options, expected_db
):
    args = cli.build_parser().parse_args(global_options + TRAIN_COMMAND + training_options)

    assert args.db == expected_db
    assert args.handler is cli.cmd_model_train


@pytest.mark.parametrize("global_options,training_options,expected_db", DATABASE_SELECTION_CASES)
def test_model_train_registration_routes_to_selected_database(
    monkeypatch, capsys, global_options, training_options, expected_db
):
    examples = [SimpleNamespace(label_source="synthetic", reviewer=None)]
    model = SimpleNamespace(
        model_hash="synthetic-model-hash",
        classes=["database"],
        features=["service:postgresql"],
        training={"groups": 1, "feature_families": ["service"]},
    )
    monkeypatch.setattr(cli.role_model, "load_examples", Mock(return_value=examples))
    monkeypatch.setattr(cli.role_model, "train", Mock(return_value=model))
    monkeypatch.setattr(cli.role_model, "save_model", Mock(return_value="synthetic-model.json"))
    monkeypatch.setattr(cli.role_model, "dataset_hash", Mock(return_value="synthetic-data-hash"))
    resolve_backend = Mock(return_value=sentinel.backend)
    repository_factory = MagicMock()
    registered_repository = repository_factory.return_value.__enter__.return_value
    registered_repository.add_dataset.return_value = "synthetic-dataset-id"
    registered_repository.add_role_model_run.return_value = "synthetic-run-id"
    monkeypatch.setattr(repository, "resolve_backend", resolve_backend)
    monkeypatch.setattr(repository, "AssessmentRepository", repository_factory)

    result = cli.main(
        global_options
        + TRAIN_COMMAND
        + training_options
        + ["--register", "--dataset-name", "synthetic-dataset", "--allow-synthetic", "--json"]
    )

    assert result == 0
    resolve_backend.assert_called_once_with(expected_db)
    repository_factory.assert_called_once_with(sentinel.backend)
    registered_repository.add_dataset.assert_called_once()
    registered_repository.add_role_model_run.assert_called_once()
    dataset_record = registered_repository.add_dataset.call_args.args[0]
    run_record = registered_repository.add_role_model_run.call_args.args[0]
    assert dataset_record["name"] == "synthetic-dataset"
    assert dataset_record["data_kind"] == "synthetic"
    assert run_record["dataset_id"] == "synthetic-dataset-id"
    assert run_record["model_hash"] == model.model_hash
    output = json.loads(capsys.readouterr().out)
    assert output["registered"] == "synthetic-run-id"
    assert output["registered_dataset"] == "synthetic-dataset"

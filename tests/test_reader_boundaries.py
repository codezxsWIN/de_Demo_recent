"""Read-store contracts, using a fake DB transport rather than a remote PostgreSQL server."""

import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from vulnassess import repository
from vulnassess.errors import ConfigError
from vulnassess.ui import drawings, reader


@pytest.mark.parametrize("resolver", [reader.database_url, repository.resolve_backend])
@pytest.mark.parametrize("value", ["env:", "env:INVALID-NAME"])
def test_database_env_reference_requires_identifier(resolver, value):
    with pytest.raises(ConfigError, match="name is invalid"):
        resolver(value)


@pytest.mark.parametrize("resolver", [reader.database_url, repository.resolve_backend])
@pytest.mark.parametrize("value", [None, "sqlite:///wrong", "postgresql://synthetic/assessment"])
def test_database_env_reference_validates_scheme(resolver, value, monkeypatch):
    monkeypatch.delenv("COVERAGE_TEST_DATABASE", raising=False)
    if value is not None:
        monkeypatch.setenv("COVERAGE_TEST_DATABASE", value)
    if value is None or not value.startswith("postgresql:"):
        with pytest.raises(ConfigError):
            resolver("env:COVERAGE_TEST_DATABASE")
    else:
        assert resolver("env:COVERAGE_TEST_DATABASE") == value


def test_default_backend_is_explicit_and_local(monkeypatch):
    monkeypatch.delenv(repository.ENV_VAR, raising=False)
    assert repository.resolve_backend() == Path("data/vulnassess.db")
    monkeypatch.setenv(repository.ENV_VAR, "wrong")
    with pytest.raises(ConfigError, match="not a PostgreSQL URL"):
        repository.resolve_backend()
    assert repository.resolve_backend("explicit.db") == Path("explicit.db")


@pytest.mark.parametrize("value", [r"\\server\share\db", "//server/share/db"])
def test_network_share_refused(value):
    with pytest.raises(ConfigError, match="network share"):
        reader.local_path(value)


@pytest.mark.parametrize("text", ["[]", "null", '{"risk":NaN}', '{"risk":Infinity}', "not-json"])
def test_invalid_stored_json_refused(text):
    with pytest.raises(ConfigError):
        reader._object(text, "evidence")


@pytest.fixture
def pg_transport(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = []
    connect = Mock(return_value=connection)
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    monkeypatch.setitem(
        sys.modules, "psycopg.rows", SimpleNamespace(dict_row="synthetic-row-factory")
    )
    return connection, cursor, connect


def test_pg_read_store_contract_and_cleanup(pg_transport):
    connection, cursor, connect = pg_transport
    row = {
        "run_id": "synthetic",
        "started_at": "2026-10-09",
        "config_hash": "abc",
        "summary_json": {"imports": []},
    }
    with reader.open_read_store("postgresql://synthetic/assessment") as store:
        assert isinstance(store, reader.PostgresReadOnlyStore)
        cursor.fetchall.return_value = [row]
        assert store.runs()[0]["summary"] == {"imports": []}
        assert store.run_info("synthetic")["run_id"] == "synthetic"
        assert cursor.execute.call_args.args[1] == ("synthetic",)
        cursor.fetchall.return_value = []
        with pytest.raises(ConfigError, match="MISSING"):
            store.run_info("missing")
    connection.close.assert_called_once()
    statements = [call.args[0] for call in cursor.execute.call_args_list]
    assert statements[:2] == ["SET TRANSACTION READ ONLY", "SET search_path TO vulnassess"]
    connect.assert_called_once()


def test_pg_run_reports_missing_history_honestly(pg_transport):
    connection, cursor, _ = pg_transport

    def execute(query, parameters=()):
        if "FROM runs WHERE" in query:
            assert parameters == ("synthetic",)
            cursor.fetchall.return_value = [
                {
                    "run_id": "synthetic",
                    "started_at": "2026-10-09",
                    "config_hash": "abc",
                    "summary_json": "{}",
                }
            ]
        else:
            cursor.fetchall.return_value = []

    cursor.execute.side_effect = execute
    with reader.PostgresReadOnlyStore("postgresql://synthetic/assessment") as store:
        payload = store.run("synthetic")
    assert payload["scores"] == [] and payload["findings"] == []
    assert payload["config_hashes"] == {"run_config": "abc", "score_weights": []}
    assert payload["feeds_meta_scope"] == "current_store_not_frozen_per_run"
    assert payload["history"]["limitations"]
    assert payload["refusals"]["status"] == "MISSING"
    connection.commit.assert_not_called()


@pytest.mark.parametrize("value", [None, [], 123, {"unexpected": 1}, '{"unexpected":1}'])
def test_pg_records_require_known_keys(value):
    with pytest.raises(ConfigError):
        reader.PostgresReadOnlyStore._object(value, "hosts", frozenset({"ip"}))


@pytest.mark.parametrize("value", [{"ip": "192.0.2.1"}, '{"ip":"192.0.2.1"}'])
def test_pg_records_accept_dictionary_and_serialized_json(value):
    assert reader.PostgresReadOnlyStore._object(value, "host", frozenset({"ip"})) == {
        "ip": "192.0.2.1"
    }


def test_pg_read_errors_are_wrapped(pg_transport):
    _, cursor, _ = pg_transport
    with reader.PostgresReadOnlyStore("postgresql://synthetic/assessment") as store:
        cursor.execute.side_effect = RuntimeError("PRIVATE connection string")
        with pytest.raises(ConfigError, match="cannot read PostgreSQL") as caught:
            store.runs()
        assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize("factory", [reader.PostgresReadOnlyStore, repository.AssessmentRepository])
def test_pg_connect_error_is_secret_safe(factory, pg_transport):
    _, _, connect = pg_transport
    connect.side_effect = RuntimeError("PRIVATE credentials")
    with pytest.raises(ConfigError, match="cannot open") as caught:
        factory("postgresql://synthetic/assessment")
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize("factory", [reader.PostgresReadOnlyStore, repository.AssessmentRepository])
def test_missing_postgres_driver_is_actionable(factory, monkeypatch):
    monkeypatch.setitem(sys.modules, "psycopg", None)
    with pytest.raises(ConfigError, match="install psycopg"):
        factory("postgresql://synthetic/assessment")


def test_repository_pg_parameterization_and_rollback(pg_transport):
    connection, cursor, _ = pg_transport
    with repository.AssessmentRepository(
        "postgresql://synthetic/assessment", read_only=True
    ) as store:
        assert store._sql("select ? where address={INET}") == "select %s where address=%s::inet"
        cursor.fetchall.return_value = [{"evidence": '{"id":"E1"}'}]
        assert store._rows("select ?", ("untrusted'",)) == [{"evidence": {"id": "E1"}}]
        assert cursor.execute.call_args.args == ("select %s", ("untrusted'",))
        cursor.execute.side_effect = RuntimeError("write rejected")
        connection.rollback.side_effect = RuntimeError("closed")
        with pytest.raises(ConfigError, match="write failed"):
            store._exec("insert into x values (?)", ("synthetic",))
        connection.rollback.assert_called_once()
        with pytest.raises(ConfigError, match="read failed"):
            store._rows("select ?", (1,))
    connection.close.assert_called_once()


def test_sqlite_open_and_snapshot_failures_close_connections(tmp_path, monkeypatch):
    path = tmp_path / "existing.db"
    path.touch()
    monkeypatch.setattr(sqlite3, "connect", Mock(side_effect=sqlite3.OperationalError("locked")))
    with pytest.raises(ConfigError, match="cannot open read-only"):
        reader.ReadOnlyStore(path)
    connection = Mock()
    connection.execute.side_effect = sqlite3.OperationalError("snapshot failed")
    monkeypatch.setattr(sqlite3, "connect", Mock(return_value=connection))
    with pytest.raises(ConfigError, match="cannot begin read-only snapshot"):
        reader.ReadOnlyStore(path)
    connection.close.assert_called_once()


def test_drawing_errors_are_explicit(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="unknown UI drawing"):
        drawings.drawing("../private")
    with pytest.raises(ConfigError, match="no UI building"):
        drawings.building("invented-role")
    with pytest.raises(ConfigError, match="no UI badge"):
        drawings.door("Safe")
    monkeypatch.setattr(drawings, "DRAWINGS", tmp_path)
    with pytest.raises(ConfigError, match="MISSING"):
        drawings.drawing("door")
    (tmp_path / "door.svg").write_bytes(b"\xff")
    with pytest.raises(ConfigError, match="cannot read"):
        drawings.drawing("door")


def test_json_columns_preserve_non_json_and_existing_objects():
    row = {"bad": "{not JSON", "plain": "title", "nested": {"a": 1}, "list": "[1]"}
    assert repository._json_values(row) == {**row, "list": [1]}
    assert repository._encode({"a": 1}, "postgres") == {"a": 1}
    assert json.loads(repository._encode({"a": 1}, "sqlite")) == {"a": 1}

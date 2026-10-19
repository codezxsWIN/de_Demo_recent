"""Import guards reject invalid selections before parsing scanner-controlled XML."""

import pytest

from tests.test_assessment_snapshot import ROOT
from vulnassess.errors import ConfigError, ScopeError
from vulnassess.nessus_import import import_nessus_report
from vulnassess.store import Store


@pytest.mark.parametrize(
    "mode,message",
    [
        ("remote", "only for a local"),
        ("bad-run", "Invalid assessment run"),
        ("scope", "outside explicitly authorized"),
        ("missing-run", "Select an existing"),
        ("duplicate-run", "already exists"),
    ],
)
def test_import_preconditions(tmp_path, mode, message):
    database = tmp_path / "assessment.db"
    if mode == "duplicate-run":
        with Store(database) as store:
            store.connection.execute(
                "insert into runs (run_id, started_at, config_hash) values ('synthetic', '2026-01-01', 'synthetic')"
            )
            store.connection.commit()
    with pytest.raises((ConfigError, ScopeError), match=message):
        import_nessus_report(
            str(database) if mode == "remote" else database,
            ROOT / "config",
            "../bad" if mode == "bad-run" else "synthetic",
            "192.0.2.99" if mode == "scope" else "172.28.0.10",
            b"not parsed",
            new_run=mode == "duplicate-run",
        )

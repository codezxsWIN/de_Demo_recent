"""Inspect existing UI inputs offline without creating or updating a database."""

import json
import sqlite3
from pathlib import Path
from typing import Any


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "data" / "vulnassess.db"
    if not path.is_file():
        print(f"MISSING: {path}")
        return 1
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        }
        print(f"DATABASE: {path}")
        print(f"TABLES: {', '.join(sorted(tables))}")
        if "runs" not in tables:
            print(f"MISSING: runs table in {path}")
            return 1
        for row in connection.execute(
            "SELECT run_id, started_at, config_hash, summary_json FROM runs ORDER BY run_id"
        ):
            summary: dict[str, Any] = json.loads(row["summary_json"])
            print(f"RUN: {row['run_id']}; started_at={row['started_at']}")
            print(f"CONFIG_HASH: {row['config_hash']}")
            print(f"SUMMARY: {json.dumps(summary, sort_keys=True)}")
        for table in ("hosts", "findings", "context_profiles", "scores", "enrichments"):
            if table not in tables:
                print(f"MISSING: {table} table in {path}")
                continue
            rows = connection.execute(f"SELECT json FROM {table}").fetchall()
            keys = sorted({key for row in rows for key in json.loads(row["json"])})
            print(f"{table.upper()}: rows={len(rows)}; keys={','.join(keys)}")
        if "scores" in tables:
            for row in connection.execute(
                "SELECT run_id, finding_id, json, risk, band FROM scores "
                "ORDER BY run_id, risk DESC, finding_id"
            ):
                payload = json.loads(row["json"])
                stored = {
                    key: payload.get(key)
                    for key in (
                        "base_score",
                        "env_score",
                        "risk",
                        "band",
                        "threat_multiplier",
                        "weights_hash",
                    )
                }
                print(
                    f"SCORE: run={row['run_id']}; finding={row['finding_id']}; "
                    f"{json.dumps(stored, sort_keys=True)}"
                )
                if payload.get("risk") != row["risk"] or payload.get("band") != row["band"]:
                    print(f"MISMATCH: score JSON and indexed columns for {row['finding_id']}")
                    return 1
        if "feeds_meta" in tables:
            rows = connection.execute("SELECT * FROM feeds_meta ORDER BY feed").fetchall()
            print(f"FEEDS_META: {json.dumps([dict(row) for row in rows], sort_keys=True)}")
        print(f"FEEDS_DIRECTORY: {'PRESENT' if (root / 'data' / 'feeds').is_dir() else 'MISSING'}")
        fixtures = root / "tests" / "fixtures"
        if fixtures.is_dir():
            print("FIXTURE_FILES:")
            for item in sorted(fixtures.rglob("*")):
                if item.is_file():
                    print(item.relative_to(root).as_posix())
        else:
            print(f"MISSING: {fixtures}")
        print("READ-ONLY INPUT CHECK PASSED")
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())

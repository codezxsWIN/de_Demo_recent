"""Export one local VulnAssess SQLite assessment as idempotent PostgreSQL seed SQL."""

from __future__ import annotations

import argparse
import base64
import sqlite3
from pathlib import Path
from typing import Any

from vulnassess.errors import ConfigError

TABLES = (
    "runs",
    "hosts",
    "cve",
    "findings",
    "finding_runs",
    "enrichments",
    "epss",
    "kev",
    "feeds_meta",
    "context_profiles",
    "scores",
    "rationales",
)
JSON_COLUMNS = {"summary_json", "json"}
INET_COLUMNS = {"ip", "host_ip"}
TIMESTAMP_COLUMNS = {"started_at", "first_seen", "last_seen", "seen_at", "loaded_at"}
DATE_COLUMNS = {"score_date", "file_date"}


def quote(value: Any, column: str) -> str:
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("'", "''")
    literal = f"'{escaped}'"
    if column in JSON_COLUMNS:
        encoded = base64.b64encode(str(value).encode("utf-8")).decode("ascii")
        return f"convert_from(decode('{encoded}', 'base64'), 'utf8')::jsonb"
    if column in INET_COLUMNS:
        return f"{literal}::inet"
    if column in TIMESTAMP_COLUMNS:
        return f"{literal}::timestamptz"
    if column in DATE_COLUMNS:
        return f"{literal}::date"
    return literal


def export(source: Path) -> str:
    lines = [
        "-- Generated from a local assessment. Contains synthetic/authorised records only.",
        "begin;",
    ]
    with sqlite3.connect(source) as connection:
        if (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'run_intelligence'"
            ).fetchone()
            and connection.execute("SELECT 1 FROM run_intelligence LIMIT 1").fetchone()
        ):
            raise ConfigError(
                "PostgreSQL seed export cannot preserve SQLite run history yet; "
                "retain the SQLite database or export an assessment snapshot instead"
            )
        for table in TABLES:
            cursor = connection.execute(f'SELECT * FROM "{table}"')
            columns = [item[0] for item in cursor.description]
            quoted_columns = ", ".join(f'"{column}"' for column in columns)
            for row in cursor:
                values = ", ".join(quote(value, column) for column, value in zip(columns, row))
                lines.append(
                    f"insert into vulnassess.{table} ({quoted_columns}) values ({values}) "
                    "on conflict do nothing;"
                )
    lines.append("commit;")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="SQLite assessment database")
    parser.add_argument("output", type=Path, help="PostgreSQL seed SQL output path")
    arguments = parser.parse_args()
    arguments.output.write_text(export(arguments.source), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

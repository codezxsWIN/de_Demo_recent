"""Additive SQLite observation and intelligence history, shared by both readers."""

import json
import sqlite3
from hashlib import sha256
from typing import Any

from vulnassess.errors import ConfigError

DDL = (
    "CREATE TABLE IF NOT EXISTS finding_observations ("
    "run_id TEXT NOT NULL, finding_id TEXT NOT NULL, json TEXT NOT NULL, "
    "origin TEXT NOT NULL, PRIMARY KEY (run_id, finding_id))",
    "CREATE TABLE IF NOT EXISTS run_intelligence ("
    "run_id TEXT NOT NULL, revision INTEGER NOT NULL, snapshot_hash TEXT NOT NULL, "
    "json TEXT NOT NULL, PRIMARY KEY (run_id, revision))",
)


def encoded(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def exists(connection: sqlite3.Connection, table: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        is not None
    )


def snapshot(connection: sqlite3.Connection, run_id: str) -> dict[str, Any] | None:
    if not exists(connection, "run_intelligence"):
        return None
    row = connection.execute(
        "SELECT revision, snapshot_hash, json FROM run_intelligence "
        "WHERE run_id = ? ORDER BY revision DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    if row is None:
        return None
    if sha256(row["json"].encode("utf-8")).hexdigest() != row["snapshot_hash"]:
        raise ConfigError(f"intelligence snapshot hash mismatch for run {run_id!r}")
    try:
        payload = json.loads(row["json"])
    except (ValueError, TypeError) as error:
        raise ConfigError(f"invalid intelligence snapshot for run {run_id!r}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ConfigError(f"unknown intelligence snapshot schema for run {run_id!r}")
    if payload.get("run_id") != run_id:
        raise ConfigError(f"intelligence snapshot run mismatch for {run_id!r}")
    if (
        payload.get("origin") not in ("native", "legacy_at_migration")
        or payload.get("status") not in ("not_enriched", "captured")
        or not isinstance(payload.get("feeds"), dict)
        or not isinstance(payload.get("enrichments"), list)
        or any(not isinstance(item, dict) for item in payload["enrichments"])
        or (payload.get("matching") is not None and not isinstance(payload["matching"], dict))
    ):
        raise ConfigError(f"invalid intelligence snapshot fields for run {run_id!r}")
    return {**payload, "revision": row["revision"], "snapshot_hash": row["snapshot_hash"]}


def append_snapshot(
    connection, run_id, feeds, enrichments, *, origin="native", status="captured", matching=None
):
    """Caller owns the transaction; identical latest state creates no revision."""
    payload = encoded(
        {
            "schema_version": 1,
            "run_id": run_id,
            "feeds": feeds,
            "enrichments": enrichments,
            "origin": origin,
            "status": status,
            "matching": matching,
        }
    )
    digest = sha256(payload.encode("utf-8")).hexdigest()
    previous = snapshot(connection, run_id)
    if previous and previous["snapshot_hash"] == digest:
        return
    revision = 1 if previous is None else previous["revision"] + 1
    connection.execute(
        "INSERT INTO run_intelligence (run_id, revision, snapshot_hash, json) VALUES (?, ?, ?, ?)",
        (run_id, revision, digest, payload),
    )


def migrate(connection: sqlite3.Connection) -> None:
    """Capture legacy state honestly and atomically; never replace a prior capture."""
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        for statement in DDL:
            connection.execute(statement)
        runs = connection.execute(
            "SELECT run_id FROM runs WHERE run_id NOT IN (SELECT run_id FROM run_intelligence)"
        ).fetchall()
        for run in runs:
            run_id = run["run_id"]
            connection.execute(
                "INSERT OR IGNORE INTO finding_observations (run_id, finding_id, json, origin) "
                "SELECT r.run_id, f.id, f.json, 'legacy_at_migration' FROM finding_runs r "
                "JOIN findings f ON f.id = r.finding_id WHERE r.run_id = ?",
                (run_id,),
            )
            feeds = {
                row["feed"]: {key: row[key] for key in row.keys() if key != "feed"}
                for row in connection.execute("SELECT * FROM feeds_meta ORDER BY feed")
            }
            enrichments = [
                json.loads(row["json"])
                for row in connection.execute(
                    "SELECT e.json FROM enrichments e JOIN finding_runs r ON r.finding_id = e.finding_id "
                    "WHERE r.run_id = ? ORDER BY e.finding_id, e.cve_id",
                    (run_id,),
                )
            ]
            append_snapshot(connection, run_id, feeds, enrichments, origin="legacy_at_migration")


def finding_rows(connection: sqlite3.Connection, run_id: str):
    if exists(connection, "finding_observations"):
        if (
            snapshot(connection, run_id) is not None
            and connection.execute(
                "SELECT 1 FROM finding_runs r LEFT JOIN finding_observations o "
                "ON o.run_id = r.run_id AND o.finding_id = r.finding_id "
                "WHERE r.run_id = ? AND o.finding_id IS NULL LIMIT 1",
                (run_id,),
            ).fetchone()
        ):
            raise ConfigError(f"missing run observation for {run_id!r}; refusing global fallback")
        return connection.execute(
            "SELECT COALESCE(o.json, f.json) AS json FROM finding_runs r "
            "JOIN findings f ON f.id = r.finding_id LEFT JOIN finding_observations o "
            "ON o.run_id = r.run_id AND o.finding_id = r.finding_id "
            "WHERE r.run_id = ? ORDER BY r.finding_id",
            (run_id,),
        ).fetchall()
    return connection.execute(
        "SELECT f.json FROM findings f JOIN finding_runs r ON r.finding_id = f.id "
        "WHERE r.run_id = ? ORDER BY f.id",
        (run_id,),
    ).fetchall()


def status(connection: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    current = snapshot(connection, run_id)
    limitations = []
    if current is None:
        limitations.append(
            "Legacy global records are not frozen per run; original history is unverified."
        )
    else:
        legacy = connection.execute(
            "SELECT COUNT(*) FROM finding_runs r LEFT JOIN finding_observations o "
            "ON o.run_id = r.run_id AND o.finding_id = r.finding_id WHERE r.run_id = ? "
            "AND (o.origin IS NULL OR o.origin <> 'native')",
            (run_id,),
        ).fetchone()[0]
        if legacy or current["origin"] == "legacy_at_migration":
            limitations.append(
                "Legacy state was frozen at migration, not at the original scan; "
                "previously overwritten observations or intelligence cannot be recovered."
            )
        if current["status"] == "not_enriched":
            limitations.append("No intelligence snapshot has been captured for this run yet.")
    return {
        "intelligence_revision": None if current is None else current["revision"],
        "intelligence_hash": None if current is None else current["snapshot_hash"],
        "limitations": limitations,
    }

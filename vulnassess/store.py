"""SQLite persistence. Parametrised queries only; payloads are JSON text."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from vulnassess import run_history
from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Enrichment, Finding, Host, Rationale, ScoreBreakdown

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
    config_hash TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS hosts (
    run_id TEXT NOT NULL, ip TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, ip));
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, host_ip TEXT NOT NULL, tool TEXT NOT NULL,
    json TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_run ON findings (run_id);
CREATE TABLE IF NOT EXISTS finding_runs (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, seen_at TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id));
CREATE INDEX IF NOT EXISTS finding_runs_finding ON finding_runs (finding_id);
CREATE TABLE IF NOT EXISTS enrichments (
    finding_id TEXT NOT NULL, cve_id TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve_id));
CREATE TABLE IF NOT EXISTS context_profiles (
    run_id TEXT NOT NULL, host_ip TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, host_ip));
CREATE TABLE IF NOT EXISTS scores (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, json TEXT NOT NULL,
    risk REAL NOT NULL, band TEXT NOT NULL, PRIMARY KEY (run_id, finding_id));
CREATE INDEX IF NOT EXISTS scores_risk ON scores (run_id, risk);
CREATE TABLE IF NOT EXISTS rationales (
    run_id TEXT NOT NULL, finding_id TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id));
CREATE TABLE IF NOT EXISTS cve (
    id TEXT PRIMARY KEY, json TEXT NOT NULL, cvss31_base REAL, cvss40_base REAL);
CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY, epss REAL, percentile REAL, score_date TEXT);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feeds_meta (
    feed TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL,
    file_date TEXT, rows INTEGER NOT NULL, loaded_at TEXT NOT NULL);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _dumps(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _read_profile(payload: str, run_id: str, host_ip: str) -> ContextProfile:
    """Decode a stored profile without coercing containers or losing its row owner."""
    label = f"context_profiles run {run_id!r} host {host_ip!r}"
    try:
        data = json.loads(payload)
    except (TypeError, ValueError, RecursionError) as error:
        raise ConfigError(f"{label}: invalid JSON") from error
    if not isinstance(data, dict):
        raise ConfigError(f"{label}: profile must be a JSON object")
    if data.get("host_ip") != host_ip:
        raise ConfigError(f"{label}: host_ip does not match the stored row")
    for field in ("role", "exposure"):
        if not isinstance(data.get(field), dict):
            raise ConfigError(f"{label}: {field} must be a feature object")
    features = [(field, data[field]) for field in ("role", "exposure")]
    for field in ("controls", "manual"):
        values = data.get(field, {})
        if not isinstance(values, dict):
            raise ConfigError(f"{label}: {field} must be a feature mapping")
        if any(not isinstance(value, dict) for value in values.values()):
            raise ConfigError(f"{label}: {field} values must be feature objects")
        features.extend((f"{field}.{key!r}", value) for key, value in values.items())
    for field, feature in features:
        evidence = feature.get("evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ConfigError(f"{label}: {field}.evidence must be a nonblank string")
    try:
        return ContextProfile.from_json(data)
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigError(f"{label}: invalid feature field ({error})") from error


class Store:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = Path(path)
        if read_only:
            self.connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(str(self.path))
        self.connection.row_factory = sqlite3.Row
        if not read_only:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.executescript(SCHEMA)
            self.connection.commit()
            try:
                run_history.migrate(self.connection)
            except Exception:
                self.connection.close()
                raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # runs -------------------------------------------------------------
    def start_run(self, run_id: str, config_hash: str) -> None:
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO runs (run_id, started_at, config_hash, summary_json) VALUES (?, ?, ?, '{}') "
                "ON CONFLICT(run_id) DO NOTHING",
                (run_id, _now(), config_hash),
            )
            if cursor.rowcount:
                run_history.append_snapshot(self.connection, run_id, {}, [], status="not_enriched")

    def set_run_summary(self, run_id: str, summary: dict[str, Any]) -> None:
        self.connection.execute(
            "UPDATE runs SET summary_json = ? WHERE run_id = ?", (_dumps(summary), run_id)
        )
        self.connection.commit()

    def run_info(self, run_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        return {
            "run_id": row["run_id"],
            "started_at": row["started_at"],
            "config_hash": row["config_hash"],
            "summary": json.loads(row["summary_json"]),
        }

    # hosts ------------------------------------------------------------
    def upsert_host(self, run_id: str, host: Host) -> None:
        self.connection.execute(
            "INSERT INTO hosts (run_id, ip, json) VALUES (?, ?, ?) "
            "ON CONFLICT(run_id, ip) DO UPDATE SET json = excluded.json",
            (run_id, host.ip, _dumps(host.to_json())),
        )
        self.connection.commit()

    def hosts(self, run_id: str) -> list[Host]:
        rows = self.connection.execute(
            "SELECT json FROM hosts WHERE run_id = ? ORDER BY ip", (run_id,)
        ).fetchall()
        return [Host.from_json(json.loads(row["json"])) for row in rows]

    # findings ---------------------------------------------------------
    def upsert_findings(self, run_id: str, findings: Iterable[Finding]) -> int:
        """Store each finding once, link it to this run, and return how many are new to the run."""
        with self.connection:
            return self._upsert_findings(run_id, findings)

    def _upsert_findings(self, run_id: str, findings: Iterable[Finding]) -> int:
        linked = 0
        for finding in findings:
            self.connection.execute(
                "INSERT INTO finding_observations (run_id, finding_id, json, origin) "
                "VALUES (?, ?, ?, 'native') ON CONFLICT(run_id, finding_id) DO NOTHING",
                (run_id, finding.id, _dumps(finding.to_json())),
            )
            self.connection.execute(
                "INSERT INTO findings (id, run_id, host_ip, tool, json, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET last_seen = ?",
                (
                    finding.id,
                    run_id,
                    finding.host_ip,
                    finding.tool,
                    _dumps(finding.to_json()),
                    finding.first_seen,
                    finding.last_seen,
                    finding.last_seen,
                ),
            )
            cursor = self.connection.execute(
                "INSERT INTO finding_runs (run_id, finding_id, seen_at) VALUES (?, ?, ?) "
                "ON CONFLICT(run_id, finding_id) DO NOTHING",
                (run_id, finding.id, finding.last_seen),
            )
            linked += bool(cursor.rowcount)
        return linked

    def findings(self, run_id: str, host_ip: str | None = None) -> list[Finding]:
        findings = [
            Finding.from_json(json.loads(row["json"]))
            for row in run_history.finding_rows(self.connection, run_id)
        ]
        return [item for item in findings if host_ip is None or item.host_ip == host_ip]

    # enrichments ------------------------------------------------------
    def upsert_enrichment(self, enrichment: Enrichment) -> None:
        self.connection.execute(
            "INSERT INTO enrichments (finding_id, cve_id, json) VALUES (?, ?, ?) "
            "ON CONFLICT(finding_id, cve_id) DO UPDATE SET json = excluded.json",
            (enrichment.finding_id, enrichment.cve_id, _dumps(enrichment.to_json())),
        )
        self.connection.commit()

    def enrichments(self, finding_id: str, *, run_id: str | None = None) -> list[Enrichment]:
        if run_id is not None:
            return self.enrichments_for_run(run_id).get(finding_id, [])
        rows = self.connection.execute(
            "SELECT json FROM enrichments WHERE finding_id = ? ORDER BY cve_id", (finding_id,)
        ).fetchall()
        return [Enrichment.from_json(json.loads(row["json"])) for row in rows]

    def enrichments_for_run(self, run_id: str) -> dict[str, list[Enrichment]]:
        """Read a revision once for bulk ranking/reporting instead of once per finding."""
        captured = run_history.snapshot(self.connection, run_id)
        records = (
            captured["enrichments"]
            if captured is not None
            else [
                json.loads(row["json"])
                for row in self.connection.execute(
                    "SELECT e.json FROM enrichments e JOIN finding_runs r ON r.finding_id = e.finding_id "
                    "WHERE r.run_id = ? ORDER BY e.finding_id, e.cve_id",
                    (run_id,),
                )
            ]
        )
        result: dict[str, list[Enrichment]] = {}
        for record in records:
            item = Enrichment.from_json(record)
            result.setdefault(item.finding_id, []).append(item)
        return result

    def capture_intelligence(
        self, run_id: str, enrichments: list[Enrichment], feeds: dict, matching: dict
    ) -> None:
        """Called inside the enrichment transaction, including for zero matches."""
        if self.run_info(run_id) is None:
            raise ConfigError(f"MISSING: run {run_id!r}")
        run_history.append_snapshot(
            self.connection,
            run_id,
            feeds,
            [item.to_json() for item in enrichments],
            matching=matching,
        )
        self.connection.executemany(
            "INSERT INTO enrichments (finding_id, cve_id, json) VALUES (?, ?, ?) "
            "ON CONFLICT(finding_id, cve_id) DO UPDATE SET json = excluded.json",
            [(item.finding_id, item.cve_id, _dumps(item.to_json())) for item in enrichments],
        )

    def history_status(self, run_id: str) -> dict[str, Any]:
        return run_history.status(self.connection, run_id)

    def intelligence_trace(self, run_id: str) -> dict[str, Any] | None:
        captured = run_history.snapshot(self.connection, run_id)
        return None if captured is None else captured.get("matching")

    # context ----------------------------------------------------------
    def upsert_profile(self, run_id: str, profile: ContextProfile) -> None:
        self.connection.execute(
            "INSERT INTO context_profiles (run_id, host_ip, json) VALUES (?, ?, ?) "
            "ON CONFLICT(run_id, host_ip) DO UPDATE SET json = excluded.json",
            (run_id, profile.host_ip, _dumps(profile.to_json())),
        )
        self.connection.commit()

    def profile(self, run_id: str, host_ip: str) -> ContextProfile | None:
        row = self.connection.execute(
            "SELECT json FROM context_profiles WHERE run_id = ? AND host_ip = ?", (run_id, host_ip)
        ).fetchone()
        return None if row is None else _read_profile(row["json"], run_id, host_ip)

    def profiles(self, run_id: str) -> list[ContextProfile]:
        rows = self.connection.execute(
            "SELECT host_ip, json FROM context_profiles WHERE run_id = ? ORDER BY host_ip",
            (run_id,),
        ).fetchall()
        return [_read_profile(row["json"], run_id, row["host_ip"]) for row in rows]

    # scores -----------------------------------------------------------
    def upsert_score(self, run_id: str, score: ScoreBreakdown) -> None:
        self.connection.execute(
            "INSERT INTO scores (run_id, finding_id, json, risk, band) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(run_id, finding_id) DO UPDATE SET "
            "json = excluded.json, risk = excluded.risk, band = excluded.band",
            (run_id, score.finding_id, _dumps(score.to_json()), score.risk, score.band),
        )
        self.connection.commit()

    def scores(self, run_id: str) -> list[ScoreBreakdown]:
        rows = self.connection.execute(
            "SELECT json FROM scores WHERE run_id = ? ORDER BY risk DESC, finding_id", (run_id,)
        ).fetchall()
        return [ScoreBreakdown.from_json(json.loads(row["json"])) for row in rows]

    # rationales -------------------------------------------------------
    def upsert_rationale(self, run_id: str, rationale: Rationale) -> None:
        self.connection.execute(
            "INSERT INTO rationales (run_id, finding_id, json) VALUES (?, ?, ?) "
            "ON CONFLICT(run_id, finding_id) DO UPDATE SET json = excluded.json",
            (run_id, rationale.finding_id, _dumps(rationale.to_json())),
        )
        self.connection.commit()

    def rationales(self, run_id: str) -> dict[str, Rationale]:
        rows = self.connection.execute(
            "SELECT json FROM rationales WHERE run_id = ? ORDER BY finding_id", (run_id,)
        ).fetchall()
        items = [Rationale.from_json(json.loads(row["json"])) for row in rows]
        return {item.finding_id: item for item in items}

    # feeds ------------------------------------------------------------
    def replace_feeds(
        self,
        cves: list[dict[str, Any]],
        epss: list[tuple[str, float, float, str]],
        kev: list[dict[str, Any]],
        metadata: dict[str, dict[str, Any]],
    ) -> None:
        """Publish one fully validated snapshot without changing captured run evidence."""
        with self.connection:
            for table in ("cve", "epss", "kev"):
                self.connection.execute(f"DELETE FROM {table}")
            self.connection.executemany(
                "INSERT INTO cve (id, json, cvss31_base, cvss40_base) VALUES (?, ?, ?, ?)",
                [
                    (row["id"], _dumps(row), row.get("cvss31_base"), row.get("cvss40_base"))
                    for row in cves
                ],
            )
            self.connection.executemany(
                "INSERT INTO epss (cve, epss, percentile, score_date) VALUES (?, ?, ?, ?)", epss
            )
            self.connection.executemany(
                "INSERT INTO kev (cve, json) VALUES (?, ?)",
                [(row["cveID"], _dumps(row)) for row in kev],
            )
            self.connection.executemany(
                "INSERT INTO feeds_meta (feed, path, sha256, file_date, rows, loaded_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(feed) DO UPDATE SET "
                "path=excluded.path, sha256=excluded.sha256, file_date=excluded.file_date, "
                "rows=excluded.rows, loaded_at=excluded.loaded_at",
                [
                    (feed, row["path"], row["sha256"], row["file_date"], row["rows"], _now())
                    for feed, row in metadata.items()
                ],
            )

    def put_cves(self, records: Iterable[dict[str, Any]]) -> int:
        rows = [
            (record["id"], _dumps(record), record.get("cvss31_base"), record.get("cvss40_base"))
            for record in records
        ]
        self.connection.executemany(
            "INSERT INTO cve (id, json, cvss31_base, cvss40_base) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET json = excluded.json, "
            "cvss31_base = excluded.cvss31_base, cvss40_base = excluded.cvss40_base",
            rows,
        )
        self.connection.commit()
        return len(rows)

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT json FROM cve WHERE id = ?", (cve_id,)).fetchone()
        return None if row is None else json.loads(row["json"])

    def all_cves(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT json FROM cve ORDER BY id").fetchall()
        return [json.loads(row["json"]) for row in rows]

    def put_epss(self, rows: Iterable[tuple[str, float, float, str]]) -> int:
        payload = list(rows)
        self.connection.executemany(
            "INSERT INTO epss (cve, epss, percentile, score_date) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cve) DO UPDATE SET epss = excluded.epss, "
            "percentile = excluded.percentile, score_date = excluded.score_date",
            payload,
        )
        self.connection.commit()
        return len(payload)

    def epss(self, cve_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM epss WHERE cve = ?", (cve_id,)).fetchone()
        if row is None:
            return None
        return {
            "cve": row["cve"],
            "epss": row["epss"],
            "percentile": row["percentile"],
            "score_date": row["score_date"],
        }

    def put_kev(self, records: Iterable[dict[str, Any]]) -> int:
        rows = [(record["cveID"], _dumps(record)) for record in records]
        self.connection.executemany(
            "INSERT INTO kev (cve, json) VALUES (?, ?) "
            "ON CONFLICT(cve) DO UPDATE SET json = excluded.json",
            rows,
        )
        self.connection.commit()
        return len(rows)

    def kev(self, cve_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT json FROM kev WHERE cve = ?", (cve_id,)).fetchone()
        return None if row is None else json.loads(row["json"])

    def put_feed_meta(
        self, feed: str, path: str, digest: str, file_date: str | None, rows: int
    ) -> None:
        self.connection.execute(
            "INSERT INTO feeds_meta (feed, path, sha256, file_date, rows, loaded_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(feed) DO UPDATE SET path = excluded.path, "
            "sha256 = excluded.sha256, file_date = excluded.file_date, rows = excluded.rows, "
            "loaded_at = excluded.loaded_at",
            (feed, path, digest, file_date, rows, _now()),
        )
        self.connection.commit()

    def feeds_meta(self, *, run_id: str | None = None) -> dict[str, dict[str, Any]]:
        if run_id is not None:
            captured = run_history.snapshot(self.connection, run_id)
            if captured is not None:
                return captured["feeds"]
        rows = self.connection.execute("SELECT * FROM feeds_meta ORDER BY feed").fetchall()
        return {
            row["feed"]: {
                "path": row["path"],
                "sha256": row["sha256"],
                "file_date": row["file_date"],
                "rows": row["rows"],
                "loaded_at": row["loaded_at"],
            }
            for row in rows
        }

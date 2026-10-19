# Run-specific history: SQLite increment

## Contract and scope

The stable finding ID identifies a scanner check on an endpoint, not a particular
observation. Each run must retain its own finding JSON (including evidence,
timestamps and provenance). Intelligence used for a run must retain the actual
enrichment values and feed metadata, independently of the mutable feed cache.

This increment covers the core SQLite Store, its scoring/report/snapshot consumers
and the SQLite stored-assessment reader. PostgreSQL and the expanded repository's
operational finding queue are separate follow-up slices. Live capture persistence
and full assessment sealing are Task 1.3, not delivered here.

## Additive storage

- `finding_observations`: one immutable first observation per `(run_id, finding_id)`.
  Original global finding identity rows and run membership remain intact.
- `run_intelligence`: append-only, hash-verified intelligence revisions per run.
  Each revision contains feed metadata, matching decisions and the entire matched enrichment set,
  including an explicitly empty set. New runs begin with an empty, not-enriched
  revision, so another run's CVEs cannot leak into an unassessed run.

Normal reads select the most recent revision **for the requested run**. An explicit
re-enrichment of that same run creates a new revision; old revisions are retained.
An identical write is idempotent. A later run cannot advance an earlier run's
revision. This is cross-run isolation, not a claim that a draft run is sealed:
existing commands may still deliberately update its hosts, context and scores.
Frozen exported assessment bundles remain the immutable whole-assessment artifact.

The existing no-run enrichment API remains a compatibility/cache interface;
historical project readers must pass `run_id`. Feed matching deliberately reads
the current publisher cache, while historical reporting reads recorded metadata.
The scoring formula and authorization behavior are unchanged.

## Migration, provenance and rollback

Writable Store initialization installs the additive tables in a transaction. For
each legacy run without a revision, it freezes the currently available finding
and intelligence records and labels them `legacy_at_migration`. It does not claim
that these values are what the original scan observed; overwritten history cannot
be reconstructed. Reopening does not recapture changed global values.

No existing table, column or artifact is removed or rewritten by migration.
Read-only opening never migrates: an untouched legacy database uses its existing
queries and reports its unfrozen limitation. Expanded repository rows without
core run membership remain outside this migration's guarantee.

Rollback is application rollback with additive tables retained. Old schema queries
remain valid; tests exercise those queries after migration. If a database rollback
is required, stop writers and restore a verified pre-migration SQLite backup;
retain the migrated database separately so new observations/revisions are not lost.
Do not drop the history tables as a rollback shortcut. Migration-failure tests
must prove no partial history tables/rows are committed.

Do not migrate a user's live database as part of verification. Tests use temporary
databases or the repository's generated synthetic fixtures. Back up a real database
with SQLite's backup API before deployment, including any WAL state.

## Consumer map

- `Store.upsert_findings`: write run observations and legacy membership atomically.
- `intel.enrich_run`: compute and persist a complete revision in one transaction;
  retain current global enrichment cache for legacy callers.
- `pipeline.do_rank` / `do_report`: use run-bound enrichment and feed metadata.
- `audit.collect_report_audit`: use the recorded matching trace, not a recomputation
  against today's cache. Legacy runs without a trace disclose its absence.
- `assessment_snapshot.build_snapshot`: bind the selected revision and disclose
  any legacy provenance rather than claiming original historical authenticity.
- `unify.unify_run`, `experiments`, `visual_simulation`: read the requested run.
- `ui.reader.ReadOnlyStore`: use the same history helpers without opening a writer.
- `intel_online`, `intel_status`, live scanning and `trace_run`: intentionally
  inspect current cache or recompute current matching; not historical readers.
- `repository.AssessmentRepository`: its operational lifecycle/intelligence queue
  and PostgreSQL tables are not run-isolated by this increment.
- `ui.reader.PostgresReadOnlyStore`: remains explicitly current-store/legacy.
- `scripts/export_sqlite_seed.py`: must not silently discard new history when
  exporting to the older PostgreSQL schema; refuse until that migration is ready.

## Acceptance

Use two synthetic runs sharing a finding fingerprint but with different raw text,
provenance and intelligence dates/values. After enriching B, regenerate A's report,
assessment bundle and viewer payload and require equality with their saved A values.
Also verify B sees its own observation, empty enrichment stays empty, restart reads
are stable, explicit same-run refresh retains older revisions, tampering is rejected,
legacy reads/backfill are labelled, and failed migration/batch writes roll back.

## Verification status

Implemented on `codex/run-history-isolation`, following Phase 0 at `967782a`.
Twelve new tests cover cross-run isolation, observation provenance, unchanged
report/snapshot/viewer/audit output, empty intelligence, revision retention,
transaction rollback, migration compatibility, hash rejection, missing-observation
rejection, the PostgreSQL export guard and feed-inspector messages.

The first full run exposed an existing self-defence recheck ordering defect:
filesystem modification times can tie or change when records are copied. A
deterministic regression now changes the old record's file timestamp; verified
observations are sorted by their checked-at time before selecting ten results.
Hash validation, unknown-state preservation and the 100-file read bound remain.

Verified 8 October 2026. Implementation commits: `60a36a5` (SQLite history),
`21974a3` (self-defence chronology).

Focused verification: 210 integrated tests plus 461 subtests passed before that
repair; all 30 history/self-defence tests passed after it. Final full suite:
**704 tests and 500 subtests passed in 291.66 seconds; 86.28% coverage**.
Compared with Phase 0: 12 additional tests, 5 additional executed subtests and
coverage up from 86.21% by 0.07 percentage points. The 75% gate is unchanged.
Ruff lint passes; format check reports 195 files already formatted; Pyright
reports zero errors and warnings. The history module has 91% statement coverage
and the core store 97%; these numbers are not proof of production acceptance.

Reproduction commands (from the repository, using its pinned dependencies):

```powershell
python -m pytest -q -p no:hypothesispytest tests/test_run_history.py tests/test_self_defence.py
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-fail-under=75 --durations=5
python -m ruff check .
python -m ruff format --check .
python -m pyright
```

`no:hypothesispytest` disables an unrelated installed plugin blocked by local
Windows App Control; no project tests are skipped. Verification uses Python
3.12.10, pytest 9.1.1, pytest-cov 7.1.0, Ruff 0.16.6 and Pyright 1.1.411.

No live user database migration, target scan, provider request, app restart or
remote push was performed. Real-browser layout inspection and Python 3.11/Linux
CI remain unverified. PostgreSQL history and Task 1.3 live-capture recovery remain
pending; the old PostgreSQL exporter now refuses history-bearing SQLite databases
rather than discarding history. Use retained SQLite or assessment snapshots until
the PostgreSQL migration is implemented.

Large legacy migrations have not been benchmarked. Hashes detect changed payloads,
not an attacker rewriting both data and hashes. Config, same-run context/scores,
raw-file sealing and expanded operational queues are not covered by a blanket
immutability claim. This increment isolates observations and intelligence between
runs; it does not complete the durable-history checkpoint on its own.

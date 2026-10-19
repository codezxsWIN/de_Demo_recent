# VulnAssess assessment store (Supabase PostgreSQL + SQLite fallback)

The database is the evidence backbone of VulnAssess: it keeps authorised scope,
discovery history, scan provenance, finding lifecycle, scoring explanations,
human review, and reproducible research records — for real assessment history,
not only a one-time demo.

## Backends

| Backend | Selected when | Notes |
| --- | --- | --- |
| Supabase PostgreSQL | `VULNASS_DATABASE_URL` is set (backend-only env var), or an explicit `postgresql://` / `env:NAME` value is passed | The supported cloud store. Private `vulnassess` schema, RLS everywhere. |
| SQLite | no env var, local path given | Preserved local fallback, same logical tables via `vulnassess/repository.py`. |

Connection rules:

* Credentials are read from the ignored `.env` / process environment only.
  `.env.example` holds placeholders; real values are never committed.
* All queries are parameterised (`?` for SQLite, `%s` for PostgreSQL). No
  string-built SQL exists in the codebase.
* The dashboard never learns the URL: the UI server opens the store server-side
  (`read_only=True`), and no browser JavaScript contacts Supabase directly.
  `tests/test_assessment_store.py::NoBrowserWriteAccess` asserts the URL never
  appears in a response body and that non-GET verbs are refused (405).

## Schema layout (private `vulnassess` schema)

Migrations live in `db/migrations/` and are applied in filename order by
`scripts/apply_migrations.py` (records each file in
`vulnassess.schema_migrations` with its SHA-256, so re-runs skip applied
files).

* `001_vulnassess_schema.sql` — core pipeline tables (`runs`, `hosts`,
  `findings`, `finding_runs`, `cve`, `enrichments`, `epss`, `kev`,
  `feeds_meta`, `context_profiles`, `scores`, `rationales`).
* `002_assessment_evidence.sql` — run-scoped evidence model
  (`assessment_targets`, `assets`, `services`, `scan_jobs`, `scan_evidence`,
  `model_evaluations`, `audit_events`).
* `003_governance_scope.sql` — `engagements`, scope-entry extensions on
  `assessment_targets` (canary/exclusion kinds), frozen `scope_snapshots`,
  scan-job extensions (operator, tool version, hashes, error summary), and a
  trigger that refuses scan jobs pointed at a canary or exclusion entry.
* `004_asset_inventory.sql` — richer assets (MAC, OS guess, environment) and
  append-only `service_observations` plus `asset_relationships` so service
  changes can be compared between runs and app→database→DC chains stay
  evidence-backed.
* `005_findings_intel.sql` — finding lifecycle columns (severity, confidence,
  port, URL, open/resolved, recurrence), mapping tables `finding_cves`,
  `finding_cwes`, `finding_assets`, and curated `vuln_intel` (CVSS 3.1/4.0,
  EPSS, KEV, exploit maturity, patch references, feed source/date).
* `006_scoring_explainability.sql` — `role_predictions` (features, model hash,
  accepted/rejected/shadow disposition), `context_signals` (every contextual
  input with its evidence), append-only `score_history` (weights hash, CVSS/
  EPSS/KEV/environmental inputs, explanation), and `analyst_suggestions`
  permanently constrained advisory (`check (is_advisory)`).
* `007_review_workflow.sql` — `review_decisions` (append-only reviewer
  decisions), `remediation_tracking` (status + verification run; "verified"
  requires evidence), `comments` (untrusted plain text, length-capped).
* `008_research_evaluation.sql` — hash-pinned `datasets`,
  `ground_truth_labels`, `role_model_runs` (accuracy, macro-F1, per-class,
  coverage, abstention, confusion), `ablation_experiments`
  (cvss_only / cvss_epss / full_context with ranking changes).
* `009_retention_security.sql` — `retention_policies`, the migration ledger,
  and a blanket pass that enables+forces RLS on every table in the schema and
  revokes all rights from `anon`/`authenticated`.

See `docs/MIGRATION_SUMMARY.md` for the one-line-per-table version.

## Data flow

```text
authorised scope (engagements, assessment_targets)
        │  frozen at request time
        ▼
scope_snapshots ──► scan_jobs ──► scan_evidence (hash + excerpt only,
        │                            never the raw export)
        ▼                        │
assets / service_observations ◄──┘
        ▼
findings (+ finding_cves/cwes/assets) ──► vuln_intel (feeds, freshness)
        ▼
role_predictions + context_signals ──► score_history (append-only)
        ▼                                │
review_decisions / remediation / comments│
        ▼                                ▼
dashboard (GET-only) ◄── repository read API
```

Provenance is unbroken: every finding, service observation, and score can be
traced back through `scan_evidence` / `scan_jobs` to the exact scan run that
produced it. A vulnerability is never "confirmed" by the database; confirmation
comes from scanner evidence (finding rows) or a human `review_decisions` row.

## Score history and "why did this move?"

`scores` holds the latest value per run (for the dashboard); `score_history`
appends every calculation with its weights hash, CVSS/EPSS/KEV/environmental
inputs, and the explanation text. `repo.finding_score_history(finding_id)`
returns the full timeline plus `band_transitions` — the direct answer to "why
did this finding move from Medium to High between two runs?".

Model output (role predictions, analyst suggestions) is stored separately from
the authoritative score calculation and is advisory/shadow by default; nothing
outside `score_history` can change a risk value.

## Retention approach

`vulnassess.retention_policies` documents, per sensitive table, the retention
window and its basis (e.g. `scan_evidence` → 365 days, assessment window plus
review year). A backend cleanup job reads the policy table and deletes rows
older than the window using each table's own timestamp; deletions are recorded
in `audit_events`. The seed loads conservative defaults; adjust per engagement.
Raw scanner exports are never stored — only hashes, concise excerpts, parsed
facts, and provenance. Passwords, tokens, keys, student personal data, and
traffic captures are out of scope by policy.

## Setup

1. `cp .env.example .env` and fill `VULNASS_DATABASE_URL` with the Supabase
   **session/transaction pooler** URI (Dashboard → Connect). Never the anon or
   service key.
2. Apply migrations:

   ```bash
   VULNASS_DATABASE_URL="postgresql://..." python scripts/apply_migrations.py
   # --check lists pending migrations without applying them
   ```

3. Optionally load the synthetic demonstration seed (authorised, labelled,
   idempotent):

   ```bash
   psql "$VULNASS_DATABASE_URL" -f db/seeds/synthetic_assessment.sql
   ```

4. Run the dashboard; it prefers the cloud store when the env var is set and
   falls back to SQLite otherwise:

   ```bash
   python -m vulnassess ui --config config          # cloud store
   python -m vulnassess ui --db data/vulnassess.db  # local fallback
   ```

No Supabase CLI is required; the pooler URI speaks plain PostgreSQL, which is
why the backend uses `psycopg` (an existing project dependency) instead of the
Supabase SDK.

## Connecting the UI safely

The server (`vulnassess/ui/server.py`) is GET-only, loopback-bound, and
same-origin checked. New read-only routes backed by the repository:

| Route | Purpose |
| --- | --- |
| `/api/assessment-runs` | engagements with scope/snapshot counts |
| `/api/assets[?run=ID]` | asset inventory |
| `/api/asset/<id>` | asset details + service history + relationships |
| `/api/findings?run=&status=&severity=&decision=&limit=` | findings queue with filters |
| `/api/finding/<id>` | evidence, provenance, CVE/CWE mappings, reviews |
| `/api/finding/<id>/score-history` | score timeline + band transitions |
| `/api/model-evaluations` | role-model metrics and legacy evaluations |
| `/api/ablations` | research/ablation comparison summaries |

All of them open `AssessmentRepository(..., read_only=True)` per request: on
PostgreSQL the connection defaults to read-only transactions, on SQLite the
file is opened `mode=ro` with `PRAGMA query_only = ON`. The browser gets JSON
only; it never sees connection details and cannot write.

## Tests

`tests/test_assessment_store.py` covers:

* static migration guarantees (private schema, RLS + revoke per table,
  canary-scan trigger, advisory-only analyst suggestions),
* backend resolution (env var vs explicit SQLite path),
* repository constraints (canary refusal, append-only service history, score
  history transitions, review-decision checks, CWE prefix, hash-pinned
  research records, audit trail),
* no-browser-write (GET-only routes, filters, 405 on POST/PUT/DELETE, no
  credentials in responses, read-only store refuses writes).

PostgreSQL-specific behaviour (RLS enforcement, inet/jsonb handling) is
exercised by the integration check in `scripts/apply_migrations.py --check`
plus the seed load; run both against a real Supabase project before teaching
with it.

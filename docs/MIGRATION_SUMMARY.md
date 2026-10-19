# Migration summary — what each table is for

One line per table, grouped by migration. All tables live in the private
`vulnassess` schema with RLS enabled and no anon/authenticated grants.

## 001_vulnassess_schema.sql (pre-existing core)

| Table | Why it matters |
| --- | --- |
| `runs` | One row per assessment run (config hash + summary) — the unit everything else links to. |
| `hosts`, `findings`, `finding_runs` | Per-run parsed scan facts; `finding_runs` gives cross-run recurrence without overwriting history. |
| `cve`, `enrichments`, `epss`, `kev`, `feeds_meta` | Offline threat intelligence with feed hashes/dates so enrichment is auditable and fresh. |
| `context_profiles`, `scores`, `rationales` | The dashboard's current per-run context, ranking, and one-line reasons. |

## 002_assessment_evidence.sql (pre-existing evidence model)

| Table | Why it matters |
| --- | --- |
| `assessment_targets` | Approved scope entries per authorisation reference. |
| `assets`, `services` | Discovered hosts and their current services. |
| `scan_jobs`, `scan_evidence` | Every scan request/execution and safe evidence references (hash + excerpt, never raw exports). |
| `model_evaluations` | Early per-run model metrics. |
| `audit_events` | Who did what, when. |

## 003_governance_scope.sql — governance

| Table/object | Why it matters |
| --- | --- |
| `engagements` | Owner, department, authorisation reference, validity window, permitted tools, scan restrictions: the legal fence in the database. |
| `assessment_targets` extensions (`engagement_id`, `entry_kind`, `expires_at`) | Scope entries belong to an engagement; canary/exclusion entries are structurally distinct. |
| `block_non_target_scan_jobs()` trigger | A scan aimed at a canary/exclusion entry is refused by the database itself. |
| `scope_snapshots` | Frozen scope per run: later scope edits never rewrite history. |
| `scan_jobs` extensions (operator, tool_version, error_summary, result_counts, content_sha256) | Complete, hash-pinned scan provenance. |

## 004_asset_inventory.sql — discovery history

| Table | Why it matters |
| --- | --- |
| `service_observations` | Append-only per-run service records (banner, state, TLS, evidence source): service drift between runs is a query, not a loss. |
| `asset_relationships` | Evidence-backed asset graphs (app → database → domain controller). |
| `assets` extensions (`mac`, `os_guess`, `environment`, `source_scan_id`) | Fuller inventory with provenance per observation. |

## 005_findings_intel.sql — findings and intelligence

| Table/object | Why it matters |
| --- | --- |
| `findings` lifecycle columns | Severity, confidence, port/URL, open/resolved, recurrence, owning scan — a canonical finding record. |
| `finding_cves`, `finding_cwes`, `finding_assets` | Many-to-many mappings so multiple tools/sources can support one conclusion. |
| `vuln_intel` | Curated per-CVE intelligence (CVSS 3.1/4.0, EPSS, KEV, exploit maturity, patches, feed source/date) with freshness. |

## 006_scoring_explainability.sql — context and scores

| Table | Why it matters |
| --- | --- |
| `role_predictions` | Host-role output with features, model hash, and accepted/rejected/shadow disposition. |
| `context_signals` | Every exposure/control/criticality/environment/override input with source and evidence. |
| `score_history` | Append-only calculations (weights hash, CVSS/EPSS/KEV/environmental inputs, explanation) — answers "why did this move from Medium to High?". |
| `analyst_suggestions` | Local-LLM output, constrained advisory-only and required to cite stored evidence. |

## 007_review_workflow.sql — human judgement

| Table | Why it matters |
| --- | --- |
| `review_decisions` | Append-only reviewer verdicts with identity, justification, and remediation owner/due date. |
| `remediation_tracking` | Fix status with a verification run; nothing is "verified" without evidence. |
| `comments` | Analyst notes as untrusted plain text (never rendered as HTML). |

## 008_research_evaluation.sql — reproducible research

| Table | Why it matters |
| --- | --- |
| `datasets` | Registered datasets pinned by content hash, synthetic/real-authorised labelled, quality state. |
| `ground_truth_labels` | Labelled truth for host role, exposure, controls, priority. |
| `role_model_runs` | Training/evaluation runs: split, accuracy, macro-F1, per-class metrics, coverage, abstention, confusion matrix. |
| `ablation_experiments` | CVSS-only vs CVSS+EPSS vs full-context, with preserved rankings and changes. |

## 009_retention_security.sql — policy and blanket security

| Table/object | Why it matters |
| --- | --- |
| `retention_policies` | Documented retention window per sensitive table for the cleanup job. |
| `schema_migrations` | Applied-migration ledger (version + SHA-256) making re-runs idempotent. |
| Blanket DO block + revokes | Guarantees RLS (enabled + forced) on every table in the schema and zero anon/authenticated rights, regardless of which migration created the table. |

Seed data: `db/seeds/synthetic_assessment.sql` loads one fully linked
synthetic engagement (labelled, authorised-only, idempotent) so demos and
tests exercise every table above.

# VulnAssess continuation checklist

Plan prepared 7 October 2026 against `366188f`. Phase 0 is verified; the SQLite slice of Tasks 1.1–1.2 and local live-capture review in Task 1.3 are implemented. See [Phase 0](../docs/phase-zero-correctness.md), [run-history isolation](../docs/run-history-isolation.md) and [live-capture recovery](../docs/live-capture-recovery.md) for verification and backend limitations. PostgreSQL history and later phases remain pending.

## Task 0.1 — Restore the current type gate

Description: make the self-defence device-check invariant explicit where live scanner coverage reads the optional payload. Diagnose against the pinned Pyright version before choosing a narrowing/guard.

Acceptance:

- [x] The `live_assessment.py:736` optional-subscript error is reproduced or its environmental difference documented, and corrected.
- [x] Normal and self-defence payload/coverage behavior remains intact.
- [x] No diagnostic suppression, test deletion or gate reduction.

Verification: pinned Pyright, relevant live/self-defence regression tests, lint and format.

Dependencies: none. Likely files: `vulnassess/live_assessment.py`, relevant existing tests. Estimated scope: small.

## Task 0.2 — Preserve remediation boundary semantics

Description: retain inclusive/exclusive vulnerable-end metadata and stop turning an inclusive last-vulnerable version into a fixed-version target.

Acceptance:

- [x] A focused regression demonstrates the inclusive-bound defect; exclusive-bound behavior remains tested.
- [x] Advice uses attributable vendor-fixed information or an explicit verify-vendor-fix instruction; no fabricated next release.
- [x] Existing enrichment reads and canonical score arithmetic remain compatible.

Verification: matcher/schema/fix-text tests; full type/lint/format checks.

Dependencies: none; integrate sequentially with 0.1 if shared files overlap. Likely files: `intel.py`, `schema.py`, `scoring.py`, relevant tests. Estimated scope: medium; split migration work if larger.

## Checkpoint 0 — Verified baseline

- [x] Full offline suite and coverage run for the resulting SHA, with exact counts/percentage: `f988259`, 692 tests + 495 subtests, 86.21% coverage.
- [x] Python 3.11/3.12 results available locally or in CI; missing runtime entry disclosed: Python 3.12.10 verified on Windows, 3.11/Linux CI pending.
- [x] Current coverage requirement preserved; no claim that historical local success proves current CI.
- [x] Report Phase 0 to the user before continuing; later phases have not started.

## Task 1.1 — Define run-specific identity/observation/intelligence contract

Description: map core and expanded repository paths, stable finding IDs, observation bodies, feed/enrichment snapshots and report reads. Write the additive migration/backward-read/rollback design before coding.

Acceptance:

- [x] Contract distinguishes finding identity from each run's raw observation and snapshot-bound intelligence.
- [x] Every existing reader/writer impacted by historical global records is identified.
- [x] Migration preserves legacy rows/artifacts and contains a concrete cross-run isolation test plan.

Verification: design/code-path review and representative legacy-data read cases.

Dependencies: checkpoint 0. Likely files: design note, `store.py`, `repository.py`, `assessment_snapshot.py`, migration directory. Estimated scope: small design task; implementation is separate.

## Task 1.2 — Implement one isolated historical read/write slice

Description: migrate and exercise one core finding/enrichment path so later runs cannot change an earlier run's evidence or joined intelligence.

Acceptance:

- [x] Two runs of the same finding retain distinct observation bodies and dated intelligence (core SQLite).
- [x] The first run's serialized report/snapshot is unchanged after the second write (core SQLite).
- [x] Legacy records remain readable with explicit historical limitations.

PostgreSQL and the expanded operational queue remain separate follow-up slices.
The SQLite-to-PostgreSQL seed exporter refuses history-bearing databases until
equivalent history storage exists; it must not silently drop these records.

Verification: transactional migration, rollback/compatibility and cross-run tests; applicable full gate.

Verified 8 October 2026 at `21974a3`: 704 tests + 500 subtests, 86.28% coverage;
Ruff lint/format and Pyright pass. Windows/Python 3.12 only; Linux/3.11 CI,
live deployment and the full durable-history checkpoint remain pending.

Dependencies: 1.1. Likely files: core store, migration, snapshot/report read integration and tests. Estimated scope: medium per backend; split SQLite/PostgreSQL implementation instead of one large rewrite.

## Task 1.3 — Connect one live capture to recorded review/report

Description: preserve a live case as an attributable frozen assessment and restore it after restart without changing old captures, approvals or scores.

Acceptance:

- [x] Save/reopen/report resolve the same assessment and evidence/intelligence/config hashes for new local live captures.
- [x] AI failure still yields the retained evidence-only result; approval authority is not restored from disk.
- [x] Source capture, intelligence receipt/publisher dates and model-analysis completion are distinguished in the UI/report; opening history does not imply fresh retrieval.

Verification: API/store/report integration and existing stale-response/cooldown tests; real browser inspection where available.

Implemented 8 October 2026 on `codex/live-capture-recovery`: 23 focused recovery
tests pass; isolated Edge checks pass at 320/768/1024/1440 pixels with no console
errors. Existing raw captures are not retroactively certified. Subsequent
recent-memory/Redis reanalysis is not persisted as a new review revision in this
slice. Full-suite results are recorded in the linked verification note.
Final gate: **727 tests + 510 subtests, 86.33% coverage**; Ruff lint/format and
Pyright pass. No live target/model was contacted, no production app was restarted,
and no remote push or merge was performed.

Dependencies: 1.2. Likely files: `live_assessment.py`, `ui/server.py`, report/store adapters and one UI client. Estimated scope: split API/persistence and UI verification into medium slices if necessary.

## Checkpoint 1 — Durable history

Follow-up review: corrected stale feed provenance and partial-enrichment leakage
in explicit saved-CVE refreshes. Successful refresh metadata now follows the new
publisher results; a failed refresh exposes no inherited feed metadata or partial
matching batch. Original captures remain unchanged. See the follow-up section in
[live-capture recovery](../docs/live-capture-recovery.md) for regression evidence.
Replay-provenance verification recorded 9 October 2026: **731 tests + 510
subtests, 86.33% coverage**; lint, format and type checks pass. No live scan,
remote database migration, push or deployment was performed.

These are cross-backend acceptance items. Local SQLite isolation and file-based
restart recovery are implemented; do not treat this as PostgreSQL/operational
queue acceptance or permission to skip the remaining checkpoint review.

- [ ] Later imports/enrichment do not change earlier reports.
- [ ] Restart recovery and legacy compatibility verified.
- [ ] No raw sensitive evidence/secrets enter commits or browser metadata inadvertently.
- [ ] Report and review before real planning/follow-up acceptance.

## Task 2.1 — Verify existing approved planner end to end

Acceptance:

- [ ] No-history/web-history proposals, human edit and new hash validated.
- [ ] Exact approved tool order/budget/target enforced; stale approval/deviation refused.
- [ ] Real bounded local-model-to-approved-run evidence recorded on an explicitly authorized lab.

Verification: existing plan/adversarial suites plus consented real acceptance. Dependencies: checkpoint 1. Likely files: existing plan/live/UI modules and verification note. Estimated scope: small verification first; repairs separately sized.

## Task 2.2 — Verify existing typed follow-up end to end

Acceptance:

- [ ] One approved allowlisted probe returns immutable AI-origin evidence and successful cited reanalysis.
- [ ] Reject/replay/expiry/changed-scope cases remain fail-closed and audited.
- [ ] Original evidence/context/scores unchanged; model/probe failures preserve collection results.

Verification: evidence-request/adversarial/API/client tests plus explicitly approved real capture. Dependencies: 2.1. Likely files: existing request/analyst/server/client modules and verification note. Estimated scope: small verification first; contract repairs separately sized.

## Checkpoint 2 — Existing AI agency accepted

- [ ] Real and mocked results distinguished.
- [ ] Original increments 2–3 acceptance complete, or exact unmet prerequisite reported.
- [ ] No new autonomous agent introduced early.

## Later phase design checkpoints — split before implementation

- [ ] Phase 3: reconciliation annotations/source independence, then candidate-CVE ranking and score exclusion. Original Increment 4.
- [ ] Phase 4: backward-compatible labeled/time-bounded facts, contradictions and metadata monotonicity. Original Increment 5.
- [ ] Phase 5: exploitability vectors and evidence-complete confirmed-finding chains beside scores. Original Increment 6.
- [ ] Phase 6: selective critic, factual disagreement and cited coverage/change conditions. Original Increment 7.
- [ ] Phase 7: per-run usage/cost/deadline ceilings, task routing/cache lineage and durable memory. Original Increment 8.
- [ ] Phase 8: bounded versioned primary-source retrieval with server-issued IDs. Original Increment 9.
- [ ] Phase 9: independently labeled A/B/C holdout, local/cloud model comparison and baseline/ablation reports. Original Increment 10.

For each later phase: specify at most three acceptance checks per small vertical task, affected files, dependencies, real-vs-mocked verification and a report/review checkpoint. Use the detailed prompt as the requirement source; unchecked headings are not permission to skip earlier acceptance.

## Cross-cutting acceptance

- [ ] Existing overview, workflow canvas and side-by-side inspector expose each new result and its provenance.
- [ ] Self-defence retained history reloads; unknown reasons and stale advice are clear; checks stay read-only.
- [ ] Keyboard/mobile/error/partial/stale-event paths verified in a supported real browser or explicitly marked unverified.
- [ ] Repeatable test matrix covers relevant web, network CVE, Nessus import, zero findings, conflict, outage, injection and local device cases.
- [ ] Independent labels are never generated from the model under evaluation.
- [ ] Current operational docs reconciled; dated history and verification preserved.

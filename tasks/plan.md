# Implementation plan: VulnAssess continuation

Prepared 7 October 2026. Reviewed baseline: `366188f` on `main`.

This plan was prepared for the project review and continuation prompt. The subsequent "start" request authorized Phase 0. Its implementation and verification are recorded in [Phase 0 correctness](../docs/phase-zero-correctness.md); later phases remain pending. This plan does not authorize network execution.

## Objective

Complete a defensible AI-based assessment loop across context-aware prioritization, trustworthy reasoning and multi-scanner evidence reconciliation. Keep existing capabilities and make each addition attributable to immutable evidence and measurable against independent truth.

## Inputs and authoritative documents

- [Current implementation status](../docs/IMPLEMENTATION_STATUS_2026-10-07.md)
- [Reusable implementation prompt](../docs/NEXT_IMPLEMENTATION_PROMPT.md)
- [Ordered task checklist](todo.md)
- Existing dated increment notes and `docs/decisions.md`

Old roadmap/handoff documents contain superseded behavior. Current source and the dated status review control this continuation; future implementers must recheck the baseline before editing.

## Architecture constraints

1. Reuse the Python/vanilla-JavaScript application; no framework rewrite.
2. Preserve deterministic human-gated scope, scores and raw provenance.
3. Extend existing stores additively, separating stable identity from run observation and intelligence snapshot.
4. Keep model claims, candidate CVEs and proposed reconciliation beside canonical evidence.
5. Retain evidence-only success and explicit partial/unavailable/review states.
6. Finish existing planner/follow-up acceptance before the requested later reasoning increments.
7. Use existing evaluation foundations early for baselines; expanded benchmark delivery remains the final listed increment.

## Dependency sequence

Phase 0: current CI and remediation correctness

Phase 1: immutable run/snapshot history and live/report integration

Phase 2: real acceptance of existing approved planning and typed follow-up

Phase 3: reconciliation and candidate ranking (original Increment 4)

Phase 4: contradiction-aware context (original Increment 5)

Phase 5: exploitability vectors (original Increment 6)

Phase 6: selective critic/coverage (original Increment 7)

Phase 7: routing/budget/memory (original Increment 8)

Phase 8: source-grounded retrieval (original Increment 9)

Phase 9: expanded reproducible A/B/C evaluation (original Increment 10)

Each phase must be split into small vertical tasks before coding. The checklist deliberately details the first foundation tasks and records later phases as design checkpoints; it does not pretend large later agents are single-session tasks.

## First checkpoint

Repair the optional device-check type error and inclusive vulnerable-end remediation advice. Verify exact pinned tools/full offline coverage for the resulting revision. Stop and report before changing persistence or adding agents.

## Integration approach

Every phase ends with a demonstrable backend-to-UI path, preserved source records and a reportable failure outcome. Canonical writes must be transactional and history-bound. Supplementary evidence uses server-issued identifiers and request-local aliases, never model-created identifiers. Browser/approval state cannot become authority after restart.

The controlled acceptance matrix should contain web overlap, a relevant network CVE, completed Nessus import, no-finding scan, evidence conflict, provider outage, injection attempt and read-only self-defence. A single target is not expected to activate every scanner or intelligence join.

## Risks and mitigations

| Risk | Consequence | Required mitigation |
| --- | --- | --- |
| Historical enrichment is global | Earlier reports can read later intelligence | Snapshot-bound migration, legacy reads, cross-run regression |
| Valid quote does not support prose | Misleading AI recommendations pass content checks | Structured proposition checks, selective critique, independently labeled cases |
| Repeated tools share the same premise | False confidence from apparent corroboration | Source-dependency tracking and independent confirmation labels |
| Exposure is inferred from address class | Wrong protective assumptions or urgency | Separate routability, approved metadata and observed vantage; versioned policy |
| Missing real labels | Unmeasurable research success | Prepare blinded cohorts and disclose unavailable metrics |
| Provider/budget limits | Slow/partial analysis | Explicit usage ceilings and evidence-only completion |
| Additive migration mistakes | Lost evidence or invalid history | Backup/rollback design, transactions and old-data compatibility checks |
| Scope or cloud consent expands silently | Unauthorized collection/disclosure | Existing approval bindings and explicit request-specific permissions |

## Decisions that still need evidence or user choice

- Which controlled owned lab and completed scanner reports will serve as repeatable acceptance data?
- Who supplies independent context truth, duplicate/applicability labels and expert rankings?
- Which provisioned local models and opt-in cloud model can be compared within cost/hardware constraints?
- Which retention/redaction policy applies to raw network and local-device evidence?
- Whether the configured 75% coverage floor should formally return to 85%; no change is made by this plan.
- The policy for confirming candidate findings and accepting deterministic context-mapping changes.

These do not block Phase 0. Do not invent answers or broaden permissions to resolve later prerequisites.

## Deliverable and verification discipline

Maintain dated design/verification notes per slice and update `tasks/todo.md` only when its checks actually pass. Separate software verification, real integration and independent research outcomes. Push/merge only under the relevant user request. The current output is local documentation.

# VulnAssess: prompt for the next implementation session

Prepared 7 October 2026 against `main` at `366188f58731148b2e453a53792c7a53810ce039`.

Copy the section between **BEGIN PROMPT** and **END PROMPT** into the next coding session. The [source-backed status review](IMPLEMENTATION_STATUS_2026-10-07.md) explains the findings behind it. Use [the plan](../tasks/plan.md) and [task checklist](../tasks/todo.md) to track work. Recheck the current commit before relying on line numbers or old verification counts.

Progress after preparation: Phase 0 fixes are recorded in [the correctness note](phase-zero-correctness.md). Follow the checked tasks and verification status rather than reimplementing completed fixes. Later phases remain pending.

---

## BEGIN PROMPT

You are continuing **VulnAssess**, an existing local-first AI-based network vulnerability-assessment tool. Extend the current implementation in small, reviewable, verified increments. Preserve all working scanner/import, intelligence, deterministic priority, audit, comparison, UI and self-defence capabilities.

### Product outcome

The assessment must help an operator understand what is observed, what is supported by independent sources, what is uncertain, why a finding matters on this asset, what to verify/fix next, and what changed after a comparable check.

Deliver all three research objectives together:

**A — Context-aware risk:** infer trustworthy deployment context and show whether it improves expert-aligned prioritization over CVSS-only and CVSS+EPSS.

**B — Trustworthy AI assessment:** make AI useful in approved planning, evidence reconciliation, candidate reasoning, context, exploitability and verification. Measure unsupported claims, wrong CVE matches, missed genuine findings and prompt-injection success. Compare appropriately provisioned small/medium/large local models and a consented cloud baseline without assuming that size guarantees correctness.

**C — Multi-scanner evidence fusion:** produce one clean, evidence-preserving view of overlapping findings, meaningful contradictions and independently corroborated observations. Measure duplicate/false-alert reduction without losing genuine findings.

Self-defence is a separate focused local workflow with clear everyday-language explanations and read-only checks. It contributes device evidence; it must not become an unrelated antivirus suite or obscure network assessment.

### Establish the actual starting point

Read current code and tests before changing anything. Begin with:

- `docs/IMPLEMENTATION_STATUS_2026-10-07.md`, `tasks/plan.md`, `tasks/todo.md`;
- `pyproject.toml`, `scripts/check.py`, `.github/workflows/ci.yml`;
- `settings.py`, `target_intake.py`, `runner.py`, `orchestrator.py`, `live_assessment.py`, `pipeline.py`;
- `schema.py`, `store.py`, `repository.py`, `assessment_snapshot.py`, relevant migrations;
- `readers/`, `intel.py`, `intel_online.py`, `saved_cve_case.py`;
- `context.py`, `context_facts.py`, `control_applicability.py`, `scoring.py`, `cvss31.py`;
- `ai_boundary.py`, `analyst.py`, `scan_plans.py`, `evidence_requests.py`, provider clients;
- `unify.py`, `rescan.py`, evaluation/cohort/role-governance modules;
- `self_defence.py`, `ui/server.py`, affected static clients and tests.

Package modules above are under `vulnassess/`. Inspect the relevant increment docs and `docs/decisions.md` for design history. Some older README/roadmap/handoff statements are obsolete. Treat them as dated records rather than overriding executable behavior or silently rewriting historical verification.

Record branch, SHA, clean/dirty state, available prerequisites and exact current gate failures. Preserve unrelated local work. Use a focused `codex/` branch for code changes unless the user requests a different branch. Do not rewrite authors, discard history, push, merge or change repository visibility as part of feature implementation without the relevant request.

### Current capabilities to reuse

The application already has scoped/pinned live Nmap, applicable bounded Nikto paths, completed Nessus imports, legacy ZAP parsing, a specialized bounded Redis configuration check, offline/fresh CVE intelligence, rule context, finding-scoped control eligibility and deterministic scoring.

It also has strict `analyst.v4` output, trust envelopes, canary rejection, finding/evidence/score checks, server-attached evidence quotations, per-call hashes, bounded finding batches, provider-outage fallback and evidence-only completion. Human-approved hashed scan plans and three typed follow-up kinds already exist. Do not rebuild these capabilities or represent them as newly added.

The expanded database repository, frozen snapshots, conservative grouping/rescan utilities, research metrics and shadow role model are existing foundations. Check their integration; tables or helpers alone do not prove a complete product path.

### Invariants for every increment

1. AI proposes and reasons. The deterministic scope engine and explicit human approval authorize execution. No raw/model text can change scope, select arbitrary flags or launch tools.
2. AI never changes canonical risk numbers, weights, context inputs or confirmed evidence. Advisory facts, candidates and exploitability vectors are stored separately. Any approved deterministic policy change creates a new versioned assessment snapshot.
3. Every AI identifier must come from the request's server-issued inventory. The server may add retrieved candidate CVEs to a later bounded request, but the model cannot invent them.
4. Preserve raw observations, original provenance and historical snapshots. Reconciliation annotates disagreement; it does not replace inconvenient originals or silently drop findings.
5. Every displayed AI claim carries a label, citations, confidence and a verification/change condition where applicable. Hypotheses require concrete verification actions. Confidence is not described as calibrated unless measured.
6. All target-controlled and model-controlled text is untrusted. Preserve escaped/bounded envelopes, strict schemas, safe rendering, source binding, canary diagnostics and independent permissions. A canary is not the sole injection defense.
7. Invalid AI output becomes **Needs review** and is withheld. Scanner success and evidence-only reporting survive AI/provider/validation failure. Do not relax validation to make a demo green.
8. Audit each model generation and decision with model/schema/prompt/input/output hashes, stage, outcome and attributable evidence. Never log secrets; retain sensitive raw evidence only in the intended private local store.
9. Distinguish executed, retained/replayed, not applicable, not in this run mode, failed, waiting and running. No feed/CVE is not a zero threat measurement. No findings is not proof of safety.
10. Apply relevant tools to authorized services. Nessus remains import-only unless a separate API integration is requested. Do not invent CVEs or run a web scanner on Redis to activate all canvas nodes.

### Work order

Start with **Phase 0 only**. Finish it and report its verification before entering the next phase. Continue later phases only after the user authorizes continuation; approval of this overall roadmap is not approval of arbitrary network probes, cloud evidence sharing or scope expansion. Reuse existing user approvals only where their exact target, profile, context and validity still match.

#### Phase 0 — Repair and verify the present baseline

At the reviewed SHA, both repositories' latest CI fail on Python 3.11/3.12 at `live_assessment.py:736`, `reportOptionalSubscript`, because the device-check payload can be typed as `None`. Make the actual self-defence invariant explicit. Do not suppress Pyright, change its severity or weaken tests.

Correct remediation advice: `intel._in_range()` and `Enrichment.version_end` lose whether the vulnerable upper bound is inclusive/exclusive; `scoring.fix_text()` recommends that bound “or later.” Preserve the distinction. An inclusive last-vulnerable version must never become the fixed-version recommendation. Prefer sourced vendor remediation; do not manufacture the next version.

Reproduce the defects with appropriate focused checks before repair. Run lint, format, pinned type checking and the full offline suite/coverage. CI currently has a 75% floor; earlier work measured above 85%. Preserve the configured floor, report the actual number and avoid unexplained regression. Validate Python 3.11/3.12 compatibility using available runtimes or CI; disclose any matrix entry not exercised.

Acceptance: the optional-value error is gone under the pinned checker; inclusive/exclusive/unknown remediation cases behave correctly; no canonical score changes; no gate weakened; full results and coverage measured for the actual revision.

Stop and report Phase 0. Do not jump to new agents while main's current quality gate is unresolved.

#### Phase 1 — Establish durable, snapshot-specific assessment history

Inspect existing core and expanded stores before designing migration. Retain stable finding identities, but store separate immutable observations per run, and bind enrichment/feed records to the assessment snapshot. Current global enrichment replacement must not alter an older report; repeat findings must preserve the new evidence body rather than merely link the first body again.

Unify live capture, explicit save, recorded review and report around an attributable assessment ID and frozen configuration/weights/intelligence/raw hashes. Preserve private unique raw captures, recent retry behavior and evidence-only success. AI results attach to the evidence snapshot and are invalidated as current advice when inputs change. Approval state must never be restored as authority merely because it exists in a file.

Use additive migrations, transactional writes and legacy-read compatibility. Do not rebuild the entire persistence layer or pretend hashes are administrator-proof signatures. Show the source run/capture time separately from fresh intelligence retrieval time and AI analysis time.

Acceptance: assessment A's evidence/intelligence/score/report stay unchanged after assessment B imports or enriches the same finding; a new run retains its own changed observation; recovery after restart requires no rescanning; report and UI resolve the same snapshot; old data remains readable.

#### Phase 2 — Finish existing planning and follow-up acceptance

Keep the existing Nmap/Nikto planner and three follow-up kinds: `tcp_connect`, `http_head`, `tls_inspect`. Verify a minimal no-history plan, observed-web plan, edited hash, stale/replayed approval, changed scope and tool timeout/order handling.

On an explicitly authorized controlled lab, demonstrate one real model proposal, human approval, fixed bounded observation, immutable AI-origin artifact and a subsequent validated evidence-aware analysis. If model evidence transport fails, retain the observation and show its outcome. Invalid output must remain rejected. DNS/SNI/paths/arbitrary flags are not part of the current request contract; describe those limits instead of quietly expanding it.

Acceptance: no I/O before approval, exact pinned-target enforcement, one-use/expired/stale approvals refused, rejection reason audited, follow-up evidence cited by a new request-local ID with source/raw-hash/time binding, original scores/evidence unchanged. Record real model and probe results separately from mocks. Never mark missing real acceptance complete because the unit suite passes.

This closes acceptance gaps in existing increments 2–3; it does not introduce autonomous adaptive scanning.

#### Phase 3 — Original Increment 4: evidence reconciliation and CVE candidates

Add structured, audited annotations for conflicting versions, missing fingerprints, duplicate candidates and corroboration. Reuse `unify.py` and its source-preservation checks. Explicitly record source independence: repeated imports or tools relying on the same banner/upstream result are not independent confirmations.

Have the server supply candidate CVE IDs and their attributable records; the AI ranks only those as strong/weak/rejected, with supporting/contradicting evidence and verification conditions. Preserve deterministic matching as a baseline. A banner/CPE version range or scanner-asserted CVE is not equivalent to a behavior-confirmed finding.

Store candidate/disputed/confirmed dispositions separately with immutable review events. Define who/what can confirm a candidate. Advisory candidates and rejected matches must never enter canonical score inputs without a reviewed deterministic confirmation policy.

Acceptance: disagreeing scanner versions retain both originals and a reason; contradictory behavior can reject a nominal version match; all raw IDs remain covered exactly once by grouping or explicit unresolved state; no finding silently disappears; candidate-only CVEs cannot change scoring. Add hand-labeled overlap/conflict cases and keep model judgments out of their own answer key.

#### Phase 4 — Original Increment 5: multi-signal context

Add a backward-compatible fact model with observed/inferred/hypothesis/unknown label, reason code, evidence IDs, source, confidence, `as_of`, maximum age/stale state and contradiction references. Consume existing banners, approved metadata and available verified HTTP/TLS/DNS/behavior records. Any new collection kind requires its own bounded contract and human review; do not fetch opportunistically.

Distinguish globally routable addresses, reachability from a known vantage, network role and approved exposure. Surface conflicts instead of averaging them. Heuristics must never reduce exposure below approved metadata. Preserve the finding-scoped controls fence: one port's auth/WAF signal cannot protect another service, and headers do not prove mitigation.

Keep AI context reasoning advisory. Any change to canonical deterministic inference/mapping needs an explicit policy version, regression/ablation evidence and a new snapshot.

Acceptance: stale facts are visible and cannot quietly earn protective credit; conflicting signals remain cited; missing reason/provenance is rejected; exposure monotonicity and cross-port protection tests pass. Evaluate no-manual-tag inference with independent host truth using existing `context_eval.py`.

#### Phase 5 — Original Increment 6: exploitability beside priority

Produce a structured vector per finding: observed/unknown reachability, required authentication, network position, user interaction, other preconditions and chain potential. Chains reference confirmed findings and evidence for every link; they remain hypotheses until their prerequisites are established.

Show vectors beside deterministic risk and explain what a vector changes in the verification plan. Do not execute exploit chains or compute a hidden replacement score.

Acceptance: missing/unconfirmed links rejected, every link attributable, unknown preconditions preserved, original score hash unchanged. Tests include a plausible but unsupported chain and one complete labeled evidence chain.

#### Phase 6 — Original Increment 7: selective critic and coverage

Use a critic only for predefined high-impact/low-confidence cases within a measured budget. Compare structured propositions and support, not exact prose equality. The existing single-sample `verify_consistency()` call is not self-consistency sampling.

Require each surviving claim's evidence, label, confidence and `what_would_change_it`. Feed that common field through schemas/UI with legacy compatibility. A deterministic verifier remains the boundary for IDs, quote/source association and scores; a second model is an additional challenge, not a truth oracle.

Coverage reports identify unobserved services/checks, truncated evidence, failed tools, disputed facts and unverifiable preconditions, with in-scope verification steps tied to recorded omissions. Distinguish schema/content alignment from semantic entailment in UI wording.

Acceptance: materially conflicting samples/critic verdicts route to review with no silent selection; real quotations supporting the wrong conclusion are challenged; blind spots are first-class; overhead and validation failures are reported against the current one-call baseline.

#### Phase 7 — Original Increment 8: routing, budgets and target memory

Extend existing availability fallback into explicit task-tier routing, input/output token accounting where providers expose it, estimated-vs-measured cost, deadlines and per-run ceilings. Cache keys bind model, schema, prompt, evidence, intelligence and policy versions. A budget exhaustion is a disclosed outcome, not partial success.

Use verified prior snapshots for the same authorized asset to explain changes. Do not treat old evidence as current or prior model output as new raw evidence. Keep cloud sharing opt-in and local-only operation local.

Acceptance: ceilings prevent extra calls; changed inputs invalidate cache; retries/fallback/critique/batches are included in total usage; cross-target memory is excluded; user can see actual provider, age and cost/usage limitations.

#### Phase 8 — Original Increment 9: source-grounded retrieval

Add bounded retrieval of versioned vulnerability records/vendor advisories/configuration baselines/technique corpora. Start with attributable primary sources and preserve source URL, date, version/hash and license/retention rules. Returned items receive server-issued IDs before entering model requests and remain untrusted content.

Acceptance: a claim's retrieved source can be inspected; unprovided corpus/CVE IDs are rejected; changed/stale/conflicting sources are explicit; corpus text cannot execute tools or change instructions. Do not build a large generic vector platform before demonstrating useful retrieval on the labeled cases.

#### Phase 9 — Original Increment 10: reproducible A/B/C benchmark

Reuse cohort/evaluation/ablation/stability/governance code. Extend it with a gold corpus of authorized real captures plus separately labeled adversarial/synthetic cases. Independently adjudicate asset context, vulnerability applicability, duplicate groups, false alerts, important findings, expert ranks and supported/unsupported claims. Split by independent asset/environment, not by duplicated alerts or cloned hosts, before tuning.

For A report role/exposure/control accuracy, abstention/coverage, expert tau-b, NDCG@10, tie-inclusive critical queue at full recall, context/threat ablation and stability.

For B report citation/source accuracy, unsupported-claim rate, wrong CVE matches, missed or wrongly suppressed genuine findings, injection-following rate, review/validation completion, cost and latency by model. Define denominators and distinguish emitted errors from fail-closed abstention.

For C report pair/group merge precision and recall, duplicate reduction, independent corroboration, false-alert reduction and genuine-finding retention. Do not claim that reduced alert count is an improvement when a real finding was lost.

Freeze evaluation choices before inspecting holdout labels. Human labels are external prerequisites; do not create synthetic “expert” answers or claim a nonexistent research gain. A zero/undefined denominator stays unavailable.

Acceptance: reproducible dataset/config/model/feed hashes, blinding, complete source-to-group mapping, unseen holdout, baseline/ablation output and published failures. A new reasoning feature is merge-ready only when its defined software checks and relevant labeled benchmark pass; missing real truth remains disclosed.

### Presentation and self-defence requirements throughout

Integrate each finished slice into the current overview and side-by-side evidence inspector. Surface the decision, evidence, context contribution, unknowns and next action without hiding them in node details. Preserve the draggable canvas as an explanation of dependencies, with progress driven by real events.

Self-defence should restore retained history on reload, distinguish original assessment from targeted rechecks and expose sanitized reasons for unknown checks. A later bounded delta-analysis flow must mark old AI advice as stale until validated. Keep Windows queries read-only/no elevation, and do not infer compromise or internet exposure from a listener, registration record or scan absence alone.

Verify keyboard use, focus, contrast, narrow-screen stacking, empty/error/partial states and stale asynchronous responses in the real supported browser. Rendering mocks do not establish visual or usability acceptance. If browser tools cannot inspect it, report that limit instead of bypassing a tool restriction or claiming verification.

Use a repeatable authorized test matrix rather than one target expected to activate every module: a web lab for Nmap/Nikto and overlap; an appropriate network CVE case for intelligence; a completed Nessus fixture for import; conflict/zero-finding/outage/injection cases; and the local-device flow. Record which operations executed now and which used retained captures.

### Working discipline and handoff

Each slice includes a short design note, focused implementation, relevant regression/adversarial tests, real acceptance where needed and a concise status report. Define the schema/state contract before parallelizing components that share it. Do not reduce protections, remove modules, migrate frameworks, install scanners or introduce new agents outside the roadmap merely to make the canvas busy.

Report: built, changed files, exact test/gate/coverage results and delta, real-vs-mocked verification, unresolved risks, deferred work and next slice. Include the revision for every result. Never equate pushed code, schema-valid JSON, one successful model replay or passing unit tests with independently verified assessment quality.

Immediate instruction: start with Phase 0, restore the gate and remedy-version correctness, then report before proceeding.

## END PROMPT

# VulnAssess implementation audit and remaining work

Review date: 7 October 2026. Reviewed source baseline: `366188f58731148b2e453a53792c7a53810ce039`, branch `main`.

This review covers the main execution paths, schemas, persistence, scanner adapters, intelligence, context/scoring, AI boundaries, planning/follow-up interfaces, self-defence, UI state handling, evaluation infrastructure and verification records. It is a source review with read-only GitHub CI inspection. No new scanner, model, probe, installation, database migration or application-code change was performed for this audit. Existing local captures and secret files were not opened or published.

The companion [implementation prompt](NEXT_IMPLEMENTATION_PROMPT.md) is intended for a future coding session. [The plan](../tasks/plan.md) and [task checklist](../tasks/todo.md) make its ordering explicit.

Subsequent implementation: [Phase 0 correctness and verification](phase-zero-correctness.md). The audit below remains a record of the original reviewed baseline; use the follow-up note and checklist for current progress.

## 1. What the project is today

VulnAssess is a local-first, authorized vulnerability-assessment workbench with working deterministic analysis and optional bounded AI participation. Its executable AI participation currently includes advisory assessment, human-reviewed scan proposals and human-reviewed follow-up observation proposals. Those are real code paths; their existence does not establish the quality of the reasoning or reliability of every end-to-end integration.

The intended finished product answers five questions:

1. What assets, services and weaknesses were actually observed, and by which tools?
2. Which observations describe the same underlying problem, and where do sources disagree?
3. Why is a finding important on this particular asset, using context and dated threat intelligence?
4. What evidence is still missing, and which bounded check would reduce that uncertainty?
5. What should the operator verify or fix first, and what changed after a comparable recheck?

The three research themes remain relevant together:

- **A — Context Is Not Free:** accurate evidence-derived context and demonstrably better prioritization.
- **B — Trust but Verify:** useful AI conclusions whose grounding, false matches, missed findings and injection resistance are measured.
- **C — Fragmented Evidence:** justified consolidation across scanners without discarding genuine problems.

The largest remaining contribution is the reasoning-and-evaluation layer joining these themes. Additional animation or simply executing more scanners cannot establish it.

## 2. Architecture map

| Layer | Main source | Current responsibility |
| --- | --- | --- |
| Entry and configuration | `cli.py`, `settings.py`, `target_intake.py` | Commands, strict config, authorization checks, target resolution and literal-IP pinning |
| Collection | `runner.py`, `orchestrator.py`, `live_assessment.py`, `redis_probe.py` | Fixed scanner commands, bounded live paths, applicable web checks, one specialized Redis configuration check |
| Normalization | `schema.py`, `readers/` | Nmap XML, Nikto JSON, Nessus XML and retained ZAP JSON support |
| Intelligence | `intel.py`, `intel_online.py`, `intel_status.py`, `saved_cve_case.py` | Explicit/CPE matching, traces, offline snapshots, per-CVE public lookups and saved-capture refresh |
| Context and priority | `context.py`, `context_facts.py`, `control_applicability.py`, `cvss31.py`, `scoring.py` | Rule/manual facts, finding-scoped control eligibility, deterministic CVSS 3.1 Environmental/project priority |
| AI boundary and analysis | `ai_boundary.py`, `analyst.py`, `explain.py`, provider modules | Untrusted envelopes, schemas, scoped citations, numeric checks, audited generation, bounded batches and availability fallback |
| Human-reviewed AI participation | `scan_plans.py`, `evidence_requests.py` | Typed proposals, approval hashes, one-use execution and separately attributed supplementary evidence |
| Persistence | `store.py`, `repository.py`, `assessment_snapshot.py`, `db/migrations/` | Core SQLite store, expanded SQLite/PostgreSQL repository, frozen exported bundles |
| Comparison and research | `unify.py`, `diff.py`, `rescan.py`, `cohort.py`, `evaluate.py`, `context_eval.py`, `experiments.py`, role/model governance modules | Conservative grouping, comparable observation diffs, blinded cohorts, ranking/context metrics, ablation, shadow learned roles |
| Presentation | `report.py`, `ui/server.py`, `ui/static/` | Printable HTML, offline workbench, live API, vanilla-JavaScript workflow, visible context/insights and self-defence inspector |
| Self-defence | `self_defence.py`, `ui/static/self-defence.js` | Read-only local Windows protection checks, inventory, action explanations and targeted recheck history |

This is a Python package with a custom loopback HTTP server and browser JavaScript/CSS. A React rewrite is not a prerequisite. `pyproject.toml` declares Python 3.11+, package version 0.2.0, and PyYAML, packaging and psycopg dependencies.

## 3. Capability status

| Capability | Built | Important qualification / remaining work |
| --- | --- | --- |
| Deterministic scope and canary fence | Yes | Different paths also require a named asset or test environment. A permitted CIDR, URL and scanner profile are not interchangeable permissions. |
| Live Nmap | Yes | Light top-100 TCP discovery plus bounded requested-port handling; not comprehensive network vulnerability detection. |
| Nikto | Yes | Applicable authorized web paths and local dependencies; reproducible committed real Nikto fixture/provenance is still missing from its fixture directory. Historical local runs do exist in notes. |
| Nessus | Import path | Completed `.nessus` exports, target validation and preserved plugin evidence. No app-operated live Nessus scanning. |
| ZAP | Existing reader / legacy paths | Preserve import compatibility. Do not reinstate it as a mandatory live tool or introduce OpenVAS without a separate request. |
| Redis CVE example | Yes, narrow | Historical bounded Lua-configuration evidence demonstrated a CVE/intelligence/priority join; not exploitation, general Redis coverage or proof that the lab still has that condition. |
| NVD / EPSS / CISA KEV | Yes | CVE-specific joins, dates and cache provenance; not a detector or universal catalog scan. A service-only scan may have no eligible lookup. |
| Context inference | Yes, rule-based | Weighted service/banner/OS rules, configured metadata and IP/vantage exposure heuristics. No complete multi-signal, contradiction-aware, expiring fact model. |
| Finding-scoped controls | Yes | Avoids borrowing WAF/auth/TLS signals from unrelated services. Observed headers still do not prove mitigation. |
| Deterministic scoring | Yes | CVSS 3.1 implementation, frozen weights/input records, native-severity fallback. CVSS 4 data can be retained but a canonical CVSS 4 scoring engine is not delivered. |
| AI analysis | Yes | Local Ollama plus configured cloud providers, structured advisory output. Validated IDs and quotations do not prove semantic entailment or calibrated confidence. |
| Scan survives AI failure | Yes | Evidence-only completion, rejected AI withheld, attempts shown. Preserve this behavior. |
| AI scan planner | Yes | Maximum baseline Nmap plus one supported web step, fixed profiles and approval binding. Real planner-to-approved-scanner acceptance remains undocumented. |
| Typed AI evidence requests | Yes | TCP connect, HTTP HEAD and TLS inspection, immutable supplementary artifacts and reanalysis. Complete real approved probe-to-analysis acceptance remains undocumented. |
| Finding consolidation | Conservative utility | Same host/service/instance plus shared CVE groups; CWE/title similarity remains a candidate. The utility is exposed through CLI, not integrated into live ranking as a lossless semantic fusion engine. |
| Learned roles | Shadow / governance tooling | Synthetic train/validation assets and promotion checks exist. Independent host labels and canonical learned-context activation are not established. |
| Comparison / remediation | Partial | Conservative rescan outcomes including `fixed_candidate` and `not_observable`; no general automatic proof of remediation. |
| Per-target memory | Partial | Recent in-process live cases, limited stored history for planning, retained captures and separate recheck files. No unified durable assessment memory/report lifecycle. |
| Exploitability vectors, critic, semantic reconciliation, candidate-ranking agent, RAG | Not implemented as the requested agents | Existing prose correlations, CPE traces and coverage frames are not substitutes for these stages. |
| Research evaluation | Infrastructure exists | Ranking/context/cohort/ablation modules; independent gold labels and measured A/B/C outcomes remain missing. |
| Self-defence | Focused local feature | Nine Windows settings plus network/antivirus/listener/update observations; not antivirus, malware detection or a full endpoint-security suite. |

## 4. Concrete findings from this review

### 4.1 Latest main CI is failing on both repositories

The 6 October CI runs for the reviewed SHA failed in both Python 3.11 and 3.12 at:

`vulnassess/live_assessment.py:736:55 — Object of type "None" is not subscriptable (reportOptionalSubscript)`.

The code assigns optional `device_check` into the payload and accesses its limitations under the self-defence branch without a narrowing that the pinned CI checker accepts. This is a type-gate failure; this review did not establish a crashing real-device run.

Lint and formatting passed. The test/coverage step was skipped after Pyright failed. These runs cannot be reported as a passing release:

- [privwork CI run](https://github.com/codezxsWIN/privwork/actions/runs/37475199433)
- [de_work CI run](https://github.com/codezxsWIN/de_work/actions/runs/37475215378)

First implementation task: make the actual invariant explicit and verify the pinned checker; do not silence the check or lower the gate.

### 4.2 Fix-version advice loses vulnerable-range boundary semantics

`intel._in_range()` preserves an end version but returns the same string for `versionEndIncluding` and `versionEndExcluding`. `Enrichment.version_end` has no boundary-kind field. `scoring.fix_text()` then says to upgrade to that version “or later.”

For an inclusive vulnerable end, that advice can recommend a version that is still vulnerable. This is a source-established correctness issue; a reproduction test and repair have not been performed in this review. Preserve inclusive/exclusive information and prefer an attributable vendor-fixed version. Never invent the next release by incrementing a version string.

The matcher also deserves later review for unknown versions, explicit scanner CVE assertions and package/backport-specific applicability. A CPE/version match is evidence for a candidate, not universal proof of a vulnerable runtime.

### 4.3 Historical assessment isolation is incomplete

In the core store:

- Findings are stable global identities. A repeat links the identity to another run but retains the original JSON instead of storing a separate observation body.
- Enrichments are keyed by finding/CVE, not run/snapshot, and can be replaced by later enrichment.
- `assessment_snapshot.py` explicitly states that an exported bundle freezes the state at export time, not the historical state before export.

Thus there are two separate risks: later observations may not be represented in the old identity's stored JSON, and later intelligence may appear when reading an earlier run. Expanded append-only repository tables exist, but their presence does not mean all live/core paths use them correctly.

The live path retains unique raw directories, `case.json` and hash manifests before AI. It does not create a recorded assessment or printable report through the normal database/report path. Its recent-case cache expires after ten minutes and disappears on restart. Saved-CVE review supports a narrower retained-capture use case, not general recovery of all live assessments.

Before durable memory, cross-run reasoning and scientific evaluation, establish run-specific observations and snapshot-bound intelligence. Use additive migration and preserve existing artifacts.

### 4.4 Self-consistency is currently a single-sample check

`analyst.validate_grounding()` calls `verify_consistency([result['claims']])`. There is no second independent sample in that call, so it cannot detect disagreement. The helper compares exact serialized claim lists, which would also conflate harmless paraphrasing with factual conflict if simply invoked with several prose samples.

Actual selective review needs bounded independent analysis and structured fact comparison. Implement it at the critic increment, with explicit disagreement states and measured cost; do not describe the current call as multi-agent verification.

### 4.5 Citation alignment is not semantic claim verification

The boundary validates IDs, scopes findings, rejects fabricated submitted quotations and checks numeric scores. In the current analyst schema, quotations can be attached server-side from the model-selected evidence IDs. This removes quote-copying failure, but also means a perfectly real quote can still be cited for a conclusion it does not establish.

For example, a valid service or role citation cannot establish that all administrative endpoints require authentication. Fixed assertion patterns catch some mistakes, not every unsupported assurance. Build structured claim-to-fact checks and a selective critic over labeled counterexamples; retain raw evidence and label any residual semantic uncertainty.

Confidence values are constrained to a range, not calibrated. Neither a high overall confidence string nor a schema-valid number is a measured probability of correctness.

### 4.6 Context remains narrower than the intended research claim

`infer_exposure()` uses approved external-vantage tags or global-IP classification; otherwise it returns internal. This is not a measured reachability/topology model. A private address may have port forwarding, and a global address may be inaccessible from a particular vantage.

`Feature` carries value, confidence, source and evidence, but lacks the proposed common reason code, observation/inference label, `as_of`, maximum age, stale state and contradiction links. Role selection chooses the highest rule score; competing signals are not retained as an explicit contradiction set.

The next context increment should distinguish facts such as routability, observed reachability and approved exposure. Any scoring mapping change needs a versioned deterministic policy and new snapshot; AI annotations must remain beside canonical values.

### 4.7 Self-defence rechecks are retained but incompletely surfaced

Recheck files and history exist. Browser state keeps them across action selection/rerender, but the current module does not initially load that history on page refresh; history is returned with the next recheck. The original AI advice is explicitly stale after a recheck, with no validated delta-analysis flow.

Unknown checks should expose useful sanitized failure/capability reasons. The full collector has a global timeout and retains checkpoints, but this is not per-check cancellation/progress. A listener bound to all interfaces does not prove internet reachability; installed antivirus registration does not prove active protection; a latest hotfix date does not prove complete patching.

### 4.8 Documents disagree about the current product

Examples include the README's old “two dependencies”/“runtime never reaches the network” statements, legacy planner/follow-up status, early test counts and historical handoff claims. The current manifest declares three dependencies and the live path intentionally contacts authorized targets and approved providers/publishers.

Preserve dated history, but add an authoritative current capability/status index. Update operational docs only after verifying the corresponding path. Do not let a future agent rebuild an existing feature because it read an obsolete roadmap first.

## 5. Status of the requested ten AI increments

| Increment | Current position | Next required acceptance evidence |
| --- | --- | --- |
| 1 — Boundary | Substantial implementation | Current full gate, semantic limitations made explicit, regression coverage for existing bugs; canary is not a complete defense |
| 2 — Approved plan | Implemented | Real bounded local-model proposal, edit/hash invalidation, approval and runner result with preserved evidence |
| 3 — Typed requests | Implemented, real integration unverified | Approved real lab observation, provenance/integrity and subsequent validated analysis; rejection, scope and stale-request controls demonstrated |
| 4 — Reconciliation/CVE ranking | Pending | Separate annotations/candidates, originals retained, no candidate leakage into canonical scoring |
| 5 — Context reasoning | Pending beyond existing rules/controls | Multi-signal contradictions, reason codes, freshness and monotonicity against approved metadata |
| 6 — Exploitability | Pending | Vectors beside scores, confirmed-finding chain links and evidence for every link |
| 7 — Critic/coverage | Pending | Selective challenge, actual disagreement handling, cited coverage gaps and measured overhead |
| 8 — Routing/budget/memory | Partial prerequisites | Task routing, usage/cost ceilings, cache lineage and durable snapshot-specific target memory |
| 9 — RAG | Pending | Versioned primary-source retrieval, server-issued corpus IDs, grounded output and provenance/license handling |
| 10 — Gold evaluation | Existing foundations, expanded benchmark pending | Independent A/B/C labels, unseen targets, model comparisons and published denominators/limitations |

Do not restart increments 1–3 from scratch. Audit and finish their acceptance first; then proceed in the requested order. Correctness and historical-isolation maintenance are prerequisites, not new autonomous agents.

## 6. What verification currently supports

- This review freshly verified the remote CI failures and inspected the code locations above.
- `docs/self-defence.md` records 673 passing tests plus 495 passing subtests after its collector fix. That is a historical local result, not a fresh full run for this audit.
- The last documented planner coverage result is 85.80% at an earlier revision; it is not the coverage of current `main`.
- `scripts/check.py` and CI currently enforce a 75% aggregate floor. Earlier foundation work used 85%. Preserve the configured gate and disclose the difference; agreeing on a stronger target is not permission to falsify a current measurement.
- Real Redis/intelligence and provider replay successes are dated, target-specific integrations. They do not establish current target conditions or arbitrary-provider reliability.
- Latest self-defence notes record real local observations/rechecks and an Ollama result with timing qualifications. Live visual verification of the redesigned dashboard was blocked in that session.
- The checked-in Nikto fixture provenance table still says “none yet.” Local captures mentioned in historical notes are not a reproducible committed corpus by themselves.
- No independent expert results proving A, B or C were established by this review.

## 7. Recommended priorities

1. Restore main's full quality gate and correct inclusive-range remediation advice.
2. Establish run/snapshot isolation and consistent live-to-recorded assessment/report provenance.
3. Finish the real acceptance of the existing approved planner and typed follow-up loop.
4. Deliver reconciliation/CVE candidates, then contradiction-aware context, then exploitability reasoning, then selective critic/coverage.
5. Add task-specific budgets/routing/memory and source-grounded retrieval in the original order.
6. Measure A/B/C using independent labels and holdouts. Use the existing evaluation scaffolding for baselines throughout; do not postpone collection of truth until after tuning every feature.
7. Integrate results into the existing overview, evidence inspector and self-defence section with runtime accessibility/state checks.

Completion means one attributable, reviewable assessment history and defensible recommendations whose value has been measured. A workflow node should execute only when applicable, and every omitted operation should have an honest reason.

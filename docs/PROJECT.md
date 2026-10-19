# PROJECT - The whole idea

**AI-Based Network Vulnerability Assessment Tool**

**Research focus: Context Is Not Free**

Design Experience project, MPSTME, SVKM's NMIMS, 2026. Nine students, one industry mentor.

This is the canonical project brief, based on the project description supplied on
2026-09-06. Read it before planning implementation. Every task must name the
pipeline stage or cross-cutting research component it serves.

This document describes requirements and planned behavior, not completed features
or measured results. The [operating rules](../.github/copilot-instructions.md),
[fixed contracts](contracts.md), [security boundary](security.md), and append-only
[decisions](decisions.md) remain binding. The contracts arrived during preparation
of this brief and have been incorporated without changing them. No installation,
download, scan, or broader LLM permission is granted here.

## 1. What this is

A local-first system that collects authorised scan evidence, identifies security
weaknesses, matches evidence to locally cached vulnerability intelligence, ranks
findings by risk in their deployment context, explains priorities, reports
evidence-backed remediation references and next actions, and re-scans after fixes
to assess whether they worked in the future full design. Re-scan is not part of
the current prototype.

Assessment processing is intended to run on hardware inside the organisation;
the prototype uses rules and template explanations, with all LLM use deferred.
No scan data may be sent to a cloud model or service. The current implementation scope
is **the explicitly authorised isolated lab only**, not an organisation's production
network. Offline operation is a requirement to verify, not a security guarantee.

## 2. The problem it solves

1. **Fragmented output.** Multiple scanners use different formats and names.
   Correlated alerts can describe the same underlying issue, while superficially
   similar alerts can also describe different weaknesses.
2. **Context-blind ranking.** A CVSS base score is not an assessment of a specific
   deployment. The same flaw on a test asset and an internet-facing customer
   database can have different operational significance. Environmental metrics
   permit context, but collecting and maintaining that context costs effort.
3. **Unverified fixes.** A report alone does not establish that remediation worked,
   that a disappearing finding was actually fixed, or that posture improved.

Cloud-based analysis can introduce disclosure, recurring-cost, and connectivity
concerns. Local-first operation addresses those concerns without claiming that all
existing products require cloud processing or that local software is inherently safe.

## 3. The research focus: Context Is Not Free

The headline contribution is automatic, evidence-backed deployment-context
inference: asset role, exposure, and observed compensating controls. A deterministic,
published formula combines that context with CVSS Environmental metrics, EPSS, and
CISA KEV. The prototype supplies a one-line template reason, never an LLM score
or LLM-derived scoring input. A local-model explanation is future work.

The rigorously evaluated ranking method is the deliverable; the scan-to-report
tool is the vehicle that makes its evaluation real. The research question in
[problem-statement.md](problem-statement.md) takes priority over building unrelated
scanner or dashboard features. Inference must be evaluated with zero manual asset
tags; optional overrides do not establish the automatic-inference claim.

The published risk formula remains a hypothesis. The following records the
current [fixed weight configuration](contracts.md), not an approved resolution
of the prototype's missing-EPSS policy:

```text
base = environmental_score * 10
percentile = epss_percentile if available else 0.5
threat = 0.5 + 0.5 * percentile
risk = base * threat
if kev:
    risk = max(risk, 90)
```

EPSS percentile is in `[0, 1]`; it is not EPSS probability. Bands are Critical
`>= 80`, High `>= 60`, Medium `>= 35`, otherwise Low. Context mappings, missing-data
policies, translation provenance, and any later changes belong in the scoring
specification and decision log. The fixed contract's missing percentile of `0.5`
produces a threat multiplier of `0.75`; the earlier [scoring notes](scoring.md)
instead specified a missing-data multiplier of `0.5`. This discrepancy must be
reconciled before scoring implementation; do not silently conflate probability,
percentile, and multiplier. The fixed contract governs unless a human approves an
ADR. It also defines additional role mappings, criticality adjustments, and
native-evidence fallbacks absent from the older notes.

The user's prototype design instead leaves missing EPSS unscored:
`threat_multiplier=None`, environmental-only priority, and an explicit missing-data
flag, with KEV assessed separately. This is now **DECIDED and applied** as
decision APPLY-01: `ScoreBreakdown.threat_multiplier` is `float | None`, and
`weights.yaml` carries `threat.missing_epss: unscored` instead of a numeric
percentile default. The older `missing_epss_percentile: 0.5` variant is
superseded; do not reintroduce it to make an example pass.

Recruit 2-3 practitioners, targeting three, but support `N>=1` through one expert
judgment format. Each supplies tied ranks and an `expert-critical` set for the
same cohort. With `N>=2`, report tie-corrected Kendall's W before comparisons;
with `N=1`, omit W, state that inter-rater agreement is unavailable in a
single-annotator study, and continue the individual comparisons.

- **Kendall's tau-b (primary):** tie-aware ranking agreement, per expert and in aggregate.
- **NDCG@10 (secondary):** quality of the first ten findings using a documented relevance mapping.
- **Critical-queue size at full recall (practitioner headline):** the shortest
  tie-inclusive ranked queue containing every expert-critical finding. Report this
  separately from fixed-threshold band counts.
- **Baselines, ablation, and variance:** compare CVSS-only, CVSS+EPSS, and the proposed
  method; disable context/threat features individually and report variability.

Weights are hypotheses until evaluated. Do not tune on the evaluation judgments or
claim an improvement before measuring it. Negative and inconclusive results must be
reported honestly. Everything else in the tool exists to make this experiment
possible, reproducible, and auditable.

## 4. The pipeline and prototype scope

The eight names follow the supplied brief. BUILD and DEFER are scope decisions,
**not completion claims**. Module paths identify intended ownership; planned files
must not be assumed to exist. Humans capture inputs using [fixtures.md](fixtures.md);
the agent does not launch scanners, containers or downloads to manufacture evidence.

| Stage | Name | Prototype | Responsibility | Module or planned destination |
| --- | --- | --- | --- | --- |
| 1 | Target input | BUILD | Validate explicit authorised targets and the targets recorded in imported captures; reject scope violations before any scanner process. A CIDR is not discovery permission. | `settings.py` (planned), [runner.py](../src/vulnassess/adapters/runner.py), [scope.yaml](../config/scope.yaml) |
| 2 | Scan orchestrator | DEFER | Humans run the documented Nmap and ZAP capture commands per target. Automatic tool selection and launching belong to the future design. | `orchestrator.py` (planned) |
| 3 | Safe scanning | BUILD Nmap/ZAP ingestion; DEFER Nikto | Import human-provided Nmap XML and ZAP JSON with scope, provenance and malformed-input checks. Do not equate ingestion with proven scan safety. | [adapters](../src/vulnassess/adapters/) |
| 4 | Unified result engine | BUILD exact/ID-based grouping; DEFER semantic merge | Keep source records and IDs; group only justified duplicates on the same host/service/affected instance. Preserve uncertain candidates separately. New grouping interfaces require review. | [schema](../src/vulnassess/schema/), [store](../src/vulnassess/store/), `unify.py` (planned) |
| 5 | AI security analyst | BUILD rule inference and templates; DEFER all LLM use | Infer role, exposure and controls with confidence and verbatim evidence. Flag uncertainty without deleting findings or letting a model affect rank. | [context](../src/vulnassess/context/), [explain](../src/vulnassess/explain/) |
| 6 | CVE intelligence | BUILD | Read human-provided NVD, EPSS and KEV snapshots offline. Retain CVSS 4.0/3.1 vectors, dates and supported patch/advisory references; flag absence explicitly. | [intel](../src/vulnassess/intel/) |
| 7 | Report | BUILD printable HTML | Present ranked findings, template reasons, supported fixes, evidence, formula inputs, confidence, feed dates and provenance. No PDF export or re-scan trends in this prototype. | [report](../src/vulnassess/report/) |
| 8 | Re-scan validation | DEFER | Later compare comparable successful scans after remediation; distinguish fixed, still open, regressed and not observable. | `rescan.py` (planned) |

Cross-cutting components:

| Component | Prototype | Purpose | Destination |
| --- | --- | --- | --- |
| Risk ranking | BUILD; primary deliverable | Published deterministic formula and reviewed Environmental mappings, with every contribution visible | [scoring](../src/vulnassess/scoring/) |
| Evaluation | BUILD | Tie-aware expert comparison, CVSS-only and CVSS+EPSS baselines, context/threat ablation and repeatability | [eval](../src/vulnassess/eval/) |
| Lab and demo | Human-provided support | Explicit approved targets, canary evidence, real captures and reproducible demonstrations | [fixtures.md](fixtures.md); `lab/` remains planned |

These are **pipeline stages**, not the four implementation phases: Foundations
(1-4, including 3B/4B), Context inference (5-6), Scoring/explanation (7-9), and
Evaluation/lab (10-11B). Stage numbering is conceptual, not a strict execution order:
intelligence matching precedes final unification, context, ranking, and reporting.

The appendices retain the fuller historical roadmap for traceability. Their
orchestrator, Nikto, LLM and re-scan work is not part of the current prototype
commitment. The five-day planning window and variable-panel design are detailed in
[the prototype DESIGN](DESIGN.md); names and panel size
must not be architectural dependencies. A missing artifact or unapproved interface
can block an increment without justifying a placeholder or an unsupported result.

## 5. Where the implementation differs from the slides

| Deck or proposed brief | Implementation boundary | Why |
|---|---|---|
| AI prioritises risks | A deterministic formula prioritises; the LLM writes no score or scoring input. | Reproducibility and an auditable research claim. |
| AI filters false positives | Evidence-based confidence and visible flags; source findings are never silently deleted. | Avoid invisible false negatives and preserve reviewable evidence. |
| AI explains vulnerabilities | Prototype: a template sentence from validated facts. Full design: bounded local-model wording under validation, still deferred. | Keep explanations tied to evidence; do not assume generated text is harmless. |
| AI recommends fixes | Proposed deterministic, evidence-backed next actions first; optional model rewording needs an explicitly approved expansion of the rationale-only boundary. | A version-range boundary or model claim is not proof of a safe patch. |
| AI resolves ambiguous roles | **Deferred.** Current policy is rule-based roles; unresolved cases remain explicit. | An LLM-selected role indirectly changes Environmental scoring. |
| AI performs semantic duplicate merging | **Deferred; disabled by default.** Deterministic, evidence-backed unification comes first. | Model-driven merging can change finding identity, queue size, and ranking. |
| CVE layer supplies CVSS | Include dated EPSS and KEV as well as CVSS. | Add exploitation intelligence without pretending it describes the local asset. |

The full-design proposal includes label-only LLM role fallback with configured,
not model-emitted, confidence. The prototype defers it entirely. A role label can
still change Environmental scoring, so fixed confidence does not satisfy the
stricter parent prohibition on LLM-derived scoring inputs. Future expansion needs
the required mentor/reviewer approval, provenance, reproducibility controls and
revised evaluation; the brief is not that approval. See STARTER-02 in
[decisions.md](decisions.md).

## 6. The two-machine test

The test must isolate the effect of context. For the **same CVE and feed snapshot**,
both machines necessarily have the same EPSS percentile and KEV membership.
The supplied illustration's percentiles of 30 versus 95 and KEV "no" versus "yes"
cannot describe that experiment; they would require different intelligence states
or different CVEs and would confound the context comparison.

Use the following acceptance design, with human-confirmed fixture evidence:

| Input | Machine A | Machine B |
|---|---|---|
| CVE and base vector | Same confirmed CVE/vector | Same confirmed CVE/vector |
| CVSS base score | Same verified score; 9.8 only if the vector supports it | Same verified score |
| Asset role | Workstation | Database |
| Environment tag | Test | Production |
| Exposure | Internal | Internet-facing, explicitly simulated in lab scope |
| Controls | Only evidence-backed observations | Only evidence-backed observations |
| EPSS percentile | Same dated percentile `p` | Same dated percentile `p` |
| KEV for context-only comparison | False, confirmed from the same snapshot | False, confirmed from the same snapshot |
| Required contrast, not an observed result | Strictly below B; Low or Medium, risk <60 | Critical, risk >=90 |

Print both complete breakdowns. This is an acceptance requirement, not a claim
that an automated test has passed. The actual base score must come from the vector;
9.8 is not assumed. With an observed percentile and Environmental score at most 10,
the proposed formula requires a common percentile of at least 0.80 even to make
B's risk >=90 possible. Establish feasibility with valid vectors and real inputs;
never alter per-host intelligence, invent evidence or tune against expert rankings
to manufacture the required bands. Report an unmet contrast as an unmet hypothesis.

**Separate KEV-floor test:** with `kev=true`, both machines must have risk at least
90 and both must be Critical. Never change a CVE's KEV status per host to force a
desired result.

Rationales must not turn "no control observed" into "no control exists", or
"internal" into "isolated". The earlier candidate CVE remains unverified; see the
[explainer](explainer.md). Synthetic scoring cases may test pure logic, but cannot
be presented as real scanner or feed captures.

## 7. Non-negotiables

1. Scan only explicit targets permitted by [scope.yaml](../config/scope.yaml).
   CIDRs constrain authorisation; they do not authorise sweeping every host.
   Refuse violations before a scanner subprocess. A canary outside scope must
   receive no requests; missing canary logs are not proof of that requirement.
2. No cloud calls during assessment. Humans provide reviewed dependencies, images,
   models, and dated feed snapshots. Ollama runs locally. Installation, feed
   refresh, image/model pulls, Docker builds, and Compose startup are
   **not run by the agent**. Local artifact presence alone is not installation approval.
3. Scoring is pure and does not import from `explain/`. The LLM must neither compute
   scores nor select inputs that alter them under the current policy.
4. All scanner, feed, and model content is untrusted. Invariant I2 in
   [contracts.md](contracts.md) requires delimited, length-capped, control-character-
   stripped scanner content prefixed `untrusted data follows`, and schema-validated
   model output. A specified guard is not proof that its implementation passed.
5. Every inferred feature carries confidence, source (`rule`, `llm`, or `manual`),
   and a verbatim evidence quote. A provenance label does not authorise LLM scoring
   inputs. Record manual tags separately from inferred observations. Invariant I3
   requires a raw-record substring or the exact sentinel `none observed`; that
   sentinel does not prove a control or weakness is absent.
6. Preserve tool, raw path, record index, original finding IDs, and all evidence.
   Identical evidence, configuration, and pinned feed snapshots produce identical
   ranks, with deterministic tie-breaking.
7. Nothing is downloaded by the agent and nothing absent is assumed present.
   Humans capture real fixtures with a README naming capture date, command, and
   authorised target. Pure-logic synthetic data belongs in `tests/synthetic/`,
   with filenames starting `synthetic_`. Tests use no network; Ollama is mocked.
8. Missing input is an explicit error, not an empty-success result or generated
   substitute. Report exactly one evidence level per factual execution claim:
   **VERIFIED** (actual command/output), **TESTED WITH MOCKS**, **NOT RUN** (reason),
   or **MISSING** (exact prerequisite).
9. Use the current quality contract: Ruff lint/format, Pyright, pytest, and at least
   85% source coverage for implementation changes. Missing gate tools are blockers,
   never permission to install. Documentation-only changes do not establish a
   passing application gate.

## 8. What "done" looks like for the prototype

These are acceptance goals, not claims that the project has reached them:

- One reproducible processing command runs ingest, enrich, context, rank, report
  and evaluation on human-provided lab inputs and prints the two-machine comparison
  and report path. Any new public command requires the existing interface approval;
  no available end-to-end command is asserted here.
- Every reported rank exposes its reason, evidence, context, formula inputs,
  scoring version, and feed dates. Low-confidence findings remain visible.
- After the required interface approval, reports include a "Recommended fix"
  column with cited evidence or an explicit lack of supported guidance. Printable
  HTML is the target; automated PDF generation is not promised.
- `eval run` compares the method with CVSS-only and CVSS+EPSS using tied
  practitioner rankings, critical sets, ablation and variance. Recruit 2-3 and
  support N>=1 without a different format; W is available only for N>=2 with
  non-degenerate data, and N=1 states the single-annotator limitation. The research goal
  is better agreement and a smaller queue at full recall; report the measured
  outcome even if that goal is not achieved.
- Re-scan and proof of remediation are deferred. Their absence does not prevent
  testing the ranking hypothesis; do not claim the prototype verifies a fix.
- A human demonstrates offline operation after providing the required artifacts.
  Internet disconnection must not disable the isolated lab's own connectivity.
- The mentor can reproduce the run and audit its provenance. No result is inferred
  from a mock, a hypothetical table, or a missing capture.
- The four claimed efficiency improvements are reported only from the measurement
  protocol in Appendix E. Until then, slide percentages are targets, not results.

The current planning window is five days, not the older December full-design goal.
Missing real judgments mean the harness can be demonstrated but H2/H3 cannot be
claimed evaluated. An expert's identity and the eventual capture owner do not
change the data model; absence of the actual data is still reported explicitly.

## 9. Out of scope and open decisions

Future work credited in the supplied brief:

- Attack-path chaining across hosts: Arsh.
- Post-remediation verification: Maanya.
- Adversarial analyst manipulation via spoofed banners beyond the specified input
  guard: Ananya N.
- Target-side scan-safety measurement: Shravani; the prototype's scope fence remains mandatory.
- Autonomous exploitation of any kind: out of scope.
- Detecting AI-driven attackers: Shravani.

Before the relevant implementation, resolve:

- Whether to permit LLM-assisted roles or semantic merging at all; both remain
  deferred under the rationale-only rule.
- A human-confirmed golden CVE, common feed snapshot, vectors, and measured bands.
- Safe duplicate identity: a shared CWE or similar title is not sufficient proof
  that different URLs, instances, or vulnerabilities are the same weakness.
- Re-scan proof: a changed banner or missing CVE match alone cannot establish a
  patch; record scan success, comparable coverage, and vulnerability evidence.
- Align the older scoring notes with the supplied fixed weight configuration,
  including the missing-EPSS discrepancy described in section 3.
- The definitions of prompts A/1A/1B are still not supplied by this attachment.
  The [engineering contract](contracts.md), including I1-I5, now exists; its
  presence does not establish that its gates have run.
- Obtain human-approved ADRs for roadmap extensions to fixed commands, signatures,
  configuration, and storage. In particular, re-scan history must coexist with the
  fixed upsert rule that changes only `last_seen` and preserves original run
  ownership; do not invent a cross-run association table or migration.
- Obtain an ADR before adding `Enrichment.patch_references`, remediation text and
  its source/provenance, or `expert_false_positives` to fixed interfaces. Approving
  a roadmap is not approval to change the models or enable LLM remediation wording.
- Use the human-supplied [original deck](deck/de_ppt.pdf) for slide citations.
  Its arrival supersedes the earlier missing-source observation in Appendix C,
  not the need to independently verify any quantitative or literature claims.

## 10. Who did what

The following credits and work allocation are supplied by the team; they are not
a claim that the corresponding implementation has been completed.

| Contribution | Credited team members |
|---|---|
| Context-aware ranking | Arsh, Ananya K, Akshay |
| Local-first design | Akshay |
| Unified findings and evidence-based confidence | Maanya, Ananya K, Akshay |
| Re-scan and continuous assessment | Maanya |
| Evaluation rigour | Ananya N |
| Scan safety measurement | Shravani |
| Lab, expert study, and runs | Mahir, Shardul, Rudra |

The industry mentor and confirmed expert panel are not named in the supplied
brief. Do not invent identities or claim panel acceptance.

## Appendix A. Implementation sequence and missing stages

Supplied order:

```text
A -> 1A -> 1B -> 2 -> 3 -> 3B -> 4 (+patch references) -> 4B -> 5 -> 6 -> 7
  -> 8 (+fix text) -> 9 (+fix column, FP appendix, since-last-run)
  -> 10 (+expert false positives) -> 11 -> 11B
```

The initial Prompt 1 scaffold predates this expanded sequence. The latest audit
supplies objectives for A/1A/1B, not their full implementation/acceptance prompts.
[contracts.md](contracts.md) governs fixed interfaces. This roadmap does not imply
those prerequisites are implemented or passed.

Each implementation plan must name its branch, served stage, dependencies,
objective, tests, acceptance evidence, decisions, and next prompt. Read this brief,
the operating rules, and the engineering contract. Preserve one-prompt-at-a-time
review gates. New orchestrator/unification/re-scan APIs, commands, configuration
keys, and tables below are proposals: any extension to the fixed contract requires
a human-approved ADR before implementation. The brief is not that approval.

### Prompt 3B - Scan orchestrator

**Branch:** `prompt-3b-orchestrator`

**Serves:** pipeline stage 2; depends on Prompt 3.

Plan `orchestrator.py` with `plan(target, scope) -> ScanPlan` and
`execute(plan, run_id) -> RunSummary`.

- Resolve requested targets and reject any out-of-scope expansion before scanner
  execution. Maintain the explicit-host boundary.
- Discover with Nmap first. Derive HTTP endpoints from observed services/banners;
  use HTTPS for observed TLS or the documented 443/8443 rule.
- Run Nikto and ZAP baseline on those endpoints, never blindly on database ports.
  If no HTTP service is observed, record an explicit web-tool skip reason.
- Persist each tool's argv, start/end, exit code, raw path, finding count, and
  failure detail in the run summary. Ordinary tool failures may allow other tools
  to continue, but scope/canary violations fail the run and incomplete coverage
  must remain visible downstream.
- Route `scan <target>` through the orchestrator and retain an explicit `--tools`
  subset. Check an available `lab/canary_access.log`; non-empty access fails the
  safety check, while a missing log means safety evidence is missing.
- Record which tool-choice, endpoint-construction, and flag-selection decisions
  are automated and which require a human override. Report counts, not an
  unsupported setup-effort percentage.

Tests cover endpoint selection, no-web skips, TLS schemes, rejection before
subprocesses, recorded failures, complete summaries, and canary violations.
Synthetic plan tests are **TESTED WITH MOCKS**, not evidence that scanners ran.
Next: Prompt 4.

### Prompt 4B - Unified result engine

**Branch:** `prompt-4b-unify`

**Serves:** pipeline stage 4 and evidence-based false-positive handling; depends on
Prompt 4.

Plan `unify.py`, `UnifiedFinding`, and a `unified(run_id, id, json, confidence)`
store. Match within an asset/service block, preserve every source finding and
evidence string, and use stable, order-independent identities.

The supplied proposal uses shared CVE, shared CWE, or normalized title to identify
merge candidates. Before implementation, resolve the distinct-instance issue in
section 9; never treat generic CWE agreement alone as proof of a single root cause.

Proposed confidence hypothesis for future `config/unify.yaml`:

```text
start at 0.5
+0.3 for corroboration from two or more tools
+0.2 for a version-matched CVE
+0.1 for ZAP High or User Confirmed native confidence
-0.2 for an uncorroborated single Nikto/ZAP informational check
clamp to [0.05, 1.0]
below 0.3: flag likely_false_positive, retain visibly
```

These are proposed confidence weights, not risk weights or verified calibration.
**Calibration blocker:** the listed adjustments have a minimum of `0.5 - 0.2 = 0.3`,
so no combination reaches the strict `< 0.3` flag threshold. Do not claim these
defaults implement useful false-positive flagging; resolve the rule/threshold
interaction through the versioned decision and evaluation process, not by silently
changing the comparison or adding a penalty.

The attachment's optional token-similarity
`>= 0.6` / model-confidence `>= 0.8` semantic merge is **deferred** under the current
LLM boundary; `unify.semantic=false` does not authorise implementing a bypass.

After matching, `enrich` will invoke deterministic unification and downstream
stages will consume unified findings. Its proposed JSON summary reports raw and
unified counts, correctly calculated duplicate reduction, and flagged findings
without deleting their sources; see Appendix E. Tests must cover non-merges across blocks
and distinct instances, justified merges, confidence, no deletion, full provenance,
and order independence. Do not claim real duplicate-reduction percentages from
synthetic examples. Next: Prompt 5.

### Prompt 11B - Re-scan validation and posture trend

**Branch:** `prompt-11b-rescan`

**Serves:** pipeline stage 8; depends on Prompt 11.

Plan `rescan.py` and:

```text
vulnassess rescan --baseline RUN_A --run-id RUN_B [--targets ...]
```

- Default to previously affected hosts/ports using a restricted orchestrator plan.
  An explicit full scan still obeys the same approved scope.
- Compare fingerprints and unified identities. `fixed` requires successful,
  comparable observations and justified remediation evidence; `still_open` means
  the weakness persists. `not_observable` includes missing service/host or failed
  coverage and must never count as fixed.
- Record new findings separately; identify regressions on previously observed,
  clean asset/service instances. A new finding is not a previously open finding.
- If matching disappears while the vulnerable detected version is unchanged,
  retain `still_open` and flag evidence loss. A banner-only change is insufficient
  to prove a fix; distinguish the illustrative rule from real remediation proof.
- Store band counts, mean risk, KEV counts, and changes since baseline. Treat
  `B.started - A.started` as an observed time-to-confirmation proxy, not the exact
  remediation time. Keep scope, feed, scoring, and scan-coverage changes visible
  so posture comparisons are interpretable.
- Extend the report with "Since last run" and chronologically ordered trends.

Tests cover justified fixes, unavailable services, failed coverage, regressions,
fake fixes/evidence loss, restricted plans, metrics, and trend ordering. Synthetic
comparisons do not establish successful real remediation. A human supplies the
first real end-to-end re-scan evidence.

## Appendix B. Corrections to the existing prompt sequence

Prompt 0 reads this brief first. Use these objective clauses for the expanded
sequence; these are planned responsibilities, not implementation evidence.

| Prompt | Corrected objective |
|---|---|
| A | SERVES every stage: establish that the tool's claims have evidence. |
| 1A | SERVES stage 1 and the authorisation boundary of stage 3: validate the scope fence before scanner execution. |
| 1B | SERVES stages 3, 5, 6: report which pipeline stages this machine can actually run, with explicit missing prerequisites. |
| 2 | SERVES stage 4: define the single canonical finding store consumed by the pipeline. |
| 3 | SERVES stage 3: integrate the three scanners into the stage-4 format; keep the runner single-tool and callable by 3B. |
| 3B | SERVES stage 2: choose and launch the appropriate tools from observed services, within scope. |
| 4 | SERVES stage 6: match CVSS, EPSS, KEV, and supported patch references offline, subject to the reference-field ADR. |
| 4B | SERVES stage 4 and the false-positive-handling part of stage 5: preserve evidence, justify merges, and expose confidence flags. |
| 5 | SERVES stage 5 as redefined in section 5 and Module 2's proposed attack-surface profiling: infer asset role without model-derived scoring inputs. |
| 6 | SERVES stage 5 as redefined in section 5 and Module 2's proposed profiling: infer exposure and observed controls with evidence. |
| 7 | SERVES the research focus in section 3: implement the deterministic ranking part of the analyst; use the consistent tests in section 6. |
| 8 | SERVES stage 5's plain-language rationale and stage 7's proposed evidence-backed fix text, without changing scores or unapproved interfaces. |
| 9 | SERVES stage 7: printable HTML with the recommended-fix column, low-confidence appendix, and, once 11B exists, "Since last run". |
| 10 | SERVES the paper: measure ranking agreement, queue size, ablation, variance, and expert-adjudicated false-positive flags. |
| 11 | SERVES stages 1-3 in the lab and the timed mentor demo; finish with the verified section-6 comparison and later a baseline re-scan. |
| 11B | SERVES stage 8: validate remediation evidence and report comparable posture trends. |

The scope fence is the primary **authorisation** mechanism, not a complete safety
guarantee. Isolation, non-destructive settings, bounded execution, and target-side
impact evidence remain required. Download-capable lab commands are
**not run by the agent**.

## Appendix C. Coverage and source evidence

**Source limit:** the 2026-09-06 user audit attributes methodology quotations to
slides 13-15 and Module 2, but no PPT/PPTX/PDF deck was found in the workspace.
Original slide text and exact deck-line citations are **MISSING**. The quotations
and coverage below are attributed to that audit, not independently verified deck
transcriptions. Do not invent line numbers to make the audit look complete.

Repository references were inspected separately:

| Evidence | Actual local source |
|---|---|
| Fixed-interface changes require a human-approved ADR | [contracts.md](contracts.md), line 3; [copilot-instructions.md](../.github/copilot-instructions.md), line 41 |
| Current Enrichment declaration does not include patch references | [contracts.md](contracts.md), declaration at line 60 |
| Current Rationale declaration does not include fix text or fix source | [contracts.md](contracts.md), declaration at line 73 |
| Fixed report command specifies HTML | [contracts.md](contracts.md), line 124 |
| Current local-model policy is rationale-only | [copilot-instructions.md](../.github/copilot-instructions.md), line 54 |

These line references identify the inspected working-file snapshots, not a deck:
contract Git blob `074433464f3fc0166e38fb99db4f83353a3388bc` and operating-rules
blob `126b16460020fe848aed2f1b2bdb05d67c12f5df`. Re-check references when those
documents change. Interface declarations do not prove runtime integration works.

Legend: `B` = planned primary implementation, `S` = support/integration/verification,
`-` = no assigned responsibility. Columns 1-8 are the section-4 pipeline stages;
`R` is research ranking and `E` is evaluation. Neither `B` nor `S` means "built".

| Prompt | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | R | E |
|---|---|---|---|---|---|---|---|---|---|---|
| A | S | S | S | S | S | S | S | S | S | S |
| 1A | B | - | S | - | - | - | - | - | - | - |
| 1B | - | - | S | - | S | S | - | - | - | - |
| 2 | - | - | - | B | - | - | - | - | - | - |
| 3 | S | - | B | S | - | - | - | - | - | - |
| 3B | S | B | S | - | - | - | - | - | - | - |
| 4 | - | - | - | - | - | B | - | - | S | - |
| 4B | - | - | - | B | B | S | - | - | - | - |
| 5 | - | - | - | - | B | - | - | - | S | - |
| 6 | - | - | - | - | B | - | - | - | S | - |
| 7 | - | - | - | - | S | S | - | - | B | - |
| 8 | - | - | - | - | B | - | S | - | - | - |
| 9 | - | - | - | S | - | S | B | S | - | - |
| 10 | - | - | - | - | - | - | - | - | S | B |
| 11 | S | S | S | - | - | - | - | - | - | S |
| 11B | - | S | S | - | - | - | S | B | - | - |

All ten columns now have a planned primary owner. Without 3B and 11B, stages 2
and 8 have none; without 4B, stage 4 has a format/store but no assigned merge and
confidence implementation. Lab integration does not substitute for building the
orchestrator. Roles/exposure support ranking; Prompt 7 owns the scoring formula.

The audit's quoted "65,000+ ports", "7,000+ web checks", "OWASP Top 10", and
"250,000+ CVE records" are not verified run coverage. Record actual scanner
versions, port selection, enabled checks, and loaded snapshot row counts.
Do not claim that Nmap's chosen flags scan every port, that a ZAP baseline tests
the whole OWASP Top 10, or that a small offline subset contains the whole NVD.

## Appendix D. Evidence-backed remediation and printable HTML

The audit identifies two report/intelligence additions. They serve stages 6 and 7
but do not yet alter the fixed models or the rationale-only LLM policy.

### Prompt 4 addition: patch and advisory references

Propose `Enrichment.patch_references: list[str]` through an ADR. On a matched CVE,
read `cve.references[]` from the human-provided NVD record and retain URLs tagged
`Patch` or `Vendor Advisory`, with their record/source provenance and feed date.
Deduplicate deterministically. No matching references means an explicit empty list,
not invented guidance; a missing/corrupt feed remains an error, not an empty list.

The tag records NVD's classification of a link. It does not by itself prove vendor
ownership, applicability to this service, or a safe fixed version. No URL is fetched
by the agent as part of this task. The ADR must define validation and serialization
without discarding original source evidence.

### Prompt 8 addition: supported next actions before model wording

Propose storage for `fix_text`, source, and supporting evidence. The requested
`Rationale.fix_source` with values `template` or `llm` also needs an ADR; adding a
source marker alone does not define where the recommendation and its evidence live.

Use deterministic templates with explicit limits:

| Available evidence | Permitted recommendation |
|---|---|
| An applicable, supplied vendor advisory explicitly identifies a fixed release for the detected product and release branch | Name that release and the source. Say "or later" only if the advisory supports that scope. |
| An affected range has `versionEndExcluding X`, but no explicit fixed-release evidence | Cite the advisory for remediation guidance; do **not** convert X into a proven patch version. |
| A non-CVE configuration/header finding names the actual missing setting and has a validated applicable reference/template | Name the observed setting and cite supported guidance; do not infer a specific header or safe value from a generic CWE alone. |
| A relevant reference exists but no supported action is available | "Review the cited guidance; no specific fix is established by the available evidence." |
| No supported reference or action exists | "No supported remediation reference is available; manual investigation is required." No fabricated URL or version. |

Optional LLM rewording remains a **proposal requiring explicit policy approval**.
If approved, apply I2 and schema validation plus a remediation-specific validator:
no new numbers, versions, CVEs, URLs, commands, settings, or unsupported claims;
preserve every required action and citation and its scope. Rejecting new tokens
alone is not proof of semantic faithfulness. On invalid output or model
unavailability, retain the deterministic template with an explicit source/status.
Do not pass remediation text into scoring or execute suggested actions.

### Prompt 9 addition: render the recommendation and its limits

After interface approval, add "Recommended fix" beside the reason, with references,
source, and missing-evidence state. Include all low-confidence findings in a visible
appendix and "Since last run" after 11B. Escape untrusted content and validate
rendered link schemes; a supplied URL is not permission to execute it.

"PDF **or** HTML" already permits HTML; lack of an automated PDF exporter is not
itself a missing alternative. Adopt **"HTML report (printable)"** as the proposed
slide wording. No WeasyPrint dependency or `--format pdf` is added. Human browser
printing is distinct from generated PDF support: verify pagination, long tables,
citations, and all appendices before claiming a usable PDF. Do not claim printing
"loses nothing" without that check. The actual slide remains unchanged until supplied.

## Appendix E. Four claims, four measurement protocols

The supplied audit lists **four**, not three, efficiency claims. None is established
by this documentation update. Preserve the quoted percentages only as targets;
unsupported result wording must be removed from the slides when they are available.

| Claim attributed to the deck | Target only | Measurement and owner |
|---|---|---|
| Duplicate reduction | 40-50% | `100 * (R - U) / R`, where R is raw findings and U is all unified findings for the same completed run before any confidence filtering. Prompt 4B reports R, U, run ID, and the percentage. |
| False-positive reduction | 30-45% | Initially measure expert-confirmed false-positive flags, not deletion or achieved reduction: `100 * confirmed_flagged_raw_ids / R`. Prompts 4B and 10 also report adjudication coverage and flag precision/recall. |
| Manual reporting time reduction | 80% | Paired, timed human tasks using raw evidence versus the generated report; `100 * (T_raw - T_report) / T_raw`. Prompt 11 documents the protocol and observed durations. |
| Setup effort reduction | 60-70% | Count automated versus manual/overridden decision instances for tool choice, endpoint construction, and flag selection. Prompt 3B reports counts; counts alone cannot establish this percentage target. |

`U / R` is the retained fraction, not duplicate reduction. Require `0 <= U <= R`
and complete source mappings. If `R == 0`, report the rate as unavailable with a
reason, not zero. For time reduction, require a positive baseline duration and keep
negative results rather than clamping them to a claimed saving.

**Expert false positives (Prompt 10):** propose `expert_false_positives` in the
truth YAML through the required interface decision. Define stable IDs, run/cohort,
reviewer identity, adjudication policy, and treatment of unknown/disputed labels.
When judgments refer to unified findings, map them back to unique source IDs before
using a raw-count denominator; do not count a source twice or treat an unreviewed
finding as false. Specify the ranking evaluation cohort separately.

Report flag precision among reviewed flagged findings, recall among reviewed
expert-false findings, reviewed/total counts, and true or expert-critical findings
flagged incorrectly. Zero denominators are unavailable, not success. A
`likely_false_positive` label is a model of uncertainty, not ground truth; retaining
flagged findings in the appendix is not a measured reduction in detector errors.
The proposed 4B defaults cannot produce that flag at all, as shown in its
calibration blocker. Resolve that specification issue before interpreting an empty
flag set as an evaluation result.

**Timed mentor demo (Prompt 11):** write `docs/demo.md` when implementing that
prompt. Predefine five questions, using the same scans, snapshots, context, and
baseline evidence in both conditions:

1. Which findings require attention first, and on which hosts/services?
2. Which recorded risk inputs justify the highest priority?
3. Which remediation action/reference is supported, or what evidence is missing?
4. Which raw artifact and record support a selected finding?
5. What changed since the baseline, and is a fix established or not observable?

Record participant, condition order, start/end times, duration, and answer
correctness for each question. Counterbalance order to reduce learning effects;
report per-participant results and variability, not just the best run. Faster wrong
answers do not establish improved reporting. If conditions differ in available
information, record that limitation rather than attributing everything to formatting.

**Setup effort (Prompt 3B):** define what counts as a decision instance before the
demo, retain the baseline/manual workflow and overrides, and do not count every
potential flag as a decision saved. A future percentage claim needs a comparable
measured effort baseline, not a conversion from the number of decision categories.

**Acceptance evidence:** unit tests may cover arithmetic, mapping, empty
denominators, and negative savings with clearly synthetic pure-logic inputs.
Only human-captured lab runs and actual expert/demo observations support the deck's
performance claims. Keep raw counts, durations, denominators, scope, versions,
snapshot dates, and the evidence label beside every reported measurement.

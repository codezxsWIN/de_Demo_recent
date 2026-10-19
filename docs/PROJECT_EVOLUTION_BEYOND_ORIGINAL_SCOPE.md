# VulnAssess: Changes Beyond the Original Problem Statement

**Document date:** 3 October 2026  
**Repository reviewed:** `vulnassess-current`  
**Branch at review:** `codex/ai-assessment-foundation`  
**Implementation checkpoint:** `5d7a90c` — `WIP: checkpoint typed AI evidence-request workflow`  
**Purpose:** Record how the project expanded, what the additions actually do, and which claims remain unverified.

This is a retrospective of the code and recorded verification available in this checkout. It is not a claim that every feature has been deployed, merged, pushed to every remote, or scientifically validated. Development was paused at the user's request. Creating this document does not resume scans, model calls, or implementation.

## 1. Executive summary

The original research prototype focused on a specific problem: infer deployment context from existing scanner evidence, combine that context with vulnerability severity and public exploitation intelligence, and produce an explainable deterministic priority queue.

The project has since expanded into a local assessment workbench with live collection, multiple evidence formats, retained captures, optional cloud and local AI analysis, strict output validation, an interactive workflow canvas, fresh intelligence review, human-approved AI planning, and a work-in-progress follow-up evidence loop.

The most significant architectural change is the movement of AI into the assessment process before the final report. The implemented planner can propose an evidence-backed scan plan for human approval. The latest saved increment adds typed follow-up proposals and collection interfaces, although its final real-model and real-probe integration is not verified.

The other major change is reliability. Successful scanner evidence survives an AI outage or rejected model response. Invalid AI output is withheld, raw captures remain available, and the UI distinguishes work executed now from historical evidence, inapplicable stages, unavailable tools, and failed analysis.

The research objective remains incomplete. Software gates and a few successful lab runs do not establish that inferred context matches ground truth, rankings outperform expert baselines, AI reduces missed findings, or multi-scanner fusion removes duplicates without losing real vulnerabilities.

## 2. Which original scope are we comparing against?

There are two related baselines in the repository, and treating them as identical would exaggerate the expansion.

### 2.1 The broad project vision

[PROJECT.md](PROJECT.md) describes an **AI-Based Network Vulnerability Assessment Tool**. Its larger vision includes authorized scanning, multiple scanners, unified findings, vulnerability intelligence, context-sensitive ranking, explanations, supported next actions, and eventually remediation comparison.

Some later additions therefore advance the original broad vision rather than introduce completely unrelated capabilities. Scanner orchestration and re-scan comparison are examples: they were contemplated in the overall project, but deferred from the first prototype.

### 2.2 The narrower research prototype

[problem-statement.md](problem-statement.md) defines **Context Is Not Free: Automatic Inference of Deployment Context for Risk-Based Vulnerability Prioritisation**.

Its initial implementation boundary was deliberately narrower:

- Work locally from reviewed, human-provided scan artifacts.
- Import Nmap and ZAP evidence with provenance and scope checks.
- Infer role, exposure and observed controls using rules.
- Preserve source records while grouping justified duplicates.
- Read dated NVD, EPSS and CISA KEV snapshots offline.
- Calculate priorities through a published deterministic formula.
- Explain priorities with evidence-backed templates.
- Evaluate context accuracy, expert-ranking agreement, queue reduction, ablation and stability.

The initial prototype deferred all LLM use, automatic orchestration, Nikto ingestion, semantic merging, attack-path chaining and post-remediation verification. Cloud runtime was outside that offline prototype boundary.

### 2.3 How this document classifies changes

The following categories keep the comparison honest:

1. **Original requirement developed further:** context, ranking, evidence provenance and evaluation support.
2. **Deferred capability implemented:** live orchestration, additional imports, optional model analysis and comparison interfaces.
3. **Operational expansion:** browser UI, provider handling, retained captures, diagnostics and fresh-feed review.
4. **New AI participation:** approved planning and typed evidence requests.
5. **Proposed capability:** reconciliation agents, CVE candidate reasoning, exploitability chains, critique and RAG that remain deferred.

## 3. High-level expansion inventory

| Area | Initial prototype | Added or strengthened behavior | Current qualification |
| --- | --- | --- | --- |
| Evidence collection | Human-provided artifacts | Bounded live Nmap paths, web-tool handling and retained capture replay | Tool execution depends on installation, scope and run mode |
| Scanner inputs | Nmap XML and ZAP JSON | Nikto parsing and completed Nessus XML import | Nessus is not launched by the app |
| Target intake | Explicit authorized targets | URL/port intake, DNS checks and pinned literal IP | A URL is not blanket permission for its domain or redirects |
| Intelligence | Offline snapshots | Online lookups, isolated caching and fresh bounded CVE refresh | No CVE means no CVE-specific lookup to perform |
| Context | Rule-derived host profile | Finding-scoped control eligibility and audit display | A header observation is not proof of mitigation |
| AI | Deferred | Local/cloud analyst clients, structured output and fallback handling | Provider availability and model correctness remain variable |
| AI trust | General input guards | Envelopes, canary handling, exact IDs, aligned quotes and score checks | Content alignment does not prove every sentence is true |
| Planning | Manual scanner choice | Editable AI proposal, explicit approval and runner hash binding | Real planner-to-scanner efficacy remains unverified |
| Follow-up | No AI-requested collection | Three typed, approved observation requests | Latest increment is saved WIP |
| Presentation | Printable report | Interactive workbench and draggable workflow canvas | Animation represents actual states or explicitly labeled preview |
| Resilience | Offline pipeline | Evidence-only completion when AI is unavailable or rejected | Rejected analysis stays rejected |
| Research | Planned expert comparison | Evaluation, ablation, stability and governance modules | Independent labels and holdout results are still needed |

## 4. Live scanning and operational execution

### 4.1 From importing files to collecting evidence

Live assessment paths were added around the original parsing and ranking pipeline. The application can authorize a submitted target, launch bounded scanner work, normalize observations, infer context, enrich eligible findings, calculate priorities, and prepare an AI review.

This is a substantial expansion because the application now has to handle executable discovery, deadlines, subprocess failures, scanner installation, target pinning and partial completion. Those concerns do not exist to the same extent in an artifact-only prototype.

The implementation responsibilities are visible in [live_assessment.py](../vulnassess/live_assessment.py), [orchestrator.py](../vulnassess/orchestrator.py), [runner.py](../vulnassess/runner.py) and [target_intake.py](../vulnassess/target_intake.py).

### 4.2 URL, protocol and requested-port handling

Target intake grew to accommodate URLs containing a scheme, an explicit port and a path. This matters for laboratory services that are not exposed on the common ports scanned by a light discovery profile.

The submitted address and the protocol actually observed by a scanner are treated separately. Entering an HTTP-looking URL for port 6379 does not make Redis an HTTP service. A requested port also does not justify running every available scanner against it.

The corrections prevent a web scanner from being launched merely because the operator typed a URL. HTTP evidence is required for the applicable web path; unknown or `tcpwrapped` services do not automatically justify HTTP or Redis checks.

### 4.3 Local installation and readiness diagnostics

Live collection exposed practical dependency problems: Nmap executable discovery, Windows process environment differences, and Nikto's Perl/XML requirements. Readiness and failure reporting were strengthened so missing tools can be distinguished from scope rejection, failed collection and AI failure.

An installed program is not necessarily visible to the running server. The server may have an older PATH, use a different runtime, or require an explicit executable setting. Conversely, a cloud model provider does not supply a cloud scanner: scan execution occurs wherever the application's runner is hosted.

These improvements do not establish a hosted remote scanning service. No generic cloud Nmap backend should be inferred from the presence of cloud AI clients.

## 5. Expanded scanner and import coverage

### 5.1 Nikto evidence

Nikto became an additional web evidence source beyond the initial Nmap/ZAP prototype. Parsing, scanner-failure handling and finding identity were strengthened.

A notable correction addressed several missing-header observations using the same native Nikto check ID and URL. They previously collided as one canonical identifier. New observation identities include the original description while retaining the native check identifier. Old imported records are not silently rewritten.

Reports containing Nikto's native `FAIL` entry are treated as failed scanner coverage rather than converted into vulnerability findings. A zero subprocess exit code alone is insufficient evidence of a successful usable report.

See [ai-finding-batches.md](ai-finding-batches.md) and [nikto_json.py](../vulnassess/readers/nikto_json.py).

### 5.2 Nessus evidence

Completed `.nessus` XML reports can be imported through the Nessus reader/import path. This adds a network-vulnerability evidence source without pretending that the local application operates the Nessus scanner.

The distinction is important: installing Nessus elsewhere does not cause a workflow button here to launch it. A completed report must exist and pass the application's import and authorized-target checks.

The relevant code is [nessus_import.py](../vulnassess/nessus_import.py) and [nessus_xml.py](../vulnassess/readers/nessus_xml.py).

### 5.3 ZAP and OpenVAS decisions

The workflow discussion moved toward Nessus for network assessment, but the ZAP reader remains useful for existing web evidence. UI emphasis and parser support are separate concerns.

OpenVAS was considered and then declined in the discussion because of deployment and resource concerns. This document does not claim OpenVAS was installed or integrated as an executable workflow component.

### 5.4 Evidence from several tools

[unify.py](../vulnassess/unify.py) provides explicit unification and candidate-link structures. The direction is to retain source records and explain grouping decisions instead of discarding alerts based on resemblance alone.

This does not deliver the requested AI semantic reconciliation agent. Cross-tool agreement is useful evidence, but two reports can share an underlying assumption or upstream source. Agreement alone is not a guarantee that a vulnerability is real.

The present preview/grouping capability should not be described as an automatically validated, lossless semantic fusion engine.

## 6. The bounded Redis CVE assessment

A specific lab assessment path was added for Redis, demonstrating a genuinely network-oriented finding feeding the rest of the pipeline.

On an exact authorized test asset with an observed plaintext Redis endpoint, the application can issue one fixed Lua expression that inspects the types of `package` and `package.loadlib`. The exact positive response creates the documented CVE-2022-0543 configuration finding.

The operation does not load a library, execute operating-system commands, read files, access application keys, guess credentials or accept arbitrary Lua. Its raw request and response are preserved as a separate attributed evidence artifact.

The historical positive lab capture connected that finding to:

- NVD CVSS base 10.0.
- FIRST EPSS probability 0.99351 in the recorded snapshot.
- CISA KEV membership.
- Deterministic priority 100 / Critical.
- A subsequently validated Google analysis of the retained evidence.

Those values are dated results, not permanent properties of the target. A later fresh scan observed `tcpwrapped`, did not re-establish Redis, and produced no corresponding vulnerability finding. The system was corrected to represent that later observation honestly.

The result demonstrates a bounded configuration check and an intelligence join. It does not demonstrate successful remote code execution or general Redis vulnerability coverage. Full details are in [redis-cve-assessment.md](redis-cve-assessment.md).

## 7. Public intelligence: joins, freshness and display

### 7.1 The original intelligence requirement

NVD, EPSS and CISA KEV were already central to the original prioritization problem. Their existence is not a new contribution. The expansion is in provisioning, live retrieval, freshness handling, provenance and presentation.

### 7.2 Explicit lookup semantics

The application joins intelligence to CVEs established in finding evidence. It does not use intelligence lookups as a substitute for detecting a vulnerability on the target.

Therefore a scan with services but no scanner-established CVE may legitimately have no CVE-specific NVD, EPSS or KEV work. Forcing those nodes to appear successful would misrepresent evidence coverage.

Missing lookup data is also distinct from a negative lookup. An unavailable KEV source is not proof that a CVE is absent from KEV. Missing EPSS is not a measured probability of zero or an invented average.

### 7.3 Fresh review of a verified saved capture

A dedicated saved-CVE mode verifies a retained capture, checks current scope, and requests fresh publisher intelligence for that capture's own CVEs. The current documented bound is five CVEs.

This mode explicitly bypasses the regular 24-hour intelligence cache. It uses isolated atomic cache writes and preserves the raw capture, original manifest and original canonical scores. Newly derived review values do not overwrite the historical record.

Failed refresh handling clears historical enrichment from the new review rather than presenting old values as freshly retrieved. Publisher EPSS score dates are distinguished from retrieval timestamps.

See [cve-workflow-display.md](cve-workflow-display.md), [intel_online.py](../vulnassess/intel_online.py) and [saved_cve_case.py](../vulnassess/saved_cve_case.py).

### 7.4 Evidence-to-intelligence display

The live summary now links an observed finding to its raw evidence, CVE, NVD score, EPSS probability, KEV membership, snapshot dates and deterministic project priority.

This directly addresses the earlier problem of a canvas showing intelligence nodes without exposing what they contributed. The display is grounded in joined records and does not introduce additional CVE identifiers.

## 8. Context and risk: a deeper correctness improvement

### 8.1 Context was always part of the original goal

Role, exposure, controls and deployment circumstances belong to the initial problem statement. The important additions concern how narrowly their evidence is applied and how the reasoning is exposed.

An internet-facing service with unknown authentication is a verification candidate. Unknown authentication is not evidence that authentication is absent. Observed TLS does not establish that an unrelated vulnerability is mitigated.

### 8.2 Finding-scoped control applicability

The earlier host-wide control mapping could grant one service a lower priority because another service displayed a protective-looking banner. A WAF or login observation on HTTP cannot automatically protect Redis, SSH or another HTTP port.

The corrected policy creates a separate finding-scoped view before scoring. Relevant checks include matching host, protocol, port and evidence content, plus the existing confidence threshold. Imported endpoint binding is narrowly checked rather than relying on an arbitrary hostname alias.

Authentication credit requires stronger evidence than a login keyword or a generic 403 response: the documented rule requires a matching 401 status line and `WWW-Authenticate` signal in the finding evidence.

### 8.3 Audit of withheld and applied controls

Score inputs now retain both the original host observations and the effective finding-scoped controls. The applicability audit distinguishes unknown, withheld, observed, eligible and applied states, with reason codes and limitations.

A control can be observed without changing a score. A WAF indication is described with mitigation uncertainty. The original context profile is not modified, and historical scores are not silently recalculated.

This is a real correctness change: a synthetic regression showed unrelated HTTP evidence previously lowering another service's score from 73.5 to 56.2. The corrected result stays 73.5. Those figures are pure-logic test outputs, not expert-validation results.

See [context-control-applicability.md](context-control-applicability.md) and [control_applicability.py](../vulnassess/control_applicability.py).

### 8.4 Remaining context limits

Role and exposure remain rule-based in the canonical path. The planned multi-signal AI context agent, contradiction reconciliation and comprehensive age/expiry policy are not completed by this control-applicability change.

Same-finding headers can still be spoofed. Mechanical quote alignment establishes source association, not actual protection or exploitability. Independent context truth and expert ranking measurements remain necessary.

## 9. AI analyst integration and provider handling

### 9.1 Optional model analysis

LLM use was deferred in the research prototype. The application now supports model-backed analysis through local and cloud clients, including Ollama and the provider modules for Groq, Google and OpenRouter.

The analyst consumes a bounded evidence case and returns structured material for validation. Its output can explain context, suggest investigations and recommend verification actions. It cannot authorize a target, rewrite evidence, confirm an invented CVE or change deterministic scores.

The label “local AI analyst” should not be interpreted as proof that Ollama was used in every run. The selected provider and recorded attempt are the relevant provenance. A cloud model may be selected even when an older canvas label uses “local.”

### 9.2 Independent evidence and AI outcomes

Collection and analysis were decoupled. When a model is unavailable or its response fails validation, collected evidence remains available and the user can receive an evidence-only summary.

This prevents a provider outage from erasing a successful scan. It also preserves the distinction between “evidence collected” and “AI analysis accepted.” Rejected claims are not included simply to make the run appear complete.

### 9.3 Honest access status and fallback

Provider handling was strengthened around availability, configuration errors and attempts. A configured key and a reachable endpoint are different facts. Provider-specific schema failures are distinguished from ordinary outages.

Fallback handling can try configured alternatives and ultimately preserve evidence-only output. Attempts are displayed so the operator can see which provider was actually used. This does not guarantee that a free endpoint will remain available or that every model supports the same structured-output features.

No credential values belong in this document, logs, committed artifacts or exported screenshots.

## 10. Increment 1: the hardened AI boundary

### 10.1 Trust envelopes

Target-controlled strings entering a model prompt are treated as untrusted data. Bounded escaped envelopes, control-token handling and explicit system instructions reduce opportunities for banners and response text to masquerade as instructions.

This is a significant addition because the model now reads content supplied by the assessed system. A scanner banner can contain malicious instructions just as a web response can.

### 10.2 Canary handling

The shared boundary recognizes the fixed sentinel `VULNASSESS_UNTRUSTED_INSTRUCTION_DETECTED`. Raw-output detection is sticky: parsing a seemingly valid JSON object does not make an earlier sentinel disappear.

A canary signal routes analysis to review. It is a diagnostic layer, not the complete security boundary. Typed capabilities, scope checks and deterministic validation remain necessary even if no canary appears.

### 10.3 Structured claims and content verification

Claims carry defined labels, evidence IDs and confidence metadata. Hypotheses need verification actions. A reachable evidence identifier is insufficient when the claimed quote is fabricated; normalized quote content is checked against the actual evidence record.

Finding-specific assertions must cite that finding's supporting evidence. A citation from a different service cannot support a claim merely because the ID is valid.

Unknown identifiers, malformed JSON, schema violations, unsupported control assertions and canonical score mismatches are rejected. Invalid output becomes Needs review, and partial AI prose is withheld.

### 10.4 Decision auditing

Model decisions are recorded with model identity and prompt/input/output hashes, plus outcome. This supports tracing a rejected or accepted response without putting credentials or entire raw prompts into logs.

The relevant foundation is [ai_boundary.py](../vulnassess/ai_boundary.py), [analyst.py](../vulnassess/analyst.py), [audit.py](../vulnassess/audit.py) and [ai-boundary-increment-1.md](ai-boundary-increment-1.md).

## 11. Model coverage, schema compatibility and bounded recovery

### 11.1 More than the first few findings

The analyst previously selected the highest-ranked findings that fit one request. Bounded batch analysis now processes consecutive non-overlapping finding sets, with at most eight batches per provider attempt.

Each batch retains the original scores and relevant context, uses its own evidence-ID namespace and passes the same trust boundary. The UI renders separate batches so an E1 from one request cannot be confused with E1 from another.

Coverage is computed by the server. “Included in validated requests” does not imply independently confirmed, deeply reviewed or given a recommendation in every case. A rejected batch or exhausted budget withholds the aggregate AI result.

### 11.2 Provider-specific schema compatibility

Groq rejected an overlapping numeric-score schema before generation. Its request schema was adapted to enumerate permissible nullable values while leaving the server's exact finding-to-score check intact.

This distinction matters: schema compatibility was repaired at the provider interface, while canonical number validation remained in the application. Acceptance by a provider is not acceptance by the project's trust boundary.

### 11.3 One narrowly permitted regeneration

One specific failure—missing support citations for an otherwise eligible finding-associated claim—can trigger one bounded regeneration with server-issued support mappings.

The first response remains rejected and audited. The application does not inject citations into model prose to manufacture success. The replacement response must pass every check.

Canaries, invented identifiers, score mismatches, unsupported controls and malformed JSON are not general repair permissions. Repeated invalid output remains Needs review.

Historical Google batch success, subsequent semantic rejection, HTTP 503 and Groq rate limits are all recorded in [ai-finding-batches.md](ai-finding-batches.md). These records show both progress and the remaining reliability limits.

## 12. Increment 2: human-approved AI scan planning

This is the clearest completed shift beyond post-hoc narration. The model now has a pre-scan role: propose an ordered plan from server-held history and user intent.

### 12.1 Proposal inputs and bounds

The planner consumes selected prior services and signals, timestamps, stored assessment history and bounded user hints. With no history it is constrained to a minimal light Nmap baseline. Prior observed web evidence on an eligible test asset can justify a bounded Nikto step.

A hint alone does not establish a service. The planner does not launch DNS enrichment, HTTP fetches or certificate probes to fill gaps silently. Missing metadata and old evidence remain explicit limitations.

### 12.2 Human review and exact approval

The UI displays tool order, fixed profile, timeout, confidence, reason and evidence citations. A human can edit the draft, then explicitly approve its exact revision.

The approval hash binds the plan, pinned target, scope snapshot, evidence snapshot and fixed profile mapping. The registry is process-local, bounded and time-limited. Approval is atomic and one-use; server restart invalidates it.

### 12.3 Runner enforcement

The runner checks the approved order, profile, target and remaining budget before execution. A changed tool, changed scope or deviation requires reapproval. It cannot silently convert a proposed plan into arbitrary subprocess flags.

An unavailable or failed approved tool produces an explicit plan outcome. A cooldown refusal does not consume a fresh approval as though a scan happened.

### 12.4 Verification level

The final recorded software gate passed 607 tests and 485 subtests with 85.80% source coverage. Lint, formatting and type checks also passed. The local browser rendered the new planning UI and its empty-input guard without console warnings/errors.

Those checks used mocked providers/processes for orchestration. A real model-generated plan followed by approved scanner execution was not established by that increment.

See [ai-scan-plan-contract.md](ai-scan-plan-contract.md), [ai-scan-plan-increment-2.md](ai-scan-plan-increment-2.md) and [scan_plans.py](../vulnassess/scan_plans.py).

## 13. Increment 3: typed follow-up evidence requests — saved WIP

### 13.1 Purpose

The newest saved work lets a model propose a specific observation to resolve an evidence gap. This goes beyond recommending a check in prose: it supplies a narrow request/review/collection/reanalysis interface.

The saved implementation allows three kinds:

| Kind | Fixed observation | What it cannot establish by itself |
| --- | --- | --- |
| `tcp_connect` | Connect to an observed TCP port on the pinned IP | Service identity, authentication policy or vulnerability presence |
| `http_head` | Send `HEAD /` and retain selected response observations | Protection of every path, absence of vulnerabilities or redirect permission |
| `tls_inspect` | Perform a verified TLS handshake against the literal IP | Whole-application security or validity for a different hostname |

### 13.2 Bounds and approval

The request contains an observed port, a 1–10 second timeout, a reason and expected information gain. Candidate operations come from server-observed services. No arbitrary flags, URL paths, hostnames, authentication headers or shell commands are accepted.

Human approval is explicit and one-use. Rejection requires a recorded reason. The current scope is rechecked immediately before I/O, and a broad CIDR alone is insufficient for this exact named-target follow-up path.

Approval expires after ten minutes or server restart. Changing target, model or assessment invalidates the browser draft, and late responses for older selections are ignored.

### 13.3 New evidence provenance

Successful observations are stored as exclusive-create local artifacts with a server-issued source ID, target, assessment, kind, port, timestamp, AI origin, request hash, raw bytes and integrity hashes.

The analyst can consume matching supplementary observations while retaining their source and hash metadata. Raw captures, canonical findings, context controls and deterministic scores are not modified by the observation.

The hashes detect inconsistent alteration; they are not signatures against an administrator who can rewrite both data and hashes. Raw headers may contain sensitive data, so the ignored local evidence directory must remain private.

### 13.4 Real-model issues and final checkpoint

Real local `llama3.2:3b` attempts exposed claim-path, quote-copying and cross-service citation errors. The final saved schema binds operation/port alternatives to the permitted service evidence IDs. For this proposal format, the model selects allowed IDs and the server attaches their exact quotations; model-supplied quote fields are rejected.

This is a narrowly defined proposal contract, not a general permission to repair unsupported analyst claims. The selected IDs and proposal content still require validation.

The last focused run passed 44 tests. An earlier revision passed 642 tests and 490 subtests with 85.89% coverage. Subsequent schema and outage changes mean that full-suite result does not verify the final checkpoint.

The final full run was interrupted when the user paused development. The final live retest was not verified, no follow-up network probe was approved/executed, and no complete real probe-to-analysis result is claimed.

See [ai-evidence-increment-3.md](ai-evidence-increment-3.md) and [evidence_requests.py](../vulnassess/evidence_requests.py). This increment remains WIP.

## 14. Interactive workflow and assessment workbench

The original printable result grew into an interactive local browser application.

Added presentation capabilities include:

- A connected workflow canvas with active-path emphasis.
- Draggable stage positions and keyboard movement support.
- Zoom, pan, fit and reset controls.
- Node inspectors describing input, operation, output and current status.
- Assessment, host and finding selection.
- A stage/event view alongside the canvas.
- Preview flows that can be shown without launching a scanner.
- Live evidence summaries, provider attempts and coverage limitations.
- Context and finding-level inspection, provenance and report views.

This was intended to make the system understandable to a reviewer watching a run. The display grew beyond a set of backend commands into a demonstrable assessment product.

Several corrections were essential: the selected live target must replace stale stored-host UI state; preview must be labeled simulated; stored and live counts must remain distinct; and historical capture replay must not appear as fresh collection.

Stage counters were strengthened to distinguish executed, retained, not applicable, not in this run mode, failed and waiting work. A large assessed count is not a success count. Grey nodes can represent correctly inapplicable work, not necessarily broken modules.

The UI cannot make incompatible scanners applicable. Nikto does not become a useful Redis scanner because its node exists, and Nessus cannot be counted as executed when no report was imported.

The browser implementation is under [ui](../vulnassess/ui/), with historical presentation documentation in [ui.md](ui.md), [ui-phase-1.md](ui-phase-1.md) and [ui-phase-2.md](ui-phase-2.md).

## 15. Persistence, capture replay and auditability

The application gained explicit local persistence and repository interfaces around assessment records, stored observations, scores and UI reads. SQLite/local operation and broader repository support are documented separately in [DATABASE.md](DATABASE.md).

Live collection now retains raw scanner files in unique local capture directories and writes a case before model analysis. A manifest records file and case hashes. This prevents successful evidence from disappearing when a temporary directory is cleaned after model failure.

Saved-capture review checks hashes, bounds, filenames, path containment and current scope. Evidence-only replay is distinguished from a new scan.

Local artifact retention is not identical to registration as a stored database assessment. The retained-capture directory and the database assessment selector are separate mechanisms. Automatic deletion, remote backup and universal retention policy are not implied.

This supports reproducibility: a reviewer can inspect what the scanner actually produced, which intelligence was used, and which model attempt was accepted or rejected.

## 16. Reporting and concrete next actions

Reports grew beyond a severity table to expose the reasons behind prioritization and the limits of the assessment.

The expanded output can include observed services, confirmed findings, CVE intelligence, score inputs, context interpretation, control applicability, provider attempts, coverage gaps, uncertainty and verification suggestions.

An important correction is language discipline. “No vulnerability findings recorded” does not mean “safe.” “Authentication unknown” does not mean “unauthenticated.” A verification candidate is not a ranked vulnerability.

Where fixes or advisory references are supported, the report can present them alongside provenance. Model-generated wording remains bounded by the underlying evidence. A suggested patch or investigation is not proof that remediation has succeeded.

Printable HTML remains an important output because it can be reviewed without depending on animation. The implementation is in [report.py](../vulnassess/report.py).

## 17. Comparison, research tooling and governance

### 17.1 Re-scan comparison

Post-remediation comparison was deferred in the initial prototype, but [rescan.py](../vulnassess/rescan.py) now contains observation, coverage and comparison structures.

The key principle is comparability: a finding disappearing from a later incomplete scan does not establish a fix. Coverage and service evidence must support the interpretation.

The presence of this module does not establish a measured remediation-validation study or automated patching capability.

### 17.2 Evaluation infrastructure

The repository includes context evaluation, ranking evaluation, ablation and stability tooling, with related cohort and research commands.

These support the original research questions and later trust/fusion questions. They allow deterministic outputs to be inspected under controlled scenarios, but they do not supply independent expert labels automatically.

Relevant modules include [context_eval.py](../vulnassess/context_eval.py), [evaluate.py](../vulnassess/evaluate.py), [experiments.py](../vulnassess/experiments.py) and [cohort.py](../vulnassess/cohort.py).

### 17.3 Model governance

Role-model and promotion/governance interfaces were added so experiments can be distinguished from canonical scoring authority. A recommendation or model artifact does not automatically become an approved scoring input.

[model_governance.py](../vulnassess/model_governance.py) exposes promotion validation and hybrid recommendation structures. Their existence is infrastructure, not evidence that a learned model generalizes or has been promoted for production use.

### 17.4 Research targets remain targets

The original proposed accuracy, ranking-agreement and queue-reduction thresholds are acceptance goals, not achieved results. Synthetic examples and regression coverage do not prove them.

The project still needs unseen authorized captures, independently labeled context, expert rankings, duplicate ground truth, false-positive/false-negative labels and a preregistered evaluation policy.

## 18. Quality, packaging and documentation improvements

The project also accumulated work that improves reproducibility rather than adding scanner capabilities:

- Repository cleanup and correction of overclaiming setup/provisioning documents.
- Clearer distinctions between real captures, synthetic fixtures and mocked integrations.
- Feed provenance and capture-format documentation.
- CI/test tooling, lint, formatting and type-check fixes.
- Reproducible UI/demo initialization paths for clean checkouts.
- Design notes, decision records, handoffs and per-increment verification reports.
- Regression and adversarial tests for boundaries that previously failed in live use.
- Versioned local checkpoints so paused work can be resumed without losing changes.

Historical work is described in [PROJECT_JOURNEY_AND_HANDOFF.md](PROJECT_JOURNEY_AND_HANDOFF.md), [HANDOFF.md](HANDOFF.md), [FEED_PROVENANCE.md](FEED_PROVENANCE.md) and [decisions.md](decisions.md).

Presentation and walkthrough work was discussed alongside implementation. This document does not claim that a particular video, remote backup or repository publication is available merely because it was requested in the conversation.

## 19. Mapping progress to the three problem statements

### A. Context Is Not Free

**Implemented direction:** evidence-based role/exposure rules, deterministic threat/context ranking, missing-data handling, finding-scoped controls, audit explanations and evaluation tooling.

**Meaningful improvement:** unrelated service evidence no longer automatically grants protective scoring credit. Reports expose why a control was withheld or applied.

**Still needed:** independent context truth, measured expert-ranking advantage, contradictory multi-signal reasoning and validated service-level protection/reachability interpretation.

### B. Trust but Verify

**Implemented direction:** trust envelopes, raw canary detection, structured claims, allowed identifiers, quote alignment, finding-specific citations, canonical number validation, audited decisions and adversarial tests.

**Meaningful improvement:** unsupported model output cannot silently become an accepted report or erase successful evidence collection.

**Still needed:** measured injection success rate, wrongly dropped real findings, wrong CVE matches, calibrated confidence and fair local-model/cloud-model comparison on an independent dataset.

### C. Fragmented Evidence

**Implemented direction:** multiple strict readers, normalized records, source-preserving grouping/candidate structures, Nikto identity correction, provenance and coverage-aware comparison.

**Meaningful improvement:** several alerts sharing a native check identifier are no longer collapsed accidentally, and scanner errors are not scored as vulnerabilities.

**Still needed:** the approved evidence-resolution/CVE-candidate agents, independently labeled multi-scanner duplicates and measured duplicate/false-alarm reduction without loss of real findings.

## 20. AI roadmap: what is built and what is deferred

| Increment | Status at this checkpoint | Important limitation |
| --- | --- | --- |
| 1. Harden AI boundary | Implemented; recorded regression/adversarial gates | Does not prove arbitrary semantic truth or injection immunity |
| 2. Human-approved scan plan | Implemented; software gates and local UI verified | Real model-plan-scanner integration not established |
| 3. Typed bounded evidence requests | Saved WIP; focused tests passed | Final full gate and real approved probe/reanalysis pending |
| 4. Evidence reconciliation and CVE ranking | Deferred | Existing deterministic grouping/matching is not this agent |
| 5. Multi-signal context reasoning | Deferred | Scoped control correctness is not the full reasoning increment |
| 6. Exploitability vectors and chains | Deferred | No AI chain may be claimed from current scoring |
| 7. Selective critic and coverage agent | Deferred | Current coverage metadata is not an independent critic |
| 8. Multi-model task routing, budgets and memory | Partial infrastructure only | Provider choice/batching/history are not the complete increment |
| 9. RAG over corpora | Deferred | CVE feed joins are not general advisory/technique retrieval |
| 10. Golden evaluation harness | Existing research tooling; expanded gold dataset deferred | Tests are not expert-labeled assessment ground truth |

The earlier roadmap in [AI_UPGRADE_ROADMAP.md](AI_UPGRADE_ROADMAP.md) provides motivation. Newer increment notes establish the more precise current status. Older documents that say “planner deferred” or describe an earlier UI are historical context rather than evidence that the newer implementation does not exist.

## 21. Verification timeline and how to interpret it

The following figures are recorded results from the cited revisions. They were not rerun while writing this document.

| Recorded milestone | Tests / subtests | Coverage | What it establishes |
| --- | --- | --- | --- |
| Freshness/citation work | 523 / 475 | 85.40% | Recorded software suite and particular browser replay; not universal provider reliability |
| Finding-scoped control final gate | 561 / 480 | 85.59% | Synthetic/control regression, lint/type/format gates |
| Planner foundation baseline | 569 / 480 | 85.62% | Foundation reference used by planner note |
| Increment 2 final gate | 607 / 485 | 85.80% | Planner boundary/orchestration tests and local UI smoke |
| Increment 3 earlier revision | 642 / 490 | 85.89% | Earlier revision only, before final schema/outage changes |
| Latest Increment 3 focused run | 44 focused tests | Not a new full measurement | Limited checks at the saved WIP checkpoint |

Coverage percentages are source coverage, not vulnerability-detection recall, ranking accuracy or citation precision. Subtests are recorded separately rather than added to test counts to inflate a headline.

The final Increment 3 full suite was interrupted on the explicit pause. The project must not present the earlier 85.89% measurement as verification of the final saved code.

The real Redis capture and fresh intelligence replay are stronger integration evidence for that bounded case. They still do not establish present target vulnerability, complete scanner coverage or generalization to arbitrary websites.

## 22. Local commit checkpoints

Selected commits visible in this checkout provide a compact trail of recent changes:

| Commit | Recorded change |
| --- | --- |
| `971f00c` | One bounded regeneration for missing-support citations without weakening validation |
| `499666f` | Fresh publisher data for verified saved CVEs |
| `0db0c78` | Finding-scoped control credit |
| `77231fb` | Reject invalid batch coverage metadata |
| `ab676cf` | Bind TLS audit quotes to affected services |
| `29888b4` | Formatting normalization and verified context gate record |
| `2156236` | Reject raw AI canaries before accepting structured output |
| `acb8d42` | Bounded AI scan proposals and one-use approval registry |
| `c38df8b` | Reviewed plans connected to workflow and runner |
| `ce4ced4` | Planner contracts, verification and integration limits |
| `5d7a90c` | WIP typed AI evidence-request checkpoint |

This is a local source-history inventory. It does not certify that these commits are present on a particular remote default branch. No remote push or merge was performed as part of this documentation task.

## 23. What should not be claimed as completed

The following statements would go beyond the available evidence:

- “Every module executes on every target.” Applicability and run mode correctly exclude some work.
- “No findings means the host is safe.” Coverage may be limited and controls may be unknown.
- “NVD/EPSS/KEV detected the vulnerability.” They enrich a finding established elsewhere.
- “The Redis check demonstrated RCE.” It inspected a bounded configuration condition.
- “The AI is immune to prompt injection.” The boundary has protections and tests, not a universal proof.
- “A valid quote proves the full claim.” Alignment is mechanical support, not complete semantic verification.
- “Nessus is automated by this app.” The documented path imports completed reports.
- “The planner learns from experience.” It reads prior evidence; continuous learning is not delivered.
- “All AI agents are implemented.” Increment 3 is WIP and later reasoning agents remain deferred.
- “Context ranking beats experts or CVSS baselines.” The independent study is still required.
- “Semantic fusion removes false positives without losing findings.” That needs labeled evaluation.
- “The latest checkpoint passed the full suite.” Its final full run was interrupted.
- “Everything is published/backed up remotely.” Local checkpointing and remote publication are separate facts.

The mistakenly supplied DPDP checker prompt was withdrawn. No DPDP compliance checker is counted as part of this project evolution.

## 24. Saved state and the next legitimate resume point

The current implementation is saved at the typed evidence-request WIP checkpoint. The immediate unfinished work is verification of that increment, not jumping to autonomous reconciliation or adding unrelated agents.

When development resumes, the documented sequence is:

1. Inspect the saved Increment 3 changes and current scope/configuration.
2. Rerun lint, formatting, type and full coverage gates on the final code.
3. Verify the final proposal schema with the selected real local model.
4. Obtain explicit approval for one bounded observation on an authorized lab service.
5. Preserve its raw evidence and verify follow-up analyst inclusion without canonical mutation.
6. Record failures, limits and actual integration results.
7. Review Increment 3 acceptance before proceeding to evidence reconciliation and CVE candidate reasoning.

No scope expansion, scanner launch, installation, provider call or implementation step was performed to create this document.

## 25. Bottom line

The project has grown from an offline context-prioritization prototype into a substantially broader local assessment workbench. It now has operational collection paths, more evidence formats, clearer intelligence provenance, stricter AI trust controls, resilient evidence-only reporting, a demonstrable workflow UI and an implemented human-reviewed planning layer.

The most valuable additions are those that change assessment quality or traceability: binding controls to the affected finding, preserving raw evidence through AI failures, distinguishing fresh intelligence from retained observations, validating actual claim support and requiring exact approval before planned execution.

The next step toward a strong AI-based network assessment tool is to finish and verify the evidence-request loop, then implement the ordered reconciliation, context and exploitability reasoning increments with measured outcomes. The final goal remains an evidence-backed answer to **what is wrong, why it matters on this asset, what is uncertain, and what should be verified or fixed first**.

## 26. Source index

- [Original research problem statement](problem-statement.md)
- [Broad project scope and prototype boundaries](PROJECT.md)
- [Design and formula hypothesis](DESIGN.md)
- [Historical journey and handoff](PROJECT_JOURNEY_AND_HANDOFF.md)
- [Decision records](decisions.md)
- [Feed provenance](FEED_PROVENANCE.md)
- [Database documentation](DATABASE.md)
- [AI upgrade roadmap](AI_UPGRADE_ROADMAP.md)
- [AI boundary increment](ai-boundary-increment-1.md)
- [AI scan-plan contract](ai-scan-plan-contract.md)
- [AI planning implementation and verification](ai-scan-plan-increment-2.md)
- [Typed evidence-request checkpoint](ai-evidence-increment-3.md)
- [Finding batches and provider limits](ai-finding-batches.md)
- [Finding-scoped control correctness](context-control-applicability.md)
- [Bounded Redis assessment](redis-cve-assessment.md)
- [Fresh CVE review and display](cve-workflow-display.md)

This retrospective should be updated after verified increments. Historical measurements should remain dated, and new results should identify their revision rather than silently replacing earlier failure records.

# VulnAssess: extensive technical project reference

**AI-Based Network Vulnerability Assessment Tool**

- Document date: 17 October 2026.
- Committed implementation baseline: `6f523f61685fc7dbaede26ad81d903813017607d`.
- Working-tree qualification: uncommitted research-validation, targeted-intelligence, protocol, live/replay status, severity-basis, capture-chronology, and saved-summary corrections are described separately in sections 30 and 40. Verification checkpoints are dated and scoped; this document does not declare the entire working tree release-ready.
- Checkout: `vulnassess-current`, branch `codex/coverage-95`.
- Intended readers: developers, technical reviewers, maintainers, research supervisors, and contributors.
- Companion: [plain-language project guide](PROJECT_GUIDE_FOR_EVERYONE.md).
- Basis: source/configuration inspection, local CLI help, document-integrity checks, and the explicitly dated quality-gate results in sections 32 and 40. No scanner, intelligence refresh, cloud request, or local model was executed to write this reference.

This document describes the named baseline, with explicitly identified working-tree updates. It is not a replacement for authorisation policy, a declaration that every integration is currently available, or evidence that the research hypotheses have succeeded. Some existing design notes and command descriptions refer to earlier stages of the project. When they disagree with this reference, inspect the named implementation and the relevant approved contract before changing behaviour.

Documentation purpose: support PROJECT.md stage 7, reporting and explanation, and the cross-cutting evaluation/reproducibility component. Describing implemented behaviour is not approval to expand a fixed interface or relax the repository's execution policy.

### How to use this reference

- **First-time developer:** read sections 1-4, then follow the source navigation in section 35.
- **Assessment operator:** read sections 7-19, 24, 26, 28, 31, and 38.
- **Research reviewer:** read sections 2, 13-15, 22, 30, 32, 34, and 40.
- **Maintainer investigating a failure:** start with sections 37-40, then inspect the linked implementation.
- **Nontechnical reader:** use the [plain-language guide](PROJECT_GUIDE_FOR_EVERYONE.md) first.

Read “implemented” as “a source implementation exists.” Read “preview” as “an output that does not control the canonical assessment.” Read “verified” only with its stated command, date, inputs, and limits. None of these words means that every feature ran against a real target in this documentation task.

### What this reference should let you explain

After reading the relevant sections, a maintainer should be able to trace the following chain without treating a graph label as evidence:

1. A submitted target becomes a deterministic scope decision and a pinned address.
2. An installed scanner, supplied report, or approved bounded request produces an observation with provenance.
3. Parsing and matching turn observations into identifiable records and supported vulnerability associations.
4. Intelligence and context add separate, dated or qualified facts; neither makes the original observation infallible.
5. Finding-specific eligibility decides which context can enter the published calculation.
6. A deterministic score is produced from supported inputs, or the finding remains explicitly unscored.
7. A model interprets a bounded case; validation can withhold its output without discarding successfully collected evidence.
8. A report or saved artifact retains what happened, including failed coverage, missing inputs, and uncertainty.
9. Independent evaluation tests usefulness; local test coverage is not a substitute for that experiment.

Three different authorities remain separate throughout: the human and scope engine govern permitted actions; the scoring implementation governs canonical numbers; the AI proposes and explains. This separation limits what a model failure can damage, but it does not establish that the overall tool is complete or that its risk method is empirically superior.

### Reading source capability without mistaking it for permission

The reference describes implementation, execution evidence, and unresolved work separately. Source inspection establishes that a route or function exists. It does not establish that its prerequisites are provisioned, that the current operator may use it, or that a real external integration has been tested. A command example is informational unless it appears with an actual execution result and its evidence label.

This Markdown refresh does not change application behaviour, repair the remaining H1 defect, approve cloud processing, rewrite authorship, commit files, or publish a release. Those are separate tasks. It preserves the existing implementation changes and makes their status inspectable.

### Current-state warning before reading the feature inventory

The latest completed local gate passed 4,194 tests and 525 subtests with 99.33% Python statement coverage. Section 40.24 records minimal HTTP metadata and whole-tree verification; sections 40.22-40.23 retain earlier rationale/source-switch checks and integration blockers. Older numerical and provenance checkpoints remain historical. A local gate does not establish production readiness, independent research effectiveness or authenticated historical identity.

There are four different kinds of information in this reference:

- **Implementation facts:** what the inspected source currently contains. These do not prove a live integration worked.
- **VERIFIED local execution:** named local commands and their actual outputs. Their scope is limited to those commands and inputs.
- **TESTED WITH MOCKS:** external boundaries exercised through injected substitutes. A test double is not a publisher, scanner, model, or expert.
- **NOT RUN / MISSING:** an operation that was not exercised, or a required artifact that is absent. Neither can be converted into a successful result by documentation.

The repository also contains historical specifications whose paths, stack choices, and deferred-feature descriptions no longer exactly match the implementation. In particular, the source uses a flat package, dataclasses, argparse, and optional outbound integrations, while older contracts describe a `src` package, Pydantic, and a stricter local-only prototype. This reference documents the difference; it is not a human-approved ADR resolving it. Existing scope, dependency, credential, and execution restrictions remain in force.

## Contents

1. [Purpose and intended result](#1-purpose-and-intended-result)
2. [Three project problems and their implementation](#2-three-project-problems-and-their-implementation)
3. [Architecture and execution paths](#3-architecture-and-execution-paths)
4. [Technology stack and repository organisation](#4-technology-stack-and-repository-organisation)
5. [Core records and identity](#5-core-records-and-identity)
6. [Configuration and reproducibility](#6-configuration-and-reproducibility)
7. [Target intake and authorisation](#7-target-intake-and-authorisation)
8. [Scanners and external tools](#8-scanners-and-external-tools)
9. [Capture ingestion and parser protection](#9-capture-ingestion-and-parser-protection)
10. [Unification and evidence grouping](#10-unification-and-evidence-grouping)
11. [Vulnerability intelligence](#11-vulnerability-intelligence)
12. [Deterministic CVE matching](#12-deterministic-cve-matching)
13. [Deployment-context inference](#13-deployment-context-inference)
14. [Finding-specific control applicability](#14-finding-specific-control-applicability)
15. [Scoring and ranking](#15-scoring-and-ranking)
16. [Explanation and AI assessment](#16-explanation-and-ai-assessment)
17. [AI schemas, citations, and validation](#17-ai-schemas-citations-and-validation)
18. [Prompt injection, audit, and provider failures](#18-prompt-injection-audit-and-provider-failures)
19. [Model providers and privacy](#19-model-providers-and-privacy)
20. [Human-approved AI scan plans](#20-human-approved-ai-scan-plans)
21. [Typed follow-up evidence requests](#21-typed-follow-up-evidence-requests)
22. [Learned asset-role classifier and governance](#22-learned-asset-role-classifier-and-governance)
23. [Fine-tuning preparation](#23-fine-tuning-preparation)
24. [Self-defence](#24-self-defence)
25. [Databases and persistence](#25-databases-and-persistence)
26. [History, snapshots, replay, and integrity](#26-history-snapshots-replay-and-integrity)
27. [Diff and re-scan comparison](#27-diff-and-re-scan-comparison)
28. [Browser interface and server boundary](#28-browser-interface-and-server-boundary)
29. [Reports and offline exports](#29-reports-and-offline-exports)
30. [Research evaluation](#30-research-evaluation)
31. [CLI reference and example workflows](#31-cli-reference-and-example-workflows)
32. [Testing, CI, and what verification means](#32-testing-ci-and-what-verification-means)
33. [Security properties and remaining risks](#33-security-properties-and-remaining-risks)
34. [Implemented versus unfinished roadmap](#34-implemented-versus-unfinished-roadmap)
35. [Source-code navigation](#35-source-code-navigation)
36. [Maintenance and handoff checklist](#36-maintenance-and-handoff-checklist)
37. [Following one finding from input to report](#37-following-one-finding-from-input-to-report)
38. [Failure diagnosis and correct interpretation](#38-failure-diagnosis-and-correct-interpretation)
39. [Demonstration and acceptance evidence](#39-demonstration-and-acceptance-evidence)
40. [17 October working-tree status and unresolved cracks](#40-17-october-working-tree-status-and-unresolved-cracks)
41. [Stage-by-stage implementation and acceptance checklist](#41-stage-by-stage-implementation-and-acceptance-checklist)
42. [Developer onboarding and release-readiness handoff](#42-developer-onboarding-and-release-readiness-handoff)

## 1. Purpose and intended result

VulnAssess collects or imports authorised scanner evidence, turns it into consistent records, associates findings with vulnerability intelligence, infers deployment context, calculates deterministic priorities, and explains the resulting assessment.

The intended output is an evidence-backed investigation and remediation queue. A useful result should answer:

- What was observed, by which tool, on which host and endpoint?
- What vulnerability identifiers are supported by those observations?
- Which vulnerability facts were obtained from which feed snapshot?
- What role, exposure, and control signals were inferred?
- Which of those signals were eligible to affect this finding's score?
- What arithmetic produced the priority and band?
- What does the AI suggest, and what evidence supports it?
- What was not checked, and what should be verified next?
- Can the evidence and configuration used for the result be recovered later?

The product contains a research method and an assessment application. The research method concerns contextual ranking, evidence quality, and evaluation. The application makes those ideas usable through a CLI, a local browser workbench, retained captures, and reports.

It is local-first: local evidence processing, SQLite, and Ollama are supported. Explicit cloud-model choices, public intelligence lookups, and an optional PostgreSQL backend mean the complete application is not unconditionally offline.

## 2. Three project problems and their implementation

### 2.1 Context Is Not Free

A severity score describes aspects of a vulnerability. It does not automatically establish the importance of a particular affected asset. VulnAssess adds a deployment-context profile and configurable Environmental mappings before calculating its project priority.

Implemented foundations include rule-based asset roles, exposure classification, control signals, confidence/evidence records, finding-specific control eligibility, deterministic scoring, baselines, ablations, and expert-evaluation tooling.

The outstanding research requirement is an independent, real assessment cohort demonstrating whether these mappings improve decisions. A working formula and tests do not establish that result.

### 2.2 Trust but Verify

The AI reads potentially attacker-controlled banners and reports. Its conclusions may also be mistaken. VulnAssess therefore constrains inputs, requires structured responses, checks identifiers and score consistency, associates claims with evidence, and withholds rejected output.

Implemented foundations include trust envelopes, an instruction canary, versioned JSON contracts, claim metadata, provider-outage classification, audit records, and adversarial tests.

The outstanding research requirement includes measured unsupported-claim rates, finding omissions, wrong CVE associations, and injection success across models on independently labelled cases. Schema acceptance alone does not prove semantic truth.

### 2.3 Fragmented Evidence

Nmap, Nikto, Nessus, and ZAP produce different formats and identifiers. VulnAssess supplies canonical records and an evidence-preserving grouping preview.

Canonical ingestion is part of normal assessment processing. The grouping preview is a separate diagnostic artifact. It does not currently replace the canonical scoring queue with a fully semantic merged queue.

## 3. Architecture and execution paths

### 3.1 Main data dependencies

```text
Submitted target / existing scanner reports
                    |
             Scope validation
             and target pinning
                    |
       Scanner execution or report import
                    |
       Hosts + services + findings + provenance
                    |
          +---------+----------+
          |                    |
   CVE intelligence     Context inference
   NVD / EPSS / KEV     Role / exposure / controls
          |                    |
          +---------+----------+
                    |
       Deterministic finding-specific scoring
                    |
          Priorities + deterministic reasons
                    |
       Optional structured AI interpretation
                    |
        Schema / evidence / score validation
                    |
       Evidence summary, retained capture,
       recorded workbench, or HTML report
```

Intelligence and context are separate because they answer different questions. Intelligence describes a vulnerability and its external threat signals. Context describes the deployment. Both contribute to scoring; neither is a substitute for the other.

### 3.2 Recorded-assessment path

The CLI pipeline imports supplied files, stores canonical records, loads local intelligence snapshots, enriches findings, builds profiles, ranks findings, optionally explains them, and produces a report. Individual stages read earlier stages' stored output.

### 3.3 Live browser path

The live path pins one authorised address, runs light Nmap, may check a requested endpoint, normalises results, obtains applicable intelligence, infers context, calculates priorities, retains raw evidence, and attempts AI analysis.

The live payload and review checkpoints are distinct from a conventional recorded SQL assessment. A browser run is not automatically a printable-report command or a full import into the selected stored assessment.

### 3.4 Other paths

- Recent evidence can be reanalysed without repeating the scan.
- Saved CVE evidence can receive refreshed intelligence and another AI assessment.
- Self-defence adds local Windows protection observations.
- A planner can propose a hash-bound scanner plan for human approval.
- The AI can propose an individually approved typed follow-up observation.
- Research commands consume frozen assessment and cohort artifacts.

Each path has different prerequisites. The workflow graph represents possible dependencies and source categories, not a requirement to execute every node for every target.

## 4. Technology stack and repository organisation

### 4.1 Runtime

The package declares Python 3.11 or newer and version `0.2.0`. Runtime dependencies are `pyyaml`, `packaging`, and `psycopg[binary]>=3.2,<4`.

The implementation relies heavily on the standard library: dataclasses, argparse, SQLite, XML/JSON parsing, subprocess execution, sockets/TLS, HTTP requests, hashing, and a threaded local HTTP server.

The interface uses server-rendered HTML, CSS, JavaScript modules, SVG, and bundled local assets. It does not require React or a FastAPI/Django server.

### 4.2 Source organisation

```text
vulnassess/
  cli.py, __main__.py              Command entry points
  schema.py, settings.py           Records and validated configuration
  pipeline.py                     Recorded assessment stages
  orchestrator.py, runner.py       Scanner planning/execution helpers
  live_assessment.py               Live browser assessment
  readers/                        Scanner-format ingestion
  intel.py, intel_online.py        Offline and targeted online intelligence
  context.py                      Canonical rule-based context
  protocols.py                    Shared service-label/protocol interpretation
  control_applicability.py         Finding-specific control eligibility
  cvss31.py, scoring.py            Deterministic arithmetic
  score_facts.py                  Read-only interpretation of stored score basis
  analyst.py, explain.py           Structured analysis and rationale
  ai_boundary.py                  Shared AI validation and audit helpers
  scan_plans.py                    Plan proposal/approval/execution binding
  evidence_requests.py             Typed follow-up evidence
  role_model.py                    Learned role classifier
  model_governance.py              Promotion validation and hybrid preview
  self_defence.py                  Local Windows protection observations
  store.py, repository.py          Persistence layers
  capture_history.py               Retained live-review artifacts
  run_history.py                   Run-bound findings/intelligence history
  assessment_snapshot.py           Frozen research snapshots
  unify.py, diff.py, rescan.py      Grouping and comparison
  cohort.py, evaluate.py           Cohort and ranking evaluation
  context_eval.py, experiments.py  Context evaluation and ablation
  audit.py, report.py              Artifact audit and printable reports
  ui/                             Browser server, rendering, export, assets

config/                           Scope, roles, controls, weights
db/migrations/                    Expanded database schema
tests/                            Logic, integration-boundary, adversarial tests
tests/synthetic/                  Explicitly synthetic test inputs/cases
tests/fixtures/                   Curated captures and associated provenance
models/                           Model artifacts, including a synthetic model
finetune/                         Corpus preparation and candidate supervision
scripts/                          Maintenance, migration, and validation tools
docs/                             Contracts, design history, guides, evidence notes
examples/                         Supplied examples with their own evidence limits
project-starter-kit/               Historical setup/reference material
tasks/                            Development task material
data/, reports/                   Local runtime/generated output; normally ignored
```

The outer workspace can contain older checkouts and presentation artifacts. Their presence does not make them part of this package's current execution path.

## 5. Core records and identity

The canonical schema uses dataclasses and explicit JSON conversion. Many records are frozen; not every mutable aggregate or stored run is immutable.

### 5.1 Host and Service

A `Host` contains an IP, optional hostname, optional OS guess, and observed services. A `Service` contains port, protocol, service name, product, version, CPE, banner, and TLS indication.

An open service is inventory evidence. It is not automatically a vulnerability.

### 5.2 Finding and Provenance

A `Finding` contains identity, host, endpoint information, tool/native identifier, title, description, evidence, CVE/CWE references, scanner severity/confidence, and timestamps.

`Provenance` records the tool, raw-file path, record index, and run ID. The finding identity derives from a SHA-256 fingerprint of host, port, protocol, tool, native identifier, and URL, then a UUID5. The same identity inputs produce the same ID.

The evidence field keeps up to 2,048 verbatim characters plus a truncation marker. Consumers must not assume it contains the whole raw report.

### 5.3 Feature and ContextProfile

A `Feature` carries a value, confidence in `[0,1]`, source, and evidence string. Canonical scoring accepts rule/manual sources. The wider record format also represents model/LLM sources for other uses.

A `ContextProfile` combines role, exposure, segment, controls, and manual metadata. Missing control observations are represented explicitly rather than being silently interpreted as absent protection.

### 5.4 Enrichment

An enrichment binds a finding to one CVE and stores method/confidence, CVSS 3.1 and 4.0 fields, EPSS probability/percentile, KEV presence/date, patch references, description, range-end metadata, and feed dates.

One finding can have several enrichments. The canonical scoring selector favours KEV, then the available CVSS 3.1 base score, with a deterministic CVE-ID tie break. It does not independently maximise every possible resulting contextual score.

### 5.5 ScoreBreakdown and Rationale

`ScoreBreakdown` retains the selected CVE, vectors, Environmental modifications, threat input, native fallback, project risk, band, configuration-derived inputs, weights hash, reason, and fix guidance.

`Rationale` stores explanatory text, whether it came from a template or LLM, the model name if relevant, and validation metadata. It does not store an alternative authoritative risk score.

## 6. Configuration and reproducibility

Four validated YAML files configure the main method:

- [scope.yaml](../config/scope.yaml): boundaries, explicit assets, metadata, and canary.
- [roles.yaml](../config/roles.yaml): weighted role signatures.
- [controls.yaml](../config/controls.yaml): observed-control signatures.
- [weights.yaml](../config/weights.yaml): Environmental mappings, threat arithmetic, native priorities, and bands.

Configuration loading rejects unknown keys and malformed values. It validates mappings, number bounds, regular expressions, roles, and permitted values.

The project records hashes so a result can be associated with the configuration used. The complete configuration hash and the score weights hash have different scopes. A matching hash establishes matching content, not that the assumptions were independently approved or scientifically validated.

Reproducibility requires more than the code commit: record raw evidence, intelligence snapshots, configuration, selected model identity, and evaluation inputs. Cloud model behaviour and public feeds may change even when the repository is unchanged.

## 7. Target intake and authorisation

### 7.1 Boundary versus explicit target

`Scope.contains()` checks configured addresses/ranges and excludes the canary. Named lab targets supply metadata and explicit asset identity. The legacy runner/core import path additionally requires a named target. The current CLI orchestrator instead accepts a requested literal, in-scope non-global IP without requiring an inventory name; it rejects public IPs and does not implement CIDR sweeping. Do not describe these entry points as having identical authorisation checks.

The current live browser scope checks are implemented separately; do not assume all entry points apply an identical named-target requirement.

### 7.2 URL intake

The browser accepts a literal address or a suitably formed host/HTTP(S) URL. It rejects credentials in URLs, query strings, fragments, invalid ports, and unsupported schemes. Recognised project/lab landing pages are classified as setup references rather than scan permission.

DNS resolution currently requests IPv4 addresses. A submitted domain must not resolve to any address outside scope. Execution requires one authorised resolved address, which is pinned for scanner use.

An explicit URL supplies a requested scheme, port, and path. It does not establish that HTTP is actually listening. Service detection determines whether the web-check branch is eligible.

### 7.3 Scope failures

Common causes are an unlisted IP, changed DNS, multiple addresses, a canary address, or a malformed URL. No model selection can override these checks.

The canary must be provably outside allowed networks/hosts. Defining a broad CIDR that includes it makes configuration invalid before assessment processing.

## 8. Scanners and external tools

### 8.1 Nmap in the browser

The live baseline uses a pinned IP with `-n -Pn -sT --top-ports 100 -sV --version-light -T3`, writing XML. It is a light TCP inventory/service scan.

For an explicit URL, another Nmap check can inspect its requested port. An approved plan shares discovery's time budget with that check.

The live path does not automatically execute a full vulnerability-script library. That explains why a successful run can produce services and zero vulnerability findings.

### 8.2 Nmap in CLI orchestration

The CLI orchestrator builds discovery using service/OS detection and the `vulners` script. It derives candidate web endpoints from supported TCP HTTP service labels before building Nikto steps. The 17 October protocol follow-up removed common-port and loose-substring eligibility: SSH on port 80, UDP HTTP, and an unknown service on 443 do not justify a web-scanner step. HTTPS selection uses a TLS flag or supported HTTPS/TLS service label, not the port number alone. This is a different scan profile from the light browser baseline.

The shared helper is [protocols.py](../vulnassess/protocols.py), used by CLI orchestration, live endpoint eligibility, and planner endpoint selection. A scanner classification remains an input observation, not independent proof of an HTTP or TLS handshake. The canonical Service record does not retain the full scanner detection-method/confidence metadata; raw artifacts remain necessary for that review.

External scanner availability, script support, privileges, and target responses affect real execution. An XML parser test cannot establish that the installed scanner currently works.

### 8.3 Executable preflight

The live Nmap discovery checks an explicit `VULNASSESS_NMAP_BIN`, then the server PATH, then supported Windows installation registry locations. It runs a version check to establish launchability before claiming readiness.

Nikto can be found as an executable or as a Perl script. Relevant configuration names include `VULNASSESS_NIKTO_BIN`, `VULNASSESS_NIKTO_SCRIPT`, `VULNASSESS_PERL_BIN`, and `VULNASSESS_PERL_LIB`. A downloaded checkout can use a vendor library containing `XML/Writer.pm`.

The `XML::Writer` error is a Perl dependency failure. It is unrelated to whether the target passes scope checks.

### 8.4 Bounded Nikto branch

For the explicit live endpoint branch, the affected port must be open, HTTP must be identified, the asset must carry the required test tag, and any approved plan must include the web step.

The bounded invocation uses a literal pinned endpoint, a recorded Host header, a limited tuning profile, disabled lookup/interactive behaviour, output capture, and time limits. Scanner-specific behaviour still depends on the installed Nikto version.

### 8.5 Nessus and ZAP

Nessus integration imports a completed `.nessus` XML report. Every report host must match the selected authorised IP. Informational inventory records are excluded from vulnerability findings. The app does not launch Nessus.

ZAP JSON ingestion remains implemented. ZAP is not in the current executable-tool allowlist used by the orchestrator. A remaining parser does not imply a live ZAP integration.

### 8.6 Redis-specific configuration observation

The fixed Redis check sends one Lua type-inspection expression. It checks for the exact expected `table:function` response, preserves request/response evidence, and associates that observation with the configuration relevant to CVE-2022-0543.

It requires a scoped test asset. It does not load a library, access keys, or execute an OS command. The finding describes the observed configuration; successful remote-code execution has not been demonstrated by this check.

Source: [orchestrator.py](../vulnassess/orchestrator.py), [live_assessment.py](../vulnassess/live_assessment.py), [redis_probe.py](../vulnassess/redis_probe.py).

## 9. Capture ingestion and parser protection

Authorisation precedes the normal import pipeline's report parsing. Imported artifacts are copied into a local raw-evidence directory associated with the run.

Supported readers are Nmap XML, Nikto JSON, Nessus XML, and ZAP JSON. Their output becomes canonical records rather than tool-specific objects leaking throughout the application.

The shared input boundary enforces:

- Maximum capture size: 16 MiB, including a bounded read after the initial size check.
- Maximum nested depth: 128.
- Maximum XML elements or JSON values: 200,000.
- No network-share capture paths.
- No empty input masquerading as a successful empty report.
- No duplicate JSON keys or non-finite JSON constants.
- Rejection of malformed or unsupported encodings through an adapter error.

XML is inspected with an encoding-aware parser before ElementTree constructs the full tree. Internal DTD subsets are rejected, including UTF-16 attempts. Bare Nmap DOCTYPEs remain supported, while external subsets are not loaded by this inspection.

Nmap records open services and generates findings from CVEs found in applicable script output. Nessus validates host identity and meaningful plugin/severity data. The JSON adapters validate their own record and target requirements.

These safeguards bound accepted files and reduce parser abuse. They do not prove scanner truth, provenance authenticity, or safe future maintenance of the interpreter/XML libraries.

Source: [readers/_input.py](../vulnassess/readers/_input.py) and the four adjacent adapters.

## 10. Unification and evidence grouping

Canonical normalisation is part of ordinary processing. Semantic grouping is a separate concern.

The newer unification repair requires a nonblank matching host, a known bounded integer port and TCP/UDP protocol, a matching nonblank whitespace/control-free instance URL, and identical nonempty complete raw/enriched CVE sets. Missing URLs no longer establish affected-instance identity. Partial CVE overlaps become review links rather than merging compound alerts transitively. This is conservative exact-field grouping, not semantic equivalence, authenticated observation, or proof that two tools independently confirmed the same root cause. Section 40.17 records this newer increment and its verification scope.

The grouping engine preserves source IDs and source evidence. Weaker connections, such as title similarity, shared CWE, different/unknown URLs, or partial CVE overlap, become candidate review links rather than accepted merges. Syntactically valid CVE identifiers are not proof that a publisher confirms applicability. A finding without sufficient instance evidence remains in the raw queue; absence of a merge does not remove or dismiss its vulnerability evidence.

The CLI `unify` command emits a preview over a verified snapshot. It does not replace canonical findings, erase duplicates from the store, or recalculate the main ranking over merged groups. Group confidence values are heuristics, not calibrated probabilities.

Outstanding work includes independently labelled grouping evaluation, semantic equivalence, reliable instance evidence for non-URL/compound records, and measured duplicate/false-positive reduction without losing true findings. The current record format cannot safely split one compound alert into multiple canonical issue instances while preserving its one-to-one raw-source mapping; the repair does not invent that missing support.

Source: [unify.py](../vulnassess/unify.py).

## 11. Vulnerability intelligence

### 11.1 Distinct source roles

NVD supplies CVE descriptions, available CVSS fields, affected-product configuration, and references. EPSS supplies probability and percentile data. KEV supplies known-exploitation catalogue membership and associated metadata.

EPSS probability and percentile are separate fields. The project priority formula uses the percentile.

### 11.2 Offline snapshots

`intel load` accepts a supplied directory containing NVD JSON pages, EPSS CSV or gzip CSV, and KEV JSON. It calculates metadata/hashes and parses all feeds before replacing the operational cache in one database transaction.

The loader bounds file reads to 256 MiB and separately bounds gzip expansion. Non-finite, out-of-range, blank, or invalid EPSS values are rejected. A malformed late feed or a database write failure preserves the prior intelligence state.

Successful snapshot replacement removes obsolete operational cache rows. Recorded per-run intelligence history is separate and must not be confused with the current global cache.

### 11.3 On-demand public lookups

The targeted live path supports one to five valid scanner-named CVEs. It uses the NVD CVE endpoint, FIRST EPSS endpoint, and the CISA-maintained KEV catalogue source. It does not mirror the NVD catalogue.

The implementation uses a 24-hour freshness interval, response-size bounds, source dates, hashes, and NVD public-request pacing. An intelligence key is not required by this implementation; that does not guarantee publisher availability or quota.

It requires the isolated `intel-cache.db` store. Requests with more than five distinct CVEs exceed this targeted path's current contract rather than silently receiving complete-catalogue coverage.

### 11.4 Not-applicable versus unavailable

No identified CVE means the targeted lookup can be not applicable. Identified CVEs plus a failed publisher/cache operation mean intelligence is unavailable or failed. A cache-status screen reports stored data; it is not proof a new request occurred.

Fixture-sourced feeds are not presented as operational intelligence by the live path. Missing publisher data is not replaced with invented vulnerability facts.

Source: [intel.py](../vulnassess/intel.py), [intel_online.py](../vulnassess/intel_online.py), [intel_status.py](../vulnassess/intel_status.py).

## 12. Deterministic CVE matching

### 12.1 Explicit scanner IDs

A scanner-named CVE is retained as an explicit association, even if the loaded NVD snapshot has no corresponding record. The absence of that row is recorded; unavailable details are not fabricated.

An explicit-match confidence of `1.0` describes the association method: the scanner named the ID. It does not mean exploitation was confirmed with 100% certainty.

### 12.2 CPE and version ranges

For an applicable finding/service, the matcher compares CPE product identity and vulnerable version constraints. It supports inclusive/exclusive start/end constraints and records match/rejection traces.

Unknown or unparsable versions can yield weaker matches in supported cases. Product matching can be broad, and loaded data may be incomplete. These are matching limitations, not proof of safe or vulnerable behaviour.

The matching trace is bounded to 200 entries per finding. Patch-reference and version-end fields retain boundary semantics. A vulnerable-range end must not be advertised as a proven fixed release.

### 12.3 What the matcher does not do

It does not independently resolve vendor backports, custom builds, spoofed banners, or all combinations of NVD applicability conditions. It does not automatically turn every open service into a new confirmed CVE finding.

The proposed AI candidate-ranking and evidence-resolution passes are not separate completed production agents at this commit. Existing accepted enrichments must be understood through their recorded method and limitations.

## 13. Deployment-context inference

### 13.1 Role rules

Configured rules can match ports, service names, banners, and OS guesses. Matching weights are summed per role and capped at `1.0`; the highest role wins with a stable tie break. No matching role yields `unknown` with low confidence.

The current role vocabulary is database, web frontend, application server, domain controller, mail, file share, IoT/embedded, workstation, network device, and unknown.

For example, database ports and a matching database service name contribute separate evidence. A light scan with little OS/banner detail naturally has less information for some roles.

These confidence values are rule weights. They have not automatically become calibrated probabilities because they are stored as decimals.

### 13.2 Exposure

An explicit external-vantage tag takes precedence. Otherwise a globally routable address is classified internet-facing, while private/loopback and other non-global addresses receive the internal classification.

This implementation does not discover routing, NAT, firewalls, VPN access, or actual reachability from independent network positions. Private addressing alone is not proof of strong isolation.

### 13.3 Control observations

Patterns in service banners and finding evidence can indicate WAF, authentication, or rate-limiting signals. TLS comes from an explicit service/tunnel classification, not simply port 443 or 8443. A port-table HTTPS guess is not promoted to a positive TLS flag. Missing TLS evidence remains unknown in context; the parser does not establish that encryption is absent. Retained `Service.tls` values must be JSON booleans, so a string such as `"false"` cannot become true through truthiness conversion. Titles alone are not used as raw control evidence.

Unknown controls carry no positive observation. A visible login or denial can be an observed signal without qualifying as a score-reducing precondition.

### 13.4 Manual metadata

Scope metadata supports environment, criticality, and vantage. Environment and criticality are recorded in the manual-feature dictionary. Newly built external-vantage exposure now uses `source="manual"` and retains its literal scope-tag quote; the consumed `vantage` tag is not duplicated in `profile.manual`. Address-derived exposure remains rule-based. Section 40.14 records this correction and its verification status.

Historical saved exposure may still have `source="rule"` despite being scope-derived. The H1 checker therefore inspects its quote as well as the source label. Old profiles and numeric priorities are not silently relabelled or rewritten. A source label or an empty manual dictionary must not substitute for inspecting the actual provenance of an evaluated prediction.

A research claim about zero-manual-tag inference must be evaluated without using manual tags to supply the answer. Merely having an empty manual-feature dictionary does not establish that condition.

### 13.5 Current limitations

The rule engine chooses a primary role; it is not a complete contradiction-reconciliation system. Canonical context does not provide the full proposed per-fact freshness/maximum-age policy or an AI reasoning stage across independent TLS, DNS, HTTP, and behaviour observations.

Role evidence can be a joined, truncated collection of service excerpts, rather than one contiguous span of the original raw report. The confidence/evidence fields make the rule inspectable, but their presence does not mean every context feature has passed raw-file byte-offset alignment.

Source: [context.py](../vulnassess/context.py), [context_facts.py](../vulnassess/context_facts.py).

## 14. Finding-specific control applicability

Host-wide observations must not automatically reduce unrelated finding scores. `profile_for_finding()` builds an isolated scoring view and records eligibility decisions while preserving the original profile observations.

Checks include:

- The control belongs to the same host.
- Confidence meets the configured threshold.
- The affected service is an applicable HTTP endpoint for web controls.
- A supporting control quote occurs in the affected finding's own evidence.
- Authentication has stronger support than a login form or generic denial.
- TLS belongs to the affected service rather than another port.

Authentication eligibility requires an HTTP 401 challenge with `WWW-Authenticate` in the relevant record. A login form or 403 can remain visible as a signal while its score reduction is withheld.

Decisions include status, reason code, evidence, source, confidence, endpoint, and limitation. Applied WAF/auth mappings record the corresponding Environmental metric.

TLS and rate-limiting observations are useful assessment context. The current weights do not assign them automatic risk reductions in the same way as the configured WAF/auth mappings.

Source: [control_applicability.py](../vulnassess/control_applicability.py).

The follow-up found that this predicate still accepted loose HTTP-like prefixes after scanner selection had been hardened. New regressions reproduced 22 failures, including unsupported labels earning control credit and legitimate `tls/http` labels being rejected. Control eligibility now uses the shared exact TCP/HTTP classifier. The input-policy identifier is `finding-scoped-controls-v2`; older v1 decisions/numbers are preserved rather than relabelled or rescored. The literal imported-URL fallback remains available only without a matching service fingerprint, and all evidence/host/endpoint checks remain in force. Verification is recorded in section 40.12; it does not independently prove protocol identity or mitigation.

## 15. Scoring and ranking

### 15.1 Canonical arithmetic

The scoring module is deterministic and imports no model provider or network transport. Equal inputs produce equal numeric results. Canonical context from learned/model/LLM sources is rejected by the current scoring boundary.

The arithmetic engine computes CVSS v3.1 Base and Environmental values. CVSS v4.0 fields are retained by intelligence, but there is no complete v4.0 Environmental scoring implementation at this commit.

### 15.2 Environmental mappings

Current configured mappings include:

- Internal exposure with base `AV:N`: apply `MAV:A` when confidence qualifies.
- Eligible WAF: apply `MAC:H`.
- Eligible authentication with base `PR:N`: apply `MPR:L`.
- Asset role: select confidentiality/integrity/availability requirements.
- Test environment: apply the configured low requirements.
- Manual criticality above the configured reference: step requirements upward.

The default minimum inference confidence is `0.5`. These mappings are published hypotheses about prioritisation. They must not be described as proof that a control mitigates an individual vulnerability.

### 15.3 Threat arithmetic

When an Environmental score `E` and EPSS percentile `P` exist:

```text
B = E * 10
T = 0.5 + 0.5 * P
R = B * T
```

For KEV membership:

```text
T = at least 1.0, where an Environmental base exists
R = R + 10
if internet_facing:
    R = max(R, 90)
R = min(R, 100)
```

The result is rounded to one decimal. `P` must be a finite numeric value in `[0,1]`; booleans and coerced strings are not accepted as canonical percentiles.

If EPSS is missing, the multiplier is `None` and Environmental-only priority is retained; missing threat information is explicit. KEV can still supply its configured override/boost.

### 15.4 Native fallback

When no usable v3.1 vector exists, configured scanner-native priorities can be used:

- Nessus: Critical 80, High 60, Medium 40, Low 20.
- Legacy ZAP: High 60, Medium 40, Low 20, Informational 5.
- Nikto: 30.
- Nmap: 25.

The stored `native_fallback` identifies the source. An unsupported tool without a usable vector has no invented scanner severity. Native priorities must not be displayed as CVSS calculations.

Native fallback does not apply the Environmental metric adjustments or an EPSS multiplier. Its recorded threat multiplier stays `None`, even if EPSS data are available. KEV still receives the configured boost and, for internet-facing exposure, the applicable floor. Consequently, “the assessment has EPSS data” does not mean every native-fallback number used those data. Inspect the recorded calculation branch.

At the last clean protocol/summary checkpoint, no usable vector or configured native fallback could still produce numerical `0` with band Low. Unknown Nessus severity could also select the lowest configured severity. Neither is evidence of low risk. `redis-check` has no scalar native fallback in the current weights, making an intelligence outage a relevant example.

The newer, uncommitted repair changes this boundary: `score()` raises `IntelUnavailable` when neither a usable vector nor an applicable explicit native fallback exists. Unknown/missing entries in severity tables are no longer replaced with the minimum entry. `score_available()` lets live/saved analysis retain those findings separately as unscored while calculating supported priorities. It does not change the published arithmetic for valid inputs. A genuine zero derived from a supported CVSS vector remains a genuine zero.

The follow-up now validates unscored annotations and surfaces them in the Overview, assessment brief, live summary, saved review and printable report. Known historical scores whose complete fields explicitly lack a severity basis receive warnings rather than being silently rewritten. Minimal DTOs that omit inputs and genuine zero values are not guessed invalid. Strict recorded ranking refuses missing severity before replacing any stored priority. Section 40.11 records the integrated verification; section 40.10 preserves the earlier failing checkpoint. No numeric formula or valid-input weights were changed.

### 15.5 Bands

Critical is at least 80; High at least 60; Medium at least 35; otherwise Low. These are project bands, not a reinterpretation of an external standard's native bands.

### 15.6 Illustrative arithmetic only

Suppose an Environmental score is `8.0` and an EPSS percentile is `0.8`. Then `B=80`, `T=0.9`, and `R=72`, producing High under the current bands. This is an arithmetic illustration, not a captured finding or a measured result.

The score is a project priority, not a probability of compromise. An `80` project priority does not mean an 80% chance of exploitation.

### 15.7 Explanation and remediation provenance

Every breakdown keeps inputs, modifications, weights hash, reason, and fix guidance. Remediation references prefer supported vendor/patch material. A version-range boundary alone is not treated as a verified vendor-fixed release.

Source: [cvss31.py](../vulnassess/cvss31.py), [scoring.py](../vulnassess/scoring.py), [score_facts.py](../vulnassess/score_facts.py). Presentation imports only the read-only facts helper, not the scoring engine; the existing UI import wall remains unchanged.

## 16. Explanation and AI assessment

### 16.1 Deterministic rationale

`scoring.describe()` creates a plain-language reason directly from the stored calculation and eligible context. This does not need a model.

### 16.2 Per-finding model rewrite

The optional rationale model rewrites a deterministic verdict through `rationale.v1`. Invalid or unavailable output produces a labelled deterministic template result, with rejection metadata where appropriate.

### 16.3 Target-level analyst

The analyst receives a bounded case of services, context, findings, intelligence, canonical priorities, scanner coverage, and applicable supplemental observations.

Its `analyst.v4` contract contains a summary, confidence, context effect, recommended actions, correlations, investigations, and uncertainties. Current per-batch limits include two recommended actions, one correlation, one investigation, and two uncertainty claims.

The investigation includes a hypothesis, concrete verification, and an alternative explanation. It is advisory reasoning rather than a new scanner finding.

### 16.4 Case and batch budgets

- Maximum model evidence items: 128.
- Maximum included services: 16 per case.
- Maximum included intelligence records: three per finding.
- Maximum prompt: 14,000 characters.
- Analyst context setting: 16,384 tokens.
- Maximum sequential finding batches: eight.

Many evidence strings are shortened for the model. Omitted services/intelligence are disclosed. Unreviewed findings can move into later batches. If coverage cannot be completed within the batch budget, partial AI output is withheld.

There is no cross-batch reasoning/synthesis agent. A collection of validated batches must not be advertised as a single global analysis of every relationship.

### 16.5 One bounded correction

A narrow support-association validation error can request one new complete answer using server-provided finding/evidence associations. The system does not rewrite the model's citations to make an unsafe answer pass, and it does not relax score/identifier checks.

Source: [explain.py](../vulnassess/explain.py), [analyst.py](../vulnassess/analyst.py).

## 17. AI schemas, citations, and validation

Every displayed model prose field is represented as a structured claim. Metadata includes a label, evidence IDs, finding IDs, confidence, verification action where permitted, and a nullable score.

Validation rejects unknown schema fields, missing metadata, unknown references, invented identifiers, unsupported numbers, score mismatches, and malformed hypotheses. It checks that finding-related sections reference evidence supporting the associated finding.

### 17.1 Quote handling

Shared claim validation can compare a supplied quote with an evidence record after Unicode/whitespace/case normalisation. It is not a raw-file byte-offset verifier.

In the current analyst wire contract, the model selects evidence IDs and the server attaches the corresponding known evidence text when constructing the validated display claims. That improves citation integrity but does not constitute an independent semantic proof that the prose follows from the cited record.

### 17.2 Unsupported assurances and unknown controls

When no vulnerability findings exist, an answer must not convert a limited scan into an assurance that the host is secure. Unknown WAF/authentication/rate-limiting/TLS status must not be asserted as confirmed absence outside supported uncertainty/hypothesis wording.

### 17.3 Sample consistency

`verify_consistency()` exists, but the ordinary analyst path calls it with one sample. Full self-consistency sampling and proposer/critic/verifier debate are not active production stages.

### 17.4 Action/claim association

Recommended actions are validated in their original model order. Display sorting then moves associated claim metadata with each action, preserving the relationship between the prose and its citations.

## 18. Prompt injection, audit, and provider failures

### 18.1 Trust envelopes

The shared envelope accepts server-issued identifiers, strips recognised role/control syntax, removes unsuitable control characters, escapes markup, and bounds text. The standing system instruction declares evidence to be untrusted data.

The fixed sentinel is `VULNASSESS_UNTRUSTED_INSTRUCTION_DETECTED`. If it appears in accepted transport output, AI processing routes to review. Recognised escape attempts can cause evidence IDs to be flagged.

This is defence in depth. It does not establish a measured zero injection-success rate.

### 18.2 Two different canaries

The scope canary is an IP that must remain out of scope. The instruction sentinel concerns model output. They have different purposes and must not be conflated in diagnosis or documentation.

### 18.3 Audit

AI audit records include model/stage information, input and prompt hashes, schema/output hashes where available, decision, outcome, and selected identifiers. Provider routing also records attempts.

The shared audit writer avoids storing supplied text in its normal decision records. Raw assessment artifacts remain separately sensitive. An append-only file convention does not provide a signed, externally anchored audit ledger.

### 18.4 Failure classification

Transport or endpoint failure can produce `ProviderUnavailable` and permit an explicitly enabled fallback. Malformed or rejected output produces `NeedsReview` and stops AI processing.

Ollama streaming distinguishes malformed JSON from transport/deadline failures. A canary observed before a stream timeout remains a rejection; it must not become an outage that enables another provider.

### 18.5 Independent scan outcome

A successful evidence collection remains complete when AI is unavailable or rejected. The live report stage attaches an evidence summary and records the separate AI outcome. Rejected AI prose is not published as partial success.

Source: [ai_boundary.py](../vulnassess/ai_boundary.py), [errors.py](../vulnassess/errors.py).

## 19. Model providers and privacy

The current code contains these configured integrations:

- Ollama: default local model `llama3.2:3b`; custom model names can be supplied.
- Groq primary: `openai/gpt-oss-120b`, using `GROQ_API_KEY`.
- Groq secondary: `qwen/qwen3.8-27b`, using `GROQ_SECONDARY_API_KEY` separately.
- Google: `gemini-3.5-flash-lite`, using `GEMINI_API_KEY`.
- OpenRouter: `deepseek/deepseek-v4-flash-0731:free`, using `OPENROUTER_API_KEY`.

These strings describe the source configuration, not a verified catalogue of serving models on the document date. Keys, quotas, provider availability, and schema compatibility affect real calls.

Credential sources include ignored local environment files and process environment variables. Actual credential values must not be copied into documentation, logs, reports, or browser responses.

Cloud use requires explicit evidence-sharing consent. The local-only selection does not automatically fall back to cloud. For an eligible cloud selection with fallback enabled, the selected provider is tried first, followed by configured alternatives in the code's order: Google, Groq primary, Groq secondary, OpenRouter, then Ollama, omitting duplicates.

Credential configuration is distinct from endpoint availability. The UI reports that distinction; generation establishes whether the provider actually answers the request.

Local hosting does not imply that every backend operation remains local: the model choice, intelligence path, and database backend determine outbound data flow.

Operational policy is a separate question from source capability. The standing repository rules prohibit the agent from exercising these network/model paths and retain a local-only research requirement. A browser consent flag is a technical safeguard, not an ADR approving a change to that requirement. An operator must resolve the applicable policy and data-sharing approval before using an outbound integration; this documentation refresh made no provider calls or credential changes.

## 20. Human-approved AI scan plans

The planner reads bounded prior records for the pinned target and user hints. It can use recent evidence and a small set of recorded histories. Planning itself does not launch additional DNS/certificate probes, beyond the existing target-intake resolution.

The current `scan_plan.v1` proposal supports a mandatory Nmap light step and at most one Nikto web step. A web step must cite an observed endpoint. No history means the model is instructed to propose the minimal Nmap baseline.

Each step includes tool, fixed profile, bounded timeout, optional endpoint evidence ID, reason, and confidence. Model output and human edits pass through the same validator.

The approval hash binds the plan, context, and supported profile identity. Editing produces a draft/new binding. Execution requires explicit approval and matching evidence/scope. Target changes, unsupported order, stale hashes, budget exhaustion, or unfinished required steps can require approval again.

Authority is held in memory, with a 30-minute lifetime and a bounded draft registry. A restart invalidates it. Saved assessments do not resurrect execution authority.

The Nmap profile allows up to 180 seconds; the bounded Nikto profile up to 150, subject to validated step bounds. This is a fixed supported plan vocabulary rather than a general scanner-command agent.

Source: [scan_plans.py](../vulnassess/scan_plans.py).

## 21. Typed follow-up evidence requests

The `evidence_request.v1` allowlist contains exactly `http_head`, `tls_inspect`, and `tcp_connect`. There is no arbitrary shell or general tool-name/flag interface.

Requests require the literal pinned target, an observed eligible service/port, a deadline from one to ten seconds, a reason, expected information gain, and cited claim metadata. A request proposal does not execute anything.

The user approves or rejects. Rejection includes a reason. Approval is one-use, context/hash-bound, and expires after ten minutes. Execution rechecks the scope hash.

Wire operations use fixed implementations, bounded to 8 KiB of raw evidence. HTTP requests do not follow redirects. TLS validation is against the literal IP; virtual-host certificates may differ, which can make this check fail without proving the site's normal hostname certificate is invalid.

The HTTP observation is a plaintext `HEAD /` request with the literal IP in the Host header. It does not preserve an original hostname or application path, negotiate an authenticated session, or become an HTTPS request merely because the port is commonly used for HTTPS. TLS inspection is a separate request kind, and TCP connect establishes connectivity without service/authentication verification. These limited observations do not independently establish application-wide authentication, WAF protection, or a vulnerability.

Stored observations carry AI-request origin, request hash, run, target, port, time, and raw hash. They are written to local evidence artifacts and can be packaged as supplemental analyst observations. Their existence does not automatically change findings, context, or scores.

New HTTP HEAD records retain a labelled `website_metadata.v1` projection, not the original response. Cookie names/values, redirect URLs, policy nonces, arbitrary headers and page bodies are discarded. `raw_sha256` hashes the retained projection; it does not authenticate a complete wire response. Header observations and cookie-attribute counts produce response-specific precautions, not confirmed vulnerabilities. Separately citable statements reach the analyst as one atomic request group or are explicitly omitted for budget. Existing captures and TLS/TCP evidence are not rewritten.

Source: [evidence_requests.py](../vulnassess/evidence_requests.py).

## 22. Learned asset-role classifier and governance

### 22.1 Model

The learned role model is deterministic, class-balanced multinomial logistic regression. It is separate from the LLM analyst. Features cover structure/ports, services, products, banners, CPE information, OS, and TLS.

The model supports interpretable feature contributions and abstention when structural evidence, feature coverage, confidence, or class margin is insufficient.

### 22.2 Training and evaluation

Commands support human-label export, training, optional calibration, grouped cross-validation, feature-family ablation, evaluation, prediction, and artifact inspection. Metrics include confusion matrices, F1, coverage, selective accuracy, log loss, Brier score, and calibration error.

Training/calibration group overlap is checked. Independently supplied evaluation data still needs real provenance; invoking an evaluation command does not prove independence.

The bundled synthetic artifact declares 54 training examples and 18 calibration examples. Its labels are not operational validation data.

### 22.3 Promotion

The governance module checks artifact identity, preprocessing, declared human/verified test evidence, disjoint groups, no manual tags, approval identifiers, validity dates, and minimum evidence/metric thresholds.

Defaults include accuracy at least 0.85, coverage at least 0.80, ECE at most 0.10, and at least three test groups. Hybrid recommendations retain strong rule evidence and flag conflicts.

Manifest validation checks supplied declarations; it does not authenticate approvers or independently recompute all reported metrics. A valid promotion manifest enables recommendations, not canonical role activation.

The current `build_profile()` explicitly rejects learned-model activation, even though an older CLI help string suggests `context --model` can use it. Predictions remain shadow/candidate outputs.

Source: [role_model.py](../vulnassess/role_model.py), [model_governance.py](../vulnassess/model_governance.py).

## 23. Fine-tuning preparation

The `finetune/` directory contains assessment examples, a candidate SFT corpus, a builder/validator, and a training runbook. The builder rejects unsupported identifiers and other boundary violations when preparing examples.

This is preparation infrastructure. It does not establish a completed LoRA/SFT run, trustworthy reviewer provenance, representative training coverage, or a held-out improvement over the baseline analyst.

Existing corpus entries include synthetic material and may predate the latest boundary contract. They require review and revalidation before any actual training.

Source: [fine-tuning runbook](../finetune/README.md), [build_corpus.py](../finetune/build_corpus.py).

## 24. Self-defence

### 24.1 Target and platform

Self-defence checks the machine running the VulnAssess Python process. The reserved browser target maps to `127.0.0.1`. It is not a remote browser-device inspection feature.

The protection collector requires Windows and `powershell.exe`. It uses fixed queries, does not request elevation, and has a 20-second collection timeout. Unsupported platforms, denied queries, and unavailable values remain unknown.

### 24.2 Collected states

Nine protection/configuration states are queried: Remote Desktop, SMB1, Secure Boot, system-drive encryption protection, pending Windows Update restart, Domain firewall, Private firewall, Public firewall, and Defender real-time protection.

Additional inventory includes active network profiles, up to eight antivirus registrations, up to 64 listening TCP/application entries, and the latest recorded hotfix date.

### 24.3 Guidance and rechecks

The deterministic precaution queue highlights supported concerns, such as an active network profile with its firewall disabled. It can connect Remote Desktop configuration with a non-loopback 3389 listener while retaining uncertainty about reachability.

The dedicated workspace provides manual precautions, supporting observations, comparisons with a prior check, and individual recheck buttons. Individual rechecks accept only an allowlisted check ID and retain observation history. They do not re-run the entire Nmap/AI assessment.

### 24.4 Dependencies and limits

A full self-defence run currently passes through Nmap before collecting protection observations and inherits the live target cooldown. It requires authorised loopback scope and rejects incompatible plan/reuse combinations.

The app does not change firewall, antivirus, encryption, firmware, remote-access, or update settings. Antivirus registration does not establish activity; a hotfix date does not prove complete patching; a listener does not establish internet exposure.

Malware scanning, EDR telemetry, backup verification, router configuration, full installed-software coverage, and continuous protection are outside this collector.

Source: [self_defence.py](../vulnassess/self_defence.py), [self-defence.js](../vulnassess/ui/static/self-defence.js).

## 25. Databases and persistence

### 25.1 Core SQLite Store

The core Store holds assessment runs, canonical records, profiles, enrichment, scores, rationales, and operational intelligence. Writable initialisation enables WAL and applies the supported schema/history setup. Read-only consumers use read-only connections.

### 25.2 Expanded AssessmentRepository

The repository layer supports SQLite and PostgreSQL and provides structures for engagements, scope snapshots, assets, service history, relationships, jobs/evidence, audit events, review decisions, remediation, comments, and research metadata.

These methods and SQL migrations are broader than the current browser's complete write workflows. A table or repository method does not imply a finished UI feature. In particular, storing a remediation status records a supplied claim; it does not independently prove a fix.

### 25.3 Separate artifacts

Live cases use local raw directories and review checkpoints. On-demand intelligence uses `intel-cache.db`. AI-request observations and device rechecks have their own local artifacts. These mechanisms have different retention and integrity guarantees.

The presence of retention-policy schema is not evidence of an implemented automatic cleanup worker. Maintain backup/retention procedures explicitly.

### 25.4 Git backup scope

The repository ignores normal runtime `data/`, generated `reports/`, environment files, and specified raw-export locations. A source push preserves tracked code and curated inputs; it does not automatically back up local secrets, databases, scans, reports, or installed tools.

Source: [store.py](../vulnassess/store.py), [repository.py](../vulnassess/repository.py), [database migrations](../db/migrations/).

## 26. History, snapshots, replay, and integrity

### 26.1 Recorded run history

Run history preserves finding observations per run and hash-checked intelligence revisions. Repeating identical latest state need not produce another revision. Legacy migration can preserve available state but cannot reconstruct previously overwritten history.

Hosts, profiles, scores, and rationales can still be updated within a run. Do not describe every database field as immutable.

### 26.2 Live capture checkpoints

The live path writes raw artifacts, a `case.json`, and a manifest. It publishes an evidence checkpoint before AI completes so that model failure does not destroy collected evidence. A final receipt can link the validated/rejected/unavailable AI outcome to that checkpoint.

Saved review verifies manifests, evidence, intelligence, and checkpoint hashes. Malformed unrelated discovery candidates can be skipped with diagnostics. Once a candidate identifies the requested target, invalid scope/hash/evidence must fail rather than silently select an older successful result.

### 26.3 Recent replay and saved-CVE reuse

Recent replay uses the server's short-lived in-memory case. Restart removes that cache. Saved-CVE reuse verifies retained evidence and may refresh publisher facts. Neither should be labelled a fresh target scan.

The earlier saved-CVE loader derived `captured_at` from the manifest's filesystem modification time and ordered candidates by directory modification time. The follow-up replaces both assumptions with recorded chronology. A valid receipt supplies a hash-bound recorded date, otherwise an explicit manifest date is used. A lone undated legacy capture remains usable with an unknown date and a visible warning. Several undated candidates cannot supply a trustworthy newest capture; selection refuses that ambiguity. Dated selection discloses undated candidates and timestamp ties rather than claiming unique chronology.

New live manifests record collection completion before AI, and their initial receipts preserve that time rather than assigning receipt-publication time. Legacy receipt times retain their original interpretation as locally recorded checkpoints, not independently authenticated scanner start/end provenance. Malformed or timezone-naive timestamps and conflicting manifest/receipt capture times are rejected. The receipt validator does not establish chronological ordering among every collection, intelligence, and analysis timestamp. Selected raw evidence is parsed from the same bytes whose hashes were checked, including receipt-backed review.

Automatic discovery refuses more than 100 directories instead of silently dropping candidates. Explicit saved review remains read-only and requires its own review receipt; legacy raw captures are not retroactively certified. Neither recorded dates nor hashes authenticate the capture operator or defend against an adversary able to replace all related files.

### 26.4 Research snapshots

Assessment snapshots capture run information, configurations/drift, feed metadata, canonical records, context, scores, rationale, optional model identity, and limitations. Validation checks content hashes, schema, and references.

Hashes detect inconsistency. They are not signatures, external attestations, or protection against an attacker able to replace both data and expected hashes.

Source: [run_history.py](../vulnassess/run_history.py), [capture_history.py](../vulnassess/capture_history.py), [saved_cve_case.py](../vulnassess/saved_cve_case.py), [assessment_snapshot.py](../vulnassess/assessment_snapshot.py).

## 27. Diff and re-scan comparison

The basic diff compares finding identities across stored runs. The richer re-scan module consumes hash-checked observation artifacts with scanner coverage information.

Possible classifications are `still_open`, `fixed_candidate`, `not_observable`, `new_finding`, and `regression_candidate`.

A previously present finding is not automatically fixed because it disappeared. Fixed-candidate reasoning requires compatible successful scanner coverage, observed service continuity, and a parseable version increase for the same product in the supported comparison.

`still_open` has two meanings in this implementation: the same finding fingerprint was observed again, or comparable coverage exists but a disappeared alert lacks an established version increase. The latter retains `evidence_loss=true`; it is a conservative unresolved label, not repeated positive detection. `regression_candidate` can mean a newly observed finding under comparable baseline coverage with the service previously present. It does not require an earlier adjudicated fixed state, so it must not be described as proven recurrence after a successful repair.

Configuration, feed, and scope drift are disclosed; not every drift condition blocks classification. Human adjudication remains necessary. The module compares supplied observations; it is not an autonomous remediation/verification executor.

Source: [diff.py](../vulnassess/diff.py), [rescan.py](../vulnassess/rescan.py).

## 28. Browser interface and server boundary

### 28.1 Recorded workbench

The main workbench exposes Evidence, Context, Risk, and Findings sections over selected stored assessments. It includes supporting evidence, context displays, risk arithmetic/comparisons, and provenance. The visual asset/finding representations are presentations of underlying records.

### 28.2 Workflow workspace

The workflow UI includes Overview, Workflow explorer, AI & next steps, Self-defence, and Saved assessments. The graph supports host/finding filters, draggable nodes, pan/zoom, inspectors, a stage-list alternative, and browser-local layout persistence.

Moving a node changes layout. It does not change scanner authority or backend dependencies. Preview animations are explicitly simulated and do not generate evidence.

States distinguish Executed, Not applicable, Not in this run mode, Failed, Waiting, and Running. Counters must not treat a skipped or failed stage as executed.

### 28.3 Saved review

`/captures` and individual capture pages provide retained historical assessments. Opening a page verifies local artifacts without scanning, refreshing feeds, or contacting a model. Old approval authority is not restored.

### 28.4 Local server

The server uses Python's threaded HTTP server and explicitly requires binding to IPv4 `127.0.0.1`. It validates the exact Host/port, rejects inappropriate Origin requests, and requires an action header for explicit POST operations. It sets content/security headers and confines static assets.

There is no application login, per-user role system, or multi-tenant isolation boundary. Local request checks reduce browser-origin misuse; they do not establish the identity or trustworthiness of other processes on the computer.

Source: [ui/server.py](../vulnassess/ui/server.py), [workflow.html](../vulnassess/ui/static/workflow.html), [workflow-data.js](../vulnassess/ui/static/workflow-data.js).

### 28.5 Route families and their operational effects

The following is a source-navigation map, not a promise of a versioned public REST API. Exact payload checks live in the server and the owning module.

- **Presentation:** `/` serves the entry/workbench page; `/workflow` serves the workflow workspace. `/static/` is constrained to supported assets under the static root, with bounded reads. Loading the workspace is not permission to start a scanner.
- **Stored assessment queries:** `/api/runs`, `/api/run/<run-id>`, and the expanded repository's asset/finding routes expose retained data. These are not new observations of the target.
- **History:** `/captures`, `/captures/<capture-id>`, and their `/api/captures` equivalents read retained reviews. They validate available local bindings without reviving a scanner approval.
- **Target readiness:** `/api/target-check?target=...` parses the submitted target, may resolve DNS, checks scope, and probes local Nmap readiness. It does not scan the target. A readiness request is therefore not necessarily a network-free or subprocess-free operation.
- **Tool readiness:** `/api/scanner-status` runs the local executable preflights and reports Nessus as import-only. A successful version check is not a successful scan.
- **Intelligence status:** `/api/intel-status` describes the applicable stored/cache status. It is not equivalent to a complete catalogue refresh or proof that every cached CVE is fresh.
- **Explicit live collection:** `POST /api/live-assessment/events` is the live execution/replay entry point. It validates the requested mode and streams newline-delimited JSON events; it is not a browser `EventSource` guarantee merely because the route ends in `events`.
- **Analysis:** `/api/analyst/<run-id>/<host-ip>` and its events form invoke stored-target analysis. These GET routes are operational, not passive database reads; the cloud POST path additionally checks the selected provider and evidence-sharing action. Do not infer “cannot call a model” from the HTTP verb alone.
- **Plan authority:** the `/api/scan-plans/propose`, `/edit`, and `/approve` POST family separates proposal, human changes, and approval. Executable authority still depends on the pinned context/hash and the runner's checks.
- **Follow-up observations:** the `/api/evidence-requests/propose`, `/approve`, `/reject`, and `/analyze` POST family uses the strict request allowlist. Approval is not a reusable grant for arbitrary commands.
- **Local protection recheck:** `POST /api/device-recheck` accepts an allowlisted check ID. It does not apply a Windows fix or perform a new full vulnerability assessment.
- **Imported evidence:** `POST /api/nessus-import` validates a supplied completed export. It does not invoke the installed Nessus application.

State-changing POST requests require the exact loopback Origin and the appropriate `X-VulnAssess-Action` value. Request length/type/field bounds differ by operation. A successful HTTP response, a completed event stream, a complete collection, and validated AI are separate outcomes; diagnosis must inspect the structured result rather than the transport status alone.

### 28.6 Where to start when the screen and evidence disagree

Follow the complete path: browser action → server route → target/approval check → owning pipeline → emitted event or result → browser reducer/renderer → retained artifact. The arrow denotes a dependency to inspect, not a claim that every path mutates storage.

For example, an “Invalid live assessment event” can arise when the browser rejects the backend's result shape even though scanning produced evidence. A citation rejection instead concerns model publication. A scope refusal occurs before a scan command. These need different repairs; changing a label or weakening the AI validator cannot address all three.

Use [workflow.js](../vulnassess/ui/static/workflow.js), [workflow-data.js](../vulnassess/ui/static/workflow-data.js), [ui/server.py](../vulnassess/ui/server.py), and the stage owner identified in section 35. Compare actual retained coverage and collection status before concluding that a grey node is a failure or that a green report stage proves every requested scanner completed.

## 29. Reports and offline exports

The printable HTML report renders ranked findings, context, score inputs, reasons, references, provenance, feed information, and optional audit/research attachments. Its content is escaped and self-contained, with inline CSS and no external script dependency.

The offline workbench export embeds a recorded assessment and required assets. Its CSP disables network connections. It is a view of a selected stored run, not an export of live scanner/probe/device-recheck functionality.

The live summary is another output: evidence counts, priorities where present, intelligence status, coverage gaps, AI attempts/status, and next actions. Retaining that summary does not imply the printable report command ran.

Attached audit artifacts are checked for the supported artifact kind, required top-level fields, strict string run identity, allowed evidence-status label, content hash, and applicable bindings. This is not general full-schema validation of every version and nested outcome. Stability has additional repeat/hash/determinism consistency checks. Context-specific validation checks supplied provenance, classification arithmetic and H1 decisions, including supporting fields required for VERIFIED claims.

The report-state guard in section 40.14 also reconciles the evaluated subset with current observed hosts/profiles, checks prediction marginals and feasible clean control subsets, and verifies an existing snapshot binding against freshly read state. Without an input binding, a compatible artifact keeps its original evaluation data but the report's context correspondence row is NOT RUN with a visible unbound limitation. This does not mean its arithmetic failed or erase its metrics. It means historical input identity was not established. Acceptance and a self-consistent hash do not authenticate reviewers or recreate absent ground truth.

Source: [report.py](../vulnassess/report.py), [audit.py](../vulnassess/audit.py), [ui/export.py](../vulnassess/ui/export.py).

## 30. Research evaluation

### 30.1 Frozen snapshots and blinded cohorts

The tooling exports/verifies an assessment snapshot, selects a cohort, produces blinded scanner/host evidence, and binds artifacts through a manifest. Expert material withholds system scores, predictions, inferred context, and rationales to reduce answer leakage.

Verified cohort requirements include a 20-50-finding range and supplied reviewer/approval identifiers. Expert truth must cover the declared cohort rather than silently omit inconvenient findings. Those identifiers remain supplied metadata, not authenticated signatures.

### 30.2 Context evaluation

Context evaluation measures role, exposure, controls, missing predictions, abstentions, and disagreements using independently supplied host truth. Synthetic truth is not eligible to establish the real inference claim.

The implemented H1 checks use declared targets including 85% rule-role accuracy and 95% exposure accuracy. These are acceptance hypotheses, not achieved results.

The audit reproduced a defect in the earlier evaluator: `manual_tags_used=False` was hardcoded, and metadata-derived exposure did not fence H1 eligibility. A pure synthetic diagnostic supplied exposure evidence explicitly naming `scope.yaml ... .tags.vantage=external`; the evaluator still returned `manual_tags_used=False` and `h1.eligible=True` for declared-human test labels. That was a provenance/eligibility defect, not a real expert result.

The new working-tree repair inspects the sources and scope-tag evidence of evaluated role/exposure/control features. It retains descriptive metrics while withholding H1 pass/fail and VERIFIED evaluation status for contaminated, synthetic, or incomplete inputs. Unused metadata and unlabelled profiles are not falsely counted as prediction inputs. Truth and shadow-prediction types, labels, duplicate identities and duplicate YAML keys are checked rather than coerced. Section 40.13 records the regressions and passing local gate. These checks inspect declared provenance; they do not authenticate reviewers, establish independent truth, demonstrate actual automatic-inference accuracy, or close the separate old-artifact/current-state binding gap.

### 30.3 Ranking evaluation

The evaluator includes Kendall tau-b, tie-corrected Kendall W, NDCG@10, and critical-queue size. Baselines include CVSS-only and CVSS plus EPSS. Critical-queue size asks how much of the ranked list must be reviewed to include the expert's complete critical set.

At the committed baseline, tie-aware metric functions existed, but system-order construction sorted equal numeric scores by stable finding ID instead of consistently preserving score-tie blocks. That distinction can change measured agreement and shorten the apparent critical queue.

The 17 October uncommitted changes add `ranking_blocks()` and `restrict_ranking()`, use tied numeric priorities in baseline and ablation evaluation, and calculate expected NDCG gain within tied score blocks. The flat order remains available for deterministic presentation; display ordering must not be interpreted as an expert preference between equal scores. These changes do not alter canonical risk scores.

### 30.4 Ablation and stability

Eleven configured scenarios include full, no role, no exposure, no controls, no manual, no EPSS, no KEV, context only, threat only, CVSS only, and CVSS plus EPSS.

Ablations recompute in memory without rewriting the assessment. Stability repeats scoring against supplied state and compares hashes. Determinism is not generalisation, and an evidence-status label does not substitute for inspecting the actual result.

At the committed baseline, the stability CLI could set a VERIFIED label independently of a failed deterministic flag. The 17 October working tree now rejects a failed stability result before writing a successful artifact. Audit loading also checks hash-list shape, repeat counts, uniqueness, and the deterministic claim instead of trusting the outer content hash alone. These uncommitted corrections are included in the local verification checkpoints in section 40. A passing development-tree gate is not an independent research result or a published release.

The working tree also validates expert-truth shapes, duplicate expert names and finding IDs, critical-set membership, and method/cohort completeness. Synthetic truth cannot become eligible for H2/H3 simply by carrying a VERIFIED string. Supplied reviewer/provenance fields still do not authenticate a real expert or establish independent labels.

### 30.5 Research conclusions that cannot yet be assumed

This implementation does not itself establish improved expert agreement, a smaller critical queue, real role accuracy, semantic-merge precision, model superiority, or injection resistance measured across real deployments. Those claims need the declared independent evidence and evaluation protocol.

Source: [cohort.py](../vulnassess/cohort.py), [context_eval.py](../vulnassess/context_eval.py), [evaluate.py](../vulnassess/evaluate.py), [experiments.py](../vulnassess/experiments.py).

## 31. CLI reference and example workflows

### 31.1 Command families

- `scan`: build a scoped Nmap-first plan; execution requires the explicit execution option.
- `import`: ingest supplied Nmap/Nikto/Nessus/legacy-ZAP reports for one target.
- `intel load/status`: load or inspect supplied intelligence snapshots.
- `enrich`, `context`, `rank`, `explain`, `report`: recorded assessment stages.
- `ui`, `visualize`: local workbench or offline export.
- `diff`, `rescan`: comparison tools with different evidence requirements.
- `unify`: conservative grouping preview over a snapshot.
- `model`: labels, train, cross-validate, ablate, evaluate, predict, inspect, validate-promotion, hybrid-preview.
- `research`: snapshot export/verify, cohort freeze/verify, context evaluation, ranking evaluation, ablation, stability.
- `two-machine`: display a shared-CVE/different-context comparison when the supplied run contains one.
- `demo`: process explicitly supplied files; input provenance remains essential.

Global options include configuration and database selection. The default SQLite path is `data/vulnassess.db`. Commands provide JSON output options, while run-bound commands require the applicable run identifier. Exact option placement follows argparse; use command-specific help rather than inferring flags from another command.

### 31.2 Informational examples

The following examples are **NOT RUN** in this documentation task. Paths/IDs are placeholders unless explicitly described as repository defaults. They require existing authorised inputs; they do not install anything.

```powershell
python -m vulnassess --help
python -m vulnassess import --help
python -m vulnassess research --help
python -m vulnassess model --help
```

A recorded assessment using human-supplied files follows this shape:

```powershell
python -m vulnassess intel load --from-dir <approved-feed-directory>
python -m vulnassess import --run-id <run-id> --target-ip <authorised-ip> --nmap <capture.xml>
python -m vulnassess enrich --run-id <run-id>
python -m vulnassess context --run-id <run-id>
python -m vulnassess rank --run-id <run-id>
python -m vulnassess explain --run-id <run-id> --no-model
python -m vulnassess report --run-id <run-id> --out <report.html>
```

An existing local assessment can be viewed with:

```powershell
python -m vulnassess ui --run <existing-run-id> --port 8765
```

The browser address is `http://127.0.0.1:8765`; `/workflow` opens the workflow interface. A different port changes the expected Host/Origin as well as the URL.

Commands capable of downloads or scanner execution are **not run by the agent** as part of this guide. Actual provisioning/execution must follow the repository's existing approved-artifact and target-authorisation requirements.

### 31.3 Expected CLI errors

The public hierarchy maps configuration errors to exit 2, scope errors to 3, adapter errors to 4, intelligence errors to 5, and model/boundary errors to 6. A normal successful command returns 0. Expected public errors are printed without an application traceback through the main CLI handler.

## 32. Testing, CI, and what verification means

### 32.1 Previously verified local result

The last full local verification performed during the 12 October 2026 work reported:

```text
1883 passed, 510 subtests passed
TOTAL 9916 statements, 0 missed, 100% statement coverage
```

The command was:

```powershell
python -m pytest -q -p no:hypothesispytest --cov=vulnassess --cov-report=term-missing
```

The installed Python 3.12 executable was used. The optional Hypothesis pytest plugin was disabled for the local environment; test cases were not skipped to obtain the result. Ruff lint, Ruff formatting, and Pyright also passed in that verification sequence.

This reference records that prior reported result. It does not claim that the uncommitted tree retains that result. The follow-up in section 40 distinguishes reproduced defects, regression tests, and current verification from this historical figure. No live integration was exercised in that follow-up.

### 32.2 Test boundaries

The pytest transport guard blocks socket operations. Real external transports are replaced by injected test doubles. Synthetic cases are labelled and live under the designated test directory. Curated captures carry separate provenance requirements.

Adversarial suites cover the AI boundary, rationale boundary, control boundary, scan plans, and evidence requests. Further regressions cover parser limits, feed atomicity, score integrity, replay, database selection, provider failures, and UI contracts.

### 32.3 CI

GitHub Actions targets Python 3.11 and 3.12, runs lint/format/type checks and pytest, and enforces a 95% package statement-coverage floor. Repository configuration is not evidence that the latest remote run passed; inspect the actual CI run for that claim.

### 32.4 Meaning of 100%

Statement coverage means the measured Python statements executed during the test suite. It does not mean 100% branch coverage, JavaScript/browser coverage, detection accuracy, integration uptime, project completion, or security.

A model mock proves a tested protocol path. A real model call proves that particular call. Independent labelled evaluation is needed for an accuracy claim.

### 32.5 Current repair-batch verification

The latest completed clean checkpoint passed with **4,194 tests and 525 subtests**, zero failures/skips, and **99.33% whole-package Python statement coverage**, with clean lint/format and zero Pyright diagnostics. Section 40.24 records this run. The 11,784 measured Python statements include 79 misses; this does not measure JavaScript coverage. The 95% floor was not reduced. Earlier sections preserve prior checkpoints and actual failures. Later source changes require their own gate; real integration and empirical effectiveness remain separate acceptance work.

### 32.6 Verification of the two-audience documentation refresh

VERIFIED, 17 October, documentation-only work: source inspection and two independent read-only code reviews informed the final corrections. They narrowed claims about endpoint grouping, audit-attachment checks, native-fallback arithmetic, manual vantage provenance, timestamp validation, comparison labels, and the actual HTTP probe. The accessible guide removes unnecessary test-development history and adds reading routes, practical distinctions, and vocabulary. No application source was edited for this refresh.

VERIFIED local CLI inspection: `python -B -m vulnassess --help`, using the installed Python 3.12 executable, exited `0` and printed the command families `ui, import, scan, intel, research, enrich, context, rank, report, eval, two-machine, unify, rescan, explain, diff, model, visualize, demo`. Displaying help did not run any of those operational commands.

VERIFIED document checks: a local PowerShell validator used `Test-Path`, parsed local heading anchors outside fenced code, checked sequential chapter numbering and paired fences, and searched the two guides plus README for common secret-like token formats. It returned `DOC_CHECK_OK`; `git diff --check` returned `DIFF_CHECK_OK`. These checks cover local references and the specified patterns, not internet-link availability, a complete secret audit, or browser rendering. The checker was corrected to accept valid directory links and ignore shell comments inside fenced examples rather than changing valid documentation to satisfy false positives.

VERIFIED source identity: the 276-file aggregate covering package, tests, configuration, scripts, models, fine-tuning inputs, and `pyproject.toml` was still `b8d195c9b53dde7645a15aa70e9f5ba95d26ca42aef76cd78ed3f0a30069402f`. The command printed `SOURCE_SNAPSHOT_UNCHANGED_FROM_RECORDED_GATE`. The complete application gate was **NOT RUN again for this documentation-only refresh**; section 40.12 remains the dated source-verification record, not a freshly executed test result here.

STATUS: both requested Markdown references are saved locally. BRANCH / COMMIT: `codex/coverage-95`, baseline `6f523f6` plus the preserved existing working tree. BUILT / CHANGED: the technical reference, accessible guide, and existing decision log; README already links both guides. DECIDED / DECISIONS: DOCS-REFERENCE-02 keeps implementation, permission, verification, and unresolved work separate. EVIDENCE: local source/help/document/hash checks only. DEFERRED: runtime repairs and real scanner/provider/expert verification are outside this documentation request. MISSING: independently captured Nikto JSON with completed provenance under `tests/fixtures/nikto/`. NEXT: use the appropriate guide; do not treat these documents as closure of the open H1 defect. No commit, push, deployment, installation, or credential change was performed.

## 33. Security properties and remaining risks

### 33.1 Implemented safeguards

- Deterministic scope checks and pinned execution targets.
- Separate canary refusal.
- Bounded parser input and complexity.
- Argument-list scanner execution rather than model-generated shell strings.
- Fixed scanner profiles and bounded evidence-request kinds.
- Explicit approval/hash binding for AI proposals.
- Evidence/provenance retention and integrity checks.
- Deterministic scoring with context-source restrictions.
- Structured AI output, citation and identifier checks, and fail-closed publication.
- Separate scan/AI outcomes and evidence-only completion.
- Server-side credentials with explicit cloud evidence consent.
- Loopback hosting, Origin/Host checks, output escaping, and security headers.
- Offline test transport guards and adversarial cases.

### 33.2 Remaining risk categories

- **Evidence truth:** banners, headers, reports, and apparent control signals can be incomplete, spoofed, or wrong.
- **Inference validity:** confidence weights and context mappings need independent calibration/evaluation.
- **Semantic grounding:** a valid citation does not prove the attached interpretation.
- **Coverage:** top-100 TCP discovery excludes other ports/protocols and many application paths.
- **Provider/runtime behaviour:** installed tools, quotas, model versions, and dependencies can fail or change.
- **Local trust:** loopback controls are not authentication against a malicious local process/user.
- **Artifact authenticity:** hashes are replaceable by someone with sufficient local write authority.
- **Persistence:** a Git source push does not back up ignored operational data.
- **Retention:** policy tables alone do not remove sensitive artifacts.
- **Research correctness:** tie handling, supplied approvals, and evidence-status labels require careful interpretation.

### 33.3 Recent hardening represented by the baseline commit

The named baseline includes encoding-aware XML declaration rejection, bounded capture reads, atomic feed replacement, strict EPSS validation, command-line database selection correction, action/claim binding preservation, saved-capture discovery isolation, and Ollama outage/canary classification fixes.

Those repairs close specific reproduced defects. They are not a guarantee that every possible defect has been found.

## 34. Implemented versus unfinished roadmap

### 34.1 Active assessment capabilities

Canonical ingestion, configured scope checks, live light Nmap, eligible bounded endpoint/Nikto checks, Nessus import, targeted Redis observation, offline/targeted intelligence, rule context, finding-specific control eligibility, deterministic ranking, structured AI analysis, provider fallback, retained evidence, self-defence, browser views, and reporting are implemented.

### 34.2 Explicitly bounded or preview capabilities

AI planning supports two fixed scanner profiles. Follow-up evidence supports three kinds. Learned role inference remains shadow/candidate. Unification is a non-mutating preview. Re-scan outcomes are candidates. Fine-tuning material is preparation. Research tooling needs independently supplied truth.

### 34.3 Original agent roadmap status

- **AI boundary:** implemented with the limitations in sections 17-18.
- **Human-approved plans:** implemented within a fixed vocabulary and bounded history.
- **Typed evidence requests:** implemented for HTTP HEAD, TLS, and TCP connection checks.
- **Evidence reconciliation/CVE ranking agents:** separate full passes remain unfinished.
- **Context reasoning agent:** canonical context is still rules; full contradiction/freshness reasoning remains unfinished.
- **Exploitability vectors and confirmed-finding chains:** not a completed separate production reasoning pass.
- **Selective critic and independent coverage agent:** not an implemented multi-agent debate; coverage review is largely deterministic packaging plus analyst output.
- **Routing/budget/memory:** provider routing, request limits, batching, cache/replay, and prior-record lookup exist; complete cost accounting and richer memory remain unfinished.
- **RAG over corpora:** no complete cited retrieval system over approved advisory/technique corpora.
- **Golden AI evaluation:** generic research infrastructure exists; a complete independently labelled AI-quality benchmark is not established.

The next improvement should be judged by a measurable user/research outcome, not by adding another animated node or declaring every stage executed.

## 35. Source-code navigation

For a first technical reading, follow this order:

1. [cli.py](../vulnassess/cli.py): executable command surface.
2. [schema.py](../vulnassess/schema.py): shared records and identity.
3. [settings.py](../vulnassess/settings.py): validated configuration and scope.
4. [pipeline.py](../vulnassess/pipeline.py): recorded processing stages.
5. [live_assessment.py](../vulnassess/live_assessment.py): actual browser scan-to-summary path.
6. [orchestrator.py](../vulnassess/orchestrator.py): CLI scanner planning/outcomes.
7. [readers](../vulnassess/readers/): scanner adapters and input guards.
8. [intel.py](../vulnassess/intel.py) and [intel_online.py](../vulnassess/intel_online.py): source facts and matching.
9. [context.py](../vulnassess/context.py), [control_applicability.py](../vulnassess/control_applicability.py), and [scoring.py](../vulnassess/scoring.py): contextual priority.
10. [analyst.py](../vulnassess/analyst.py), [ai_boundary.py](../vulnassess/ai_boundary.py), and [explain.py](../vulnassess/explain.py): model input/output contracts.
11. [scan_plans.py](../vulnassess/scan_plans.py) and [evidence_requests.py](../vulnassess/evidence_requests.py): AI agency with approval.
12. [self_defence.py](../vulnassess/self_defence.py): local protection checks.
13. [store.py](../vulnassess/store.py), [repository.py](../vulnassess/repository.py), and history modules: persistence.
14. [ui/server.py](../vulnassess/ui/server.py) and [ui/static/workflow.js](../vulnassess/ui/static/workflow.js): request handling and browser interaction.
15. [role_model.py](../vulnassess/role_model.py), research modules, [unify.py](../vulnassess/unify.py), and [rescan.py](../vulnassess/rescan.py): advanced analysis and evaluation tooling.

Additional support files include the provider-specific transports, `intel_status.py`, `target_intake.py`, `report.py`, `audit.py`, and `visual_simulation.py`. `ui/runtime.py` retains legacy learned-inference helpers but is not exposed/imported as an active UI server feature. `visualize` is an offline-workbench compatibility command rather than an independent assessment engine.

## 36. Maintenance and handoff checklist

Before presenting or extending this project:

1. Confirm the checkout and commit; this workspace has contained multiple historical copies.
2. Identify the relevant path: recorded assessment, new live scan, replay, saved refresh, or self-defence.
3. Check scope and installed-tool readiness separately from provider configuration.
4. Identify whether the result is live, retained, synthetic, or a preview.
5. Record scanner coverage and the actual finding/CVE prerequisites.
6. Keep unknowns visible; do not make a missing observation look like a clean result.
7. Preserve raw evidence and associate priorities with configuration/feed identity.
8. Evaluate scoring changes on frozen inputs, including missing-data and control-eligibility cases.
9. Keep model proposals outside authorisation and canonical arithmetic.
10. Read previews and supplied approval manifests according to their actual guarantees.
11. Back up ignored operational artifacts separately when required, with attention to their sensitivity.
12. Re-run appropriate checks after code changes and report exact evidence, dates, and limitations.

For presentations and nontechnical onboarding, start with the [plain-language guide](PROJECT_GUIDE_FOR_EVERYONE.md). Use this reference when someone needs to inspect the implementation, reproduce a workflow with their own authorised inputs, or understand a boundary in detail.

## 37. Following one finding from input to report

This walkthrough describes data movement. It is not a real scan result, a supplied capture, or a claim that any example vulnerability is present.

### 37.1 Evidence enters the system

A human selects an authorised target and either supplies a scanner report or explicitly starts a permitted live operation. The entry path checks scope and target identity. A URL's hostname is not permission to scan every address it might resolve to.

For import, the adapter reads the bounded supplied file and constructs host, service, and finding records. For a live scan, scanner output is captured first, then parsed. A raw report remains important even when the canonical finding includes only a shortened evidence excerpt.

### 37.2 A finding becomes an identifiable record

The canonical finding describes the host, service endpoint, originating tool, native identifier, observation, and supported vulnerability identifiers. Its provenance points back to the raw file, record index, and run.

Two tools reporting the same CVE do not automatically establish one identical affected instance. Endpoint identity and original source records must survive normalisation. The grouping preview can help inspect justified overlap, but it is not the official score queue.

### 37.3 Intelligence supplies vulnerability facts

If the scanner names a supported CVE, an enrichment can associate it with available NVD, EPSS, and KEV facts. The record identifies the matching method and feed dates. If facts are unavailable, the system must expose the absence rather than manufacture a severity vector or exploitation likelihood.

A CVE association is not equivalent to an exploit demonstration. An explicit-ID match means the scanner supplied that identifier; a CPE/version match means the implemented product/version conditions matched. Both require interpretation in light of tool coverage, backports, and evidence quality.

### 37.4 Context describes the deployment

Rule-based inference builds a profile from observed services, banners, and permitted metadata. It selects a primary role, estimates exposure, and records control signals with confidence and evidence.

Before scoring, finding-specific eligibility isolates the context that may affect that finding. A TLS listener on one port does not protect every other port. An unrelated authentication observation does not justify changing a finding's privileges-required metric. Unknown protection stays unknown.

### 37.5 The deterministic score is calculated

The score uses the selected enrichment, eligible context, and configured weights. It retains the Environmental changes, threat multiplier or missing-data state, native fallback where used, KEV effect, risk band, and weights hash.

This output is the canonical arithmetic record. A later model cannot replace its score with a preferred value. The evaluator must also distinguish equal numerical priorities from the stable finding-ID order used to draw or print them.

### 37.6 AI receives a bounded case

The analyst receives a selected case rather than unrestricted access to the database or computer. Server-issued evidence identifiers refer to records in that case. Target-controlled text is enclosed as untrusted material, and the model is instructed to return a versioned JSON structure.

The model may explain, connect observations, or propose an investigation. Its prose is checked against the permitted identifiers, canonical scores, claim metadata, and available evidence associations. A hypothesis remains a hypothesis, even when it is useful.

### 37.7 Publication depends on validation, not just generation

An accepted response can be shown with its supporting citations and limitations. A rejected response becomes Needs review; an unavailable provider remains unavailable. Neither outcome erases successfully retained scanner evidence.

The report should distinguish at least three questions:

1. Was the requested evidence collection successful and complete for its declared coverage?
2. Were the required intelligence and scoring inputs available?
3. Was the optional AI interpretation accepted?

The current status/replay defects in section 40 show why one undifferentiated “complete” label is insufficient.

## 38. Failure diagnosis and correct interpretation

### 38.1 “At least one resolved address is outside the authorised scope”

This comes from target resolution and deterministic scope checking, before a scanner command is accepted. A valid-looking website, an installed Nmap binary, or a responsive model does not resolve it.

Inspect the submitted host, resolved IPv4 set, configured boundaries, explicit asset entries, and canary. A changed DNS answer or an additional out-of-scope answer can explain why a previously accepted hostname is rejected. Do not disable the gate or widen a network simply to make the error disappear.

### 38.2 “Nmap is unavailable” even though Nmap is installed

Installation on the desktop and discovery from the Python server process are different conditions. The server may have a different PATH, a configured binary override may be wrong, or the discovered executable may fail its version check.

Inspect the preflight detail and the server-side configuration described in section 8.3. A user-facing browser cannot execute the desktop installation by itself. Running Nmap from a cloud deployment would require a separately provisioned scanner environment and approved network vantage; changing a model key would not create that environment.

### 38.3 “Nikto dependency-error: XML::Writer”

Nikto is Perl-based, and the configured runtime cannot load the required XML writer. Check the exact Perl executable and library path selected by the app, not only whether another Perl installation works in a terminal.

This document does not install or download that dependency. Dependency provisioning remains governed by the reviewed-artifact process. A missing dependency is not a scope violation and must not be presented as a successful Nikto assessment.

### 38.4 “Nessus report can be imported”

That is an integration description, not a failed live Nessus launch. The implemented path accepts a completed authorised-target `.nessus` export. It does not invoke the Nessus application, schedule its scans, or assert that a file was imported merely because Nessus is installed.

### 38.5 NVD, EPSS, or KEV did not execute

First distinguish a missing prerequisite from a failing source. No scanner-supported CVE can make a targeted lookup not applicable. A named CVE with a publisher error, missing local snapshot, or invalid cache is an unavailable-input condition instead.

Inspect the intelligence mode, checked CVE IDs, per-feed status, dates, and hashes. A grey node cannot, by itself, distinguish these cases. A feed's global timestamp also cannot prove that every retained cache row was refreshed; see section 40.3.

### 38.6 “Needs review” at citation/score validation

Generation succeeded at the transport level, but the answer violated an output contract. Relevant causes include malformed JSON, missing claim metadata, unsupported identifiers, changed canonical values, unsupported control assertions, and an injection sentinel.

Preserve the rejection detail and audit metadata. Check the case/evidence IDs and the exact validator branch. Do not edit a canonical score, fabricate citation text, or bypass validation to turn the status green. A provider outage and rejected content require different handling.

### 38.7 “0 findings” with several observed services

The scanner observed inventory but did not emit a vulnerability finding under that profile. This is a legitimate result for a light scan. It is neither proof that no vulnerabilities exist nor permission to invent CVEs from a service name alone.

Improve assessment coverage only through an appropriate, authorised tool/profile or supplied report. Choosing a target merely to make every node green is not a valid coverage strategy.

### 38.8 A saved result looks newer than the underlying scan

Capture time, intelligence-refresh time, and AI-analysis time are different timestamps. Replaying evidence or refreshing CVE facts does not produce a new target observation. Preserve all three identities when demonstrating freshness.

### 38.9 GitHub does not contain a local result

First check the repository, branch, commit, and tracked-file state. Then inspect ignore rules. A database or raw capture under ignored `data/` is not included in an ordinary source push. API keys should not be added to make a repository seem like a complete runtime backup.

## 39. Demonstration and acceptance evidence

### 39.1 A representative demonstration is a set of cases

No single target can legitimately exercise every feature. HTTP checks, a Redis-specific observation, Nessus import, local Windows protection, and expert evaluation have different inputs and purposes.

A defensible demonstration can contain:

- An authorised network capture with supported findings and traceable raw records.
- An applicable web endpoint to demonstrate the bounded Nikto path.
- A separately supplied Nessus report to demonstrate ingestion and target binding.
- A finding with dated NVD, EPSS, and KEV facts, where those facts actually exist.
- A deterministic score breakdown showing eligible and withheld context effects.
- Accepted AI analysis and a separate rejected/unavailable-model case.
- A self-defence case on the supported local platform.
- A saved assessment reopened without claiming a new scan.
- Independent expert labels for a frozen ranking cohort, when those labels are genuinely available.

Cases must be labelled live, imported, replayed, synthetic, or preview. A synthetic metric example cannot stand in for a real feed or an expert study.

### 39.2 What to record for a real claim

Record the code commit, relevant working-tree changes, configuration identity, authorised target, raw-evidence paths/hashes, tool versions, argv/profile, start/end, exit outcome, scanner coverage, feed identity, and model/provider identity where relevant.

For AI, also retain the applicable prompt/input/output hashes, validation decision, and provider attempts. For research, retain the frozen cohort, truth provenance, tie policy, missing-data policy, and actual metric denominators.

These are traceability requirements. Local hashes and typed approval IDs do not independently authenticate the people or observations behind them.

### 39.3 Questions a reviewer should be able to answer

1. Which observations justify this finding?
2. Which tool/profile actually produced them?
3. Which CVE association method was used, and what could make it wrong?
4. Which context feature changed the score, and why was it eligible here?
5. Was a model statement observed, inferred, or hypothetical?
6. Which parts were not checked or failed?
7. Was this a new scan, a replay, or a refresh of external facts?
8. Does an evaluation result use independent real truth, or only synthetic inputs?
9. Can someone reproduce the deterministic part from the retained inputs?
10. What remains uncertain even if all local unit tests pass?

## 40. 17 October working-tree status and unresolved cracks

This section prevents the detailed feature inventory from being read as a declaration of completion. It separates reproduced defects, current repairs, and unfinished capability. The initial documentation task did not execute the application gate. The subsequent active-goal audit resumed code changes and offline tests; its outcomes must be distinguished from a live scanner, feed, or provider verification.

### 40.1 Research-validation corrections exist but are not a verified release

Uncommitted changes affect [evaluate.py](../vulnassess/evaluate.py), [pipeline.py](../vulnassess/pipeline.py), [experiments.py](../vulnassess/experiments.py), [cli.py](../vulnassess/cli.py), and [audit.py](../vulnassess/audit.py). They address score ties, expert-truth validation, synthetic-evidence eligibility, failed stability commands, and inconsistent stability artifacts.

The associated regression files are [research completion claims](../tests/synthetic/test_synthetic_research_completion_claims.py), [truth integrity](../tests/synthetic/test_synthetic_research_truth_integrity.py), and the updated [artifact validation tests](../tests/test_audit_validation_boundaries.py).

Focused runs cover research and completion-claim paths. An additional regression showed that a two-expert all-tied result was incorrectly described as a single-annotator study; the limitation now identifies degenerate or incomparable rankings. Later full local gate results are recorded below, most recently in section 40.12. Neither focused metrics tests nor that complete local gate establish independent expert agreement or a released build.

### 40.2 An unfinished test scaffold was repaired, not counted as coverage

[Targeted intelligence freshness tests](../tests/synthetic/test_synthetic_targeted_intel_freshness.py) initially failed during fixture construction because `Feature.source="synthetic"` is not a valid source value. Those initial failures did not reproduce the suspected bug and were not counted as successful evidence.

The corrected synthetic inputs use a permitted source and remain explicitly labelled synthetic. They reproduce the old unrestricted-match behaviour and exercise the implemented bounded view, missing requested rows, unchanged unrelated cache rows, malformed unrelated records, and both saved/live integration paths. A successful test here is TESTED WITH MOCKS for external transports, not evidence that a publisher or real scanner answered.

### 40.3 Targeted freshness overstated the set of usable matches

The defect was that refreshing selected CVEs left unrelated old cache rows in place, while CPE matching could inspect the full cache. An older unrelated match could drive the score of the freshly reviewed case.

The working tree adds `intel_online.requested_cache()`. Its `cve`, `epss`, `kev`, and `all_cves` methods expose only a copied, normalised set of requested IDs. Point reads avoid decoding unrelated records. Saved refresh and on-demand live matching use the view after sync; offline snapshot matching retains the full catalogue. No unrelated records are deleted to manufacture freshness. The view itself is not proof of a new request: publisher/cache status still supplies that distinction.

### 40.4 Saved replay overstated retained stage completion

The old saved replay path emitted completion for scope, scanner, endpoint, canonical records, and context before checking retained prerequisites. It also used a Redis-specific Nikto skip message regardless of the actual case.

The working-tree helper checks the selected host, context profile, and supplied outcome labels before publishing completion. Saved refresh separately validates matching host/context/finding inputs before cache access. Missing or ambiguous prerequisites raise a controlled configuration error rather than `StopIteration` or a green context stage. Replay derives endpoint/Nikto states from retained coverage, preserves a partial outcome, and identifies that no new scan ran. Legacy captures without a status require retained coverage evidence instead of an automatic success default.

### 40.5 Partial scanner failure was flattened into complete

The live path correctly retained successful baseline evidence after an optional requested operation failed, but its generic `scan_status="complete"` and “Scan complete” messages obscured incomplete requested coverage. The browser also accepted only complete evidence-only results, so a partial result could become an invalid event.

The working tree now carries `scan_status="partial"` and failed-check details through live payloads, summaries, captures, recent/saved replay, receipts, and history pages. Browser acceptance and outcome labels handle a supported partial result; Overview and the assessment brief explicitly warn about incomplete coverage. A final AI receipt cannot change the collection status or core collection identity, even with a recomputed receipt hash.

Stage states remain the existing pending/running/complete/skipped/error vocabulary. A built evidence summary can have a complete report stage while the result remains a partial scan. A failed model does not, by itself, turn a successfully collected scan into partial coverage. [Partial completion tests](../tests/synthetic/test_synthetic_partial_completion.py) and [replay completion tests](../tests/synthetic/test_synthetic_replay_completion.py) exercise these distinctions with injected transports and pure UI checks.

### 40.6 Broader unfinished capability is still unfinished

The roadmap in section 34 remains the source-level summary: independent critic/debate, full self-consistency sampling, richer contradiction/freshness context reasoning, confirmed-finding exploitability chains, substantial cited retrieval, operational semantic merging, complete software inventory, and real independent effectiveness measurements are not established as completed capabilities.

The right completion criterion is a tested behaviour with appropriate evidence, not the presence of a module, table, Markdown description, green node, or high statement-coverage percentage.

The earlier protocol-eligibility concern was reproduced and repaired in the subsequent batch: the old test named `test_discovery_derives_only_observed_http_endpoints` missed non-HTTP services on common web ports. New negative cases cover those services, other transports, and misleading substrings. This is a code-path regression result, not a real scanner/protocol verification.

At that earlier protocol/coverage checkpoint, newly identified follow-ups were the no-severity-basis zero/Low result in section 15.4 and the filesystem-derived saved-CVE capture time in section 26.3. They were subsequently repaired and locally checked in section 40.11; they were not repaired by the earlier checkpoint. H1 provenance remained open at that point and was addressed in the later section 40.13 increment; the wider audit remains active.

### 40.7 Initial documentation verification and handoff

VERIFIED, 17 October, documentation checks: a local PowerShell check enumerated Markdown links, checked relative targets with `Test-Path`, compared local anchors with headings, and checked paired code fences. It returned:

```text
DOC_CHECK_OK: relative links, local anchors and code fences passed
```

VERIFIED, command syntax only:

```text
python -B -m vulnassess import --help
usage: vulnassess import [-h] [--json] --run-id RUN_ID --target-ip TARGET_IP
                         [--nmap NMAP] [--zap ZAP] [--nikto NIKTO]
                         [--nessus NESSUS]

python -B -m vulnassess ui --help
usage: vulnassess ui [-h] [--json] [--run RUN_ID] [--port PORT] [--db DB]
                     [--config CONFIG] [--model ANALYST_MODEL]
                     [--ollama-host OLLAMA_HOST] [--export PATH]
```

These help commands used the installed Python 3.12 interpreter. They do not establish a working scanner, provider, database run, or browser session.

- **STATUS:** two documentation guides prepared and locally checked; no new application release claim.
- **BRANCH / COMMIT:** `codex/coverage-95`; baseline `6f523f6`, with the separately described uncommitted work preserved.
- **GATE:** NOT RUN for the whole application during this documentation task. No new Ruff/Pyright/pytest/coverage result is claimed.
- **BUILT / CHANGED:** this technical reference and the companion plain-language guide under `docs/`; no runtime changes by the documentation task.
- **DECIDED / DECISIONS:** keep detailed implementation and accessible explanation separate, with explicit baseline/working-tree distinctions, rather than one ambiguous feature checklist. This editorial decision is recorded here; no scoring, scope, dependency, or interface decision was changed.
- **EVIDENCE:** inspected source/configuration, local document validation, and CLI help output. Historical test figures remain historical.
- **DEFERRED:** live scanner/provider/feed checks and independent expert/AI-quality evidence were not run or supplied here. Real-integration fixture availability was not re-audited; no missing fixture was replaced with synthetic evidence.
- **NEXT at the initial handoff:** repair and verify sections 40.2-40.5. The follow-up implementation is now described above; it remains separate from real-integration and independent research evidence.

### 40.8 Local verification of the repair batch

VERIFIED on Windows with the installed Python 3.12.10 interpreter. The official gate script was executed after application/test changes were finished. The workstation-specific optional Hypothesis plugin was disabled through temporary pytest options; no project test was skipped or excluded.

```powershell
$taskPriorPytestOptions = $env:PYTEST_ADDOPTS
try {
    $env:PYTEST_ADDOPTS = "$taskPriorPytestOptions -p no:hypothesispytest -q --durations=8"
    python -u -B scripts/check.py
} finally {
    $env:PYTEST_ADDOPTS = $taskPriorPytestOptions
}
```

Actual result excerpts:

```text
All checks passed!
PASS    ruff lint
259 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10133     10    99%
Required test coverage of 95% reached. Total coverage: 99.90%
2147 passed, 510 subtests passed in 2891.59s (0:48:11)
PASS    pytest + coverage
GATE PASSED
```

There were zero test failures and zero skips in this clean run. Compared with the previously reported 1,883-test/9,916-statement baseline, this is 264 additional test cases and 217 additional source statements. Coverage is 99.90%, not 100%; the required 95% floor, whole-package measurement, and fail-closed assertions were not lowered or bypassed.

The wall-clock report contains an anomalous 2,551.12-second duration in a mocked endpoint-timeout case. Its scanner, parser, Redis, and analyst paths were injected test doubles; it did not perform a real network scan. The cause of that wall-clock pause was not established. Do not turn this run into a latency benchmark or claim it demonstrates a real endpoint timeout of that duration.

An earlier full run ended with two failures in legacy success fixtures. Those fixtures supplied missing context/coverage or retained findings from another target. They were corrected to provide explicit, target-bound synthetic records while retaining their success assertions; new negative tests retain rejection coverage for the invalid cases. The gate above is the subsequent clean run, not a claim that the earlier run passed.

An aggregate fingerprint over 208 source/test/script/configuration files was unchanged during verification:

```text
b7a2be147f1be4a9e9ce2a2e3ecb1e5ca760a364af0f33bc5149e9ee1e6e2766
```

VERIFIED separately: `git diff --check` completed without whitespace errors. A pattern-only search of tracked files found no matches for the checked high-confidence API-token/private-key patterns. That search is not a comprehensive secrets or dependency audit.

TESTED WITH MOCKS: scanner failures, publisher responses, model outcomes, replay callbacks, and UI event/rendering contracts. Pure ranking, artifact validation, and local SQLite paths also executed using synthetic inputs. These results do not establish detection accuracy, fresh public-feed availability, current provider uptime, or a deployed browser/server instance.

NOT RUN: live scanners, public feed downloads, real cloud/local-model calls, remote CI, fresh browser end-to-end execution, dependency vulnerability assessment, server restart, commit, or push. MISSING: an independent real Nikto JSON capture with completed provenance under `tests/fixtures/nikto/`; synthetic examples are not a replacement.

The repairs at this checkpoint are implemented and locally verified on `codex/coverage-95`, but remain uncommitted. Decisions CLAIMS-01 through CLAIMS-04 are in [decisions.md](decisions.md). At that checkpoint the CLI protocol issue remained open; the subsequent batch addresses it. The bounded/unfinished capabilities in section 34 are not declared complete by either gate.

### 40.9 Protocol and coverage follow-up

This batch addresses PROJECT.md stages 2-5 and 7. Initial tests reproduced 70 failures in an 86-case protocol suite: common ports were treated as HTTP, non-TCP and loose substring labels became web endpoints, port 443/8443 implied TLS, and malformed retained TLS values were coerced. Supported protocol classifications and negative cases are now in [protocol claim tests](../tests/synthetic/test_synthetic_protocol_claims.py); added endpoint-recovery cases also prevent a UDP Redis label from redirecting a confirmed TCP HTTP check.

The shared [protocols.py](../vulnassess/protocols.py) interpreter is used by CLI/live web eligibility and planner endpoint construction. The Nmap reader records explicit TLS classifications rather than a port convention. A port-table HTTPS guess does not establish a TLS control. Strict `Service.tls` deserialisation enforces its existing boolean wire type; no schema field or model-derived scoring authority was added. Labels/classifications are not independent handshake verification.

Initial summary tests also reproduced invented top-100 coverage, false absence of Nessus imports, and a completed-priority claim when scores were missing. [Coverage claim tests](../tests/synthetic/test_synthetic_coverage_claims.py) now verify that summaries quote retained coverage, expose missing metadata as unknown, count scored/unscored findings separately, and refuse invalid identities, orphan/duplicate priorities, invalid bands, or unsupported numeric values. Orphaned enrichment cannot inflate the matched-finding count. These are record-binding/publication checks, not recomputation or proof of the scientific validity of each score.

VERIFIED local gate, using the same temporary optional-plugin workaround and official `scripts/check.py` command as section 40.8:

```text
All checks passed!
PASS    ruff lint
262 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10166     11    99%
Required test coverage of 95% reached. Total coverage: 99.89%
2265 passed, 515 subtests passed in 256.13s (0:04:16)
PASS    pytest + coverage
GATE PASSED
```

The clean run has zero failures/skips and 118 more tests than the preceding 2,147-test checkpoint, with five additional observed subtests. The required whole-package 95% floor was unchanged. Coverage is 99.89%, not 100%, against 10,166 measured statements. No exclusions or weakened validator assertions were used. The consistent empty-case display fixture retains its original no-CVE assertion and adds empty-priority/matched-count checks; separate negative cases reject orphaned records.

The aggregate source/test/script/configuration fingerprint over 211 files remained unchanged during verification:

```text
b0838a4262fee214fecd56c46f13e501611fd58676240b11b975078ec5630e62
```

TESTED WITH MOCKS / synthetic inputs: scanner selection, Nmap XML interpretation, live branches, planner inputs, retained JSON and summary publication. Existing curated captures were also parsed by the offline tests. No fresh scanner, TLS handshake, publisher retrieval, model call, browser end-to-end session, remote CI, server restart, commit or push is claimed. The independent real Nikto fixture remains MISSING.

BRANCH / COMMIT: `codex/coverage-95`, baseline `6f523f6` plus uncommitted changes. CHANGED: shared protocol logic, Nmap reader, strict Service reads, CLI/live/planner use, summary validation/wording, tests, and existing reference documents. DECIDED / DECISIONS: CLAIMS-05; preserve the evidence/scoring/authority boundaries instead of inventing protocol or completion facts. NEXT: reproduce and repair missing-severity zero/Low presentation and saved-CVE timestamp provenance, subject to their existing contracts. The overall audit remains active.

### 40.10 Documentation-refresh check of the newer development tree

This is a newer checkpoint than section 40.9. The documentation refresh preserves the already modified runtime/test files; it does not complete or revert their pending implementation. The previously clean checkpoint must not be treated as verification of files modified afterward.

VERIFIED local command: the installed Python 3.12 executable ran `python -u -B scripts/check.py`, with the same temporary `PYTEST_ADDOPTS` settings shown in section 40.8. The optional Hypothesis plugin alone was disabled; no project tests were excluded or skipped. Actual output excerpts:

```text
Found 1 error.
FAIL    ruff lint: exit 1
4 files would be reformatted, 260 files already formatted
FAIL    ruff format: exit 1
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10180     11    99%
Required test coverage of 95% reached. Total coverage: 99.89%
16 failed, 2270 passed, 515 subtests passed in 306.69s (0:05:06)
FAIL    pytest + coverage: exit 1
GATE FAILED: ruff lint, ruff format, pytest + coverage
```

There were zero skipped tests. The 16 failures comprise 12 capture-chronology cases and four older scoring-edge cases that still expect an invented zero/minimum fallback. The lint finding is the import block in the new capture-time test; formatting findings cover that test, the new missing-severity test, and live/saved scoring integration. Pyright passed. The measured coverage cleared the floor, but the combined pytest/coverage stage and the overall gate **failed**. Coverage is not a substitute for the failed acceptance checks.

Two workstreams explain the current integration risk:

- **Missing severity:** a new guard and live/saved unscored helper exist, together with [missing-severity regressions](../tests/synthetic/test_synthetic_missing_severity.py). The intended invariant is no invented Low score, no lost finding, no KEV-only manufacture of a severity basis, and no rejection of a legitimate computed zero. The complete old/new test contract and publication paths still need reconciliation.
- **Capture chronology:** [capture-time regressions](../tests/synthetic/test_synthetic_capture_time.py) require explicit recorded provenance, honest unknown dates for legacy captures, and selection that does not mistake copied-file modification times for scan chronology. The inspected loader still derives chronology from filesystem times. These tests specify unfinished behaviour, not a repaired integration.

The four legacy scoring expectations need deliberate reconciliation with the intended missing-input policy, not deletion or weakened assertions to make the gate green. The timestamp implementation is still missing. This documentation task did not change either production behaviour or those test expectations.

VERIFIED focused follow-up:

```text
python -B -m pytest -q -p no:hypothesispytest -p no:cacheprovider tests/synthetic/test_synthetic_missing_severity.py --tb=short
9 passed in 0.42s
```

This confirms the nine new cases in isolation. Its scanner, publisher, and live/saved execution boundaries are TESTED WITH MOCKS; it does not overturn the failing whole-project gate.

NOT RUN: live target assessments, fresh publisher retrieval, real model inference, browser end-to-end interaction, remote CI, dependency installation, commit, and push. They were unnecessary for explaining the source and were not authorised by this documentation task. MISSING: an independent real Nikto JSON fixture with completed provenance under `tests/fixtures/nikto/`; the existing example and empty provenance table do not supply it.

VERIFIED documentation checks: the local PowerShell validator checked relative file links, linked Markdown anchors, and paired fenced blocks in both guides. It returned `DOC_CHECK_OK: relative links, local anchors and code fences passed`. `git diff --check` reported no whitespace errors. CLI `--help`, `import --help`, and `ui --help` also executed locally; these establish the documented command surface, not a running server or scanner.

- **STATUS / GATE:** documentation updated and locally checked; application gate failed as quoted above. No release-readiness or 100%-completion claim.
- **BRANCH / COMMIT:** `codex/coverage-95`, baseline `6f523f6`, with the existing dirty worktree preserved.
- **BUILT / CHANGED:** extensive technical reference and plain-language guide under `docs/`; documentation navigation/current-status wording in `README.md`; append-only editorial decision in `docs/decisions.md`. No runtime fix was added by this documentation refresh.
- **DECIDED / DECISIONS:** DOCS-REFERENCE-01 records the two-audience reference and the separation of implementation, verification, and unfinished work. A duplicated feature brochure without status qualification was rejected.
- **EVIDENCE:** source/configuration inspection, CLI help, local document checks, and the full local gate. External integration behaviour remains TESTED WITH MOCKS where covered by tests, not newly verified live.
- **DEFERRED / NEXT:** finish the missing-severity integration and capture-time provenance repair, then rerun the complete gate on the final source tree. Independent real fixtures and expert/model-quality evidence remain separate prerequisites for their respective claims. No commit or push was performed.

### 40.11 Severity-basis and capture-chronology follow-up

This implementation follows the failing checkpoint in section 40.10. It serves PROJECT.md stages 3-7 and the cross-cutting reproducibility component. Decisions CLAIMS-06 and CLAIMS-07 record the reasoning and rejected alternatives; valid-input score arithmetic, canonical fields, dependency list and scope were not changed.

Missing severity now produces an explicit error/unscored record instead of invented zero/Low or minimum-table severity. Live/saved analysis retains all findings and scores the supported subset. Strict recorded ranking refuses unsupported input before publishing replacements. Summary annotations reject unknown/duplicate identities, contradictory scored IDs and missing reasons. Overview, brief, live summary, saved review, stored workbench and printable report expose the missing basis; historical stored values are not rewritten. Genuine supported zero remains a valid zero.

Capture discovery now uses recorded dates. New manifests retain collection completion before AI and initial receipts preserve it. Legacy missing dates remain unknown, ambiguous undated selection refuses, and equal dates or incomparable undated candidates are disclosed. Invalid/timezone-naive/conflicting timestamps and selected corrupt evidence fail closed. Receipt-backed and legacy paths parse the exact case bytes whose hashes were verified. Bounded reads and discovery limits remain explicit rather than silently claiming complete search.

The first integrated gate caught a genuine architectural violation: UI modules imported the scoring engine to reuse a display predicate. That run ended with `1 failed, 2315 passed, 515 subtests passed`, 99.83% statement coverage, and `GATE FAILED: pytest + coverage`. The import wall was not weakened. The predicate moved to the pure, read-only `score_facts.py`; a subsequent targeted run returned `30 passed in 1.27s`, including the unchanged wall test. An earlier broader focused run returned `117 passed in 3.28s`. These results are not substitutes for the separate final gate.

VERIFIED final local gate, using the installed Python 3.12.10 interpreter:

```powershell
$taskPriorPytestOptions = $env:PYTEST_ADDOPTS
try {
    $env:PYTEST_ADDOPTS = "$taskPriorPytestOptions -p no:hypothesispytest -q --durations=8 --tb=short"
    python -u -B scripts/check.py
} finally {
    $env:PYTEST_ADDOPTS = $taskPriorPytestOptions
}
```

Actual output:

```text
All checks passed!
PASS    ruff lint
266 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10287     17    99%
Required test coverage of 95% reached. Total coverage: 99.83%
2316 passed, 520 subtests passed in 256.35s (0:04:16)
PASS    pytest + coverage
GATE PASSED
```

There were zero failures and zero skipped tests. The optional workstation Hypothesis plugin alone was disabled; no project test, validator assertion or 95% whole-package floor was removed or lowered. Compared with the previous clean 2,265-test checkpoint, this adds 51 tests and five observed subtests. Statement coverage is 99.83%, not 100% accuracy or completion.

The aggregate SHA-256 over 274 files comprising retained source/configuration/test/script/model/fine-tuning inputs and `pyproject.toml`, excluding Python/test cache files, was unchanged across the final gate:

```text
c634bfb7b55c75ae0faff9b9d8cf3c8d5ed67812da097e69e1c2450004ac5fc8
```

STATUS: the two named defects have implementation and local regression evidence; the broad audit remains active. BRANCH / COMMIT: `codex/coverage-95`, baseline `6f523f6` plus uncommitted work. BUILT / CHANGED: score guards and read-only score facts, bounded capture chronology/byte verification, live/server propagation, report/UI presentation and synthetic regressions. DECIDED / DECISIONS: CLAIMS-06 and CLAIMS-07; preserve findings/history and explicit unknowns instead of inventing numbers/dates. The first failing integration attempt is retained above rather than reported as successful.

TESTED WITH MOCKS / synthetic inputs: publisher outages, scanner/live callbacks, UI fake-DOM rendering, replay inputs and scope objects. Local SQLite, hash validation and pure logic executed. No real integration or independent research result is inferred.

NOT RUN: real scans, publisher refresh, cloud/local-model calls, browser end-to-end/layout checks, remote CI, dependency installation, server restart, commit and push. MISSING: independently captured Nikto JSON with completed provenance under `tests/fixtures/nikto/`. The bounded/unfinished research and agent features in section 34 remain unfinished. The next audit includes the distinct HTTP control-eligibility predicate and binding of final-review summaries, neither claimed repaired by this increment.

### 40.12 Control-protocol and saved-summary binding follow-up

This increment serves PROJECT.md stages 3-7 and research reproducibility. It follows the completed severity/chronology batch rather than changing its historical verification record. Decisions CLAIMS-08 through CLAIMS-10 record the design.

- **Control eligibility:** the shared exact TCP/HTTP classifier replaces the separate loose prefix check. New input-policy version `finding-scoped-controls-v2` identifies corrected decisions. Literal imported URLs remain a fallback only without a matching service fingerprint. Raw observations and old numeric priorities remain unchanged; reconstructed v1 descriptions explicitly identify the legacy eligibility policy and uncertain mitigation.
- **Unknown outcomes:** summary construction no longer turns a missing collection status into complete. Missing/null stays unknown in summary metadata; malformed supplied values raise a controlled error. Actual live/replay collection and stage-state vocabularies are unchanged.
- **Saved summaries:** final review freezes all non-AI summary contents and verifies available structured facts against retained payloads. Only six intended AI projection fields may change, and they remain bound to the outer AI outcome and retained analyst output. Boolean/numeric substitution, non-finite values, fabricated batch totals/omissions/counts, and claimed cross-batch reasoning are rejected. Verification compares saved facts without recomputing old scores or importing scanner/model/scoring engines.

Red evidence: the new control suite first reported `22 failed, 24 passed`; the collection-status cases first reported `9 failed, 2 passed`. The delegated receipt-summary suite first reported `106 failed, 3 passed`. Parent review added 14 failing cases for internally matching but impossible batch metadata, then repaired the missing invariants. These are synthetic logic/artifact tests, not real scanner or expert evidence.

Focused integration returned `481 passed in 11.35s`, then `303 passed in 9.88s` after the extra batch guards. The first full gate exposed one remaining invalid fixture and returned `1 failed, 2556 passed, 520 subtests passed`, with 99.76% coverage and `GATE FAILED: pytest + coverage`. The escaping fixture claimed validated prose without a retained analyst source. Its repair supplies that source, retains every escaping assertion, and adds explicit source-binding coverage; validation was not weakened. A subsequent focused run returned `267 passed in 8.89s`. Final full-gate evidence follows separately.

NOT RUN: real scanners, publisher retrieval, cloud/local-model inference, browser end-to-end/layout verification, remote CI, installation, server restart, commit and push. MISSING: independent real Nikto JSON with completed provenance under `tests/fixtures/nikto/`. Hash/summary agreement does not authenticate an operator, establish mathematical correctness of a stored priority, or prove model prose semantically true.

The wider audit remains active. The H1 provenance defect in section 30.2 is reproduced but not repaired here: explicit metadata-derived exposure can still be reported as zero-manual-tag evaluation. A passing gate for this increment must not be used to declare that research claim complete.

VERIFIED final local gate, using the installed Python 3.12.10 interpreter and official `python -u -B scripts/check.py` with the same temporary optional-plugin settings as section 40.11:

```text
All checks passed!
PASS    ruff lint
268 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10431     23    99%
Required test coverage of 95% reached. Total coverage: 99.78%
2557 passed, 520 subtests passed in 260.43s (0:04:20)
PASS    pytest + coverage
GATE PASSED
```

There were zero failures/skips; no project tests, assertions or whole-package coverage floor were excluded or lowered. This is 241 additional test cases compared with section 40.11. The aggregate over the same input directories plus `pyproject.toml` now covers 276 files and was unchanged across final verification:

```text
b8d195c9b53dde7645a15aa70e9f5ba95d26ca42aef76cd78ed3f0a30069402f
```

STATUS: the three named boundaries are implemented and locally verified; the wider audit remains active. BRANCH / COMMIT: `codex/coverage-95`, baseline `6f523f6` plus uncommitted work. BUILT / CHANGED: shared control eligibility and v2 provenance, unknown outcome handling, receipt-summary consistency and synthetic regressions. DECIDED / DECISIONS: CLAIMS-08 to CLAIMS-10; preserve evidence, legacy uncertainty and canonical arithmetic rather than trusting an incomplete or merely rehashed success claim. EVIDENCE: offline synthetic/mocked boundaries and local artifact validation, not live integration. DEFERRED / NEXT: repair H1 provenance eligibility; independently captured Nikto evidence remains missing. No push or restart was performed.

### 40.13 H1 provenance and context-artifact consistency follow-up

This increment serves PROJECT.md stage 5 and the RQ1/H1 evaluation component, plus stage 7's research attachments. Decisions CLAIMS-11 and CLAIMS-12 record the alternatives and boundaries. It changes [context_eval.py](../vulnassess/context_eval.py), [audit.py](../vulnassess/audit.py), and two new synthetic regression suites: [context provenance](../tests/synthetic/test_synthetic_context_provenance.py) and [artifact integrity](../tests/synthetic/test_synthetic_context_artifact_integrity.py). Existing raw observations, profiles, canonical scores, thresholds and scope are unchanged.

- **Provenance eligibility:** inspect inputs actually evaluated for labelled hosts. A manual/model/LLM source or generated scope-tag quote cannot establish rule-only inference. Record actual manual use even if exposure is currently labelled rule. Unused metadata and separate shadow predictions are not mistaken for canonical prediction inputs.
- **Truth integrity:** reject type coercions, duplicate hosts/keys, unsupported labels, malformed shadow metadata and bad encoding through controlled errors. A synthetic document comment cannot be hidden behind row-level human declarations. No input file is rewritten to obtain eligibility.
- **Artifact consistency:** check H1 eligibility and status, fixed targets, nullable pass/fail fields, host/group counts, metric denominators, supported labels, classification arithmetic and required supporting metric fields. A new content hash does not excuse contradictory content. Sparse legacy NOT RUN artifacts remain unknown.
- **Preserved usefulness:** descriptive accuracy/confusion data still include difficult and missing hosts. An ineligible evaluation is not silently discarded, rescored, or made accurate by removing cases. It cannot report an H1 pass/fail.

Initial main regressions returned `54 failed, 12 passed`. Additional red runs exposed 18 shadow/synthetic/encoding cases, eight malformed shadow collection/identity cases and five duplicate/mixed-key cases. The delegated artifact suite first returned `118 failed, 11 passed`, then `8 failed, 133 passed`. Parent review reproduced 24 further failures while adding 20 valid full-evaluator/rounding cases. These are synthetic logic fixtures, including explicitly simulated declared-human metadata; they are not independent expert evidence.

Two new artifact fixtures had used role names as exposure labels, and a CLI assertion initially assumed an unknown role was correct rather than abstained. The fixtures now use the declared vocabularies and full denominator; their existing consistency, immutability and outcome assertions remain. The production guards were not relaxed.

VERIFIED focused integration, command `python -B -m pytest` with the two new files plus context/research/audit/report boundary tests, temporary `-p no:hypothesispytest`, `-q --tb=short`: `405 passed in 31.89s`. Zero failures/skips. Scoped Ruff checks passed, and Pyright on the two changed modules returned `0 errors, 0 warnings, 0 informations`.

VERIFIED complete local gate: the installed Python 3.12.10 executable ran `python -u -B scripts/check.py`, with temporary `PYTEST_ADDOPTS` adding `-p no:hypothesispytest -q --durations=8 --tb=short`. The optional workstation plugin was disabled; no project test/assertion or coverage floor was excluded or lowered. Actual output:

```text
All checks passed!
PASS    ruff lint
270 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10697     38    99%
Required test coverage of 95% reached. Total coverage: 99.64%
2844 passed, 520 subtests passed in 676.47s (0:11:16)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips; 287 additional tests versus section 40.12. The same process completed without restart. The timing report identified existing role-training/feature-ablation calls as the slowest cases, including two calls around 49 seconds. This is a local duration observation, not a performance guarantee. The frozen 278-file source/input fingerprint was unchanged after the run: `28f6ccef002e3a41c4cac7d1ceb791e7149ebc2a7fcd38b24e9483890478ed88`.

NOT RUN: independent real context truth, expert experiments, scanner/provider/feed execution, browser layout verification, remote CI, installation, commit and push. MISSING: independently captured Nikto JSON with completed provenance. Internal coherence does not authenticate reviewers, reconstruct absent ground truth, ensure every research artifact is bound to independently trusted inputs, or establish measured inference effectiveness. The wider audit remains active. Grouping's missing-instance identity assumptions remain a separate review target, not claimed fixed here.

At this checkpoint, read-only follow-up found a concrete binding gap: `context-eval` hashed its output and recorded run/model identity, but did not retain a full profile/truth binding. Report attachment checks accepted absent snapshot/cohort bindings even with a current report snapshot. An internally coherent old context result for the same run could therefore remain accepted after profiles changed; a different run ID was rejected. This was initially a source-traced counterexample, **NOT RUN** as a runtime reproduction at this checkpoint. The later section 40.14 reproduces and addresses the current-provenance contradiction without new fields. Exact historical identity still cannot be reconstructed when the original per-host mapping was never retained. The internal-consistency tests in this older increment did not establish that relationship.

STATUS: the named provenance/input/internal-consistency repairs passed local verification; the wider goal remains active. BRANCH / COMMIT: `codex/coverage-95`, baseline `6f523f6` plus existing uncommitted changes. BUILT / CHANGED: two implementation modules, two synthetic suites and existing references. DECIDED / DECISIONS: CLAIMS-11 and CLAIMS-12; preserve inputs and full descriptive denominators, withhold unsupported research conclusions instead of changing predictions or targets. EVIDENCE: local pure logic, artifact validation and mocked external boundaries, not independent empirical effectiveness. DEFERRED / NEXT: reproduce and repair the stale-context/current-provenance attachment case, then continue the broader audit. No real integration, commit, push or deployment is claimed.

### 40.14 Report-state binding and exposure-provenance follow-up

This increment serves PROJECT.md stages 5 and 7 and research reproducibility. Decisions CLAIMS-13 and CLAIMS-14 describe the constraints. It addresses the actual stale-context attachment path identified in section 40.13, rather than relying solely on the internal artifact validator.

- **Current-state compatibility:** a VERIFIED context attachment must have a reconcilable labelled subset, current observed hosts, eligible role/exposure provenance, matching prediction counts and feasible clean-source control subsets. An excluded or inapplicable manual control is not blindly treated as an evaluated input. Orphan/duplicate/malformed profiles and contradicted observations fail closed.
- **Binding versus compatibility:** matching aggregates do not establish original host-to-truth identity. Unbound compatible artifacts preserve their original metrics and label, but the report correspondence row is NOT RUN with an adjacent explanation and visible limitation. Existing snapshot bindings are checked against fresh state, including profile contents; an earlier check cannot excuse later drift. These are point-in-time consistency checks, not a transaction-wide concurrency or authenticity guarantee.
- **Truthful source labels:** fresh external-vantage exposure is manual, with unchanged value, confidence, quote, segment and score for equivalent inputs. Address rules remain rules. Saved legacy JSON and old scores remain untouched, and the legacy H1 quote guard remains active.
- **Publication and identity:** numeric/Boolean run identifiers cannot become string identities. Rejection occurs before replacing an existing HTML report. Actual HTML tests verify that the unbound explanation appears in the research-evidence table and limitations, not merely inside an internal JSON object.

Code: [audit.py](../vulnassess/audit.py), shared private semantics in [context_eval.py](../vulnassess/context_eval.py), and the source-label correction in [context.py](../vulnassess/context.py). New tests: [report binding](../tests/synthetic/test_synthetic_context_report_binding.py) and [exposure provenance](../tests/synthetic/test_synthetic_exposure_provenance.py). The earlier actual-constructor source assertion now requires manual, while separate legacy rule-labelled scope-quote cases remain.

Red evidence: initial report cases returned `29 failed, 1 passed`; the extended binding cases returned `34 failed, 2 passed`. Two identifier-coercion cases then failed while the HTML-warning case passed. A separate simulated change between snapshot validation and attachment publication reproduced one additional failure before the fresh-state guard. The exposure-source suite returned `20 failed, 8 passed` before its one-line provenance correction, then all 28 cases passed, including 12 score-equivalence combinations. These are synthetic test constructions, not real reviewer judgments or scanner findings.

VERIFIED focused integration: `python -B -m pytest` with the context/report/research/audit/core suites and `-p no:hypothesispytest -q --tb=short` returned `576 passed, 409 subtests passed in 75.54s`. There were zero failures/skips. Ruff lint/format passed for the six changed source/test files, and scoped Pyright returned `0 errors, 0 warnings, 0 informations`.

VERIFIED complete local gate, completed by 18 October: using the installed Python 3.12 executable, `python -u -B scripts/check.py` with `PYTEST_ADDOPTS` temporarily appending `-p no:hypothesispytest -q --durations=8 --tb=short` returned:

```text
PASS    ruff lint
272 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10777     40    99%
Required test coverage of 95% reached. Total coverage: 99.63%
2934 passed, 520 subtests passed in 334.75s (0:05:34)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips; the workstation's optional Hypothesis plugin was disabled, not project tests. The whole-package 95% floor and test socket guard remained active. Pre/post scoped input fingerprints matched for 280 files (`e471b1ea3d7939553c7036c035ceb3f1f0621cd76a4a728a39c17852b95ba3d3`); the broader tracked/nonignored working-input aggregate also matched for 389 files (`9185dcf31848ee85692128a2ef620ad1d3e4c135f9e57c91238b903d5abd8647`). No files were edited until both checks completed. Later guide/result edits and section 40.15 code are not part of that frozen checkpoint. The previous section's 2,844-test count remains historical.

No public command/field/signature/schema, table, dependency, target scope, numeric weight or canonical arithmetic changed. The current context-eval producer does not itself emit a complete immutable input binding. This increment qualifies that absence rather than inventing a binding or claiming the protocol is complete; future producer/interface work must follow its approval process. Independent truth and measured effectiveness also remain unestablished. The user delegated the optional reviewer choice. The specialised Security Review agent was unavailable; a separate read-only general-agent security audit completed as an explicitly labelled fallback, not a formal specialised review or certification. It found two medium-severity provenance gaps despite this passing gate; section 40.16 records them. No new partial-HTML-publication path was found within its scope. Store initialisation can still run migrations before attachment validation, so this is not a claim that every rejected CLI invocation is database-write-free.

NOT RUN: real scanners, publishers, providers/models, expert experiments, remote CI, installation, commit and push. MISSING: independently captured Nikto JSON with completed provenance under `tests/fixtures/nikto/`. The broader audit remains active, including grouping-instance/bridge assumptions and the incomplete historical-input protocol.

### 40.15 Cohort-manifest type-confusion follow-up

This increment serves the cross-cutting evaluation/reproducibility component and stage 7 report evidence in PROJECT.md. The pre-existing cohort loader converted schema versions, NDCG cutoffs, identities and digests with `int()`/`str()` before validating their content hash. A manifest changed from integer schema `1` to `true`, `1.0`, `1.9` or `"1"`, or cutoff `10` to `10.9`, could therefore reuse the original accepted manifest hash after coercion. Numeric-looking IDs/digests and numeric finding IDs could be converted similarly. This is a typed-contract/content-identity failure, not proof that the caller can forge independent approval or bypass the separate evidence/snapshot checks.

Malformed non-string reviewer or approval metadata could also raise AttributeError instead of the controlled ConfigError/CLI exit 2, and malformed maps could fail before reaching the intended error boundary. Rehashed malformed non-confirmatory manifests could retain incorrect metadata types. Synthetic tests reproduced these cases before implementation: `71 failed, 20 passed in 2.54s`.

The repair enforces the existing declared types before string operations and comparisons, requires actual integer schema/cutoff values (not Boolean, float or text), requires JSON arrays/maps at the loader boundary, and removes lossy conversions. Valid typed manifests retain their fields, hashes and round-trip representation. No new schema version, field, command, dependency, score formula, scope or approval mechanism was added. A caller-written reviewer name remains a declaration, not authentication.

Source: [cohort.py](../vulnassess/cohort.py). New regression cases: [synthetic manifest types](../tests/synthetic/test_synthetic_cohort_manifest_types.py). VERIFIED focused command: `python -B -m pytest tests/synthetic/test_synthetic_cohort_manifest_types.py tests/test_cohort.py tests/test_research_validation_boundaries.py tests/test_research_cli.py -q -p no:hypothesispytest --tb=short` returned `168 passed in 3.66s`, zero failures/skips. Ruff lint passed; Ruff format reformatted the two edited files; scoped Pyright returned `0 errors, 0 warnings, 0 informations`. The separate complete gate subsequently passed and is recorded in section 40.16. Section 40.14's earlier full gate does not verify later edits.

Decision CLAIMS-15 records the repair and alternatives. These tests use synthetic declarations, not genuine independent reviewers or captures. NOT RUN: live services, actual models/scanners, human studies, remote CI, commit/push. MISSING: independently captured completed Nikto JSON/provenance under `tests/fixtures/nikto/`. The wider completion audit remains active.

### 40.16 Independent provenance review follow-up

The read-only fallback reviewer reproduced two medium-severity gaps using synthetic in-memory data and mocked input loading, not live scanners/models or independent truth. It made no file changes. The user explicitly authorised fixing both after receiving the findings.

- **Multiline legacy metadata:** scope accepts names containing CR/LF, but the historical rule-labelled scope-quote detector excluded those characters. Such a quote could therefore retain H1 eligibility and attach as VERIFIED with a matching snapshot. The corrected constructor's new manual label did not repair historical representations.
- **Contradictory model identity:** a context artifact could declare model A but bind a snapshot with model B. Supplying that snapshot changed a rejected attachment into VERIFIED because the fresh-state check substituted the report snapshot's model declaration without checking agreement.

This follow-up serves PROJECT.md stages 5/7 and research provenance. Regression tests cover validated in-memory scope names, legacy rule-labelled evaluated features, report attachment and CLI rejection before overwriting existing HTML, and matching/contradictory/absent model declarations. Before the fixes, the two expanded context/provenance files returned `29 failed, 177 passed in 70.44s`. This is parent-executed reproduction, separate from the independent reviewer's synthetic evidence.

Implementation now recognises multiline target names without changing scope rules or historical records. Context-artifact model identity must be null or a nonblank string, must agree with a supplied report snapshot, and remains the declaration used to rebuild the fresh snapshot. A snapshot option cannot replace that identity. Missing legacy model declarations retain the null-compatible path; missing/null identity cannot impersonate a non-null model. The guard also rejects contradictory model declarations for a VERIFIED evaluation whose snapshot binding is absent; an unbound row is not an excuse to accept incompatible declarations.

VERIFIED focused integration: the installed Python `-B -m pytest` command with `-q -p no:hypothesispytest --tb=short` over `test_synthetic_context_provenance.py`, `test_synthetic_context_report_binding.py`, `test_synthetic_context_artifact_integrity.py`, `test_synthetic_exposure_provenance.py`, `test_synthetic_cohort_manifest_types.py`, `test_context_eval.py`, `test_cohort.py`, `test_audit.py`, `test_audit_validation_boundaries.py`, `test_audit_report.py`, `test_synthetic_audit_edges.py`, `test_research_validation_boundaries.py` and `test_research_cli.py` returned `625 passed in 87.67s`, zero failures/skips. The `test_synthetic_*` files are under `tests/synthetic/`; the other files are under `tests/`. Ruff lint passed for the six changed source/test files, Ruff format normalised them, and scoped Pyright on audit/context_eval/cohort returned zero errors/warnings/informations.

VERIFIED complete local gate on 18 October: the installed executable `C:/Users/aksha/AppData/Local/Programs/Python/Python312/python.exe` ran `-u -B scripts/check.py` from this repository, with `PYTEST_ADDOPTS` temporarily appending `-p no:hypothesispytest -q --durations=8 --tb=short` and restored afterward. Terminal output:

```text
PASS    ruff lint
273 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10802     40    99%
Required test coverage of 95% reached. Total coverage: 99.63%
3059 passed, 520 subtests passed in 733.46s (0:12:13)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips. The workstation's optional Hypothesis plugin was disabled; no project tests were excluded and the 95% whole-package floor/socket guard stayed active. Compared with section 40.14, the suite adds 125 cases (91 manifest-type and 34 review-regression/positive cases); the rounded statement coverage remains 99.63%, with 40 missed statements. This is not branch coverage, browser coverage, detection accuracy, a speed benchmark, or independent review of the fixes. The slowest observed tests were the existing role-training feature-ablation cases, at 50.64 and 49.89 seconds.

Before and after the complete run, the scoped input fingerprint matched for 281 files: `b20c37156cd75d21f4c9981963968b5e5e86cb4ee67aa3a597e6ba2c4a68cf7a`. The broader tracked/nonignored working-input aggregate also matched for 390 files: `81ebd4eaf6ef45547a292415f51eff449d983811ee8ad74792db7a234f2f39a2`. Both comparisons completed before any result/document edits. Subsequent changes to README, these guides and the decision log are documentation-only and separately checked; they are not falsely included in that earlier frozen working-input aggregate. No application/test/configuration code changed after the passing gate.

STATUS: these three repairs are implemented and locally verified; the wider completion audit remains active. BRANCH / COMMIT: `codex/coverage-95`, baseline `6f523f6` plus preserved uncommitted work. BUILT / CHANGED: cohort/audit/context-evaluation validation, one new synthetic test file, expanded existing synthetic regressions and existing references. DECIDED / DECISIONS: CLAIMS-15 and CLAIMS-16 enforce declared identity rather than coercion or substitution; schema, scope, canonical scoring and historical records are unchanged by this increment. EVIDENCE: executed offline checks using synthetic or mocked inputs, not real independent truth. DEFERRED / NEXT: affected-instance/grouping assumptions, the incomplete immutable-input producer protocol and empirical validation remain open. MISSING: independently captured completed Nikto JSON/provenance under `tests/fixtures/nikto/`. NOT RUN: actual scanners/providers/models/publishers, remote CI, second independent review, installation, commit and push.

These tests do not establish reviewer authenticity or whole-project security. Decision CLAIMS-16 records the rationale. NOT RUN: a second independent review or the unavailable specialised review. The broader audit remains active, including current input-binding producer limitations, grouping identity/bridge assumptions, and independent empirical validation.

### 40.17 Grouping identity and preview integrity follow-up

This increment serves PROJECT.md stage 4 and report-stage evidence integrity. Source inspection found that equal missing endpoint fields were treated as identity and connected components of overlapping CVEs became one group. Thus A, A+B and B could become one allegedly same-instance duplicate group, and a pairwise-overlap triangle could merge without any single CVE common to all records. The same API accepted a foreign finding's enrichment or malformed CVE values as grouping support.

Parent-executed synthetic regressions returned `38 failed, 4 passed in 0.87s`. A separate malformed-CVE check returned `16 failed, 42 deselected in 0.79s`, and seven malformed raw-source-ID cases also failed before the string-ID guard; these were targeted diagnostic selections, not full-gate exclusions. The repair requires complete declared instance/service identity and equal complete CVE sets, rejects foreign enrichment ownership and malformed identifiers, and retains ambiguous/overlapping relationships as visible candidates. Existing group-ID hashing and heuristic confidence values are unchanged. It does not change scopes, scores, raw evidence or public fields/signatures.

Two existing positive fixtures now supply explicit matching instance URLs; every assertion remains unchanged. The former missing-instance scenario is covered by new negative cases. A three-scanner positive case still verifies a valid complete group. New cases exercise all input permutations for CVE chains/triangles/compound bridges, valid raw and enriched grouping, immutable input data, visible candidate explanations in generated HTML, and unchanged logical SQL dumps/score records across the read-only preview. That is not a byte-for-byte physical SQLite-file comparison. A test setup initially called a nonexistent singular Store method; correcting it to the existing plural upsert API, not modifying production storage or removing assertions, resolved those two test-authoring errors.

Source: [unify.py](../vulnassess/unify.py). Parent regressions: [synthetic unification identity](../tests/synthetic/test_synthetic_unification_identity.py). VERIFIED focused results include `73 passed in 6.02s`, then `119 passed in 32.01s` across grouping/core/audit/report/research paths; the expanded identity file passed 62 cases in 2.14 seconds, including local database and HTML checks. After seven source-ID cases were added, `python -B -m pytest tests/synthetic/test_synthetic_unification_identity.py tests/test_unify.py tests/synthetic/test_synthetic_core_final.py tests/synthetic/test_synthetic_remaining_final.py -q -p no:hypothesispytest --tb=short` returned `112 passed in 15.17s`. Scoped Ruff and Pyright passed before the final small source-ID guard; the integrated gate must recheck the complete tree. These are synthetic unit/local-integration checks, not real scanner corroboration or calibrated precision.

A separate coding agent completed the unification-attachment validator and its regressions, then stopped all writes. It checks rehashed impossible counts, source coverage, IDs, candidate endpoints and the preview-only contract. Sparse lower-status facts remain unknown rather than becoming invented complete facts. A VERIFIED attachment must also match the actual recomputed preview and applicable snapshot/model/run bindings before a report is written. The agent recorded initial red results of `259 failed, 21 passed`; additional report-boundary cases returned `27 failed, 8 passed, 288 deselected`. Its combined focused run returned `800 passed in 140.61s`, and a later producer-focused run returned `429 passed in 16.37s`. Those delegated results are not substitutes for the parent's final frozen-tree gate.

Parent integration review then reproduced six further failures: reuse of an initially checked snapshot after assessment drift, plus invalid optional model-ID types. The repair always rebuilds the current snapshot and recomputes grouping from the exact findings/enrichments captured inside it, rather than from another sequence of live reads. Explicit model declarations are string-or-null and may not contradict a report snapshot or selected model. The existing producer need not acquire a new model field: its bound snapshot can carry that identity. This is point-in-time/internal correspondence, not a transaction-wide concurrency or authenticity guarantee.

The parent also reproduced a scale defect: 200 records in unrelated service blocks required 39,800 service comparisons. A deterministic service-block index now needs zero cross-service comparisons in that test. It does not change valid grouping/candidate output or the ID algorithm. Dense single-service candidate generation remains potentially quadratic; no timing benchmark or universal scalability claim is made.

VERIFIED final focused parent command: installed Python `-B -m pytest` over the two new synthetic unification files plus `tests/test_unify.py`, `tests/test_audit.py`, `tests/test_audit_report.py`, `tests/synthetic/test_synthetic_audit_edges.py`, `tests/synthetic/test_synthetic_context_report_binding.py`, `tests/test_operations_cli.py` and `tests/test_research_cli.py`, with `-q -p no:hypothesispytest --tb=short`, returned `521 passed in 120.21s`. A subsequent targeted operation-count/invalid-service-identity check returned `3 passed, 69 deselected in 0.37s`; the latter strengthens the comparison assertion to exactly zero. There were no failures/skips. Ruff lint/format passed for the changed source/test files, and scoped Pyright on audit/unify returned zero errors/warnings/informations.

Code: [audit.py](../vulnassess/audit.py), [unify.py](../vulnassess/unify.py). Additional cases: [artifact integrity](../tests/synthetic/test_synthetic_unification_artifact_integrity.py). Decisions CLAIMS-17, CLAIMS-18 and CLAIMS-19 record the constraints. No independent-review certification or empirical detection gain is asserted.

VERIFIED complete local gate on 18 October: `C:/Users/aksha/AppData/Local/Programs/Python/Python312/python.exe -u -B scripts/check.py`, from this repository, with `PYTEST_ADDOPTS` temporarily appending `-p no:hypothesispytest -q --durations=8 --tb=short` and restored afterward. Terminal output:

```text
PASS    ruff lint
275 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 10953     45    99%
Required test coverage of 95% reached. Total coverage: 99.59%
3466 passed, 520 subtests passed in 745.73s (0:12:25)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips. No project tests were excluded; the optional workstation Hypothesis plugin was disabled, and the 95% whole-package floor/socket guard remained active. Compared with section 40.16, this adds 407 test cases and 151 measured source statements. Missed statements rise from 40 to 45; coverage falls from 99.63% to 99.59%. Those uncovered guard/error paths remain a testing limitation, not erased by a passing gate. A separate `python -B -m coverage report --include='vulnassess/audit.py' -m` confirmed its 22 missed statements. The unification module has 169 measured statements and zero misses, which still does not establish branch completeness or real-world grouping accuracy.

Both pre/post fingerprints matched before any documentation update: 283 scoped source/input files, `bca54550df406621a757fe9c2fb5afdcc111bd6faefe76a265cef5f91775016c`; 392 tracked/nonignored working inputs, `d3b612922369fd4f89652b132c3748fcc5d8bd77f4e753b990528002f59c1476`. Subsequent result/guide edits are documentation-only and separately checked; they are not included in the frozen full-input aggregate. No application/test/configuration code changed during or after that run.

STATUS: this grouping/preview increment is implemented and locally verified; the wider audit remains active. BRANCH / COMMIT: `codex/coverage-95`, baseline `6f523f6` plus preserved uncommitted work. BUILT / CHANGED: matching/indexing, report attachment validation, two synthetic test files, two stronger positive fixtures, and existing references. DECIDED / DECISIONS: CLAIMS-17 through CLAIMS-19 retain uncertainty and raw provenance instead of manufacturing duplicate reduction or current correspondence. EVIDENCE: offline synthetic/mocked behaviour, generated HTML and temporary SQL-state comparisons, not real scanner corroboration. DEFERRED / NEXT: stricter snapshot validation is a separate source-traced audit lead, not yet runtime-reproduced; independent grouping truth, non-URL/compound instance support, dense-workload budgets and historical-input protocol remain open.

NOT RUN: real scanners/providers/models, publishers, expert studies, remote CI, commit/push, installation and server restart. MISSING: independently captured completed Nikto JSON/provenance under `tests/fixtures/nikto/`. The wider audit, historical-input protocol and independent empirical validation remain open.

### 40.18 Snapshot and promotion-input boundary follow-up

This increment serves PROJECT.md stage 7 and cross-cutting reproducibility.
VERIFIED synthetic reproduction: hash-valid snapshots could contain malformed
record shapes, duplicate identities, contradictory ownership and wrongly typed
numbers. The first new set returned `85 failed, 10 passed`. A hash establishes
content identity, not that the content follows its declared record contract.

Implementation now checks the existing snapshot structure, unique identities,
host/finding/profile/score/enrichment/rationale relationships, bounded numeric
types, Boolean declarations and configuration-drift consistency. Export validates
before publishing. Malformed data becomes a controlled ConfigError. Valid
partial assessments remain valid; absent optional legacy metadata stays absent;
original capture run IDs and raw evidence are not rewritten. Canonical scores
are neither recomputed nor modified by these checks.

Stored JSON conversion needed its own guard: `true`, `"false"`, fractional record
indices and numeric strings could become plausible ports, flags, confidence or
scores before validation. Numeric regressions returned `23 failed, 1 passed`
before correction. Eight additional collection cases showed object keys becoming
identifier/reference lists and pair arrays becoming metadata objects. These
conversions now require the declared input type first. A new export test initially
edited the old global finding table rather than the actual run-observation path;
that test setup was corrected, not counted as another product defect. SQL-dump
comparisons check that rejected exports leave the test-owned stored records
unchanged. These tests do not authenticate files, verify CVE applicability or
recalculate historical score arithmetic.

The promotion-manifest loader now uses the existing bounded local JSON reader.
It rejects duplicate keys, nonfinite numbers, invalid encoding, network-share
paths and excessive bytes/depth/nodes before constructing a declaration. Its
50-case synthetic suite changed from `25 failed, 25 passed` to 50 passes. A parsed
synthetic declaration remains ineligible for genuine model promotion. The old
read-failure test now targets the actual byte-read seam without relaxing its
assertions. The initial parent integration returned `210 passed in 17.70s`.
After the collection guards and corrected run-observation test setup, the
expanded snapshot/manifest/core integration returned `243 passed in 23.60s`,
zero failures/skips. Scoped Ruff lint passed; formatting was normalised.

Sources: [snapshot boundary](../vulnassess/assessment_snapshot.py),
[JSON models](../vulnassess/schema.py),
[promotion loader](../vulnassess/model_governance.py). Regression cases:
[snapshot integrity](../tests/synthetic/test_synthetic_assessment_snapshot_integrity.py)
and [promotion input](../tests/synthetic/test_synthetic_promotion_manifest_input.py).
Decisions CLAIMS-20 through CLAIMS-22 record implementation constraints and
verification limitations. Those focused results preceded the complete-gate
results below; section 40.17 remains an earlier checkpoint, not verification of
these later edits.

**Execution deviation:** the parallel task reported an unplanned PyPI version
lookup by the installed Python Pyright wrapper during an ordinary checker
invocation. No package was installed. The user was informed and that wrapper is
no longer used for this work. Its later pinned/socket-guarded check reported zero
network attempts, but the earlier lookup remains a deviation. Historical pytest,
type-check and coverage results are retained; the pytest socket guard alone did
not prove that a separate checker/updater subprocess was offline. Earlier blanket
offline/no-network descriptions must be read with this correction. A direct,
already-installed JavaScript checker with a network-denying preload is now
implemented and fails closed if its local prerequisites are absent. It is
not an OS-wide isolation claim.

VERIFIED tooling follow-up: [offline launcher](../scripts/offline_pyright.py)
and [Node denial preload](../scripts/offline_pyright_guard.cjs) are now wired into
the existing Python gate, Makefile and CI checker command. Discovery never imports
the Python updater, checks both local JS entry files and the existing Node
executable, binds the default interpreter, and fails with MISSING instead of
provisioning. Child-only NODE_OPTIONS removes ambient preloads for this process;
it does not alter the user's environment. The 28-case gate suite passed in 3.20s.
Network API tests replace originals with fail-fast stubs before requiring the
guard; a removed guard fails safely without making a request. These are TESTED
WITH MOCKS denial paths, not an actual-network experiment.

The actual direct checker first found three typing errors in the new schema
helpers. They were corrected with typed views after validation, not ignored.
Scoped Ruff lint/format passed (eight files already formatted), and the checker
then returned `0 errors, 0 warnings, 0 informations`. The original provenance
regression also returned `625 passed in 57123.47s (15:52:03)`; the cause of this
unusually long elapsed time was not investigated and is not a speed measurement.
That scoped check was not itself a complete gate; the complete results follow.

The first complete frozen-tree run is now recorded, and it **failed**: lint and
format passed (279 files), direct Pyright returned zero errors/warnings/info,
but pytest returned `4 failed, 3669 passed, 520 subtests passed in 754.38s
(0:12:34)`. Coverage was 99.46% (11,204 statements/60 missed); that did not make
the gate pass. Both pre/post fingerprints matched: 288 scoped files
`8901ff31f6a38bbc0926d4b8ff2726579eca6db0cc012ccdd0adcaddbefd435e`;
397 working inputs `67127d1832a6897e13f6e270165037db579bf72c0113cec426e8af562b5c5d19`.

The failures came from an existing remediation safety contract, not the two
original provenance cases: unclear legacy optional range-boundary metadata must
stay unknown without guessing an inclusive/exclusive boundary or safe upgrade.
Restore that established reader behaviour and leave its tests unchanged. The
new imported-snapshot boundary still rejects those explicitly wrong JSON types,
with added tests for both paths. Score, KEV, confidence, port and provenance-index
type checks remain strict. This narrow legacy exception is not a claim to reject
every malformed stored optional field. The corrected tree then received another
complete gate, rather than treating a focused pass as sufficient.

VERIFIED final focused check: the installed Python `-B -m pytest` command over
snapshot integrity, remediation versions, snapshot/cohort/research/audit-report,
governance, promotion-input, core and offline-gate suites returned
`294 passed in 22.87s`, zero failures/skips. No existing remediation assertion was
changed. The imported-boundary and legacy-unknown cases test different contracts.

VERIFIED complete corrected-tree gate on 18 October: from this repository,
`C:/Users/aksha/AppData/Local/Programs/Python/Python312/python.exe -u -B scripts/check.py`
ran with temporary PYTEST_ADDOPTS appending
`-p no:hypothesispytest -q --durations=8 --tb=short`, restored afterward:

```text
PASS    ruff lint
279 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11202     59    99%
Required test coverage of 95% reached. Total coverage: 99.47%
3679 passed, 520 subtests passed in 675.06s (0:11:15)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips. No project tests were excluded; only the optional workstation
Hypothesis plugin was disabled. The 95% whole-package floor and pytest socket
guard remained active. Pyright used the installed bundle/direct guarded launcher,
not the Python updater. The guard is standard Node API denial, not OS isolation.
Compared with section 40.17: 213 additional cases (135 snapshot, 50 promotion-input,
28 tooling), 249 additional statements, 14 additional missed statements and a
0.12-percentage-point coverage decrease. These remaining paths are not erased by
the pass. A separate read-only coverage report identified 14 missed snapshot
statements and 22 missed audit statements; neither module has complete statement
or branch verification.

Both pre/post aggregates matched before result edits: 288 scoped files,
`156cbdd36e5b6f4cbf39547cc4cc95e76ec205041d89c67d41c6f05d633edff7`;
397 tracked/nonignored working inputs,
`d8bdad5df2523799509bec28b393a281e87c11612d76a896d04f143bdb5cdb84`.
Only existing documentation changes afterward; it is checked separately and is
not falsely included in the frozen full-input aggregate. No application, script,
test or configuration code changed after the passing run.

STATUS: the requested two provenance repairs and this input/gate follow-up are
implemented and locally verified; the wider audit remains active. BRANCH / COMMIT:
`codex/coverage-95`, baseline `6f523f6` plus preserved uncommitted work. BUILT /
CHANGED: snapshot/schema/governance boundaries, guarded checker/gate wiring,
three synthetic test files, one actual-read-seam correction and existing guides.
DECIDED / DECISIONS: CLAIMS-20 through CLAIMS-22 require typed consistency without
inventing origin, rewriting scores or discarding safe legacy unknowns. EVIDENCE:
executed local checks and synthetic/mocked behaviour, not independent scanner,
model or human-study validation. DEFERRED / NEXT: uncovered error guards,
historical-input protocol and independent empirical evaluation remain open.

NOT RUN: real scanners/providers/models, expert studies, remote CI, commit/push,
installation and server restart. MISSING: independently captured completed
Nikto JSON/provenance under `tests/fixtures/nikto/` and `.pre-commit-config.yaml`;
the present example/README and a local gate do not fill those gaps. They do not
block verification of these code repairs, but they prevent claiming complete
integration/hook/research acceptance. The wider completion audit remains active.

### 40.19 Cross-record score correspondence and actual JSON limits

This follow-up serves PROJECT.md stage 7 and cross-cutting reproducibility.
The preceding 3,679-test checkpoint did not establish every relationship inside
a frozen assessment. TESTED WITH MOCKS reproduction: a rehashed artifact could
retain a score with an unknown/foreign CVE or contradictory KEV, EPSS, vector or
context input and still pass snapshot verification. Explicit enrichment matches
could also name a CVE missing from their own scanner record. After correcting an
ineffective test mutation and CLI spelling, the new command returned
`23 failed, 1 passed in 6.78s`; the CLI returned success for four invalid examples.

The [snapshot validator](../vulnassess/assessment_snapshot.py) now checks selected
enrichment ownership, explicit scanner-ID membership, retained intelligence/vector
correspondence, and supplied role/exposure/manual/observed-control inputs against
the host profile. Range-derived CVEs remain supported. Filtered per-finding
controls are not confused with all observed controls. Numeric confidence
representations can agree without Boolean declarations masquerading as numbers.
Absent legacy input bindings remain unknown and are not invented. The code does
not recompute score arithmetic, verify CVE applicability, authenticate original
captures or reconstruct absent historical policy. No official score is changed.

The first integrated snapshot/core set passed 173 cases. A broader report/context
set then returned `28 failed, 839 passed in 148.32s`: the context-attachment fixture
changed profiles while keeping score inputs from an earlier profile state. That
fixture now explicitly uses supported legacy-unbound score metadata so its
existing attachment assertions can reach their intended boundary; its nonempty
queue and every numeric/identity field are retained and checked. Separate current
score-binding cases test rejection and unchanged SQL state with complete inputs.
No existing assertion was weakened or removed. Broader re-verification is pending.

The shared [JSON reader](../vulnassess/audit.py) also had two reproducible limits
gaps. A file growing/replaced after the size stat could bypass an unbounded read,
and a JSON number such as `1e1000` became infinity without using the NaN/Infinity
token hook. The sidecar's synthetic suite changed from `12 failed, 25 passed`
to 37 passes. It now bounds actual descriptor reads to cap+1 bytes, rejects excess
before decoding and rejects nonfinite floats anywhere in the decoded structure.
Finite unknown metadata survives. A consumer test's old read_bytes mock was
moved to the actual open seam, preserving all error assertions. The parent's
resource-limit/snapshot/boundary subset passed 87 cases.

This is not an atomic-file capture, total memory budget or OS sandbox. Structure
limits still run after JSON decoding. Sources/tests:
[score correspondence](../tests/synthetic/test_synthetic_snapshot_score_binding.py),
[resource limits](../tests/synthetic/test_synthetic_json_resource_limits.py).
Decisions CLAIMS-23 and CLAIMS-24 record alternatives and limits. These focused
results preceded the complete-tree result below; section 40.18 is historical.

VERIFIED parent consumer integration: an rg search for
`assessment_snapshot|load_json_payload` under tests, restricted to Python files,
selected 32 modules. The installed Python `-B -m pytest` command over those paths
with `-q -p no:hypothesispytest --tb=short` returned
`1251 passed in 303.02s (0:05:03)`, zero failures/skips. The repaired attachment
plus score-binding subset separately returned `113 passed in 88.11s`. Ruff lint
and format passed (281 files already formatted); full Pyright through the direct
guarded launcher returned zero errors/warnings/info. That selected run was not
itself the whole-project gate; the complete-tree run follows.

VERIFIED complete local gate on 18 October: from this repository, the installed
Python 3.12.10 executable ran `-u -B scripts/check.py`, with temporary PYTEST_ADDOPTS
appending `-p no:hypothesispytest -q --durations=8 --tb=short`, restored afterward:

```text
PASS    ruff lint
281 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11256     61    99%
Required test coverage of 95% reached. Total coverage: 99.46%
3746 passed, 520 subtests passed in 793.29s (0:13:13)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips; the optional workstation Hypothesis plugin was disabled,
not project tests. The 95% whole-package requirement and pytest socket guard
remained active. The direct installed Pyright launcher was used, never the Python
updater. Compared with section 40.18, this adds 67 cases (30 score-correspondence
and 37 reader-limit cases), 54 source statements and two missed statements.
Coverage falls by 0.01 percentage points, from 99.47% to 99.46%. A separate read-only
coverage report identifies 16 missed snapshot and 22 missed audit statements;
passing the gate does not prove those guards, branch completeness or effectiveness.

Both pre/post fingerprints matched before any result edits: 290 scoped inputs
`31625804d02ae684b5632b7ec82a38c03006cabe296a88bfaa1e86cc95708692`;
399 tracked/nonignored working inputs
`2c2d7e8143b19a67c31a60f2886ed30561ec10e7a87ae0e3fdebe67ba5049baa`.
Only existing documentation changes afterward; it is separately checked and not
included in the frozen full-input claim. No source/test/configuration/script code
changed after the passing gate. SQL-dump comparisons establish the tested read-only
behaviour, not immutable filesystem bytes or a transaction-wide capture guarantee.

STATUS: this bounded integrity increment is implemented and locally verified;
the wider audit remains active. BRANCH / COMMIT: `codex/coverage-95`, baseline
`6f523f6` plus preserved uncommitted work. BUILT / CHANGED: snapshot cross-record
validation, shared JSON reader, two new synthetic suites, an actual-read-seam
mock correction, explicitly legacy-unbound context fixture and existing guides.
DECIDED / DECISIONS: CLAIMS-23/24 reject contradictions and enforce actual input
bounds, preserving raw records, scores and legitimate unknowns rather than
repairing numbers silently. EVIDENCE: executed local checks and synthetic/mocked
behaviour. DEFERRED / NEXT: arithmetic replay, historical policy/input identity,
remaining error guards and independent real-world validation remain open.

MISSING hook prerequisites were also checked directly: the installed Python
`-B -c "from importlib.util import find_spec; print('pre_commit module present:', find_spec('pre_commit') is not None)"`
returned `pre_commit module present: False`; `.pre-commit-config.yaml` is absent.
No package was installed and no hook runner was invoked. A passing local gate
does not establish that the required pre-commit integration exists or works.

NOT RUN: real scanners/providers/models, external services, expert studies,
remote CI, installs, commits and pushes. MISSING: completed human-captured Nikto
JSON/provenance under `tests/fixtures/nikto/`, `.pre-commit-config.yaml` and the
approved `pre_commit` runtime. These gaps still prevent complete acceptance;
they do not invalidate this bounded code-regression result.
The wider audit remains active, including score arithmetic replay, historical
input identity and independent empirical validation.

### 40.20 Supported numerical replay and separate arithmetic status

This increment serves PROJECT.md stage 7 and the cross-cutting deterministic
ranking/reproducibility component. The preceding checkpoint checked record links,
not risk arithmetic. TESTED WITH MOCKS reproduction: a rehashed score could carry
wrong risk with a matching band, wrong CVSS/environmental values, multiplier,
modifications or effective controls and still be accepted. The first dedicated
suite returned 21 failures: 15 wrong-data/export/CLI acceptances and six missing
private-helper expectations, not 21 independent product defects.

The [snapshot validator](../vulnassess/assessment_snapshot.py) now reuses the
existing deterministic scorer; its formula and weights were not changed. Recorded
v3.1 numbers can be checked against retained vectors. Matching retained weights
permit checking the band against the recorded risk even for otherwise unbound
legacy input; that is not full risk replay. Full replay
requires supported current policy, retained matching weights, finding/enrichment,
profile and service observations. It checks canonical numeric fields, effective
controls and semantic applicability decisions. Equivalent metric ordering,
explanation wording and unrelated notes are not silently normalised or discarded.
Official scores, raw evidence and encoded input remain unchanged.

Unknown historical recipes and incomplete data remain explicitly unreplayed;
CVSS 4.0 is not reinterpreted as the supported v3.1 calculation. A known current
contradiction cannot hide by omitting another optional field. Typed environmental
metric declarations remain enforced for legacy data too. This is reproduction
by the current implementation, not independent standards conformance, approved
weight provenance, genuine capture authentication or empirical risk accuracy.

The [report audit](../vulnassess/audit.py) adds a score-arithmetic row within its
existing schema. A complete nonempty replay is VERIFIED with that scope caveat;
partial, unavailable, unsupported, empty and no-snapshot cases are NOT RUN.
Counts and reasons are visible, without changing the assessment's original
capture-evidence status. The exact validated snapshot is replayed only after its
fresh-state match. Rejection preserves existing HTML, snapshot bytes and SQL state;
unknown limitation text is escaped rather than interpreted as markup.

Tests: [arithmetic](../tests/synthetic/test_synthetic_score_arithmetic.py),
[report diagnostics](../tests/synthetic/test_synthetic_score_replay_report.py).
The first parent snapshot/core integration passed 203 cases; the final dedicated
arithmetic suite passed 34 cases. Arithmetic/report integration returned
`58 passed in 11.61s`. Full guarded Pyright returned zero errors/warnings/info;
Ruff lint/format passed (283 Python files already formatted). The disjoint report
agent was closed after code/test review. These focused results preceded the
broader consumer and complete-gate results below; section 40.19 is historical,
not verification of these later edits. Decisions CLAIMS-25/26 record alternatives.

VERIFIED final consumer integration: the existing rg search for snapshot/shared
JSON-reader consumers selected 34 Python test modules. The installed Python
`-B -m pytest` command over those paths with `-q -p no:hypothesispytest --tb=short`
returned `1309 passed in 303.26s (0:05:03)`, zero failures/skips. The arithmetic/
report pair separately passed 58 cases. Full Ruff/Pyright checks passed; this is
not itself a whole-project coverage gate. That complete run follows.

VERIFIED complete local gate, 18 October: from this repository, installed Python
3.12.10 ran `-u -B scripts/check.py` with temporary PYTEST_ADDOPTS appending
`-p no:hypothesispytest -q --durations=8 --tb=short`, restored afterward:

```text
PASS    ruff lint
283 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11364     65    99%
Required test coverage of 95% reached. Total coverage: 99.43%
3804 passed, 520 subtests passed in 734.97s (0:12:14)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips. No project test was excluded; only the optional workstation
Hypothesis plugin was disabled. The 95% whole-package requirement and pytest
socket guard remained active; Pyright used the installed guarded direct launcher,
not its Python updater. Relative to section 40.19: 58 additional cases (34 arithmetic,
24 report), 108 additional statements, four more missed statements and a coverage
decrease of 0.03 percentage points. Read-only coverage output identifies 20 missed
snapshot and 22 missed audit statements. This is not complete branch verification.

Before any result/document edits, both pre/post fingerprints matched: 292 scoped
inputs `29ee4fcd7bacb71cd6c9447628f5fc452565661955f53701f4372c9a5f98d360`;
401 tracked/nonignored working inputs
`8d671a882a8b387fecf8e7a594d86cc2c231480e382dc9610a8f3a144c590ee6`.
Only existing documentation is updated afterward and checked separately; it is
not included in the frozen full-input claim. No source, script, configuration or
test code changed after the passing gate.

STATUS: the supported replay/diagnostic increment is implemented and locally
verified; the wider goal remains active. BRANCH / COMMIT: `codex/coverage-95`,
baseline `6f523f6` plus preserved uncommitted work. BUILT / CHANGED: private
read-only replay in assessment_snapshot.py, a separate arithmetic component in
audit.py's existing row schema, two synthetic suites and existing references.
DECIDED / DECISIONS: CLAIMS-25/26 reuse the existing engine and retain historical
unknowns instead of changing scores, guessing policy or promoting capture evidence.
EVIDENCE: executed local checks and synthetic/mocked behaviour. Replaying this
implementation is not independent proof that its CVSS math or risk method is correct.

The pre-commit prerequisite check was scoped and repeated without execution:
PowerShell `Get-Command pre-commit` found no PATH command, and the selected
Python's `find_spec('pre_commit')` probe returned False. No install or hook runner
was invoked. Missing hook configuration/runtime still prevents hook acceptance.
DEFERRED / NEXT: historical-policy authentication, v4 arithmetic, independent
conformance/effectiveness, remaining error guards and the direct canonical-input
boundary remain separate audit work, not declared finished by this pass.

NOT RUN: real scanners/providers/models, publishers, expert studies, remote CI,
installations, commits and pushes. MISSING: completed human-captured Nikto
JSON/provenance under `tests/fixtures/nikto/`, `.pre-commit-config.yaml` and the
approved `pre_commit` runtime. The wider audit remains active, including historical
policy/input identity and independent empirical/standards validation.

### 40.21 Direct scoring input and stored-profile boundaries

Serves deterministic ranking/reproducibility and PROJECT.md stage 7. Numerical
replay after export was not enough: a caller could submit malformed context to
the scorer before that snapshot existed. The [scorer](../vulnassess/scoring.py)
now validates declared context enums, feature maps/types and rule/manual sources,
manual environment/criticality, host/finding ownership, enrichment numeric fields
and provided v3.1 base/vector agreement before priority selection. NaN, infinity,
numeric strings and numeric booleans cannot receive an official priority. Mixed
enrichment owners cannot be selected as if they belonged to one finding.
Empty batch calls cannot bypass context validation. Valid values retain the same
published formula and weights; this is not an algorithm change or research result.

The low-level environmental helper still safely ignores malformed optional
criticality as its old regression requires, but no longer coerces it or loops on
unbounded integers. Canonical score rejects malformed manual values. The band
helper preserves finite boundary mapping; no-basis low-level math is not an
official priority. Missing severity remains explicitly unscored. This does not
authenticate evidence or completely validate all Finding/Service/configuration
fields: the normal settings boundary remains required for weights.

[Stored-profile decoding](../vulnassess/store.py) now checks JSON/feature-map
shapes and binds the payload host to its SQLite row, with controlled ConfigError
diagnostics. CLI rank returns exit 2 with no partial stdout or traceback. The
existing compute-before-persist ordering preserves the entire score queue and
SQL state when a later profile is invalid. Existing snapshot errors retain their
export-stage label; no raw record or saved number is repaired in place.

Tests: [pure inputs](../tests/synthetic/test_synthetic_scoring_input_boundary.py)
and [Store/CLI rejection](../tests/synthetic/test_synthetic_rank_input_boundary.py).
The new pair returned `155 passed in 24.28s`; separate control/snapshot/
missing-severity integration passed 188 cases. Initial failing checks and test
fixture relationship corrections are retained in decisions CLAIMS-27/28. Original
numeric, missing-data and control assertions were retained, not loosened.
These synthetic/mocked checks do not demonstrate real integrations. The disjoint
worker hit a usage limit and was closed; parent implemented/reviewed both paths.
Full Ruff and guarded Pyright passed; the complete gate is pending for this edit.

During verification, a separate synthetic diagnostic showed that matching the
finding owner was insufficient: an explicit CVE not named by that finding still
received a priority. The in-flight gate was interrupted, not reported as passed.
Two red tests reproduced this. Scoring now requires explicit CVE membership in
the finding's own canonical identifier tuple and rejects container laundering;
valid CPE-based matches remain supported without pretending the scanner named
them. A remediation fixture now names the explicit CVE it deliberately uses;
all original numerical-equality assertions remain. Verification is restarted on
the final tree rather than borrowing the interrupted run's partial result.

The stored quote-type matrix subsequently reproduced eight decoder crashes from
truthy non-string evidence. Quotes are now checked before Feature construction,
without replacing their raw text. Twenty new role/exposure/control/manual cases
verify controlled failure, empty CLI stdout and unchanged SQL state. The previous
gate was interrupted for this repair too; neither partial run is a passing gate.
The final boundary/remediation integration returned `198 passed in 60.68s
(0:01:00)`. Full Ruff (285 files) and guarded Pyright passed again. The complete
gate is restarted with fresh input fingerprints below.

VERIFIED complete local gate, 19 October: installed Python 3.12.10 executed
`-u -B scripts/check.py` with temporary PYTEST_ADDOPTS appending
`-p no:hypothesispytest -q --durations=8 --tb=short`, restored afterward:

```text
PASS    ruff lint
285 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11502     66    99%
Required test coverage of 95% reached. Total coverage: 99.43%
3986 passed, 520 subtests passed in 893.17s (0:14:53)
PASS    pytest + coverage
GATE PASSED
```

Zero failures/skips. Whole-package 95% floor/socket guard retained; no project
test exclusions. Pyright used the installed guarded direct launcher, not its
updater wrapper. The longest tests were two role-feature ablations at about 46
seconds each; the complete gate took almost 15 minutes, not a stuck terminal.
The 182 added synthetic cases comprise 144 direct-scoring and 38 Store/CLI cases.
Relative to 40.20: 138 added statements, one additional miss, same rounded
99.43% aggregate coverage. Scoring is 284/284 covered statements; that is not
proof of every branch, source authenticity or risk effectiveness.

Before documentation-result edits, pre/post fingerprints matched: 294 scoped
inputs `1b9a94bbf7ff31b5b096daed9581098355381c6293b05d010b7b7018e67085db`;
403 tracked/nonignored inputs
`831f6ecf7d97d4b16eec16f5836a16f40550900dfc88618166821375fbd6ed34`.
Only existing documentation was updated afterward and checked separately.

VERIFIED local product smoke check, at the user's request: the installed runtime
started `-u -B -m vulnassess --db data/vulnassess.db --config config ui --run
scanme-2026-09-24 --port 8765`. Any PostgreSQL override was removed only from
the launched child environment to keep this SQLite check local; no secret was
printed or changed. Output was `VulnAssess: http://127.0.0.1:8765/` and the
listener bound only 127.0.0.1. In the actual browser, the stored overview showed
two services/zero findings, context and explicit coverage limits; stages/canvas
navigation worked and browser error logs returned `[]`. These are saved records,
not a fresh scan. The feed nodes explicitly said test fixture only. No model,
scanner or publisher call was launched; this is not an end-to-end integration
pass. The overview screenshot is an ignored operational artifact under data/.

STATUS: increment locally verified; full goal active. BRANCH / COMMIT:
codex/coverage-95, baseline 6f523f6 plus preserved uncommitted work. BUILT / CHANGED:
private guards in scoring/store, snapshot error context, two new synthetic suites,
correctly bound existing fixtures and existing references. DECIDED / DECISIONS:
CLAIMS-27/28 reject malformed data before scoring instead of coercing or repairing
history. EVIDENCE: actual local gate/browser checks and synthetic/mocked inputs,
not real scanner/feed/model validation. MISSING: completed human-captured Nikto
JSON/provenance, .pre-commit-config.yaml and approved pre_commit runtime.
DEFERRED / NEXT: explanation fidelity, historical-policy identity, real integration
captures and independent standards/empirical evaluation. No commits or pushes.

### 40.22 Bounded rationale wording and fact-specific quotation

PROJECT.md stages 5/7 require explanations not to overstate their evidence.
TESTED WITH MOCKS: the new [fidelity suite](../tests/synthetic/test_synthetic_rationale_fidelity.py)
initially returned 31 failures/nine passes. Formatting, a reachable quote and
number checks were not enough to reject current-compromise assertions, missing
controls promoted into no protection, contradictory context, or an EPSS
percentile promoted into an absolute exploitation probability.

The [rationale validator](../vulnassess/explain.py) now recognises bounded typed
fact-slot sentence forms. Unsupported wording/relationships fail closed; a title
can be quoted as recorded data but cannot supply arbitrary conclusion words.
Each used factual slot needs a complete supporting quote from its own issued
evidence block. Rewrites are inferred, not promoted to observation. Accepted
validation metadata keeps the policy version, used slots and a detached copy
of checked claims/citations under the existing open validation mapping. Invalid
output becomes a Needs review template fallback, not partially displayed model
text; audit hashes/decisions remain. Format failures return before grammar work.
The 600-token/4096-context bounds accommodate full-block citations; they are
authored limits, not a claim of observed real-model completion or latency.

This is deliberately not a general natural-language entailment engine or a
validation of every AI path. The supported rationale-only forms still permit
faithful model wording; unsupported paraphrases fall back. Real-model utility,
false-rejection rates, source authenticity and context-inference accuracy require
independent evidence. It does not retroactively validate old saved prose.

[Shared threat wording](../vulnassess/score_facts.py) now distinguishes a matched
CVE's dated KEV listing from compromise of the target. EPSS wording identifies
relative rank and rounding, not absolute probability or low likelihood. New
deterministic reasons use that description too; existing stored text and all
canonical numbers remain unchanged. Existing positive fixtures were corrected
to use supported statements while retaining their attribution/immutability
assertions. Dedicated final tests returned `84 passed in 0.44s`; an earlier
broader consumer selection passed 272 cases/424 subtests. The complete final
gate passed 4,071 cases/520 subtests at 99.42% Python statement coverage;
CLAIMS-29 records its matching pre/post fingerprints, alternatives and limits.

The first full attempt found one older test requiring the literal behind a
synthetic filter; it was interrupted, not passed. The replacement retains the
vendor signal, requires unverified applicability/mitigation, and proves the
original score JSON unchanged. A further red test exposed that I2's warning was
only tested on the old prompt builder, not the structured call actually used.
That structured request now puts untrusted data follows before all seven
envelopes. Final focused integration returned `258 passed, 424 subtests passed
in 8.11s`, including 85 dedicated cases. The complete gate restarts on the final
tree; no real model or new scanner was executed. That restarted run completed
with `4071 passed, 520 subtests passed in 564.94s (0:09:24)` and `GATE PASSED`.
The later source-switch checkpoint below also includes these rationale repairs.

### 40.23 Runtime source switch and open integration gaps

VERIFIED in the local browser: Refresh changed the badge to STORED ASSESSMENT
while leaving simulated completed nodes and the simulated execution rail.
The actual JavaScript loader now invalidates the preview sequence, clears its
display overlay and inspector, and renders the stored source or an unavailable
state. Refresh refuses to disrupt an actual live scan or stored-analysis batch.
Raw evidence, prior stage objects and canonical scores are not rewritten.
Eight fake-DOM regressions failed before the repair; all pass afterwards.
The browser transition was rechecked after reloading the changed client.

VERIFIED final command: `python -u -B scripts/check.py` returned clean Ruff
lint/format, guarded offline Pyright with zero diagnostics, and:

```text
Required test coverage of 95% reached. Total coverage: 99.42%
4079 passed, 520 subtests passed in 757.82s (0:12:37)
GATE PASSED
```

The 296-file scoped and 405-file complete working-input fingerprints matched
before/after execution. CLAIMS-30 retains hashes and the earlier red test result.
This gate is not a real scanner/provider integration or JavaScript coverage claim.

Actual read-only runtime inspection also reproduced an open blocker:
`load_saved_cve_case` raised `Multiple saved captures have unknown chronology;
recorded capture time is required`. The Saved assessments browser page showed
`No saved review checkpoints yet` although legacy capture files exist locally.
Explicitly inspecting `assessment-40tb2mgg` verified its retained local file
hashes and recomputed one retained CVE-2022-0543 finding at 100 / Critical using
the current scoring function. Its capture timestamp is absent. This is historical
component processing, not a successful automatic replay, fresh scan, current
publisher lookup, AI invocation, source authentication or completed user journey.

Live capture files, canonical SQL assessments and printable reports still use
separate paths. A coherent persistent lifecycle and explicit legacy-capture
selection remain unfinished; do not invent chronology or force module completion.
Real Nikto capture/provenance and approved pre-commit prerequisites remain missing.
The separate score-to-explanation context-binding diagnostic also remains open.

### 40.24 Minimal website metadata and whole-tree verification

The existing human-approved HTTP follow-up now uses [website_metadata.py](../vulnassess/website_metadata.py), a pure bounded interpreter. It retains status, declared media family, security-header observations, cookie-attribute counts, redirect category and challenge presence. It discards cookie names/values, redirect URLs, arbitrary header values, policy nonces and bodies before saving. The retained bytes are explicitly a metadata projection, not a complete wire response. Original evidence files remain immutable.

The output explains response-specific precautions without inventing a CVE, missing application authentication, or a score. Quoted ambiguous cookie attributes remain unverified. Each statement has a server-issued model citation; the request group is included whole or reported omitted. Approved supplemental evidence can support zero-finding precautions without unrelated service citations. This does not add probes to existing scan plans, follow redirects, inspect virtual hosts, validate HTTPS policy, or crawl a site. TLS/TCP probes retain their existing boundaries.

The new synthetic suite has 33 cases; the final focused selection passed 202 cases. Network/model behavior was mocked. The complete command `python -u -B scripts/check.py`, with invocation-local `-p no:hypothesispytest -q --durations=8 --tb=short`, returned:

```text
PASS    ruff lint
292 files already formatted
PASS    ruff format
0 errors, 0 warnings, 0 informations
PASS    pyright
TOTAL                                 11784     79    99%
Required test coverage of 95% reached. Total coverage: 99.33%
4194 passed, 525 subtests passed in 967.38s (0:16:07)
PASS    pytest + coverage
GATE PASSED
```

The 410 tracked/nonignored input fingerprint matched before/after the gate: `622f922b5fbed4b0580e8fd6d56a5304728201fe86f9465fbda4fc00e649d840`. Only documentation was edited afterward. WEB-01 in [decisions.md](decisions.md) records the interrupted earlier attempt and actual quoted-attribute failure. The full console output is retained under ignored `data/verification/website-metadata-final-gate-2026-10-19.log`.

This tree also contains the retained-score-context explanation guards, five legacy HTML capture views and the planet-effect resize repair. Their full-gate inclusion does not establish historical capture authenticity, a completed replay/SQL/report lifecycle, independent context/model accuracy or a current real website assessment. Backend startup on loopback port 8765 was verified; browser inspection was blocked by browser policy and no visual pass is claimed. No external scanner, provider or publisher was called. A reviewed real HTTP capture/provenance and the existing Nikto/pre-commit prerequisites remain missing. No new Markdown file, dependency, scope change, commit or push.

## 41. Stage-by-stage implementation and acceptance checklist

This is a maintainer's dependency checklist, not an instruction to run every operation. The inputs below must exist before a stage can make its corresponding claim. A missing prerequisite should produce a truthful unavailable/not-applicable/review state, not fabricated evidence.

### 41.1 Target intake and deterministic authorisation

- **Input:** submitted address or URL, validated scope configuration, and any applicable explicit target metadata.
- **Owner:** `settings.py`, `target_intake.py`, and the selected runner/server entry point.
- **Output:** a permitted, pinned address and an explanation of the authorisation decision.
- **Acceptance:** refuse the canary and disallowed addresses before scanner execution; do not accept a hostname merely because one DNS result is permitted.
- **Review question:** did this path use the same target identity when approving, executing, importing, and retaining evidence?
- **Not established:** legal authority, ownership, or safe behaviour of a remote service. Configuration is an application gate, not proof of permission from a third party.

### 41.2 Scanner readiness, plan, and execution

- **Input:** permitted target, installed executable/runtime, fixed supported profile, and explicit approval where required.
- **Owner:** `orchestrator.py`, `runner.py`, `live_assessment.py`, and `scan_plans.py` for AI-proposed plans.
- **Output:** a bounded command result, raw artifact, tool/profile identity, exit status, and coverage.
- **Acceptance:** retain useful baseline observations when an additional requested check fails, but do not call requested coverage complete. Require re-approval when an approved plan's binding changes.
- **Review question:** does the UI explain the difference between not applicable, missing tool, failed execution, and not part of this mode?
- **Not established:** comprehensive discovery, safe operation on arbitrary production systems, or that an installed tool is launchable by the server process.

The CLI orchestrator and browser live runner are related but not identical. Do not use a profile, timeout, or completion guarantee from one as evidence for the other.

### 41.3 Parse, normalise, and preserve evidence

- **Input:** a supported bounded report with matching target identity.
- **Owner:** `readers/`, `schema.py`, `pipeline.py`, and `nessus_import.py`.
- **Output:** hosts, services, findings, stable identifiers, and provenance linked to raw records.
- **Acceptance:** reject malformed/oversized input; preserve source records; a successfully imported zero-finding report is not interchangeable with no imported report.
- **Review question:** does each finding point to the actual tool, file, record index, host, and run?
- **Not established:** that the scanner's conclusion is true. Normalisation makes evidence consistent, not infallible.

The live canonical payload can exist in memory and retained files without becoming the selected recorded database assessment. A node titled “Normalize & store” must not be used to infer a database import that did not occur.

### 41.4 CVE association and intelligence

- **Input:** finding/service evidence, supported CVE/CPE associations, and approved snapshots or the applicable targeted publisher path.
- **Owner:** `intel.py`, `intel_online.py`, `intel_status.py`, and store cache/history helpers.
- **Output:** bound enrichment records, matching traces, source dates, freshness information, and explicit unavailable fields.
- **Acceptance:** do not treat unrelated historical cache rows as freshly reviewed matches. Preserve probability/percentile distinctions and the limited scope of a targeted lookup.
- **Review question:** was this CVE named by a scanner or inferred by a supported product/version rule, and what evidence could contradict the association?
- **Not established:** that the target is exploited, that a version banner accounts for backports, or that a current global cache timestamp means every row was refreshed.

### 41.5 Canonical context and finding-specific eligibility

- **Input:** observed services/banners, finding evidence, configured rules, and separately labelled approved metadata.
- **Owner:** `context.py`, `context_facts.py`, and `control_applicability.py`.
- **Output:** role, exposure, control features, confidence, evidence quotes, and recorded eligibility/withholding decisions for scoring.
- **Acceptance:** unknown controls remain unknown; an observation from a different endpoint cannot silently protect this finding. Learned/model sources remain outside canonical context activation.
- **Review question:** is a displayed control merely observed, or was it actually eligible to change this particular calculation?
- **Not established:** complete network topology, verified business importance, exploit prevention, or contradiction-aware temporal reasoning over all signal sources.

### 41.6 Deterministic priority and explanations

- **Input:** a finding, selected enrichment where available, eligible context, and validated weights.
- **Owner:** `cvss31.py`, `scoring.py`, and the recorded/live caller.
- **Output:** supported numerical priorities with complete breakdowns, or an explicit missing-severity/unscored condition in the newer in-progress path.
- **Acceptance:** same valid inputs produce the same numbers; no model-selected input or output changes the calculation. Missing information is not evidence of Low severity.
- **Review question:** can the number be reconstructed, including native fallback, Environmental changes, EPSS treatment, KEV effect, and weights identity?
- **Not established:** a calibrated probability of compromise or a scientifically validated ranking improvement.

Retain three different quantities: total findings, findings with supported scores, and findings without supported scores. An unscored finding is still a finding. A lack of a number is not a reason to omit it from investigation.

### 41.7 AI interpretation and publication

- **Input:** a bounded evidence case with server-issued identifiers and existing canonical values.
- **Owner:** `analyst.py`, `explain.py`, `ai_boundary.py`, and provider transports.
- **Output:** a validated structured assessment, provider-unavailable outcome, or Needs review decision.
- **Acceptance:** unknown identifiers, unsupported numbers, invalid schema, changed scores, and instruction canaries cannot become published valid prose. Availability fallback must not bypass a safety rejection.
- **Review question:** does the model's sentence follow from its citation, rather than merely reference an existing record?
- **Not established:** independent verification of meaning, zero hallucinations, a complete multi-agent debate, or a universal injection defence.

Transport success, schema success, evidence alignment, and semantic correctness are different checks. Do not compress them into “the AI worked.” Preserve the exact validated/rejected/unavailable outcome and the scope of any batch coverage.

### 41.8 Retain, report, compare, and evaluate

- **Input:** bound assessment records and artifacts, plus suitable comparison inputs or independent truth when applicable.
- **Owner:** store/repository/history modules, `report.py`, `rescan.py`, `cohort.py`, `evaluate.py`, and `experiments.py`.
- **Output:** readable assessment artifacts, hash-checked retained views, bounded comparison candidates, or explicitly qualified research metrics.
- **Acceptance:** distinguish a new scan from replay, a refresh from a capture, a candidate fix from a verified fix, and synthetic tests from independent effectiveness evidence.
- **Review question:** can another reviewer recover the relevant inputs, limitations, and actual comparison denominator?
- **Not established:** authenticated approvals, externally anchored artifact integrity, a backup of ignored runtime data, or successful research hypotheses without real judgments.

## 42. Developer onboarding and release-readiness handoff

### 42.1 Identify the correct checkout before changing anything

The checkout documented here is `vulnassess-current` under the supplied `DE_Project` workspace. The outer directory and other nested checkouts contain older material. Read the current branch, HEAD, and dirty state before assuming a fix is absent or a GitHub branch contains it.

The baseline commit is `6f523f61685fc7dbaede26ad81d903813017607d`; the documentation describes additional uncommitted files. A commit hash alone therefore does not reproduce the entire documented working tree. Preserve the diff and new files when handing off, and do not overwrite existing work to make a checkout look clean.

### 42.2 Trace behaviour through a real entry point

For a browser problem, follow the UI action to the server route, target/approval validation, live or recorded pipeline, event/result payload, and rendered consumer. For a CLI problem, start with argparse and its handler, then the pipeline/store operation. Do not repair only a label when the underlying state is wrong, or only the backend when the browser rejects its new event shape.

Read one finding end to end using section 37. Then inspect the failure classes in section 38 and the current cracks in section 40. This is more reliable than treating the largest module or the most visible graph node as the whole system.

### 42.3 Keep the fixed boundaries distinct from implementation drift

Before extending a feature, inspect [contracts.md](contracts.md), [the operating instructions](../.github/copilot-instructions.md), and relevant approved entries in [decisions.md](decisions.md). A proposed roadmap, old comment, existing optional transport, or permissive tool environment is not approval to change authorisation, canonical schema, dependencies, numeric policy, or data sharing.

Known specification drift should be resolved through the required review process rather than concealed. Examples include the package layout and dataclass implementation, older CVSS v4.0 language versus the current v3.1 Environmental engine, and local-only requirements versus optional online source paths. This reference makes those differences inspectable without rewriting the governing requirements.

### 42.4 What a release claim still needs

A defensible release handoff needs all of the following, not merely high statement coverage:

1. A frozen, identified source/test/configuration tree and a complete passing local gate after the final implementation change.
2. No failing tests hidden behind an old green count, new exclusion, weakened assertion, or coverage-only success.
3. Explicit disposition of open defects, including H1 provenance eligibility, while preserving the positive and negative regressions for the repaired severity-basis, chronology, protocol, and summary boundaries.
4. Matching frontend/backend contracts for partial results, unscored findings, replay, and validation failures.
5. Separately labelled real integration evidence for each advertised scanner/provider path; missing fixtures remain missing until genuinely supplied.
6. Resolved policy/interface approvals where a capability exceeds the standing contract.
7. Clear migration/compatibility handling for old saved results; newly strict validation must not silently rewrite their evidence or numeric history.
8. A backup plan for operational artifacts that Git normally ignores, without publishing secrets or sensitive raw data.
9. Independent expert/model/grouping evidence before claiming research effectiveness, not a synthetic example promoted into ground truth.
10. An exact account of what was committed, pushed, deployed, and actually exercised. Those are separate events.

This documentation task provides the reference and accessible guide. It does not claim to satisfy that release checklist or finish the active engineering audit. The next engineering handoff is the smallest pending implementation repair with its acceptance evidence, not a promise that every roadmap item is already complete.

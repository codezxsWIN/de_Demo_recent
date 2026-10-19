# Context Is Not Free: Automatic Inference of Deployment Context for Risk-Based Vulnerability Prioritisation

Prototype design update, 2026-09-06: evaluated ranking is the primary deliverable; the tool is its
vehicle. All LLM use and re-scan are deferred. The literature/novelty assertions below require source
review and are not new verification results. The five-day plan does not authorise invented inputs.

## Statement

Vulnerability assessment pipelines prioritise findings by technical severity — typically the CVSS score
attached to a matched CVE — yet technical severity is not organisational risk. The scoring ecosystem
already recognises this, but its components are split along a line no current tool bridges
automatically: CVSS v4.0's Environmental metric group can express deployment context (asset criticality,
exposure, reachability, compensating controls) but only when that context is supplied manually, while
EPSS and the CISA Known Exploited Vulnerabilities catalogue supply exploitation likelihood but know
nothing about the organisation's assets. In practice the manual context is widely reported to go
unpopulated and, where entered, goes stale as the network and threat landscape change — so a CVSS 9.8
on an isolated test host is triaged identically to the same CVE on an internet-facing production
database, producing alert fatigue and misallocated remediation effort. Commercial risk-based platforms
partially close this gap, and at least one derives asset criticality automatically, but these methods
are proprietary, opaque, priced for enterprises and dependent on cloud-hosted asset inventories.

To our knowledge, no open, transparent method infers deployment context — asset role, exposure,
reachability and compensating controls — from the reconnaissance and scan evidence an assessment
already collects, operating on findings consolidated from multiple scanners, and fuses it with CVSS,
EPSS and KEV signals in an auditable model in which every inferred feature carries a confidence and the
scan evidence supporting it, the language model explains but never computes the score, priorities are
re-evaluated on every scan, and the ranking is delivered as an ordered, actionable remediation plan —
executing entirely on local infrastructure.

## In one sentence

Scanners rank by a score that is the same everywhere; we infer where each weakness actually sits and
whether attackers use it, and rank by that — automatically, transparently, offline.

## Research questions

- RQ1 Inferability: how accurately can role, exposure and controls be inferred from Nmap/ZAP evidence alone?
- RQ2 Ranking quality: does context-inferred ranking agree more closely with expert triage than CVSS-only
  and CVSS+EPSS?
- RQ3 Efficiency: how much shorter is the "critical" queue at full recall of expert-critical findings?
- RQ4 Attribution and stability: which context features drive the gain (ablation), and how stable are
  ranks across repeated runs?

## Hypotheses — pre-registered; each may fail, and a failure is a result

- H1 Rule-based inference reaches >= 0.85 role accuracy and >= 0.95 exposure accuracy on the lab set.
- H2 Mean per-expert Kendall's tau-b (tie-aware) exceeds CVSS-only by >= 0.20 and CVSS+EPSS by >= 0.10.
- H3 Critical queue at full expert-critical recall is >= 40% smaller than under CVSS-only.
- H4 Removing any single context feature lowers tau; removing KEV changes at least one band.

Weights, cohort selection, tie policy and relevance mapping must be frozen and published before
expert rankings are collected. These are predeclared hypotheses, not evidence of external registration
or achieved results; no post-label tuning is allowed to rescue H2 or the golden example.

## Evaluation protocol

Primary metric: per-expert Kendall's tau-b, with the mean of defined per-expert values reported for H2.
Practitioner headline: the smallest tie-inclusive queue retaining each expert's entire critical set
(H3). Secondary: NDCG@10 using a frozen relevance map; not whichever metric favours the new method.

Accept N>=1 experts through the same experts[] format. Each expert supplies a pseudonymous ID,
tied ranks and a critical/not-critical label for every finding in the same cohort. Target three,
with two as the minimum for inter-rater evidence, not the minimum for running the evaluation.
For N>=2, present tie-corrected Kendall's W and pairwise tau-b before method comparisons. For N=1,
do not compute W; print "single-annotator study — inter-rater agreement not available" and continue
the individual comparisons. With N=0 or missing judgments, report the missing truth explicitly.

Plan for 20-50 findings and confirm after inspecting genuine captures. If sampling is needed, freeze
a seeded CVSS-band-stratified cohort before seeing expert labels and publish its raw/unified ID map.
The suggested 30-80 lab yield is only a planning estimate, not a measured fixture count. Preserve
ties for evaluation even when stable finding IDs order equal scores in JSON. Report undefined metrics
and evaluation coverage explicitly; no critical labels or constant ranks must not manufacture a zero.

Missing EPSS remains missing: compare the environmental-only fallback against equally disclosed
baseline policies and report a complete-data sensitivity analysis. Include context and threat
ablations so an apparent gain cannot be attributed to context merely because KEV was added.
Confidence/false-positive flags do not remove or down-rank findings; judging their correctness needs
separate false-positive labels, not critical/not-critical labels. Report negative results and the
limitations of a small, lab-only cohort and one to three experts.

## Evidence the problem is real

- CVSS v4.0 itself defines Environmental metrics for exactly this purpose and leaves them to the
  consumer (FIRST, CVSS v4.0 Specification, 2023).
- About 6% of published CVEs have ever been exploited in the wild; half of those were observed in fewer
  than 0.02% of organisations (Cyentia Institute and FIRST, A Visual Exploration of Exploitation in the
  Wild, 2024).
- Equifax 2017: CVSS 10.0 flaw, fix available two months, one internet-facing portal (US GAO-18-559).
  WannaCry / NHS 2017: fix available two months, hospital systems on an ordinary patch list (UK NAO HC 414).
  Log4Shell 2021: identical 10.0 on thousands of instances, score useless for ordering (CISA AA21-356A).
- Prioritisation and explainability listed as unresolved (Malkawi and Alhajj, Machine Learning and
  Knowledge Extraction, 2026); CAVP adds temporal signals, not deployment context (Jung, Li and Bechor,
  Computers & Security, 2022); LLM-triage studies evaluate cloud models only (Al Haddad et al., arXiv
  2510.18508, 2025).

## Contributions

- C1 An open method inferring deployment context from scan evidence, with confidence and verbatim
  evidence per feature.
- C2 A standards-aligned deterministic score: auto-populated CVSS v4.0 Environmental metrics fused with
  EPSS and KEV.
- C3 An evaluation protocol: expert rankings with inter-rater agreement, two baselines, ablation,
  repeated-run variance.
- C4 A working, fully offline, open-source implementation.

## Scope exclusions

Attack-path chaining; post-remediation verification; adversarial manipulation of context via spoofed
banners (named limitation); autonomous exploitation.

## Contributors to this statement

Arsh Shaikh, Ananya Kapote, Akshay Damle (core); Maanya Oberoi (continuous re-evaluation, actionable
plan); Ananya Navani (evaluation rigour); Shravani Shinde (scope and safety framing).

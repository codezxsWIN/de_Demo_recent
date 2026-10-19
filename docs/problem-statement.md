# Context Is Not Free: Automatic Inference of Deployment Context for Risk-Based Vulnerability Prioritisation

Research specification supplied on 2026-09-06. Hypotheses and contributions below are proposed
and falsifiable, not measured outcomes or evidence of a completed implementation. The
[project brief](PROJECT.md), [fixed contracts](contracts.md) and [security boundary](security.md)
remain binding.

## Statement

Technical severity is not organisational risk. A severity-first workflow can assign the same
CVSS base score to a flaw on an internal test host and on an internet-facing production database,
even though the operational priorities differ. CVSS Environmental metrics can express selected
deployment-specific exploitability, impact and security requirements, but the standard does not
itself discover trustworthy context. Collecting and maintaining that context requires inventory,
inference, validation, provenance and expert review. Context is therefore not free: a method must
show that the context it adds improves prioritisation enough to justify its complexity.

EPSS supplies per-CVE exploitation probability and percentile; CISA KEV records known exploitation.
KEV membership is not a probability, and neither signal by itself establishes an asset's role,
business importance, exposure or actual compromise. Asset-aware commercial systems may already
automate parts of this process. Their capabilities and the prevalence of unused or stale
Environmental metrics require evidence; this project does not assume that no existing tool
bridges the gap or that every alternative requires cloud processing.

The research investigates an open, transparent method that infers asset role, exposure,
reachability and observed compensating controls from the reconnaissance and scan evidence an
assessment already collects. It consolidates findings without losing their source records and
combines the inferred context with CVSS, EPSS and KEV through a deterministic, published formula.
Every inferred feature carries confidence and a verbatim evidence quote, or an explicit absence
of observation. Every priority exposes its inputs and rationale. Assessment processing is
designed to run locally with reviewed, human-provided artifacts and no cloud calls at runtime.

The candidate novelty is the combination of evidence-derived context, transparent inference,
auditable ranking and local-first reproducibility. A scoped literature and implementation review
must establish which parts are new; an unsupported universal claim that no such method exists
would not establish novelty. The prototype uses rule inference and template reasons. Future LLM
wording must be validated and cannot compute scores or supply ranking inputs without the required
policy approval. Recomputing ranks from a new approved evidence snapshot is not proof of a fix;
post-remediation re-scan validation remains deferred.

## In one sentence

Infer where a weakness sits from the evidence already collected, combine that context with
per-CVE exploitation evidence, and test whether the resulting priorities improve expert triage:
automatically, transparently and offline.

## Research questions

- **RQ1 - Inferability:** how accurately can role, exposure and controls be inferred from Nmap/ZAP evidence alone?
- **RQ2 - Ranking quality:** does context-inferred ranking agree more closely with expert triage than CVSS-only and CVSS+EPSS?
- **RQ3 - Efficiency:** how much shorter is the critical queue at full recall of expert-critical findings?
- **RQ4 - Attribution and stability:** which context features drive any gain under ablation, and how stable are ranks across repeated runs?

## Predeclared hypotheses

Each hypothesis may fail; failure or an inconclusive result must be reported. These are the
user-supplied targets, not claimed successes:

- **H1:** rule-based inference reaches >=0.85 role accuracy and >=0.95 exposure accuracy on the lab set.
- **H2:** mean per-expert Kendall's tau-b exceeds CVSS-only by >=0.20 and CVSS+EPSS by >=0.10. These are absolute tau-b differences, not percentage improvements.
- **H3:** the critical queue at full expert-critical recall is >=40% smaller than under CVSS-only, using the predeclared aggregation below.
- **H4:** removing any single context feature lowers tau-b; removing KEV changes at least one band. Report absent or inactive features and an unmet hypothesis rather than selecting new data to force a change.

Intended preregistration is a requirement, not a status asserted by this document. Before expert
rankings are collected or inspected, freeze and publish the hypotheses, weights, mappings,
missing-data policy, cohort selection, tie handling and metric definitions. Record a reviewable
revision, timestamp and content hashes, and a registration identifier if an external registry is
used. No such approval, freeze record or external registration is fabricated here. Necessary
post-freeze amendments must be logged and distinguished from the original confirmatory analysis.

## Evaluation protocol

The evaluated ranking method is the primary deliverable; ingestion and reporting make the
evaluation real. Compare all methods using the same declared findings and data availability.
Preserve unmatched findings and disclose any non-comparable cases rather than silently dropping
difficult records. Publish the mapping from raw IDs to grouped findings.

- **Primary:** per-expert Kendall's tau-b, preserving expert and score ties, plus the mean of defined per-expert values for H2. Stable-ID sorting of output must not manufacture strict ranking preferences.
- **Practitioner headline:** the shortest tie-inclusive prefix containing the expert's entire critical set, not a count of findings in a fixed Critical band.
- **Secondary:** NDCG@10 using a predeclared relevance map, ideal ordering and score-tie policy. Do not select whichever metric favours the proposed method after observing results.

For each expert, H3's reduction is `100 * (queue_cvss_only - queue_context) / queue_cvss_only`.
Report each result and the mean of defined per-expert reductions as the H3 summary. An empty
critical set or zero baseline queue makes the reduction unavailable, not zero or 100%. Report
negative reductions as regressions. Expose the denominator and the number of experts included in
every aggregate. Undefined correlations, including degenerate tied rankings, stay explicit.

Target three practitioners, with two as the floor for inter-rater evidence, while supporting
N>=1 through one judgment format. For N>=2, present tie-corrected Kendall's W before method
comparisons; report its unavailability when the data are degenerate. For N=1, omit W, state the
single-annotator limitation specified in the [prototype DESIGN](DESIGN.md),
and continue defined individual comparisons. N=0 or missing judgments is missing truth, not a
successful evaluation. Expert identities and eventual panel size are logistics, not architecture.

Plan a 20-50-finding pilot after inspecting genuine captures. Freeze any seeded, stratified
sampling before expert labels. H1 requires independently supplied host/context truth: repeated
findings from one host are not independent host-label observations. Report the sample unit,
class balance, confusion matrices, abstention/unknown rate and coverage so selective abstention
cannot conceal difficult cases. Report context accuracy with zero manual asset tags; optional
overrides do not demonstrate automatic inference.

For RQ4, isolate context and threat effects through ablation and report repeated-run determinism
for identical inputs separately from changes caused by different evidence or snapshots. Report
per-expert results, supported uncertainty estimates and small-sample/lab limitations. Do not
tune and evaluate on the same judgments or promise that three experts establish generalisability.

The same CVE and feed snapshot must have the same EPSS and KEV facts on every host. Missing EPSS
must not be filled with an invented value to obtain desired bands. The nullable missing-EPSS
proposal remains subject to the existing runtime-contract review; this statement is not that ADR.

## Evidence leads requiring verification

NOT RUN: independent verification of the user-supplied bibliography and claims below. This is an
offline documentation edit, not an authorised network literature search. The entries preserve
the leads supplied by the user; they do not imply that the sources, numbers or interpretations
have been checked. Human-provided source copies or an approved review must establish exact
bibliographic details, source locations, quotations and applicability before publication.

| Source as supplied | Claim to verify, not a verified project finding |
| --- | --- |
| FIRST, CVSS v4.0, 2023 | Environmental metrics and the consumer's responsibility for assigning them; distinguish a standard's input requirements from claims about every tool's automation. |
| Cyentia Institute and FIRST, 2024 | The supplied claim that about 6% of published CVEs were exploited, with half observed in fewer than 0.02% of organisations. Verify study dates, observed population and denominators before quoting either percentage. |
| US GAO-18-559; Equifax, 2017 | The supplied CVSS 10.0/two-month-fix/one-portal example. Verify the CVE, CVSS version, dates and the causal interpretation; none of these numbers is assumed for the prototype. |
| UK NAO HC 414; WannaCry/NHS, 2017 | The supplied two-month patch and ordinary-patch-list account. Verify the report's actual findings and avoid extending them beyond the studied incident. |
| CISA AA21-356A; Log4Shell, 2021 | The supplied identical-10.0/many-instances example. Verify the advisory and score version; a common score alone does not prove that severity was useless in every workflow. |
| Malkawi and Alhajj, 2026 | The claimed remaining prioritisation/explainability gap; verify the publication and the scope of its conclusions. |
| Jung, Li and Bechor, 2022; CAVP | The claimed temporal-versus-deployment-context distinction; check the actual inputs, method and evaluation rather than inferring capability from its title. |
| Al Haddad et al., 2025 | The claim that the cited LLM-triage studies use cloud models. Verify the identified studies; do not generalise that claim to all LLM-triage research. |

Incident examples can motivate a question; they do not themselves prove that the proposed ranking
would have prevented an incident. The supplied slide deck likewise does not independently validate
these references or the research's novelty and performance.

## Intended contributions

- **C1:** an open method inferring deployment context from scan evidence, with confidence, explicit uncertainty and verbatim evidence per feature.
- **C2:** a standards-aligned deterministic score combining reviewed CVSS Environmental mappings with EPSS and KEV. Alignment and mapping assumptions must be demonstrated, not inferred from the use of a CVSS library.
- **C3:** a reproducible evaluation protocol with tied expert rankings, inter-rater reporting where defined, two baselines, ablation and repeated-run stability.
- **C4:** a working, fully offline, open-source implementation. This is an acceptance target requiring real inputs and verification, not a description of the current scaffold's completeness.

## Scope exclusions and boundaries

The initial study uses only the isolated targets in [scope.yaml](../config/scope.yaml). It is a
prioritisation experiment, not a production scanner, penetration-testing service or autonomous
remediation system. Follow the [capture guide](fixtures.md) and reviewed artifact process; do not
create scanner, feed or expert evidence to fill a missing input. Synthetic cases prove pure logic
only, and mocks prove their tested boundary rather than a real integration.

Exclude attack-path chaining, post-remediation verification, adversarial manipulation of context
via spoofed banners beyond the mandatory input safeguards (a named limitation), and autonomous
exploitation. The prototype also defers all LLM use, Nikto ingestion, automatic orchestration and
semantic merging; it uses rule context, template reasons and printable HTML. These exclusions do
not relax provenance, uncertainty reporting, the scope fence, fixed interfaces or the quality gate.

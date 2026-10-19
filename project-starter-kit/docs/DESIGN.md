# Prototype DESIGN

2026-09-06. Proposed design, not an implementation or evaluation result. Five-day planning window,
ending 2026-09-11; no dependency on a named capture owner, integrator or fixed expert count.
Serves PROJECT stages 1, 3, 4, 5 (rules), 6 and 7, with risk ranking and evaluation as the deliverable.

## Architecture and data

Human captures -> scope-checked Nmap/ZAP file adapters -> canonical findings and SQLite -> offline
NVD/EPSS/KEV -> evidence-backed context -> pure ranking -> template reasons, printable HTML and evaluation.
Use existing provenance, UUID5 identity and last-seen-only upserts. Preserve source findings; derived
groups require the same CVE, host, service and affected instance. A shared CWE alone gives only a
possible-duplicate link. No semantic merge or approval gate for routine report generation.

## Formula hypothesis

Use CVSS 4.0 when supplied, otherwise native 3.1 Environmental metrics; never translate a vector.
Let E be the Environmental score (0-10) and p an observed EPSS percentile (0-1):

```text
observed p: threat_multiplier = 0.5 + 0.5*p; priority = 10*E*threat_multiplier
missing p:  threat_multiplier = None;        priority = 10*E
KEV true:   priority = max(priority, 90)
bands: Critical >=80; High >=60; Medium >=35; otherwise Low
```

Missing EPSS means the threat contribution is unscored, not a fabricated percentile; flag "no
exploitation data (EPSS missing)" and display KEV separately. Missing required snapshots fail by path.
Compare the same missingness policy and cohort across methods; report complete-data results separately.
The golden context test uses the same CVE/vector/feeds, common p and KEV=false: B >=90/Critical,
A <60/Low-or-Medium, both breakdowns printed. Common p must be >=0.80 even for E=10 to permit B>=90.
KEV=true is a separate test where both are >=90. Failure is a design result, not licence to alter evidence.

## Seven design choices

1. **Role:** weighted service co-occurrence and specific product evidence; weak names/certificate hints
   cannot outweigh contradictory observations. Keep unknown explicit. Reject LLM roles and required tags.
2. **Exposure:** successful observations from a documented vantage establish reachability; public-looking
   IPs, DNS names and redirects alone do not. Unknown visibility earns no risk reduction; record coverage.
3. **Controls:** require applicable raw evidence, not an inference that a 403 or vendor header protects
   every finding. "None observed" means no observation. Do not actively trigger controls to create proof.
4. **Confidence:** keep it separate from risk. Q6's provisional 0.20 low-evidence case is flaggable below
   0.30, never deleted or down-ranked. Freeze rules before labels; measure misflags independently.
5. **Explanation:** templates show which Environmental metrics changed and why. Recommend a fixed
   release only when the matching vendor advisory establishes it; NVD bounds alone are not patch proof.
6. **Evaluation:** one experts[] format for N>=1; N>=2 reports tie-corrected Kendall's W first, then
   per-expert tau-b (primary), critical-queue/full-recall (headline), and NDCG@10 (secondary). N=1
   omits W and states "single-annotator study — inter-rater agreement not available"; comparisons still run.
7. **Uncertainty display:** pair a risk band with evidence confidence, quotes, missing-data flags and
   per-feature contributions. A low-confidence Critical remains in the Critical queue and flagged appendix.

## Evaluation and acceptance

Proposed truth format: cohort finding IDs plus experts[], each containing a pseudonymous expert_id
and judgments[] of finding_id, rank (ties allowed), critical (boolean). Every expert covers the same
cohort; missing/duplicate IDs fail validation. Preserve score ties for tau-b; stable IDs order output only.
Use tie-inclusive full-recall cutoffs and tie-averaged NDCG with predeclared linear gain from expert
midranks. N=0 is missing truth, not a successful evaluation. Constant rankings or no critical labels
produce explicit unavailable metrics where undefined. Target 20-50 findings; freeze any stratified
sample and seed before labels. Report individual experts, agreement and limitations before averages.

Risks and checks: (1) weak context -> held-out capture review and zero-tag tests; (2) score/missingness
artefacts -> version-specific golden arithmetic, observed-value monotonicity and context/threat ablations;
(3) sparse or late labels -> N=1/2/3 arithmetic tests and honest missing-truth output, never invented experts.
The lab's expert-label collection cannot be assumed to finish within five days.

## Increments and approval boundary

D1: design, [capture guide](../../docs/fixtures.md), fixture gating and existing schema/store checks.
D2: real fixture adapters and offline feed loading. D3: reviewed context/scoring mappings and goldens.
D4: template report and desktop/print checks. D5: real-truth evaluation and reproducibility handoff.
An unavailable prerequisite blocks that increment, not the architecture. Keep every increment on a
review branch; no merge to main. No full gate pass is claimed without Ruff, format, Pyright and >=85%
source coverage. The kit's older 75% line is not permission to lower the parent gate.

PROPOSED — awaiting reviewer: nullable threat fields/returns and missing-value config; honest unknown
exposure representation; any new grouping/confidence/truth or pipeline interface. Existing contracts
remain unchanged until an integrator-plus-reviewer ADR. Future LLM role influence additionally needs
mentor approval. Defer all LLM use, Nikto, orchestration, semantic merge, re-scan, PDF export, attack paths
and security research beyond the walls. Human provisioning and captures are not run by the agent.

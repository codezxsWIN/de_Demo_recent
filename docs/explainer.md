# VulnAssess Explainer

## 1. The prioritisation gap

CVSS measures technical severity, not the complete urgency of a finding on a particular machine. Scanner labels also differ, and duplicated observations can make a queue look larger than the underlying risk. VulnAssess separates evidence collection from prioritisation so that every rank can be traced back to scanner, intelligence, and asset facts.

## 2. Inputs and normalization

Nmap, Nikto, and ZAP provide heterogeneous observations. Adapters preserve the raw source reference and map observations into a common finding schema. Normalization identifies assets, services, vulnerabilities, confidence, timestamps, and evidence without upgrading guesses into facts. Duplicate observations may be linked, but source evidence remains independently inspectable.

## 3. Intelligence

Normalized CVEs are enriched from dated, reduced snapshots:

- NVD supplies CVSS and vulnerability metadata.
- EPSS supplies an estimated probability of exploitation.
- CISA KEV supplies evidence of known exploitation.

Every enrichment records its source, retrieval or publication date, and match key. Missing intelligence remains missing rather than becoming zero.

## 4. Context

Context includes exposure or vantage, asset role, observed controls, and inference confidence. Manual environment and business-criticality tags are recorded separately from inference. Inference must cite its evidence and may return `unknown`. Per Prompt 0, the local model writes rationales only; it cannot infer a role that affects scoring. Prompt 5's conflicting LLM role fallback is deferred in `decisions.md`.

## 5. Figure 2 — why identical vulnerabilities rank differently

Figure 2 is a two-branch evidence flow:

1. An identical normalized vulnerability enters both branches with the same CVE, CVSS, EPSS, and KEV facts.
2. Branch A joins the finding to an internal test asset with low business criticality and no external exposure.
3. Branch B joins it to an internet-facing production database with high business criticality.
4. The scoring function fills CVSS v4.0 Environmental metrics, applies the EPSS percentile factor, and then applies the KEV floor.
5. Technical base severity stays constant. Only documented context mappings differ.
6. Branch B may rank higher for appropriate non-KEV inputs. If KEV is true for this CVE, both branches must be Critical because risk is at least 90.

This demonstrates that context changes priority without rewriting vulnerability evidence.

## 6. Evaluation and limits

Experts receive the same lab findings and return a full ranking plus an `expert-critical` set. The study compares CVSS-only and context-aware rankings with Kendall's tau, NDCG@10, and critical-queue reduction. Results apply to this lab and panel; they do not establish universal weights. Stage 4 may tune the hypothesis only with a recorded decision and a held-out evaluation.

## Golden two-machine example

**Candidate CVE, not yet verified:** `CVE-2012-2122`, retained from the provisional day-zero notes. No scan artifact or dated feed has been supplied, so neither applicability to the selected Metasploitable 2 image nor KEV status is established here. Confirm affected product/version and intelligence evidence before using any CVE as a golden fixture.

| Input | Machine A | Machine B |
|---|---|---|
| Vulnerability evidence | Identical confirmed CVE evidence | Identical confirmed CVE evidence |
| Environment | `test` | `prod` |
| Exposure | Internal-only | Internet-facing |
| Role | Database | Database |
| Criticality | 1 | 5 |
| Expected relation | Context-dependent Environmental score | Context-dependent Environmental score |

Prompt 7 requests Medium/Low versus Critical and printed breakdowns. Its formula also imposes `risk >= 90` whenever KEV is true. These cannot both hold for identical CVE/feed evidence with KEV=true. Do not change KEV status per host to force a desired result.

Before Prompt 7, choose confirmed evidence that supports a context-only comparison with the same non-KEV facts on both machines, and verify the resulting bands rather than assuming them. Separately test that KEV=true makes both machines Critical and print both breakdowns. Any replacement CVE or revised acceptance expectation must be recorded in `decisions.md`.

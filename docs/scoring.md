# Hypothesis — to be tuned in Stage 4

Scoring specification `prompt-7-v0` replaces the provisional day-zero weighted mean. It is taken from the supplied Prompt 7 and is not implemented by the Prompt 1 scaffold. It is a hypothesis, not a validated risk model. Changes require a decision, a version increment, and evaluation on judgments not used for tuning.

## CVSS Environmental mapping

Use a CVSS v4.0 base vector and the `cvss` package's `CVSS4` class to compute the Environmental score. When only v3.1 is available, record the original vector, translation method/version, assumptions, and translated vector; do not describe the translation as an exact equivalence.

| Condition | Environmental metrics | Hypothesis justification |
|---|---|---|
| Internal exposure and base `AV=N` | `MAV=A` | Model an internal foothold as a reduced attack surface. |
| WAF observed | `MAC=H` | Model the control as additional exploitation difficulty. |
| Authentication required and base `PR=N` | `MPR=L` | Model a need for prior authentication. |
| Role `database` or `domain_controller` | `CR=H`, `IR=H`, `AR=H` | Treat confidentiality, integrity, and availability as highly important. |
| Role `web_frontend` | `CR=M`, `IR=H`, `AR=H` | Emphasise integrity and availability of the frontend. |
| Role `workstation` | `CR=M`, `IR=M`, `AR=L` | Use moderate confidentiality/integrity requirements and lower availability requirements. |
| Environment `test` | `CR=L`, `IR=L`, `AR=L` | Reduce impact requirements for the declared test environment. |

Apply the test-environment requirements after role requirements. Other metrics inherit the base/default CVSS behavior. Record confidence, source, and evidence for every input. Manual environment/criticality tags remain separate from inferred context; criticality has no additional numeric multiplier in this formula.

These mappings are study assumptions, not universal CVSS rules: internal reachability alone does not establish Adjacent access, and WAF/auth observations do not prove that a control mitigates a particular CVE. Stage 4 must assess these limitations.

Prompt 7 will make this mapping editable in `config/weights.yaml`; the file is currently a placeholder.

## Formula

Use the EPSS **percentile**, in `[0, 1]`, not the EPSS probability:

```text
base = env_score * 10
threat = 0.5 + 0.5 * epss_percentile
         # use 0.5 when EPSS is missing
risk = base * threat
if kev:
    risk = max(risk, 90)
```

The Environmental score is in `[0, 10]`; final risk is in `[0, 100]`. Missing EPSS remains explicitly marked missing even though the formula defines a threat fallback. KEV sets a floor of 90; it is not a weighted contribution.

## Findings without a CVE

Keep every finding. Prompt 7 specifies a documented native-evidence table, with ZAP High -> 60 and Medium -> 40 as starting examples. The remaining table entries and treatment of unscored evidence must be recorded before implementing that path. Nmap and Nikto have no native severity; never invent one.

## Priority bands

| Band | Score |
|---|---:|
| Critical | `>= 80` |
| High | `>= 60` and `< 80` |
| Medium | `>= 35` and `< 60` |
| Low | `< 35` |

## Audit trail and baselines

`ScoreBreakdown` must retain the base and Environmental vectors/scores, translations, context inputs, applied mappings, EPSS probability and percentile, missing-data indicators, KEV/feed provenance, intermediate values, formula version, and band.

Prompt 10 compares `cvss_only` (base score), `cvss_epss` (base score times threat), and `ours` (final risk). Sort descending by the relevant score, with a stable finding ID as deterministic tie-breaker.

## Approved role list (Prompt 5 v0)

- `database`
- `web_frontend`
- `app_server`
- `domain_controller`
- `mail`
- `file_share`
- `iot_embedded`
- `workstation`
- `network_device`
- `unknown`

## Golden-test constraint

KEV membership belongs to a CVE in a dated feed, not to its host. With identical CVE/feed evidence and `kev=true`, both machines have risk at least 90 and must be Critical. Prompt 7's requested Medium/Low versus Critical result cannot be guaranteed by changing context alone in that case. Keep the context comparison and KEV-floor check separate, and confirm real fixture evidence before choosing a golden CVE. See `explainer.md`.

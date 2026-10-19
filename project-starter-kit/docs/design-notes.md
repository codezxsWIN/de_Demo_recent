# Design notes — reference only

> A reference design from early planning. The lead engineer may use, adapt or replace any of it.
> Only the seven walls in .github/copilot-instructions.md are binding.

When this kit is reviewed inside the existing repository, its parent security rules, fixed
interfaces and 85% coverage requirement also apply. The resolutions below are design decisions,
not approval to change a runtime contract, provision dependencies, or claim a measured result.

## A possible layout

```text
src/vulnassess/
  cli.py  errors.py  settings.py
  schema/    canonical Finding, Host, Service, ContextProfile, Enrichment, ScoreBreakdown
  adapters/  nmap_xml.py, zap_json.py (nikto_json.py deferred)
  store/     sqlite persistence
  intel/     nvd / epss / kev loaders, cve matcher
  context/   role.py, exposure.py, controls.py
  scoring/   pure: cvss_env.py, formula.py, bands.py
  report/    html.py + templates/
  eval/      metrics.py, baselines.py
tests/       fixtures/ (real, human-provided) · synthetic/ · golden/
config/      scope.yaml · weights.yaml · roles.yaml · controls.yaml
docs/
```

## A possible canonical finding

id (stable hash of host, port, protocol, tool, tool-native id, url) · host_ip · port · protocol · url ·
tool · tool_native_id · title · description · evidence (verbatim, capped) · cve_ids · cwe_ids ·
reference_urls · native_severity (None for Nmap and Nikto — they have no severity field) ·
native_confidence · first_seen · last_seen · provenance {tool, raw_path, record_index, run_id}.

## A possible inferred-feature shape

Feature { value, confidence 0-1, source rule|llm|manual, evidence verbatim or "none observed" }.
ContextProfile { host_ip, role: Feature, exposure: Feature, segment, controls: {waf, auth_required, tls,
rate_limiting}: Feature, manual: {criticality?, environment?}: Feature }.

## Possible role signals (starting points, not rules)

- database: 3306 mysql, 5432 postgresql, 1433 ms-sql, 27017 mongodb, 6379 redis
- web_frontend: 80/443/8080/8443 with an http server banner; app_server if a framework banner
  (Tomcat, JBoss, Node, Gunicorn) appears
- domain_controller: 88 kerberos + 389/636 ldap + 445 smb + 53 dns together
- mail: 25/465/587 smtp, 110/143/993/995 pop/imap
- file_share: 445/139 smb or 2049 nfs without web or database services
- iot_embedded: 23 telnet and/or embedded http banners (lighttpd, boa, GoAhead, mini_httpd, RomPager)
- network_device: Cisco IOS / JunOS / RouterOS fingerprints
- workstation: desktop OS guess with few or no server ports
Other signals worth considering: service co-occurrence, hostname conventions, TLS certificate subjects.

Prototype: rules only; all LLM use is deferred. In the full design, a local model may write the
one-line rationale and reword evidence-backed remediation under validation, without adding numbers,
IDs or URLs. LLM-sourced roles receive a fixed configured confidence, never a model-emitted one (W4).
A later role fallback returns a role LABEL only. This remains proposed future work: the label can
still change Environmental scoring, so fixed confidence alone does not satisfy the parent rule
against LLM-derived scoring inputs. Mentor approval of that wall change is required before use.

## Possible exposure signals

Public IP (not RFC1918 / loopback / link-local / CGNAT) · scope.yaml vantage tag · public DNS name ·
redirect chains · cloud-provider or load-balancer headers.

## Possible control signals

WAF: header/cookie fingerprints (Cloudflare, Akamai, F5 BIG-IP, AWS WAF, ModSecurity, Imperva).
auth_required: 401/403 on root, login forms. tls: certificate observed on 443/8443. rate_limiting: 429s.

## A possible scoring shape (a hypothesis, not a design)

1. Take the CVE's CVSS v4.0 base vector (or v3.1 if v4.0 is absent — they have separate Environmental
   metric sets; there is no translation between versions).
2. Populate Environmental metrics from the context profile, e.g. internal + AV:N -> MAV:A;
   WAF -> MAC:H; auth required + PR:N -> MPR:L; CR/IR/AR from role (database/domain controller high,
   workstation low, test environment low).
3. Compute the environmental score with the `cvss` package.
4. With an observed EPSS percentile: threat_multiplier = 0.5 + 0.5 x percentile;
   risk = env_score x 10 x threat_multiplier. Missing EPSS -> unscored threat component;
   threat_multiplier = None; rank on environmental score only (risk = env_score x 10);
   report flags "no exploitation data" and clarifies that EPSS is missing. KEV remains a
   separate observed input: if KEV, risk = max(risk, 90). Never fill a missing percentile.
5. Bands: Critical >= 80, High >= 60, Medium >= 35, else Low.
6. Findings without a CVE: a documented fallback from the tool's native severity.

The word "unscored" refers to the unavailable EPSS/threat contribution, not to discarding the
finding. Missing snapshot files still raise IntelUnavailable; an absent CVE row in a valid,
dated EPSS snapshot is the missing-value case above. Rankers must share the same missingness
policy and report their comparable-data coverage. EPSS monotonicity compares observed values;
missing is not a numeric percentile. A newly available low percentile can reduce an earlier
environmental-only priority, which must be visible rather than silently smoothed away.

Keep evidence confidence separate from the numeric risk in this prototype. Unsupported context
must not earn a compensating-control discount. The parent ScoreBreakdown.threat_multiplier and
risk() return contracts currently require floats, and weights specify a missing percentile.
The nullable design requires an integrator-plus-reviewer ADR before implementation.

## Evidence confidence and false-positive flags (Q6)

Proposed pre-evaluation heuristic v0, not a calibrated probability:

- Start at 0.50; add 0.25 for validated applicability to the observed product/version or exact
  response condition; add 0.15 for independent corroboration of the same finding.
- Subtract 0.30 only when there is neither validated applicability nor independent corroboration.
  Duplicate records from one scanner do not constitute independent corroboration.
- Flag confidence < 0.30 as "likely false positive (low-evidence heuristic)". The attainable
  weak-evidence case is 0.20, resolving the old unreachable-threshold sketch.
- Preserve every finding, original evidence and rank; confidence neither deletes nor down-ranks.
  List flagged findings in the report appendix with the actual missing evidence.
- Freeze the policy before expert labels. Measure flag precision, recall and true-finding
  misflags on independently supplied labels; expert criticality is not a false-positive label.
  A poor result is reported, not tuned away on the evaluation set.

All weights, threshold and signal definitions will live in reviewed configuration, not code.
New configuration or confidence/link fields need the parent contract's ADR before implementation.

## Possible evaluation metrics

Report tie-corrected Kendall's W and pairwise tau-b across experts first. Primary: mean Kendall's
tau-b per method against each expert, preserving ties. Practitioner headline: critical-queue size
at full recall of each expert's critical set. Secondary: NDCG@10 with a predeclared relevance map.
Baselines: CVSS-only, CVSS+EPSS. Zero-denominator metrics are unavailable, never invented zeroes.
Hand-computed check: expert [A,B,C,D], ours [A,C,B,D] -> 6 pairs, 1 discordant -> tau = 4/6 = 0.667.

Use one experts[] truth format for N>=1, with pseudonymous expert IDs and complete per-finding
rank/critical labels. For N>=2 report tie-corrected W before comparisons. For N=1 omit W and print
"single-annotator study — inter-rater agreement not available"; individual method comparisons still
run. N=0 or absent labels is missing truth. Names and actual panel size are not model/config switches.

## Duplicates, remediation and deferred validation

Keep uncertain duplicates separate with a possible-duplicate link. A shared CVE on the same host,
service and affected instance supports a derived merge; a shared CWE alone does not prove common
root cause. Retain original IDs/evidence, and compare all rankers on the same declared grouped cohort.
New grouping/link representations are PROPOSED — awaiting reviewer under the parent contracts.

Use NVD affected-version bounds plus matching Patch/Vendor Advisory references to check applicability.
Name a fixed release only when the referenced vendor evidence actually supports that release.
versionEndIncluding names an affected endpoint, not a fixed release; versionEndExcluding alone
does not prove a patch exists. Otherwise provide applicable advisory links without a release guess.
No display-approval gate is added. Prototype reasons and recommendations use templates, not an LLM.

Use offline HTML with a verified print layout, not PDF export. Re-scan remains deferred. Its future
"fixed" classification must retain service observation and comparable coverage, with either a
version change supported by remediation evidence or disappearance of CVE evidence for a reason other
than banner loss. "Not observable" is never "fixed"; a changed banner alone is not patch proof.

## Two-machine golden test (from PROJECT.md section 6)

Candidate synthetic vector, for pure arithmetic tests only and not yet scored:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N.
For the same CVE, use the same base vector and feed snapshot, including identical observed EPSS
percentile and KEV=false for the context-only comparison. Machine A has evidence-backed internal,
test/workstation context; Machine B has evidence-backed internet-facing/database context. Require
B to be Critical with risk >= 90, and A strictly lower in {Low, Medium}; print both breakdowns.
No verified inputs or passing result are asserted. Under the proposed formula and a 0-10
environmental score, observed EPSS percentile must be at least 0.80 even to make risk >= 90 possible.
Use a separate KEV=true test: the same snapshot forces BOTH machines to risk >= 90. Never vary KEV
or EPSS per host to force the contrast, equate internal with isolated, or infer absence of controls
from "none observed". If honest context cannot produce the contrast, report the failed hypothesis
and reconsider the design before expert evaluation; do not invent captures or tune on expert ranks.

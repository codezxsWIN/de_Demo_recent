# The whole idea

Design brief, not an implementation or results report. Read [DESIGN.md](DESIGN.md) for the five-day
plan and [decisions.md](decisions.md) for resolutions. The parent repository's fixed interfaces,
no-install boundary and 85% source coverage gate remain in force while this kit is reviewed here.
Interface/dependency changes are proposed for review, not applied by this brief.

## 1. What this is

An AI-Based Network Vulnerability Assessment Tool: a local-first system that scans a network, finds
security weaknesses, matches them to the public vulnerability database, ranks them by real risk to
THIS network, explains each rank in plain English, reports, and (later) re-scans to confirm fixes.
Everything runs on hardware inside the organisation. No scan data leaves it.

Design Experience project, MPSTME, SVKM's NMIMS, 2026. Nine students, one industry mentor.

## 2. The problem

Scanners produce thousands of findings ranked by CVSS severity — a score identical for the same flaw
on every machine. Three failures follow:

1. Fragmented output: several tools, each with its own format; the same weakness under different names.
2. Context-blind ranking: a 9.8 on an isolated test box equals a 9.8 on the internet-facing customer
   database. Standards allow context to be added by hand; nobody does. Threat feeds (EPSS, CISA KEV)
   know what attackers exploit but nothing about your network.
3. Unverified fixes: reports end at "here is the list".

Existing AI security tools add a fourth: they send scan output — a map of your weak points — to
cloud models, at per-use cost, and stop working offline.

## 3. The research focus

See docs/problem-statement.md. The headline contribution is the ranking layer: infer deployment
context automatically from scan evidence (asset role, exposure, compensating controls), fuse it with
CVSS, EPSS and KEV through a deterministic, published formula, deliver every rank with a one-line
reason, and prove the ranking agrees more closely with expert judgement than CVSS alone.

Test that claim rather than assume the method will win. The evaluated ranking method is the
deliverable; the scan-to-report tool is its evaluation vehicle, not an equally weighted product goal.
Everything else in the tool exists to make that layer possible and honest.

## 4. The pipeline (the deck's eight steps) and prototype scope

| # | Stage | Prototype |
|---|---|---|
| 1 | Target input — IP/domain/subnet, refused unless in scope.yaml | BUILD |
| 2 | Scan orchestrator — picks and runs the right tools | DEFER (humans run 2 commands) |
| 3 | Safe scanning — Nmap, Nikto, ZAP, non-destructive, scope-checked | BUILD Nmap + ZAP ingestion; Nikto DEFER |
| 4 | Unified result engine — one finding format, duplicates merged | BUILD (exact/ID-based merge; semantic DEFER) |
| 5 | AI security analyst — redefined, see section 5 | BUILD inference by rules; LLM parts DEFER |
| 6 | CVE intelligence — NVD (CVSS 3.1/4.0), EPSS, KEV, patch refs, offline | BUILD |
| 7 | Report — ranked, reasons, fixes, evidence, methodology, provenance | BUILD (HTML) |
| 8 | Re-scan validation — fixed / still open / regressed; posture trend | DEFER |
| — | Risk ranking (the research) | BUILD — the centre of everything |
| — | Evaluation against experts | BUILD |

## 5. Where the code deliberately differs from the slides

| Deck said | We build | Why |
|---|---|---|
| AI prioritises risks | A deterministic formula prioritises; the AI never emits a number that affects a rank | Reproducible, auditable; the research claim needs a published formula |
| AI filters false positives | Evidence-based confidence: tools agreeing and version-matched CVEs raise it; lone speculative checks are flagged, never silently dropped | Silent model drops create invisible false negatives |
| AI explains vulnerabilities | Prototype uses templates; full-design model text adds no numbers, IDs or URLs under validation | Explanations remain evidence-backed, not presumed harmless |
| — | Future role fallback emits a label only with fixed configured confidence; all LLM use is deferred in the prototype | The label still affects ranking and needs mentor approval under the parent wall |
| CVE layer: CVSS | CVSS + EPSS + KEV | Exploitation likelihood is half the story; slide to be updated |

## 6. The two-machine test — the whole project in one example

Acceptance experiment, not observed results: the same CVE, base vector and dated feed snapshot on
two machines. Compute the base score from the actual vector; do not attach an assumed 9.8 to it.

| | Machine A | Machine B |
|---|---|---|
| Inferred role | workstation / test system | database |
| Exposure | internal | internet-facing |
| Controls | Only applicable observed controls | Only applicable observed controls |
| EPSS percentile | Same observed p in [0, 1] | Same observed p |
| KEV, context-only test | false | false |
| Required risk/band | Strictly below B and <60; Low or Medium | >=90; Critical |
| Reason | Template quoting the evidence and metric changes | Template quoting the evidence and metric changes |

Both complete breakdowns must be printed. The formula needs p>=0.80 even with Environmental=10 to
permit B>=90. Real captures/vectors must establish feasibility; no passing result is claimed yet.
If consistent inputs fail the contrast, report the failed hypothesis and reconsider the design before
expert evaluation. Never change per-host EPSS/KEV or invent evidence to make a demo pass.

Use a separate same-snapshot KEV=true case: both machines must have risk >=90. "Internal" does not
mean isolated, and "none observed" does not establish that no control exists.

Missing EPSS has no threat score: threat_multiplier=None, environmental-only priority, and an explicit
"no exploitation data (EPSS missing)" flag, with KEV shown separately. Missing snapshot files are errors.
This replaces the two conflicting design defaults, but needs the parent nullable-field/config ADR
before implementation. See [design-notes.md](design-notes.md) for the unvalidated formula proposal.

## 7. Non-negotiables

The seven walls in .github/copilot-instructions.md.

## 8. What "done" looks like for the prototype

- One command runs ingest -> enrich -> context -> rank -> report -> eval on the lab and prints the
  two-machine table and the report path.
- The report shows every rank with reason, recommended fix, evidence and formula inputs.
- Evaluation supports N>=1 experts without changing its format: tau-b is primary, critical-queue size
  at full recall is the practitioner headline, and NDCG@10 is secondary. For N>=2 report tie-corrected
  Kendall's W first. For N=1 omit W and state "single-annotator study — inter-rater agreement not available".
- Produce offline HTML with a human-verified print layout; no automated PDF export.
- Assessment runs without internet after humans provide reviewed inputs; preserve isolated lab
  connectivity when capturing evidence. Missing truth yields no invented evaluation result.

## 9. Out of scope — future work, credited

Attack-path chaining (Arsh). Post-remediation verification (Maanya). Manipulating the analyst through
spoofed scan content beyond the W5 guard (Ananya N). Target-side scan-safety measurement (Shravani).
Detecting AI-driven attackers (Shravani). Autonomous exploitation: never.

## 10. Who did what

Context-aware ranking: Arsh, Ananya K, Akshay. Local-first design: Akshay. Unified findings and
evidence-based confidence: Maanya, Ananya K, Akshay. Continuous assessment: Maanya. Evaluation rigour:
Ananya N. Scan safety: Shravani. Lab, expert study, runs: Mahir, Shardul, Rudra.

## 11. Five-day planning assumptions

Plan from 2026-09-06 for a five-day window ending 2026-09-11, not the earlier November target.
The actual faculty date may be confirmed separately. Capture owner and integrator/reviewer names
are logistics, not schema fields or prerequisites for design. Use the owner-independent
[capture guide](../../docs/fixtures.md). Target three experts, seek at least two for agreement, and
support a one-annotator study honestly. A two-week expert response would arrive after this demo window;
without timely real judgments the harness can be demonstrated but H2/H3 cannot be claimed evaluated.

Work only on review branches; never merge to main. Wall/scope approval belongs to the mentor.
Fixed-interface/dependency changes require integrator plus one reviewer. Until approvals arrive, log
them as "PROPOSED — awaiting reviewer" and do not apply them. Missing capture tests use @needs_fixture
with `fixture not provided: <path>`; never manufacture files or hide missing gate tools behind that marker.

The original supplied deck is preserved at [de_ppt.pdf](../../docs/deck/de_ppt.pdf): pages 13/15 contain
methodology text, page 7 is the gap radar and page 14 the module diagram. Its percentages are slide
claims, not project measurements. "HTML report (printable)" is the proposed replacement wording; the
original PDF is not rewritten by this design task.
